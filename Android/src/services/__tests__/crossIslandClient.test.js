// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The Android client's cross-island half, driven the way the screens drive it.
 *
 * What runs here is the real thing: ForeignService, CryptoService, CryptoManager
 * and NetworkService, unlocked with a real identity key. Only the two islands
 * are stubbed — a pair of in-process servers that answer the handful of
 * endpoints this path uses and check what they are sent, so the test can fail
 * for the reason a server would fail.
 *
 * The distinction this file exists for: `crossIsland.test.js` covers the
 * PROTOCOL (foreign-dm.js, byte-identical in both clients). This covers the
 * CLIENT — the wiring around it, which is written twice and where every
 * cross-island bug so far has actually lived:
 *
 *   - minting a local DM key for a mailbox on somebody else's island, because
 *     the local path took a 404 as "create one and share it";
 *   - signing our own copy with the number of the thread it was delivered to,
 *     then verifying it against the thread it is read in and calling our own
 *     message a forgery.
 *
 * Both are asserted below, and both fail without the code that fixed them.
 */

const { ed25519, x25519 } = require('@noble/curves/ed25519');
const { hmac } = require('@noble/hashes/hmac');
const { sha256 } = require('@noble/hashes/sha2');

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import ForeignService from '../ForeignService';
import FD from '../foreign-dm';

// The React Native preset defines this; a node project does not, and the
// services log through it on their unhappy paths — where this test lives.
globalThis.__DEV__ = false;

const HOME = 'https://a.example';
const AWAY = 'https://b.example';

const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);
const unb64 = (s) => new Uint8Array(CryptoUtils.base64ToArrayBuffer(s));
const utf8 = (s) => new TextEncoder().encode(s);

// ---- the two islands ----------------------------------------------------

const home = {
  islandId: 'a.example',
  boxes: new Map(),          // thread_id -> { peer_kid, encrypted_thread_key, key_id }
  nextThreadId: 1001,
  delivered: [],             // our own copies
  // Every /crypto/dm-key touch, read or write. A mailbox has no key on this
  // island, so ASKING is already the bug: the 404 is what the local path turns
  // into "create one and share it with the peer".
  dmKeyCalls: [],
};

const away = {
  islandId: 'b.example',
  nonces: new Set(),
  mailbox: null,             // the box Bob opened for us
  delivered: [],
  down: false,
};

function json(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
    async arrayBuffer() { return utf8(JSON.stringify(body)).buffer; },
  };
}

/** The transport tag the island checks before accepting a delivery. */
function expectedTag(secretB64, threadId, ts, nonceB64, ciphertextB64) {
  const nonce = unb64(nonceB64);
  const pt = unb64(ciphertextB64);
  const digest = sha256(pt);
  const sep = utf8('|');
  const parts = [utf8(String(threadId)), sep, utf8(String(ts)), sep, nonce, sep, digest];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const msg = new Uint8Array(total);
  let at = 0;
  for (const p of parts) { msg.set(p, at); at += p.length; }
  return b64(hmac(sha256, unb64(secretB64), msg));
}

function handleHome(path, opts) {
  const body = opts.body ? JSON.parse(opts.body) : null;

  if (path === '/.well-known/wsapp-island') return json({}, 404);
  if (path === '/crypto/ed25519-key') return json({ ok: true });

  if (path === '/foreign/box' && opts.method === 'POST') {
    const tid = home.nextThreadId++;
    home.boxes.set(tid, {
      peerKid: body.peer_kid,
      ownerKey: body.encrypted_thread_key,
      keyId: body.key_id,
    });
    return json({ thread_id: tid, island_id: home.islandId, peer_kid: body.peer_kid }, 201);
  }

  let m = path.match(/^\/foreign\/box\/(\d+)\/peer-key$/);
  if (m) {
    const box = home.boxes.get(Number(m[1]));
    if (!box) return json({ detail: 'no such box' }, 404);
    box.peerWrapped = body.encrypted_thread_key;
    return json({ ok: true }, 201);
  }

  m = path.match(/^\/foreign\/box\/(\d+)$/);
  if (m && opts.method === 'DELETE') {
    return home.boxes.delete(Number(m[1])) ? json({ ok: true }) : json({ detail: 'gone' }, 404);
  }

  m = path.match(/^\/dm\/(\d+)\/delivery-secret$/);
  if (m) return json({ delivery_secret_b64: b64(new Uint8Array(32).fill(7)) });

  if (path === '/ud/dm/send') {
    home.delivered.push(body);
    return json({ ok: true });
  }

  if (path.startsWith('/crypto/dm-key')) {
    // Recorded rather than refused, so the test can say what happened instead
    // of only that something failed.
    home.dmKeyCalls.push({ path, method: opts.method || 'GET' });
    return opts.method === 'POST' ? json({ ok: true }) : json({ detail: 'not found' }, 404);
  }

  return json({ detail: `home: no route ${path}` }, 404);
}

function handleAway(path, opts) {
  if (away.down) throw new TypeError('Network request failed');
  const body = opts.body ? JSON.parse(opts.body) : null;

  if (path === '/foreign/challenge') {
    const nonce = new Uint8Array(16);
    for (let i = 0; i < 16; i++) nonce[i] = (away.nonces.size * 16 + i) & 0xff;
    const nb = b64(nonce);
    away.nonces.add(nb);
    return json({ island_id: away.islandId, nonce_b64: nb });
  }

  if (path === '/foreign/claim') {
    // One answer to every refusal, and the nonce is spent either way — the
    // island's own rule, kept here so the client is tested against it.
    const spent = away.nonces.delete(body.nonce_b64);
    const box = away.mailbox;
    if (!spent || !box || box.peerKid !== String(body.kid).toLowerCase()) {
      return json({ detail: 'forbidden' }, 403);
    }
    const ok = ed25519.verify(
      unb64(body.sig_b64),
      FD.claimSigBytes(away.islandId, body.kid, unb64(body.nonce_b64)),
      unb64(box.claimantEd25519),
    );
    if (!ok) return json({ detail: 'forbidden' }, 403);
    return json({
      thread_id: box.threadId,
      delivery_secret_b64: box.secretB64,
      encrypted_thread_key: box.wrappedForClaimant,
      key_id: box.keyId,
      expires_at: null,
    });
  }

  if (path === '/ud/dm/send') {
    const box = away.mailbox;
    if (!box || Number(body.thread_id) !== box.threadId) return json({ detail: 'no thread' }, 404);
    const tag = expectedTag(box.secretB64, body.thread_id, body.ts, body.nonce_b64, body.ciphertext_b64);
    if (b64(unb64(body.tag_b64)) !== tag) return json({ detail: 'bad tag' }, 403);
    if (away.delivered.some((d) => d.nonce_b64 === body.nonce_b64)) {
      return json({ detail: 'replay' }, 409);
    }
    away.delivered.push(body);
    return json({ ok: true });
  }

  if (path === '/.well-known/wsapp-island') return json({}, 404);
  return json({ detail: `away: no route ${path}` }, 404);
}

// ---- identities ---------------------------------------------------------

const me = { username: 'alice' };
const bob = { username: 'bob' };

function makeIdentity(who) {
  who.privRaw = x25519.utils.randomSecretKey();
  who.pubB64 = b64(x25519.getPublicKey(who.privRaw));
  who.edSeed = CryptoUtils.deriveEd25519Seed(who.privRaw);
  who.edPubB64 = b64(CryptoUtils.ed25519GetPublicKey(who.edSeed));
}

/** The card Bob hands over, signed by Bob — the root of trust for everything. */
async function bobsCard(overrides = {}) {
  const kid = await CryptoUtils.fingerprintPublicKey(bob.pubB64);
  const blob = await FD.buildContactBlob(
    {
      kid,
      x25519PubB64: bob.pubB64,
      ed25519PubB64: bob.edPubB64,
      displayName: bob.username,
      ...overrides.me,
    },
    {
      islandId: away.islandId,
      signingKeyB64: b64(new Uint8Array(32).fill(3)),
      entryPoints: [{ apiBase: AWAY, wsBase: 'wss://b.example', label: 'away' }],
      ...overrides.island,
    },
    async (bytes) => ed25519.sign(bytes, bob.edSeed),
  );
  return blob;
}

/** Bob, on his island, writing into the mailbox we opened for him. */
async function bobWrites(contact, text) {
  const key = await CryptoUtils.importRoomKey(contact.inbox.keyB64);
  const kid = contact.inbox.keyId;
  const envelope = {
    ss: 1,
    from: bob.username,
    body: text,
    sig: b64(ed25519.sign(
      CryptoUtils._dmSigMessage(contact.inbox.threadId, bob.username, text),
      bob.edSeed,
    )),
  };
  const enc = await CryptoUtils.encryptMessage(key, JSON.stringify(envelope), utf8(String(kid)));
  return JSON.stringify({ encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true });
}

// ---- wiring -------------------------------------------------------------

let contact = null;

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = String(url);
    if (u.startsWith(HOME)) return handleHome(u.slice(HOME.length), opts);
    if (u.startsWith(AWAY)) return handleAway(u.slice(AWAY.length), opts);
    throw new TypeError(`unexpected host: ${u}`);
  });

  makeIdentity(me);
  makeIdentity(bob);

  NetworkService.setServerConfig(HOME, 'wss://a.example');
  NetworkService._token = 'test-token';
  // Deliberately NOT NetworkService._username: `/auth/login` answers with
  // tokens and no name, so for the whole first session after a fresh sign-in
  // that field is empty and the persisted active user is the only thing that
  // knows who we are. Filing contacts or signing envelopes off the empty one
  // is a bug this test is here to keep out.
  await StorageService.setActiveUsername(me.username);

  const unlocked = await CryptoService.unlockWithRawKey(new Uint8Array(me.privRaw), me.pubB64);
  expect(unlocked).toBe(true);

  // Bob's side of the arrangement: he added our card, so a mailbox for our key
  // exists on his island, with our half of its thread key waiting in it.
  const awayKeyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  away.mailbox = {
    threadId: 2002,
    peerKid: await CryptoUtils.fingerprintPublicKey(me.pubB64),
    claimantEd25519: me.edPubB64,
    secretB64: b64(new Uint8Array(32).fill(9)),
    keyB64: awayKeyB64,
    keyId: await CryptoUtils.fingerprintRoomKeyBase64(awayKeyB64),
    wrappedForClaimant: await CryptoUtils.encryptRoomKeyForUser(me.pubB64, awayKeyB64),
  };
});

afterAll(() => {
  CryptoService.lockSession();
  ForeignService.clearCache();
});

// ---- the tests ----------------------------------------------------------

describe('taking a card', () => {
  test('opens a mailbox here and claims the one waiting there', async () => {
    contact = await ForeignService.addContact(JSON.stringify(await bobsCard()));

    expect(contact.displayName).toBe('bob');
    expect(contact.island.islandId).toBe(away.islandId);
    // A mailbox on this island, with the key wrapped for both sides.
    const box = home.boxes.get(contact.inbox.threadId);
    expect(box).toBeTruthy();
    expect(box.peerKid).toBe(contact.kid);
    expect(box.ownerKey).toBeTruthy();
    expect(box.peerWrapped).toBeTruthy();
    // And theirs, claimed with a signature over their island's nonce.
    expect(contact.outbox.threadId).toBe(2002);
    expect(contact.outbox.keyB64).toBe(away.mailbox.keyB64);
    expect(contact.outbox.apiBase).toBe(AWAY);
  });

  test('refuses a card whose signature does not cover what it says', async () => {
    const blob = await bobsCard();
    blob.payload.display_name = 'not-bob';
    await expect(ForeignService.addContact(JSON.stringify(blob)))
      .rejects.toThrow(/Card rejected/);
  });

  test('refuses a card whose kid is not the hash of the key beside it', async () => {
    const blob = await bobsCard();
    blob.payload.kid = '0'.repeat(32);
    await expect(ForeignService.addContact(JSON.stringify(blob)))
      .rejects.toThrow(/Card rejected/);
  });

  test('our own card verifies against itself', async () => {
    const card = JSON.parse(await ForeignService.buildMyCard());
    const seen = await FD.verifyContactBlob(card, {
      sha256: async (bytes) => CryptoUtils.sha256Raw(bytes),
      verify: (pub, sig, msg) => CryptoUtils.ed25519Verify(pub, sig, msg),
    });
    expect(seen.ok).toBe(true);
    expect(seen.contact.kid).toBe(await CryptoUtils.fingerprintPublicKey(me.pubB64));
    expect(seen.contact.ed25519PubB64).toBe(me.edPubB64);
    // No island list is published in this test, so the card carries the address
    // this client is actually using — which is what the peer needs.
    expect(seen.contact.entryPoints[0].apiBase).toBe(HOME);
  });
});

describe('sending', () => {
  test('goes to their island under their mailbox key, and to ours as a copy', async () => {
    const before = away.delivered.length;
    const res = await ForeignService.sendMessage(contact, 'hello from a');
    expect(res.ok).toBe(true);
    expect(away.delivered.length).toBe(before + 1);

    const wire = away.delivered[away.delivered.length - 1];
    const ciphertext = Buffer.from(wire.ciphertext_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const parsed = JSON.parse(ciphertext);
    // The shape the receiving client keys on. Without `encrypted: true` and the
    // kid, its own decryptor throws the message away.
    expect(parsed.encrypted).toBe(true);
    expect(parsed.kid).toBe(contact.outbox.keyId);
    expect(parsed.aad_v1).toBe(true);

    // Their key, not ours: the copy in our own island is the same ciphertext.
    const key = await CryptoUtils.importRoomKey(away.mailbox.keyB64);
    const plain = await CryptoUtils.decryptMessage(key, parsed, utf8(String(parsed.kid)));
    const envelope = JSON.parse(plain);
    expect(envelope.body).toBe('hello from a');
    // Named, though NetworkService never learned the name.
    expect(envelope.from).toBe('alice');
    // Signed over the thread it was DELIVERED to, which is their mailbox.
    expect(CryptoUtils.ed25519Verify(
      unb64(me.edPubB64),
      unb64(envelope.sig),
      CryptoUtils._dmSigMessage(contact.outbox.threadId, 'alice', 'hello from a'),
    )).toBe(true);

    const ownCopy = home.delivered[home.delivered.length - 1];
    expect(Number(ownCopy.thread_id)).toBe(contact.inbox.threadId);
    expect(ownCopy.ciphertext_b64).toBe(wire.ciphertext_b64);
  });

  test('our own copy reads back as ours, not as a forgery', async () => {
    // The bug this pins: the signature covers their mailbox's number, the copy
    // is read under ours, and verifying against the wrong one accuses us of
    // forging our own message.
    const wire = away.delivered[away.delivered.length - 1];
    const ciphertext = Buffer.from(wire.ciphertext_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

    const out = await CryptoService.decryptDm(contact.inbox.threadId, ciphertext, contact.displayName);
    expect(out).toBeTruthy();
    expect(out.text).toBe('hello from a');
    expect(out.from).toBe('alice');
    expect(out.sigValid).toBe(true);
  });

  test('reading a foreign thread never mints a key on this island', async () => {
    // The other bug this pins: decryptDm opens with the local key path, which
    // takes a 404 from this island as "create one and share it with the peer" —
    // for a peer with no account here at all.
    const fresh = await ForeignService.getContact(contact.kid);
    const incoming = await bobWrites(fresh, 'hello from b');

    // Cold, the way a client that has just started is cold: nothing in memory,
    // only what is in storage. That is the state the bug needed — with the keys
    // already loaded, the local path is never reached to go wrong.
    const rid = CryptoService._dmRid(fresh.inbox.threadId);
    cryptoManager.roomKeys.delete(rid);
    cryptoManager.roomKeyArchive.delete(rid);
    ForeignService.clearCache();
    home.dmKeyCalls.length = 0;

    const out = await CryptoService.decryptDm(fresh.inbox.threadId, incoming, fresh.displayName);
    expect(out.text).toBe('hello from b');
    expect(home.dmKeyCalls).toHaveLength(0);
  });

  test('a message from them verifies against the key their card carried', async () => {
    const fresh = await ForeignService.getContact(contact.kid);
    const incoming = await bobWrites(fresh, 'signed by bob');
    const out = await CryptoService.decryptDm(fresh.inbox.threadId, incoming, fresh.displayName);
    expect(out.from).toBe('bob');
    expect(out.sigValid).toBe(true);
  });

  test('a message signed by somebody else is reported as forged', async () => {
    const fresh = await ForeignService.getContact(contact.kid);
    const impostor = { username: 'bob' };
    makeIdentity(impostor);

    const key = await CryptoUtils.importRoomKey(fresh.inbox.keyB64);
    const kid = fresh.inbox.keyId;
    const envelope = {
      ss: 1,
      from: 'bob',
      body: 'not really bob',
      sig: b64(ed25519.sign(
        CryptoUtils._dmSigMessage(fresh.inbox.threadId, 'bob', 'not really bob'),
        impostor.edSeed,
      )),
    };
    const enc = await CryptoUtils.encryptMessage(key, JSON.stringify(envelope), utf8(String(kid)));
    const ciphertext = JSON.stringify({ encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true });

    const out = await CryptoService.decryptDm(fresh.inbox.threadId, ciphertext, fresh.displayName);
    expect(out.text).toBe('not really bob');
    expect(out.sigValid).toBe(false);
  });
});

describe('when their island is down', () => {
  test('the message is queued, then delivered with the nonce it was queued under', async () => {
    away.down = true;
    const fresh = await ForeignService.getContact(contact.kid);
    const res = await ForeignService.sendMessage(fresh, 'while you were out');
    expect(res.queued).toBe(true);
    expect(await ForeignService.outboxSize()).toBe(1);
    // Our own island is not the one that failed, so our half is stored anyway.
    expect(Number(home.delivered[home.delivered.length - 1].thread_id))
      .toBe(fresh.inbox.threadId);

    away.down = false;
    const before = away.delivered.length;
    await ForeignService.drainOutbox();
    expect(away.delivered.length).toBe(before + 1);
    expect(await ForeignService.outboxSize()).toBe(0);

    const wire = away.delivered[away.delivered.length - 1];
    const ciphertext = Buffer.from(wire.ciphertext_b64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const parsed = JSON.parse(ciphertext);
    const key = await CryptoUtils.importRoomKey(away.mailbox.keyB64);
    const plain = await CryptoUtils.decryptMessage(key, parsed, utf8(String(parsed.kid)));
    expect(JSON.parse(plain).body).toBe('while you were out');
  });

  test('repeating a message that did arrive is a 409, not a second copy', async () => {
    const fresh = await ForeignService.getContact(contact.kid);
    const ob = away.delivered[away.delivered.length - 1];
    const res = await FD.deliver(
      {
        fetchJson: async (url, opts) => {
          const r = await fetch(url, opts);
          return { ok: r.ok, status: r.status, body: await r.json() };
        },
        hmacSha256: async (k, m) => hmac(sha256, k, m),
        sha256: async (bytes) => sha256(bytes),
        randomBytes: () => unb64(ob.nonce_b64.replace(/-/g, '+').replace(/_/g, '/')),
        now: () => Date.now(),
      },
      { apiBase: AWAY, threadId: fresh.outbox.threadId, secretB64: fresh.outbox.secretB64 },
      'anything at all',
      { nonce: unb64(ob.nonce_b64.replace(/-/g, '+').replace(/_/g, '/')) },
    );
    expect(res.status).toBe(409);
  });
});

describe('removing a contact', () => {
  test('closes the mailbox and forgets the contact', async () => {
    const fresh = await ForeignService.getContact(contact.kid);
    const tid = fresh.inbox.threadId;
    expect(await ForeignService.removeContact(fresh.kid)).toBe(true);
    expect(home.boxes.has(tid)).toBe(false);
    expect(await ForeignService.getContact(fresh.kid)).toBeNull();
    expect(await ForeignService.listContacts()).toHaveLength(0);
    expect(ForeignService.cachedForThread(tid)).toBeNull();
  });
});
