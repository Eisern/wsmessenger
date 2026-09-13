// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev87 <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Two people on two independent islands hold a conversation.
 *
 * Alice has an account on island A and none on island B. Bob has an account on
 * island B and none on island A. They exchange a contact blob out of band —
 * here, by passing a string from one half of the test to the other — and from
 * then on each writes into a mailbox the other opened at home.
 *
 * What runs is the extension's own code: chrome_extension/foreign-dm.js and
 * chrome_extension/crypto-utils.js, loaded into one vm sandbox the way the
 * pinned-vector test loads them. The servers are the two real containers. So a
 * pass here means the protocol works end to end between two databases that
 * share nothing — not that a mock agreed with another mock.
 *
 * Requires both islands; see integration/README.md.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ISLAND_A = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const ISLAND_B = process.env.TWO_ISLANDS_B || 'http://127.0.0.1:8001';

const ALICE = { username: 'xisl_alice_1', password: 'Testpass!12345' };
const BOB = { username: 'xisl_bob_1', password: 'Testpass!12345' };

const EXT_DIR = path.join(__dirname, '..', '..', '..', '..', '..', 'chrome_extension');

// One sandbox for both files: foreign-dm hands byte arrays to crypto-utils and
// back, and cross-realm typed arrays are a class of bug this test should not
// be spending its attention on.
function loadExtension() {
  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder, TextDecoder, atob, btoa, console, URL, fetch,
    setTimeout, clearTimeout,
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  for (const file of ['crypto-utils.js', 'foreign-dm.js']) {
    vm.runInContext(fs.readFileSync(path.join(EXT_DIR, file), 'utf8'), sandbox, { filename: file });
  }
  const utils = sandbox.__wsCrypto && sandbox.__wsCrypto.utils;
  const foreign = sandbox.WSForeignDm;
  if (!utils) throw new Error('crypto-utils.js did not register');
  if (!foreign) throw new Error('foreign-dm.js did not register');
  return { utils, foreign, sandbox };
}

const EXT = loadExtension();
const CU = EXT.utils;
const FD = EXT.foreign;

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) =>
  Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

async function http(base, p, { method = 'GET', body, token } = {}) {
  const r = await fetch(base + p, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  return { ok: r.ok, status: r.status, data };
}

// The dependency bundle foreign-dm takes instead of importing a platform.
function deps() {
  return {
    fetchJson: async (url, opts = {}) => {
      const r = await fetch(url, opts);
      let body = null;
      try { body = await r.json(); } catch { /* empty body */ }
      return { ok: r.ok, status: r.status, body };
    },
    sign: async (bytes) => unb64(await CU.ed25519Sign(SIGN_SEED, bytes)),
    verify: (pubBytes, sigBytes, msgBytes) => CU.ed25519Verify(pubBytes, sigBytes, msgBytes),
    sha256: async (bytes) => new Uint8Array(await CU.sha256Raw(bytes)),
    hmacSha256: async (keyBytes, msgBytes) => {
      const k = await globalThis.crypto.subtle.importKey(
        'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
      );
      return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', k, msgBytes));
    },
    randomBytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
  };
}

// Whose signing key `deps().sign` uses — set around each call that signs.
let SIGN_SEED = null;

async function newIdentity(displayName) {
  const kp = await CU.generateIdentityKeyPair();
  const pubB64 = await CU.exportPublicKey(kp.publicKey);
  const privRaw = unb64(await CU.exportPrivateKey(kp.privateKey)).slice(-32);
  const edSeed = await CU.deriveEd25519Seed(privRaw);
  const edPubB64 = b64(await CU.ed25519GetPublicKey(edSeed));
  const kid = await CU.fingerprintPublicKey(pubB64);
  return { kp, pubB64, edSeed, edPubB64, kid, displayName };
}

async function registerAndLogin(base, who, pubB64) {
  await http(base, '/auth/register', {
    method: 'POST',
    body: { username: who.username, password: who.password, public_key: pubB64 },
  });
  const r = await http(base, '/auth/login', {
    method: 'POST',
    body: { username: who.username, password: who.password },
  });
  if (!r.ok) throw new Error(`login failed on ${base}: ${r.status} ${JSON.stringify(r.data)}`);
  return r.data.access_token;
}

/**
 * Open a mailbox at home for one foreign key, and leave the thread key in it
 * wrapped for that key. This is what the recipient does; it is the only place
 * consent is expressed.
 */
async function openMailbox(base, token, me, peer) {
  const keyB64 = await CU.exportRoomKey(await CU.generateRoomKey(true));
  const keyId = await CU.fingerprintRoomKeyBase64(keyB64);

  const created = await http(base, '/foreign/box', {
    method: 'POST',
    token,
    body: {
      peer_kid: peer.kid,
      peer_x25519_pub: peer.pubB64,
      peer_ed25519_pub: peer.edPubB64,
      label: peer.displayName,
      encrypted_thread_key: await CU.encryptRoomKeyForUser(me.pubB64, keyB64),
      key_id: keyId,
    },
  });
  if (!created.ok) throw new Error(`box create failed: ${created.status} ${JSON.stringify(created.data)}`);

  const wrapped = await http(base, `/foreign/box/${created.data.thread_id}/peer-key`, {
    method: 'POST',
    token,
    body: {
      peer_kid: peer.kid,
      peer_x25519_pub: peer.pubB64,
      peer_ed25519_pub: peer.edPubB64,
      encrypted_thread_key: await CU.encryptRoomKeyForUser(peer.pubB64, keyB64),
      key_id: keyId,
    },
  });
  if (!wrapped.ok) throw new Error(`peer key upload failed: ${wrapped.status}`);

  return { threadId: Number(created.data.thread_id), keyB64, keyId };
}

// The sealed envelope the clients already exchange: the sender's name lives
// inside the ciphertext, signed, so only the recipient learns who wrote.
async function sealed(sender, threadId, text, roomKeyB64) {
  const envelope = {
    ss: 1,
    from: sender.displayName,
    body: text,
    sig: await CU.ed25519Sign(sender.edSeed, CU._dmSigMessage(threadId, sender.displayName, text)),
  };
  const key = await CU.importRoomKey(roomKeyB64);
  const enc = await CU.encryptMessage(key, JSON.stringify(envelope));
  return JSON.stringify({ ...enc, kid: await CU.fingerprintRoomKeyBase64(roomKeyB64) });
}

// The sealed path stores base64url(utf8(json)), and the panel decodes it with
// __udB64urlToUtf8Maybe before handing it to decryptDm. A reader that skips
// this sees base64 where it expects an envelope.
function udDecode(stored) {
  const t = String(stored || '').trim();
  if (t.startsWith('{')) return t;
  return Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

async function openSealed(reader, stored, roomKeyB64, senderEdPubB64, threadId) {
  const parsed = JSON.parse(udDecode(stored));
  const key = await CU.importRoomKey(roomKeyB64);
  const plain = await CU.decryptMessage(key, parsed);
  const inner = JSON.parse(plain);
  const sigOk = await CU.ed25519Verify(
    unb64(senderEdPubB64),
    unb64(inner.sig),
    CU._dmSigMessage(threadId, inner.from, inner.body),
  );
  return { from: inner.from, body: inner.body, sigOk };
}

let alice;
let bob;
let tokenA;
let tokenB;
let blobFromAlice;
let blobFromBob;

jest.setTimeout(120000);

beforeAll(async () => {
  for (const [name, url] of [['A', ISLAND_A], ['B', ISLAND_B]]) {
    const h = await fetch(`${url}/health`).then((r) => r.json()).catch(() => null);
    if (!h || h.status !== 'ok') throw new Error(`island ${name} not reachable at ${url}`);
  }

  alice = await newIdentity('alice');
  bob = await newIdentity('bob');
  tokenA = await registerAndLogin(ISLAND_A, ALICE, alice.pubB64);
  tokenB = await registerAndLogin(ISLAND_B, BOB, bob.pubB64);
});

describe('the contact blob stands on its own', () => {
  it('is built by one side and verifies at the other', async () => {
    const docA = await fetch(`${ISLAND_A}/.well-known/wsapp-island`).then((r) => r.json());
    SIGN_SEED = alice.edSeed;
    blobFromAlice = await FD.buildContactBlob(
      { kid: alice.kid, x25519PubB64: alice.pubB64, ed25519PubB64: alice.edPubB64, displayName: 'alice' },
      {
        islandId: docA.payload.island_id,
        signingKeyB64: docA.signing_key_b64,
        entryPoints: [{ apiBase: ISLAND_A, wsBase: ISLAND_A.replace('http', 'ws'), label: 'A' }],
      },
      deps().sign,
    );

    const seen = await FD.verifyContactBlob(blobFromAlice, deps());
    expect(seen.ok).toBe(true);
    expect(seen.contact.kid).toBe(alice.kid);
    expect(seen.contact.islandId).toBe(docA.payload.island_id);
  });

  it('refuses a blob whose kid does not match the key beside it', async () => {
    const tampered = JSON.parse(JSON.stringify(blobFromAlice));
    tampered.payload.kid = 'f'.repeat(32);
    const r = await FD.verifyContactBlob(tampered, deps());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('kid mismatch');
  });

  it('refuses a blob whose display name was edited in flight', async () => {
    // The name is what the recipient will see next to every message, so it is
    // inside the signature rather than beside it.
    const tampered = JSON.parse(JSON.stringify(blobFromAlice));
    tampered.payload.display_name = 'not-alice';
    const r = await FD.verifyContactBlob(tampered, deps());
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad signature');
  });
});

describe('a mailbox hands its keys only to the key it was opened for', () => {
  it('issues a challenge to anyone, so nothing can be probed by kid', async () => {
    // Both a kid with a mailbox and one without must look the same from
    // outside, or this endpoint becomes a way to map keys to islands.
    const one = await http(ISLAND_B, '/foreign/challenge');
    const two = await http(ISLAND_B, '/foreign/challenge');
    expect(one.status).toBe(200);
    expect(two.status).toBe(200);
    expect(one.data.nonce_b64).not.toBe(two.data.nonce_b64);
    expect(one.data.island_id).toBe('island-b');
  });

  it('refuses a claim signed by the wrong key', async () => {
    await openMailbox(ISLAND_B, tokenB, bob, alice);
    SIGN_SEED = bob.edSeed;   // Bob's key, Alice's kid
    const r = await FD.claimMailbox(deps(), ISLAND_B, alice.kid);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
  });

  it('refuses a claim for a kid no mailbox was opened for', async () => {
    const stranger = await newIdentity('stranger');
    SIGN_SEED = stranger.edSeed;
    const r = await FD.claimMailbox(deps(), ISLAND_B, stranger.kid);
    expect(r.ok).toBe(false);
    expect(r.status).toBe(403);
  });

  it('spends the nonce, so a captured claim cannot be replayed', async () => {
    const ch = await http(ISLAND_B, '/foreign/challenge');
    SIGN_SEED = alice.edSeed;
    const sig = await CU.ed25519Sign(
      alice.edSeed,
      FD.claimSigBytes(ch.data.island_id, alice.kid, unb64(ch.data.nonce_b64)),
    );
    const body = { kid: alice.kid, nonce_b64: ch.data.nonce_b64, sig_b64: b64(unb64(sig)) };

    const first = await http(ISLAND_B, '/foreign/claim', { method: 'POST', body });
    expect(first.ok).toBe(true);

    const replay = await http(ISLAND_B, '/foreign/claim', { method: 'POST', body });
    expect(replay.status).toBe(403);
  });
});

describe('Alice and Bob hold a conversation across two databases', () => {
  let aliceOutbox;   // Bob's mailbox on B, as Alice sees it
  let bobOutbox;     // Alice's mailbox on A, as Bob sees it
  let aliceInbox;    // what Alice opened at home for Bob
  let bobInbox;      // what Bob opened at home for Alice

  it('each opens a mailbox at home for the other', async () => {
    const docB = await fetch(`${ISLAND_B}/.well-known/wsapp-island`).then((r) => r.json());
    SIGN_SEED = bob.edSeed;
    blobFromBob = await FD.buildContactBlob(
      { kid: bob.kid, x25519PubB64: bob.pubB64, ed25519PubB64: bob.edPubB64, displayName: 'bob' },
      {
        islandId: docB.payload.island_id,
        signingKeyB64: docB.signing_key_b64,
        entryPoints: [{ apiBase: ISLAND_B, wsBase: ISLAND_B.replace('http', 'ws'), label: 'B' }],
      },
      deps().sign,
    );

    bobInbox = await openMailbox(ISLAND_B, tokenB, bob, alice);
    aliceInbox = await openMailbox(ISLAND_A, tokenA, alice, bob);
    expect(bobInbox.threadId).toBeGreaterThan(0);
    expect(aliceInbox.threadId).toBeGreaterThan(0);
  });

  it('each claims the mailbox waiting for them on the other island', async () => {
    SIGN_SEED = alice.edSeed;
    aliceOutbox = await FD.claimMailbox(deps(), ISLAND_B, alice.kid);
    expect(aliceOutbox.ok).toBe(true);
    expect(aliceOutbox.threadId).toBe(bobInbox.threadId);

    SIGN_SEED = bob.edSeed;
    bobOutbox = await FD.claimMailbox(deps(), ISLAND_A, bob.kid);
    expect(bobOutbox.ok).toBe(true);
    expect(bobOutbox.threadId).toBe(aliceInbox.threadId);

    // The thread key came back wrapped for the claimer and nobody else: the
    // island stored it without ever being able to read it.
    const keyForAlice = await CU.decryptRoomKeyForUser(alice.kp.privateKey, aliceOutbox.encryptedThreadKey);
    expect(keyForAlice).toBe(bobInbox.keyB64);
    const keyForBob = await CU.decryptRoomKeyForUser(bob.kp.privateKey, bobOutbox.encryptedThreadKey);
    expect(keyForBob).toBe(aliceInbox.keyB64);
  });

  it('Alice writes to island B and Bob reads it at home', async () => {
    const text = 'привет с острова A';
    const ct = await sealed(alice, aliceOutbox.threadId, text, bobInbox.keyB64);

    const sent = await FD.deliver(
      deps(),
      { apiBase: ISLAND_B, threadId: aliceOutbox.threadId, secretB64: aliceOutbox.deliverySecretB64 },
      ct,
    );
    expect(sent.ok).toBe(true);

    // Bob reads over the ordinary authenticated path — he is the only member
    // of that thread, and nothing about it knows the sender was foreign.
    const hist = await http(ISLAND_B, `/dm/${bobInbox.threadId}/history`, { token: tokenB });
    expect(hist.ok).toBe(true);
    const rows = hist.data.messages || hist.data;
    expect(rows.length).toBeGreaterThan(0);

    const last = rows[rows.length - 1];
    expect(last.username == null).toBe(true);   // sealed: the island has no sender

    const opened = await openSealed(bob, last.text, bobInbox.keyB64, alice.edPubB64, aliceOutbox.threadId);
    expect(opened.body).toBe(text);
    expect(opened.from).toBe('alice');
    // Verified against the key from the contact blob, not against anything
    // island B handed over: a dishonest B cannot forge a message from Alice.
    expect(opened.sigOk).toBe(true);
  });

  it('Bob answers to island A and Alice reads it at home', async () => {
    const text = 'и тебе привет, я на острове B';
    const ct = await sealed(bob, bobOutbox.threadId, text, aliceInbox.keyB64);

    const sent = await FD.deliver(
      deps(),
      { apiBase: ISLAND_A, threadId: bobOutbox.threadId, secretB64: bobOutbox.deliverySecretB64 },
      ct,
    );
    expect(sent.ok).toBe(true);

    const hist = await http(ISLAND_A, `/dm/${aliceInbox.threadId}/history`, { token: tokenA });
    const rows = hist.data.messages || hist.data;
    const last = rows[rows.length - 1];
    const opened = await openSealed(alice, last.text, aliceInbox.keyB64, bob.edPubB64, bobOutbox.threadId);
    expect(opened.body).toBe(text);
    expect(opened.from).toBe('bob');
    expect(opened.sigOk).toBe(true);
  });

  it('Alice keeps her own copy at home, under the key she sent it with', async () => {
    // Without this, her outgoing messages would live only on Bob's island,
    // where she has no account — a reinstall would restore half a conversation.
    const text = 'это моя копия';
    const ct = await sealed(alice, aliceOutbox.threadId, text, bobInbox.keyB64);

    const secret = await http(ISLAND_A, `/dm/${aliceInbox.threadId}/delivery-secret`, { token: tokenA });
    expect(secret.ok).toBe(true);

    const copied = await FD.deliver(
      deps(),
      { apiBase: ISLAND_A, threadId: aliceInbox.threadId, secretB64: secret.data.delivery_secret_b64 },
      ct,
    );
    expect(copied.ok).toBe(true);

    const hist = await http(ISLAND_A, `/dm/${aliceInbox.threadId}/history`, { token: tokenA });
    const rows = hist.data.messages || hist.data;
    const mine = rows[rows.length - 1];

    // Her island now holds both halves, encrypted under two different keys.
    // Nothing new is needed to tell them apart: each message names its key.
    expect(JSON.parse(udDecode(mine.text)).kid).toBe(bobInbox.keyId);
    expect(JSON.parse(udDecode(rows[rows.length - 2].text)).kid).toBe(aliceInbox.keyId);

    const opened = await openSealed(alice, mine.text, bobInbox.keyB64, alice.edPubB64, aliceOutbox.threadId);
    expect(opened.body).toBe(text);
    expect(opened.from).toBe('alice');
  });

  it('neither island learns the other half', async () => {
    // A's database knows Alice talks to the holder of a key. It has no row
    // naming Bob, his island, or his account.
    const boxes = await http(ISLAND_A, '/foreign/boxes', { token: tokenA });
    expect(boxes.ok).toBe(true);
    const row = boxes.data.find((b) => b.thread_id === aliceInbox.threadId);
    expect(row.peer_kid).toBe(bob.kid);
    expect(JSON.stringify(row)).not.toContain(BOB.username);
    expect(JSON.stringify(row)).not.toContain('island-b');
  });

  it('closing the mailbox stops delivery with the secret already handed out', async () => {
    const doomed = await newIdentity('doomed');
    const box = await openMailbox(ISLAND_B, tokenB, bob, doomed);
    SIGN_SEED = doomed.edSeed;
    const claimed = await FD.claimMailbox(deps(), ISLAND_B, doomed.kid);
    expect(claimed.ok).toBe(true);

    const gone = await http(ISLAND_B, `/foreign/box/${box.threadId}`, { method: 'DELETE', token: tokenB });
    expect(gone.ok).toBe(true);

    const after = await FD.deliver(
      deps(),
      { apiBase: ISLAND_B, threadId: claimed.threadId, secretB64: claimed.deliverySecretB64 },
      await sealed(doomed, claimed.threadId, 'should not arrive', box.keyB64),
    );
    expect(after.ok).toBe(false);
    expect(after.status).toBe(403);
  });
});
