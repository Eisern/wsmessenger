// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's own panel code, holding a cross-island conversation.
 *
 * crossIsland.test.js proves the protocol: it calls foreign-dm.js directly and
 * does the crypto itself. This one proves the CLIENT - it loads
 * chrome_extension/panel-crypto.js into a sandbox and calls the same functions
 * the buttons call: buildMyContactBlobText, addForeignContact,
 * claimForeignOutbox, sendForeignMessage, decryptDm.
 *
 * That distinction earned its keep immediately. The protocol test passed while
 * sendForeignMessage was emitting ciphertext without `encrypted: true` and
 * without a kid - a shape the panel's own decrypt path drops on the floor. Two
 * layers that each work and do not fit together look exactly like two working
 * layers until something runs both.
 *
 * Only what a browser would provide is stubbed: storage, permissions, the DOM,
 * and a stand-in for CryptoManager (the real one needs an encrypted identity
 * blob and an Argon2 WASM self-test to unlock, which is not what this is
 * testing). Its encryptMessage matches the real one byte for byte, because
 * that is the interface under test.
 *
 * Requires both islands; see integration/README.md.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ISLAND_A = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const ISLAND_B = process.env.TWO_ISLANDS_B || 'http://127.0.0.1:8001';
const PASS = 'Testpass!12345';

const EXT_DIR = path.join(__dirname, '..', '..', '..', '..', '..', 'chrome_extension');

const unb64 = (s) =>
  Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

function makeStore() {
  const mem = new Map();
  return {
    async get(keys) {
      if (keys == null) return Object.fromEntries(mem);
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) if (mem.has(k)) out[k] = mem.get(k);
      return out;
    },
    async set(obj) { for (const [k, v] of Object.entries(obj)) mem.set(k, v); },
    async remove(keys) { for (const k of (Array.isArray(keys) ? keys : [keys])) mem.delete(k); },
  };
}

function makeManager(CU) {
  const m = {
    userPrivateKey: null,
    userPublicKeyB64: null,
    ed25519Seed: null,
    roomKeys: new Map(),
    roomKeysExportable: new Map(),
    roomKeyIds: new Map(),
    roomKeyArchive: new Map(),
    roomKeyArchiveB64: new Map(),
    async loadRoomKey(rid, b64) {
      m.roomKeys.set(rid, await CU.importRoomKey(b64));
      m.roomKeyIds.set(rid, await CU.fingerprintRoomKeyBase64(b64));
      return true;
    },
    async loadArchivedKey(rid, kid, b64) {
      if (!m.roomKeyArchive.has(rid)) m.roomKeyArchive.set(rid, new Map());
      if (!m.roomKeyArchiveB64.has(rid)) m.roomKeyArchiveB64.set(rid, new Map());
      m.roomKeyArchive.get(rid).set(kid, await CU.importRoomKey(b64));
      m.roomKeyArchiveB64.get(rid).set(kid, b64);
      return true;
    },
    // Byte-identical to CryptoManager.encryptMessage, deliberately.
    async encryptMessage(rid, text) {
      const kid = m.roomKeyIds.get(rid) || undefined;
      const aad = kid ? new TextEncoder().encode(String(kid)) : undefined;
      const enc = await CU.encryptMessage(m.roomKeys.get(rid), text, aad);
      const out = { encrypted: true, iv: enc.iv, data: enc.data, kid };
      if (aad) out.aad_v1 = true;
      return JSON.stringify(out);
    },
    async decryptMessage(rid, parsed) {
      const kid = parsed.kid;
      const key = (kid && m.roomKeyArchive.get(rid)?.get(kid)) || m.roomKeys.get(rid);
      const aad = kid ? new TextEncoder().encode(String(kid)) : undefined;
      try {
        return await CU.decryptMessage(key, parsed, aad);
      } catch {
        return await CU.decryptMessage(key, parsed);
      }
    },
    isReady() { return !!m.userPrivateKey; },
    get userPublicKeyPem() { return m.userPublicKeyB64; },
  };
  return m;
}

function makePanel({ apiBase, islandId, username, token }) {
  const posted = [];
  const sandbox = {
    crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, console, URL, fetch,
    setTimeout, clearTimeout, setInterval, clearInterval, Event, CustomEvent,
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = { addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } };
  sandbox.document = {
    getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
    createElement: () => ({ style: {}, classList: { add() {}, remove() {} }, appendChild() {} }),
    addEventListener() {},
  };
  sandbox.chrome = {
    storage: { local: makeStore(), session: makeStore(), onChanged: { addListener() {} } },
    permissions: { async contains() { return true; }, async request() { return true; } },
    runtime: { getManifest: () => ({ version: '0.0.0' }) },
  };
  vm.createContext(sandbox);

  for (const f of ['crypto-utils.js', 'endpoints.js', 'thread-chain.js', 'island-list.js', 'outbox.js', 'foreign-dm.js']) {
    vm.runInContext(fs.readFileSync(path.join(EXT_DIR, f), 'utf8'), sandbox, { filename: f });
  }
  const CU = sandbox.__wsCrypto.utils;
  const manager = makeManager(CU);
  Object.defineProperty(sandbox.__wsCrypto, 'manager', { value: manager });

  // Before the load: panel-crypto runs a few statements at top level, and one
  // of them posts to the worker.
  sandbox.API_BASE = apiBase;
  sandbox.ISLAND_ID = islandId;
  sandbox.__apiBaseReady = Promise.resolve(apiBase);
  sandbox.__activeForeignKid = null;
  sandbox.getMeUsername = () => username;
  sandbox.requestToken = async () => token;
  sandbox.safePost = (msg) => { posted.push(msg); };
  sandbox.encryptForStorage = async () => null;
  sandbox.decryptFromStorage = async () => null;
  sandbox.__ui = { alert: async () => {}, confirm: async () => true, prompt: async () => '' };

  vm.runInContext(fs.readFileSync(path.join(EXT_DIR, 'panel-crypto.js'), 'utf8'), sandbox,
    { filename: 'panel-crypto.js' });

  // After the load: panel-crypto declares some of these itself, and a function
  // declaration wins over anything assigned before the file ran.
  sandbox.ensureCryptoReady = async () => true;
  sandbox.isCryptoUsable = () => true;

  return { sandbox, CU, manager, posted };
}

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

async function setUp(base, islandId, username) {
  const boot = makePanel({ apiBase: base, islandId, username, token: '' });
  const kp = await boot.CU.generateIdentityKeyPair();
  const pkcs8 = await boot.CU.exportPrivateKey(kp.privateKey);
  const pubB64 = await boot.CU.exportPublicKey(kp.publicKey);

  await http(base, '/auth/register', { method: 'POST', body: { username, password: PASS, public_key: pubB64 } });
  const login = await http(base, '/auth/login', { method: 'POST', body: { username, password: PASS } });
  if (!login.ok) throw new Error(`login ${username} on ${base}: ${login.status}`);

  const panel = makePanel({ apiBase: base, islandId, username, token: login.data.access_token });
  panel.manager.userPrivateKey = await panel.CU.importPrivateKey(pkcs8);
  panel.manager.userPublicKeyB64 = pubB64;
  panel.manager.ed25519Seed = await panel.CU.deriveEd25519Seed(unb64(pkcs8).slice(-32));

  // The panel publishes this on every unlock; a harness that skips it leaves
  // the island unable to answer questions the real one can.
  await http(base, '/crypto/ed25519-key', {
    method: 'POST',
    token: login.data.access_token,
    body: {
      public_key: Buffer.from(await panel.CU.ed25519GetPublicKey(panel.manager.ed25519Seed))
        .toString('base64'),
    },
  });
  panel.token = login.data.access_token;
  panel.username = username;
  return panel;
}

// What foreign-dm.deliver needs from a platform, for the two places a test has
// to put a message into a mailbox itself.
function foreignDeps(panel) {
  return {
    fetchJson: async (url, opts) => {
      const r = await fetch(url, opts);
      let body = null;
      try { body = await r.json(); } catch { /* empty body */ }
      return { ok: r.ok, status: r.status, body };
    },
    sha256: async (b) => new Uint8Array(await panel.CU.sha256Raw(b)),
    hmacSha256: async (k, m) => {
      const key = await globalThis.crypto.subtle.importKey(
        'raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
      );
      return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, m));
    },
    randomBytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
  };
}

// The panel decodes the sealed path's base64url before handing it to decryptDm.
function udDecode(stored) {
  const t = String(stored || '').trim();
  if (t.startsWith('{')) return t;
  return Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

async function lastMessage(base, threadId, token) {
  const hist = await http(base, `/dm/${threadId}/history`, { token });
  const rows = hist.data.messages || hist.data;
  return udDecode(rows[rows.length - 1].text);
}

let alice;
let bob;
let aliceSide;
let bobSide;

jest.setTimeout(120000);

beforeAll(async () => {
  for (const [name, url] of [['A', ISLAND_A], ['B', ISLAND_B]]) {
    const h = await fetch(`${url}/health`).then((r) => r.json()).catch(() => null);
    if (!h || h.status !== 'ok') throw new Error(`island ${name} not reachable at ${url}`);
  }
  const stamp = Date.now().toString().slice(-7);
  alice = await setUp(ISLAND_A, 'island-a-test', `pnl_a_${stamp}`);
  bob = await setUp(ISLAND_B, 'island-b-test', `pnl_b_${stamp}`);
});

describe('the panel exchanges contact cards', () => {
  it('builds a card that names the island and how to reach it', async () => {
    const card = JSON.parse(await alice.sandbox.buildMyContactBlobText());
    expect(card.payload.island_id).toBe('island-test');
    expect(card.payload.entry_points.length).toBeGreaterThan(0);
    expect(card.payload.display_name).toBe(alice.username);
    expect(card.sig_b64).toBeTruthy();
  });

  it('refuses its own card, which would otherwise open a mailbox to itself', async () => {
    const mine = await alice.sandbox.buildMyContactBlobText();
    await expect(alice.sandbox.addForeignContact(mine)).rejects.toThrow(/your own card/i);
  });

  it('refuses a card that was edited after signing', async () => {
    const card = JSON.parse(await alice.sandbox.buildMyContactBlobText());
    card.payload.display_name = 'somebody-else';
    await expect(bob.sandbox.addForeignContact(JSON.stringify(card)))
      .rejects.toThrow(/bad signature/i);
  });
});

describe('the panel opens mailboxes in the order two people actually do it', () => {
  it('the first to add gets an inbox and cannot write yet', async () => {
    // Bob adds Alice before she has added him. His island now accepts her key;
    // hers does not yet accept his, so there is nothing for him to claim.
    bobSide = await bob.sandbox.addForeignContact(await alice.sandbox.buildMyContactBlobText());
    expect(bobSide.inbox.threadId).toBeGreaterThan(0);
    expect(bobSide.outbox).toBeNull();
  });

  it('the second to add can write immediately', async () => {
    aliceSide = await alice.sandbox.addForeignContact(await bob.sandbox.buildMyContactBlobText());
    expect(aliceSide.inbox.threadId).toBeGreaterThan(0);
    expect(aliceSide.outbox?.keyB64).toBeTruthy();
    // Her outbox is his inbox: one mailbox seen from both ends.
    expect(aliceSide.outbox.threadId).toBe(bobSide.inbox.threadId);
  });

  it('the first can claim once the other side exists', async () => {
    bobSide = await bob.sandbox.claimForeignOutbox(bobSide);
    expect(bobSide.outbox?.keyB64).toBeTruthy();
    expect(bobSide.outbox.threadId).toBe(aliceSide.inbox.threadId);
  });

  it('walks past entry points it cannot reach', async () => {
    // Island A's list carries addresses that answer nothing from here. The
    // claim above went through one of the others, which is the whole reason a
    // card carries more than one - and an unreachable one used to abort it.
    const bases = (bobSide.island.entryPoints || []).map((e) => e.apiBase);
    expect(bases.length).toBeGreaterThan(1);
    expect(bases).toContain('http://127.0.0.1:18101');
  });
});

describe('they write to each other', () => {
  const fromAlice = 'привет из панели, я на острове A';
  const fromBob = 'и тебе привет, я на B';

  it('Alice sends, and keeps her own copy at home', async () => {
    await alice.sandbox.sendForeignMessage(aliceSide, fromAlice);
    const copies = alice.posted.filter((m) => m.type === 'dm_send');
    expect(copies).toHaveLength(1);
    expect(copies[0].thread_id).toBe(aliceSide.inbox.threadId);
    // The copy is the same ciphertext that went abroad, so it decrypts under
    // the same key rather than needing one of its own.
    expect(JSON.parse(copies[0].text).kid).toBe(aliceSide.outbox.keyId);
  });

  it('Alice reads her own copy back without being accused of forging it', async () => {
    // The copy carries the signature that went abroad, and that signature
    // covers the thread it was DELIVERED to - Bob's mailbox - not the thread it
    // is read in. Verifying it against the local thread number fails on the
    // wrong question and shows the sender a forgery warning about themselves.
    //
    // The earlier version of this suite checked the copy by passing the outbox
    // id by hand, which is precisely what the panel cannot do, so it proved
    // nothing about the panel.
    const copy = alice.posted.filter((m) => m.type === 'dm_send').pop();
    const secret = await http(ISLAND_A, `/dm/${aliceSide.inbox.threadId}/delivery-secret`,
      { token: alice.token });
    const delivered = await alice.sandbox.WSForeignDm.deliver(
      foreignDeps(alice),
      {
        apiBase: ISLAND_A,
        threadId: aliceSide.inbox.threadId,
        secretB64: secret.data.delivery_secret_b64,
      },
      copy.text,
    );
    expect(delivered.ok).toBe(true);

    await alice.sandbox.ensureForeignKeysReady(aliceSide);
    const stored = await lastMessage(ISLAND_A, aliceSide.inbox.threadId, alice.token);
    const got = await alice.sandbox.decryptDm(aliceSide.inbox.threadId, stored, '', Date.now());
    expect(got.text).toBe(fromAlice);
    expect(got.sealedFrom).toBe(alice.username);
    expect(got.sigValid).toBe(true);
  });

  it('accepts our own message whichever thread number it was signed over', async () => {
    // Not every path through this client goes abroad. The file sender encrypts
    // with the local thread's key and signs over the local thread id, and the
    // result sits in the same conversation next to messages signed over the
    // peer's mailbox. A verifier that insists on one of the two numbers calls
    // the other a forgery - which is what attaching a file used to produce.
    const local = await alice.sandbox.encryptDm(
      aliceSide.inbox.threadId, 'FILE2::local-path', bob.username,
    );
    const secret = await http(ISLAND_A, `/dm/${aliceSide.inbox.threadId}/delivery-secret`,
      { token: alice.token });
    const sent = await alice.sandbox.WSForeignDm.deliver(
      foreignDeps(alice),
      {
        apiBase: ISLAND_A,
        threadId: aliceSide.inbox.threadId,
        secretB64: secret.data.delivery_secret_b64,
      },
      local,
    );
    expect(sent.ok).toBe(true);

    const stored = await lastMessage(ISLAND_A, aliceSide.inbox.threadId, alice.token);
    const got = await alice.sandbox.decryptDm(aliceSide.inbox.threadId, stored, '', Date.now());
    expect(got.text).toBe('FILE2::local-path');
    expect(got.sealedFrom).toBe(alice.username);
    expect(got.sigValid).toBe(true);
  });

  it('Bob reads it with the panel decrypt path, sender and all', async () => {
    await bob.sandbox.ensureForeignKeysReady(bobSide);
    const stored = await lastMessage(ISLAND_B, bobSide.inbox.threadId, bob.token);

    // What the client emits and what it accepts have to be the same thing.
    const shape = JSON.parse(stored);
    expect(shape.encrypted).toBe(true);
    expect(shape.kid).toBeTruthy();

    const got = await bob.sandbox.decryptDm(bobSide.inbox.threadId, stored, '', Date.now());
    expect(got.text).toBe(fromAlice);
    expect(got.sealedFrom).toBe(alice.username);
    // Verified against the Ed25519 key from her card, not against anything
    // island B served: that is what a dishonest island cannot forge past.
    expect(got.sigValid).toBe(true);
  });

  it('Bob answers and Alice reads it', async () => {
    await bob.sandbox.sendForeignMessage(bobSide, fromBob);
    await alice.sandbox.ensureForeignKeysReady(aliceSide);
    const stored = await lastMessage(ISLAND_A, aliceSide.inbox.threadId, alice.token);
    const got = await alice.sandbox.decryptDm(aliceSide.inbox.threadId, stored, '', Date.now());
    expect(got.text).toBe(fromBob);
    expect(got.sealedFrom).toBe(bob.username);
    expect(got.sigValid).toBe(true);
  });

  it('queues a message their island did not take, and sends it later', async () => {
    // The failure this is for is invisible from here: our island is fine, we
    // are online, and the message still cannot be delivered. Before the queue
    // existed the input box was cleared anyway and the message was simply gone.
    const stored = await alice.sandbox.getForeignContact(aliceSide.kid);
    const realBase = stored.outbox.apiBase;

    await alice.sandbox.saveForeignContact({
      ...stored,
      outbox: { ...stored.outbox, apiBase: 'http://127.0.0.1:9' },   // discard port
    });

    const text = 'это должно подождать';
    const dead = await alice.sandbox.getForeignContact(aliceSide.kid);
    const outcome = await alice.sandbox.sendForeignMessage(dead, text);
    expect(outcome.queued).toBe(true);
    expect(await alice.sandbox.foreignOutboxSize()).toBe(1);

    // Their island comes back.
    await alice.sandbox.saveForeignContact({
      ...dead,
      outbox: { ...dead.outbox, apiBase: realBase },
    });
    const drained = await alice.sandbox.drainForeignOutbox();
    expect(drained.sent).toBe(1);
    expect(await alice.sandbox.foreignOutboxSize()).toBe(0);

    // And it is a real message at the other end, not just a queue that emptied.
    await bob.sandbox.ensureForeignKeysReady(bobSide);
    const got = await bob.sandbox.decryptDm(
      bobSide.inbox.threadId,
      await lastMessage(ISLAND_B, bobSide.inbox.threadId, bob.token),
      '', Date.now(),
    );
    expect(got.text).toBe(text);
    expect(got.sigValid).toBe(true);
  });

  it('repeating a queued message does not deliver it twice', async () => {
    // A retry reuses the nonce, so an attempt that did arrive but whose answer
    // was lost comes back as 409 - which the queue reads as delivered.
    const contact = await alice.sandbox.getForeignContact(aliceSide.kid);
    const before = (await http(ISLAND_B, `/dm/${bobSide.inbox.threadId}/history`,
      { token: bob.token })).data;
    const beforeCount = (before.messages || before).length;

    const ct = await alice.sandbox.encryptDm(aliceSide.inbox.threadId, 'once', bob.username);
    const box = {
      apiBase: contact.outbox.apiBase,
      threadId: contact.outbox.threadId,
      secretB64: contact.outbox.secretB64,
    };
    const first = await alice.sandbox.WSForeignDm.deliver(foreignDeps(alice), box, ct);
    expect(first.ok).toBe(true);

    const again = await alice.sandbox.WSForeignDm.deliver(
      foreignDeps(alice), box, ct, { nonce: first.nonce },
    );
    expect(again.status).toBe(409);
    expect(alice.sandbox.WSOutbox.classifySendOutcome(again)).toBe('sent');

    const after = (await http(ISLAND_B, `/dm/${bobSide.inbox.threadId}/history`,
      { token: bob.token })).data;
    expect((after.messages || after).length).toBe(beforeCount + 1);
  });

  it('finds a contact again after their island changes address', async () => {
    // The card froze their addresses at the moment it was handed over. When
    // the last of them stops answering the contact used to be lost for good.
    const stored = await alice.sandbox.getForeignContact(aliceSide.kid);
    await alice.sandbox.saveForeignContact({
      ...stored,
      island: {
        ...stored.island,
        entryPoints: [{ apiBase: 'http://127.0.0.1:9', wsBase: '', label: 'gone' }],
        lastCheckedAt: 0,
      },
    });

    // The claim walks its addresses, finds nothing, asks their island where it
    // lives now, and believes the answer only because their card pinned the
    // key that signed it.
    const claimed = await alice.sandbox.claimForeignOutbox(
      await alice.sandbox.getForeignContact(aliceSide.kid),
    );
    expect(claimed.outbox.threadId).toBe(bobSide.inbox.threadId);

    const after = await alice.sandbox.getForeignContact(aliceSide.kid);
    expect(after.island.entryPoints.some((e) => e.apiBase === ISLAND_B)).toBe(true);
    expect(after.island.pin.islandId).toBe('island-b');
    expect(after.island.pin.version).toBeGreaterThan(0);
  });

  it('refuses a list signed by anyone but their island', async () => {
    // Island A is a real island serving a real, correctly signed document -
    // just not theirs. Without the pin this is how a contact gets redirected
    // to somebody else's mailbox.
    const stored = await alice.sandbox.getForeignContact(aliceSide.kid);
    const res = await alice.sandbox.refreshForeignIsland({
      ...stored,
      island: { ...stored.island, entryPoints: [{ apiBase: ISLAND_A }], lastCheckedAt: 0 },
      outbox: { ...stored.outbox, apiBase: ISLAND_A },
    }, { force: true });

    expect(res.ok).toBe(false);
    expect(['bad signature', 'different island']).toContain(res.reason);

    // And nothing was overwritten by the attempt.
    const after = await alice.sandbox.getForeignContact(aliceSide.kid);
    expect(after.island.pin?.islandId ?? 'island-b').toBe('island-b');
  });

  it('sends through a relay, so their island never sees the sender', async () => {
    // Direct delivery hands the sender's address and typing times to a server
    // they do not trust and have no account with. The relay carries the same
    // message without being able to read it.
    const stored = await alice.sandbox.getForeignContact(aliceSide.kid);
    const refreshed = await alice.sandbox.refreshForeignIsland(
      { ...stored, island: { ...stored.island, lastCheckedAt: 0 } }, { force: true },
    );
    expect(refreshed.ok).toBe(true);

    const withRelay = await alice.sandbox.getForeignContact(aliceSide.kid);
    expect(withRelay.island.relays.length).toBeGreaterThan(0);
    // The transport key comes from the signed list and nowhere else: whoever
    // substitutes it reads the metadata of every envelope.
    expect(withRelay.island.transportKeys[0].publicKeyB64).toBeTruthy();

    await alice.sandbox.saveForeignContact({ ...withRelay, useRelay: true });
    const text = 'это ушло через реле';
    const outcome = await alice.sandbox.sendForeignMessage(
      await alice.sandbox.getForeignContact(aliceSide.kid), text,
    );
    expect(outcome.ok).toBe(true);

    await bob.sandbox.ensureForeignKeysReady(bobSide);
    const got = await bob.sandbox.decryptDm(
      bobSide.inbox.threadId,
      await lastMessage(ISLAND_B, bobSide.inbox.threadId, bob.token),
      '', Date.now(),
    );
    expect(got.text).toBe(text);
    expect(got.sealedFrom).toBe(alice.username);
    expect(got.sigValid).toBe(true);
  });

  it('does not fall back to direct delivery when the relay fails', async () => {
    // Falling back would hand over the address the user asked to withhold,
    // silently. Queuing is the right answer; giving up the property is not.
    const stored = await alice.sandbox.getForeignContact(aliceSide.kid);
    await alice.sandbox.saveForeignContact({
      ...stored,
      useRelay: true,
      island: { ...stored.island, relays: [{ id: 'dead', url: 'http://127.0.0.1:9' }] },
    });

    const before = (await http(ISLAND_B, `/dm/${bobSide.inbox.threadId}/history`,
      { token: bob.token })).data;
    const beforeCount = (before.messages || before).length;

    const outcome = await alice.sandbox.sendForeignMessage(
      await alice.sandbox.getForeignContact(aliceSide.kid), 'не должно уйти напрямую',
    );
    expect(outcome.queued).toBe(true);

    const after = (await http(ISLAND_B, `/dm/${bobSide.inbox.threadId}/history`,
      { token: bob.token })).data;
    expect((after.messages || after).length).toBe(beforeCount);

    await alice.sandbox.WSOutbox.createOutbox; // keep the queue module referenced
  });

  it('keeps the contact in storage, not in memory', async () => {
    const listed = await alice.sandbox.listForeignContacts();
    expect(listed).toHaveLength(1);
    expect(listed[0].kid).toBe(aliceSide.kid);
    expect(listed[0].displayName).toBe(bob.username);
  });

  it('removing the contact closes the mailbox on this island', async () => {
    const threadId = aliceSide.inbox.threadId;
    await alice.sandbox.removeForeignContact(aliceSide.kid);
    expect(await alice.sandbox.listForeignContacts()).toHaveLength(0);

    // Bob still holds a delivery secret for it, and it now opens nothing.
    const after = await http(ISLAND_A, `/dm/${threadId}/history`, { token: alice.token });
    expect(after.ok).toBe(false);
  });
});
