// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's half of "a key the island cannot have made".
 *
 * keyWrap.test.js holds Android to three rules; this holds the extension to the
 * same three, running the REAL chrome_extension/panel-crypto.js headless (see
 * integration/helpers/panelHarness.js) against a stubbed island - no backend:
 *
 *   - an unsigned wrap may hand back a key this device already held, and never
 *     introduce a new one;
 *   - a signed wrap must come from someone entitled to hand the key out (the DM
 *     peer, a room member) and verify under their PINNED signing key;
 *   - the island cannot swap that signing key after it was pinned; only the
 *     user verifying the peer moves the pin.
 *
 * The island here is the adversary: every answer is whatever the test says,
 * which is what a dishonest server gets to say too.
 */

const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const ROOM = 77;
const DM = 501;

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

// What the island answers. Tests rewrite it as they go.
const island = {
  members: {},   // roomId -> [username]
  roomKey: {},   // roomId -> { encrypted_room_key, key_id }
  dmKey: {},     // threadId -> { encrypted_thread_key, key_id }
  dmList: [],    // [{ thread_id, peer_username }]
  accounts: {},  // username -> { public_key, ed25519_public_key }
};

function route(url) {
  const path = new URL(url).pathname;
  let m;
  if ((m = path.match(/^\/keys\/([^/]+)$/))) {
    const a = island.accounts[decodeURIComponent(m[1])];
    return a ? reply(200, { username: m[1], ...a }) : reply(404, { detail: 'no such user' });
  }
  if ((m = path.match(/^\/rooms\/(\d+)\/members$/))) {
    const list = island.members[m[1]];
    return list ? reply(200, list.map((username) => ({ username, role: 'member' }))) : reply(403, {});
  }
  if (/^\/crypto\/(room|dm)-key\/\d+\/archive$/.test(path)) return reply(200, { keys: [] });
  if ((m = path.match(/^\/crypto\/room-key\/(\d+)$/))) {
    const k = island.roomKey[m[1]];
    return k ? reply(200, k) : reply(404, {});
  }
  if ((m = path.match(/^\/crypto\/dm-key\/(\d+)$/))) {
    const k = island.dmKey[m[1]];
    return k ? reply(200, k) : reply(404, {});
  }
  if (path === '/dm/list') return reply(200, island.dmList);
  return reply(404, {});
}

let P;
let owner;
let mallory;

async function account(CU) {
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const edPub = await CU.ed25519GetPublicKey(seed);
  const x = globalThis.crypto.getRandomValues(new Uint8Array(32));
  return {
    seed,
    edPubB64: CU.arrayBufferToBase64(edPub),
    xPubB64: CU.arrayBufferToBase64(x),
  };
}

async function freshKey() {
  const keyB64 = await P.CU.exportRoomKey(await P.CU.generateRoomKey(true));
  return { keyB64, kid: await P.CU.fingerprintRoomKeyBase64(keyB64) };
}

/** A wrap for this client, signed by `by` (an account) under `signer`, or unsigned. */
async function wrap(keyB64, { by = null, signer = '', scope = 'room', scopeId = ROOM } = {}) {
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  const opts = by ? { seed: by.seed, signer, scope, scopeId, recipient: 'alice', keyId: kid } : null;
  return { blob: await P.CU.encryptRoomKeyForUser(P.manager.userPublicKeyPem, keyB64, opts), kid };
}

function forget(rid) {
  for (const map of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive']) {
    P.manager[map]?.delete?.(rid);
  }
}

async function unlock() {
  await unlockRealManager(P.sandbox, { username: 'alice', password: PASS });
}

function serve(owners, accountFor) {
  island.accounts[owners] = { public_key: accountFor.xPubB64, ed25519_public_key: accountFor.edPubB64 };
}

beforeAll(async () => {
  P = makePanel({ apiBase: 'https://island.test', islandId: 'island.test', username: 'alice', token: 'tok' });
  P.sandbox.fetch = async (url) => route(String(url));
  await unlock();
  owner = await account(P.CU);
  mallory = await account(P.CU);
  serve('owner', owner);
  serve('mallory', mallory);
  island.members[ROOM] = ['alice', 'owner'];
  island.dmList = [{ thread_id: DM, peer_username: 'owner' }];
}, 60000);

afterEach(() => {
  forget(ROOM);
  forget(P.sandbox.dmRid(DM));
});

describe('an unsigned wrap', () => {
  test('hands back a key this device already held', async () => {
    const k = await freshKey();
    await P.manager.loadArchivedKey(ROOM, k.kid, k.keyB64);
    const w = await wrap(k.keyB64);
    island.roomKey[ROOM] = { encrypted_room_key: w.blob, key_id: w.kid };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });
  });

  test('never introduces a key this device did not hold', async () => {
    const k = await freshKey();
    const w = await wrap(k.keyB64);
    island.roomKey[ROOM] = { encrypted_room_key: w.blob, key_id: w.kid };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: false, refused: true });
    expect(P.manager.roomKeys.has(ROOM)).toBe(false);
  });
});

describe('a signed wrap', () => {
  test('from a member, under their pinned key, opens the room', async () => {
    const k = await freshKey();
    const w = await wrap(k.keyB64, { by: owner, signer: 'owner' });
    island.roomKey[ROOM] = { encrypted_room_key: w.blob, key_id: w.kid };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });
  });

  test('opens when the island sends no key_id - which is what it does for a current key', async () => {
    // GET /crypto/room-key/{id} and /crypto/dm-key/{id} answer with the blob
    // alone; checking the signature against that missing claim refused every
    // signed current key until a run against a real island showed it.
    const k = await freshKey();
    const w = await wrap(k.keyB64, { by: owner, signer: 'owner' });
    island.roomKey[ROOM] = { encrypted_room_key: w.blob };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });

    const d = await wrap(k.keyB64, { by: owner, signer: 'owner', scope: 'dm', scopeId: DM });
    island.dmKey[DM] = { encrypted_thread_key: d.blob };
    expect(await P.sandbox.loadDmKey(DM, { peerUsername: 'owner' })).toEqual({ ok: true });
  });

  test('from somebody the room does not list is refused, however valid', async () => {
    const k = await freshKey();
    const w = await wrap(k.keyB64, { by: mallory, signer: 'mallory' });
    island.roomKey[ROOM] = { encrypted_room_key: w.blob, key_id: w.kid };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: false, refused: true });

    // The control: in a room that lists her, the same kind of wrap opens. It
    // was membership that decided, not her key.
    const ROOM_M = ROOM + 9;
    island.members[ROOM_M] = ['alice', 'mallory'];
    const w2 = await wrap(k.keyB64, { by: mallory, signer: 'mallory', scopeId: ROOM_M });
    island.roomKey[ROOM_M] = { encrypted_room_key: w2.blob, key_id: w2.kid };
    try {
      expect(await P.sandbox.loadRoomKey(ROOM_M)).toEqual({ ok: true });
    } finally {
      forget(ROOM_M);
    }
  });
});

describe('a pinned signing key', () => {
  test('cannot be swapped by the island; verifying the peer is what moves it', async () => {
    // Pin the owner's real key.
    const k1 = await freshKey();
    const w1 = await wrap(k1.keyB64, { by: owner, signer: 'owner' });
    island.roomKey[ROOM] = { encrypted_room_key: w1.blob, key_id: w1.kid };
    expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });

    // The island starts serving a key of its own for "owner".
    const islandMade = await account(P.CU);
    island.accounts.owner = { ...island.accounts.owner, ed25519_public_key: islandMade.edPubB64 };
    try {
      // Lock and unlock, so nothing is answered from the session cache.
      P.sandbox.lockCryptoSession();
      await unlock();

      const k2 = await freshKey();
      const forged = await wrap(k2.keyB64, { by: islandMade, signer: 'owner' });
      island.roomKey[ROOM] = { encrypted_room_key: forged.blob, key_id: forged.kid };
      expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: false, refused: true });

      // The real owner still verifies against the pin.
      const real = await wrap(k2.keyB64, { by: owner, signer: 'owner' });
      island.roomKey[ROOM] = { encrypted_room_key: real.blob, key_id: real.kid };
      expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });

      // The user verifies the peer: the parked key becomes the pinned one.
      forget(ROOM);
      expect(await P.sandbox.markKeyVerified('owner')).toBe(true);
      island.roomKey[ROOM] = { encrypted_room_key: forged.blob, key_id: forged.kid };
      expect(await P.sandbox.loadRoomKey(ROOM)).toEqual({ ok: true });
    } finally {
      serve('owner', owner);
      await P.sandbox.chrome.storage.local.set({
        [(await P.sandbox._fpBaseOn('island.test', 'alice', 'owner')) + ':ed']: owner.edPubB64,
      });
      P.sandbox.lockCryptoSession();
      await unlock();
    }
  });
});

describe('a DM key', () => {
  test('is accepted from the other person in the thread, found from the thread list', async () => {
    const k = await freshKey();
    const w = await wrap(k.keyB64, { by: owner, signer: 'owner', scope: 'dm', scopeId: DM });
    island.dmKey[DM] = { encrypted_thread_key: w.blob, key_id: w.kid };
    // No peer passed: the receive path, where only the island's list says who.
    expect(await P.sandbox.loadDmKey(DM)).toEqual({ ok: true });
  });

  test('is refused from anybody else, however valid their signature', async () => {
    const k = await freshKey();
    const w = await wrap(k.keyB64, { by: mallory, signer: 'mallory', scope: 'dm', scopeId: DM });
    island.dmKey[DM] = { encrypted_thread_key: w.blob, key_id: w.kid };
    expect(await P.sandbox.loadDmKey(DM, { peerUsername: 'owner' })).toEqual({ ok: false, refused: true });
  });
});

describe('the writer', () => {
  test('refuses to hand out a key it cannot sign, rather than sign nothing', () => {
    const me = P.sandbox.getMeUsername;
    P.sandbox.getMeUsername = () => '';
    try {
      expect(() => P.sandbox.wrapSignOpts(ROOM, 'bob', 'kid')).toThrow(/unlock/i);
    } finally {
      P.sandbox.getMeUsername = me;
    }
  });
});
