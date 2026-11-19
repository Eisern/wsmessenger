// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * A room's key only moves forward, in the extension (chrome_extension/
 * panel-crypto.js loadRoomKey with room-key-guard.js). The real panel-crypto
 * and the real CryptoManager, against a stubbed island that keeps every
 * request.
 *
 * loadRoomKey made whatever key the island served the room's current one, as
 * long as its wrap was genuine - and a wrap the owner signed for an older key
 * is genuine. An island that kept it could put a member back on the key from
 * before a removal. And an owner the island had no copy for made a new key for
 * themselves alone: the room went on under two keys.
 */

const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const ROOM = 7;
const MEMBER_ROOM = 9;   // a room this account is a member of, not the owner
const GUARD = (rid) => `__rkguard_v1:island.test:owner:${rid}`;

function reply(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[String(k).toLowerCase()] ?? null },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

const island = {};
function resetIsland() {
  Object.assign(island, {
    members: ['owner', 'ann'],
    roomKey: { [ROOM]: null, [MEMBER_ROOM]: null },
    log: [],              // "METHOD path" of every request
    posted: [],           // bodies POSTed to /crypto/room-key
    rotations: [],        // bodies POSTed to /rotate
    gate: null,           // a promise the next key read waits for
  });
}

let P;
let s;
const people = {};

async function person(name) {
  const kp = await P.CU.generateIdentityKeyPair();
  const pub = await P.CU.exportPublicKey(kp.publicKey);
  people[name] = { public_key: pub, ed25519_public_key: '' };
}

async function route(url, opts = {}) {
  const u = new URL(url);
  const p = u.pathname;
  const method = String(opts.method || 'GET').toUpperCase();
  island.log.push(`${method} ${p}`);
  let m;
  if ((m = p.match(/^\/rooms\/(\d+)\/members$/))) {
    return reply(200, island.members.map((username) => ({ username, role: username === 'owner' ? 'owner' : 'member' })));
  }
  if ((m = p.match(/^\/keys\/([^/]+)$/))) {
    const name = decodeURIComponent(m[1]);
    return people[name] ? reply(200, { username: name, ...people[name] }) : reply(404, { detail: 'no such user' });
  }
  if (p === '/crypto/room-key' && method === 'POST') {
    const body = JSON.parse(opts.body);
    island.posted.push(body);
    island.roomKey[body.room_id] = { encrypted_room_key: body.encrypted_room_key };
    return reply(200, { ok: true });
  }
  if ((m = p.match(/^\/crypto\/room\/(\d+)\/rotate$/)) && method === 'POST') {
    const body = JSON.parse(opts.body);
    island.rotations.push(body);
    const mine = body.keys.find((k) => k.username === 'owner');
    island.roomKey[Number(m[1])] = { encrypted_room_key: mine.encrypted_room_key };
    return reply(200, { ok: true, rotated: body.keys.length, without: body.without.length });
  }
  if ((m = p.match(/^\/crypto\/room-key\/(\d+)\/archive$/))) return reply(200, { keys: [] });
  if ((m = p.match(/^\/crypto\/room-key\/(\d+)$/))) {
    // The answer is decided when the request arrives; a gate only delays it.
    const answer = island.roomKey[Number(m[1])];
    if (island.gate) {
      const g = island.gate;
      island.gate = null;
      await g;
    }
    return answer ? reply(200, answer) : reply(404, { detail: 'no key' });
  }
  return reply(404, {});
}

/** The owner's copy of `keyB64` for `rid`, as one of their devices would wrap it. */
async function ownersCopy(keyB64, rid = ROOM) {
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  return {
    kid,
    encrypted_room_key: await P.CU.encryptRoomKeyForUser(P.manager.userPublicKeyPem, keyB64, {
      seed: P.manager.ed25519Seed, signer: 'owner', scope: 'room', scopeId: rid, recipient: 'owner', keyId: kid,
    }),
  };
}

async function newKey() {
  return P.CU.exportRoomKey(await P.CU.generateRoomKey(true));
}

const currentKid = (rid = ROOM) => P.manager.roomKeyIds.get(rid);
const writesWith = async (rid = ROOM) => JSON.parse(await s.encryptMessageForRoom(rid, 'probe')).kid;

/** The panel closed and opened again: nothing in memory, the disk as it was. */
function restart(rid = ROOM) {
  for (const m of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive', 'roomKeyArchiveB64']) {
    P.manager[m].delete(rid);
  }
  vm.runInContext('_roomKeyGuard.clear(); _heldBackNoted.clear();', s);
}

/** A device with no history of the room at all. */
async function forget(rid = ROOM) {
  restart(rid);
  await s.chrome.storage.local.remove([GUARD(rid), `__rka:${rid}`]);
}

/** The island serves `keyB64` as the room's key; the panel reads it. */
async function serve(keyB64, rid = ROOM) {
  const copy = await ownersCopy(keyB64, rid);
  island.roomKey[rid] = { encrypted_room_key: copy.encrypted_room_key };
  return copy.kid;
}

let held;

beforeAll(async () => {
  P = makePanel({ apiBase: 'https://island.test', islandId: 'island.test', username: 'owner', token: 'tok' });
  s = P.sandbox;
  s.fetch = async (url, opts) => route(String(url), opts);
  s.roomOwnerById = { [ROOM]: true, [MEMBER_ROOM]: false };
  s.setTimeout = (fn) => { fn(); return 0; };
  // A storage key that works, so the archive really reaches the disk.
  s.encryptForStorage = async (json) => ({ iv: 'iv', ct: Buffer.from(json, 'utf8').toString('base64') });
  s.decryptFromStorage = async ({ ct }) => Buffer.from(ct, 'base64').toString('utf8');
  held = [];
  s.window.onRoomKeyHeldBack = (slot) => held.push(slot);
  await unlockRealManager(s, { username: 'owner', password: PASS });
  await person('ann');
}, 60000);

let K1;
let K2;
let kid1;
let kid2;

beforeEach(async () => {
  resetIsland();
  held.length = 0;
  await forget(ROOM);
  await forget(MEMBER_ROOM);
  vm.runInContext('_ownerRekeyAt.clear();', s);
  // The room was on K1, and then its key was changed to K2 - and this device
  // read both.
  K1 = await newKey();
  K2 = await newKey();
  kid1 = await serve(K1);
  expect((await s.loadRoomKey(ROOM)).ok).toBe(true);
  kid2 = await serve(K2);
  expect((await s.loadRoomKey(ROOM)).ok).toBe(true);
  expect(currentKid()).toBe(kid2);
  island.log.length = 0;
});

describe('the island offers a key this device moved on from', () => {
  test('it is refused, the room stays on the newer key, and the open room is told once', async () => {
    await serve(K1);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true, heldBack: true });
    expect(currentKid()).toBe(kid2);
    expect(await writesWith()).toBe(kid2);
    expect(held).toEqual([ROOM]);

    await s.loadRoomKey(ROOM);
    expect(held).toEqual([ROOM]);
  });

  test('the old key still opens what was written under it', async () => {
    const enc = await P.CU.encryptMessage(await P.CU.importRoomKey(K1), 'раньше', new TextEncoder().encode(kid1));
    await serve(K1);
    await s.loadRoomKey(ROOM);
    const wire = JSON.stringify({ encrypted: true, iv: enc.iv, data: enc.data, kid: kid1, aad_v1: true });
    const out = await s.decryptMessageFromRoom(ROOM, wire, null);
    expect(typeof out === 'object' ? out.text : out).toBe('раньше');
  });

  test('a key newer than both is still taken', async () => {
    await serve(K1);
    await s.loadRoomKey(ROOM);
    const K3 = await newKey();
    const kid3 = await serve(K3);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid3);
    // ...and from then on K2 is behind us too.
    await serve(K2);
    expect((await s.loadRoomKey(ROOM)).heldBack).toBe(true);
    expect(currentKid()).toBe(kid3);
  });

  test('after a restart, from the disk: the newer key comes back, not the island\'s', async () => {
    restart();
    await serve(K1);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true, heldBack: true });
    expect(currentKid()).toBe(kid2);
    expect(await writesWith()).toBe(kid2);
  });

  test('with the newer key gone from the disk, the room has no key - not the old one', async () => {
    restart();
    await s.chrome.storage.local.remove(`__rka:${ROOM}`);
    await serve(K1);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: false, refused: true, heldBack: true });
    expect(P.manager.roomKeys.has(ROOM)).toBe(false);
  });

  test('a device with no history of the room takes what the island says', async () => {
    // The limit of this protection, pinned so it is not mistaken for more.
    await forget();
    await serve(K1);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid1);
  });
});

describe('an answer that arrives after the key changed here', () => {
  test('is not applied, and does not retire the key that replaced it', async () => {
    // The read goes out while the room is on K2; before the answer (K2)
    // arrives, this device moves to K3 - a rotation of its own.
    let release;
    island.gate = new Promise((r) => { release = r; });
    const reading = s.loadRoomKey(ROOM);
    await new Promise((r) => setImmediate(r));
    const K3 = await newKey();
    const kid3 = await P.CU.fingerprintRoomKeyBase64(K3);
    expect(await P.manager.loadRoomKey(ROOM, K3)).toBe(true);
    release();
    expect((await reading).ok).toBe(true);
    expect(currentKid()).toBe(kid3);

    // K3 was not retired by the late answer: the island serving it is fine.
    await serve(K3);
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid3);
  });
});

describe('the owner, with no copy on the island', () => {
  test('puts their copy of the key the room is on back - no new key', async () => {
    restart();
    island.roomKey[ROOM] = null;
    expect(await s.loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid2);
    expect(island.rotations).toHaveLength(0);
    expect(island.posted).toHaveLength(1);
    expect(island.posted[0].key_id).toBe(kid2);
    const info = P.CU.inspectWrappedKey(island.posted[0].encrypted_room_key);
    expect(info.signed).toBe(true);
  });

  test('knowing no key, changes it for everybody - not for themselves alone', async () => {
    await forget();
    island.roomKey[ROOM] = null;
    expect((await s.loadRoomKey(ROOM)).ok).toBe(true);
    expect(island.rotations).toHaveLength(1);
    expect(island.rotations[0].keys.map((k) => k.username).sort()).toEqual(['ann', 'owner']);
    expect(island.posted).toHaveLength(0);
    expect(currentKid()).toBe(island.rotations[0].key_id);
  });

  test('does that at most once in ten minutes, and sharing never makes a key instead', async () => {
    await forget();
    island.roomKey[ROOM] = null;
    await s.loadRoomKey(ROOM);
    await forget();
    island.roomKey[ROOM] = null;
    expect((await s.loadRoomKey(ROOM)).ok).toBe(false);
    await expect(s.shareRoomKeyToUser(ROOM, 'ann', { interactive: false })).rejects.toThrow(/not available/);
    expect(island.rotations).toHaveLength(1);
    expect(island.posted).toHaveLength(0);
  });
});

describe('a member, with no copy on the island', () => {
  test('waits for one: nothing is made, nothing is sent', async () => {
    expect(await s.loadRoomKey(MEMBER_ROOM)).toEqual({ ok: false, notFound: true });
    await expect(s.shareRoomKeyToUser(MEMBER_ROOM, 'ann', { interactive: false })).rejects.toThrow(/not available/);
    expect(island.rotations).toHaveLength(0);
    expect(island.posted).toHaveLength(0);
  });
});
