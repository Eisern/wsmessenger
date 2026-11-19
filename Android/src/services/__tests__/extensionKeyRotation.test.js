// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Changing a room's key, in the extension (chrome_extension/panel-crypto.js
 * rotateRoomKey), and what a member does when the key changes under them
 * (refreshKeyForUnknownKid, refreshRoomKeyIfHeld). The real panel-crypto.js
 * and the real CryptoManager, against a stubbed island that keeps every
 * request.
 *
 * A rotation used to be one request per member and then the owner's own copy.
 * Stopped half way it left the room on two keys and the owner without the one
 * it had just handed out; one member with an unverified key kept everybody on
 * the old key; and members with the room open neither read what came under the
 * new key nor stopped writing under the old one.
 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');
const { makePanel, unlockRealManager, PASS, EXT_DIR } = require('./integration/helpers/panelHarness');

const ROOM = 7;
const OTHER_ROOM = 8;

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
    members: ['owner', 'ann', 'bob'],
    keyStatus: {},          // username -> status the key lookup answers with
    rotations: [],          // every body POSTed to /rotate
    rotateReplies: [],      // queue: a status, 'throw', or a function(body)
    onRotate: null,         // called with each body, before the answer
    keyReads: 0,
  });
}

let P;
let s;
const people = {};          // username -> { pub, priv, account }

async function person(name) {
  const kp = await P.CU.generateIdentityKeyPair();
  const pub = await P.CU.exportPublicKey(kp.publicKey);
  people[name] = { pub, priv: kp.privateKey, account: { public_key: pub, ed25519_public_key: '' } };
  return people[name];
}

function route(url, opts = {}) {
  const u = new URL(url);
  const p = u.pathname;
  let m;
  if (p === `/rooms/${ROOM}/members`) {
    return reply(200, island.members.map((username) => ({ username, role: username === 'owner' ? 'owner' : 'member' })));
  }
  if ((m = p.match(/^\/keys\/([^/]+)$/))) {
    const name = decodeURIComponent(m[1]);
    if (island.keyStatus[name]) return reply(island.keyStatus[name], { detail: 'no' });
    return people[name] ? reply(200, { username: name, ...people[name].account }) : reply(404, { detail: 'no such user' });
  }
  if (p === `/crypto/room/${ROOM}/rotate` && opts.method === 'POST') {
    const body = JSON.parse(opts.body);
    island.rotations.push(body);
    if (island.onRotate) island.onRotate(body);
    const next = island.rotateReplies.length ? island.rotateReplies.shift() : 200;
    if (next === 'throw') throw new TypeError('Failed to fetch');
    if (typeof next === 'object') return reply(next.status, next.body || {}, next.headers || {});
    if (next !== 200) return reply(next, { detail: `refused with ${next}` });
    // Applied: the owner's copy is what the island now serves them.
    const mine = body.keys.find((k) => k.username === 'owner');
    island.roomKey = { encrypted_room_key: mine.encrypted_room_key };
    return reply(200, { ok: true, rotated: body.keys.length, without: body.without.length });
  }
  if (p === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: [] });
  if (p === `/crypto/room-key/${ROOM}`) {
    island.keyReads += 1;
    return island.roomKey ? reply(200, island.roomKey) : reply(404, {});
  }
  return reply(404, {});
}

/** A key wrapped for the owner as another device of theirs would wrap it. */
async function ownersCopy(keyB64) {
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  return {
    kid,
    encrypted_room_key: await P.CU.encryptRoomKeyForUser(P.manager.userPublicKeyPem, keyB64, {
      seed: P.manager.ed25519Seed, signer: 'owner', scope: 'room', scopeId: ROOM, recipient: 'owner', keyId: kid,
    }),
  };
}

async function newKey() {
  return P.CU.exportRoomKey(await P.CU.generateRoomKey(true));
}

/** A room message as somebody holding `keyB64` would send it. */
async function messageUnder(keyB64, text) {
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  const enc = await P.CU.encryptMessage(await P.CU.importRoomKey(keyB64), text, new TextEncoder().encode(kid));
  return JSON.stringify({ encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true });
}

const currentKid = () => P.manager.roomKeyIds.get(ROOM);

beforeAll(async () => {
  P = makePanel({ apiBase: 'https://island.test', islandId: 'island.test', username: 'owner', token: 'tok' });
  s = P.sandbox;
  s.fetch = async (url, opts) => route(String(url), opts);
  s.roomOwnerById = { [ROOM]: true };
  // The waits between attempts are real seconds; nothing here is about them.
  s.setTimeout = (fn) => { fn(); return 0; };
  await unlockRealManager(s, { username: 'owner', password: PASS });
  for (const name of ['ann', 'bob', 'carl', 'dan']) await person(name);
}, 60000);

beforeEach(async () => {
  resetIsland();
  vm.runInContext('_keySweep.reset(); _unknownKid.asked.clear(); _unknownKid.slotAt.clear();', s);
  // The room is on a key, and the owner holds it.
  island.oldKey = await newKey();
  const copy = await ownersCopy(island.oldKey);
  island.oldKid = copy.kid;
  island.roomKey = { encrypted_room_key: copy.encrypted_room_key };
  expect((await s.loadRoomKey(ROOM)).ok).toBe(true);
  island.keyReads = 0;
});

describe('changing the key', () => {
  test('every copy goes in one request, each signed for its member; only then is the key the one we write with', async () => {
    const kidWhileAsking = [];
    island.onRotate = () => kidWhileAsking.push(currentKid());

    const res = await s.rotateRoomKey(ROOM, { kickedUsername: 'mallory' });
    expect(res).toEqual({ ok: true, shared: 2, failed: [] });

    expect(island.rotations).toHaveLength(1);
    const body = island.rotations[0];
    expect(body.keys.map((k) => k.username)).toEqual(['owner', 'ann', 'bob']);
    expect(body.without).toEqual([]);
    expect(body.key_id).not.toBe(island.oldKid);

    // One key, wrapped for each of them, saying who gave it and for whom.
    const mine = await P.CU.decryptRoomKeyForUser(P.manager.userPrivateKey, body.keys[0].encrypted_room_key);
    expect(await P.CU.fingerprintRoomKeyBase64(mine)).toBe(body.key_id);
    const signerPub = await P.CU.ed25519GetPublicKey(P.manager.ed25519Seed);
    for (const name of ['ann', 'bob']) {
      const wrapped = body.keys.find((k) => k.username === name).encrypted_room_key;
      expect(await P.CU.decryptRoomKeyForUser(people[name].priv, wrapped)).toBe(mine);
      const info = P.CU.inspectWrappedKey(wrapped, { scope: 'room', scopeId: ROOM, recipient: name, keyId: body.key_id });
      expect(info.signer).toBe('owner');
      expect(await P.CU.ed25519Verify(signerPub, info.sig, info.sigMessage)).toBe(true);
    }

    // Until the island said yes we wrote under the old key; now under the new.
    expect(kidWhileAsking).toEqual([island.oldKid]);
    expect(currentKid()).toBe(body.key_id);
    // And what was written before is still readable.
    expect(P.manager.roomKeyArchive.get(ROOM).has(island.oldKid)).toBe(true);
  });

  test('a member whose key cannot be trusted, or who has none, is left without - and the room still changes', async () => {
    island.members = ['owner', 'ann', 'carl', 'ghost'];
    // carl's key is not the one pinned for him; ghost has no key at all.
    const pin = await s._fpBase('owner', 'carl');
    await s.chrome.storage.local.set({ [pin]: await P.CU.fingerprintPublicKey(people.dan.pub) });

    const res = await s.rotateRoomKey(ROOM);
    expect(res).toEqual({ ok: true, shared: 1, failed: ['carl', 'ghost'] });
    const body = island.rotations[0];
    expect(body.keys.map((k) => k.username)).toEqual(['owner', 'ann']);
    expect(body.without).toEqual(['carl', 'ghost']);
    expect(currentKid()).toBe(body.key_id);
    await s.chrome.storage.local.remove([pin]);
  });

  test('not being able to find out about a member stops it: nothing is sent and the old key stays', async () => {
    island.keyStatus.bob = 500;
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.failed).toEqual(['bob']);
    expect(res.error).toMatch(/old key remains active/);
    expect(island.rotations).toHaveLength(0);
    expect(currentKid()).toBe(island.oldKid);
  });

  test('the member list changing under us: it is read again, and the same key goes to the new list', async () => {
    island.rotateReplies = [409];
    island.onRotate = () => { if (island.rotations.length === 1) island.members = ['owner', 'ann', 'dan']; };

    const res = await s.rotateRoomKey(ROOM);
    expect(res).toEqual({ ok: true, shared: 2, failed: [] });
    expect(island.rotations).toHaveLength(2);
    expect(island.rotations[1].key_id).toBe(island.rotations[0].key_id);
    expect(island.rotations[0].keys.map((k) => k.username)).toEqual(['owner', 'ann', 'bob']);
    expect(island.rotations[1].keys.map((k) => k.username)).toEqual(['owner', 'ann', 'dan']);
  });

  test('a list that never settles ends with the old key, and says so', async () => {
    island.rotateReplies = [409, 409, 409, 409];
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/kept changing/);
    expect(island.rotations).toHaveLength(3);
    expect(currentKid()).toBe(island.oldKid);
  });

  test('an island that does not answer is asked again with the very same request', async () => {
    island.rotateReplies = ['throw', 503, { status: 429, headers: { 'retry-after': '5' } }, 200];
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(true);
    expect(island.rotations).toHaveLength(4);
    for (const again of island.rotations.slice(1)) expect(again).toEqual(island.rotations[0]);
    expect(currentKid()).toBe(island.rotations[0].key_id);
  });

  test('never answered: the new key is not written with, but opens what may come under it', async () => {
    island.rotateReplies = ['throw', 'throw', 'throw', 'throw', 'throw'];
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/may or may not have changed/);
    expect(island.rotations).toHaveLength(4);
    const newKid = island.rotations[0].key_id;
    expect(currentKid()).toBe(island.oldKid);
    expect(P.manager.roomKeyArchive.get(ROOM).has(newKid)).toBe(true);
  });

  test('a rate limit too long to wait out is an answer: the old key stays, nothing is half done', async () => {
    island.rotateReplies = [{ status: 429, body: { detail: 'Too many requests' }, headers: { 'retry-after': '600' } }];
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.error).toBe('Too many requests; old key remains active');
    expect(island.rotations).toHaveLength(1);
    expect(currentKid()).toBe(island.oldKid);
    expect(P.manager.roomKeyArchive.get(ROOM).has(island.rotations[0].key_id)).toBe(false);
  });

  test.each([
    [{ status: 403, body: { detail: 'Only the room owner can change the room key' } },
      'Only the room owner can change the room key; old key remains active'],
    [{ status: 404, body: { detail: 'Not Found' } }, expect.stringMatching(/needs an update/)],
    [{ status: 404, body: { detail: 'Room not found' } }, 'Room not found; old key remains active'],
  ])('the island refusing (%j) is not asked twice, and the old key stays', async (answer, message) => {
    island.rotateReplies = [answer];
    const res = await s.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.error).toEqual(message);
    expect(island.rotations).toHaveLength(1);
    expect(currentKid()).toBe(island.oldKid);
  });
});

describe('the key changing under a member with the room open', () => {
  async function rotatedElsewhere() {
    const key = await newKey();
    const copy = await ownersCopy(key);
    island.roomKey = { encrypted_room_key: copy.encrypted_room_key };
    return { key, kid: copy.kid };
  }

  test('a message under a key this device never held: the room\'s key is read again, once for all of them', async () => {
    const now = await rotatedElsewhere();
    const texts = await Promise.all([1, 2, 3].map(async (n) => s.decryptMessageFromRoom(
      ROOM, await messageUnder(now.key, `after the change ${n}`), 'ann')));

    expect(texts.map((t) => (typeof t === 'string' ? t : t.text))).toEqual(
      ['after the change 1', 'after the change 2', 'after the change 3']);
    expect(island.keyReads).toBe(1);
    // And from here on we write under the new key, not the one a removed
    // member holds.
    expect(currentKid()).toBe(now.kid);
    const sent = JSON.parse(await s.encryptMessageForRoom(ROOM, 'hello'));
    expect(sent.kid).toBe(now.kid);
    // Yesterday is still readable.
    const old = await s.decryptMessageFromRoom(ROOM, await messageUnder(island.oldKey, 'before'), 'ann');
    expect(typeof old === 'string' ? old : old.text).toBe('before');
    expect(island.keyReads).toBe(1);
  });

  test('an id nobody will give us a key for is not a request per message', async () => {
    const stranger = await newKey();            // the island still serves the old key
    const other = await newKey();
    const first = await s.decryptMessageFromRoom(ROOM, await messageUnder(stranger, 'x'), 'ann');
    expect(first).toBe('[Encrypted message - decryption failed]');
    expect(island.keyReads).toBe(1);

    for (let i = 0; i < 5; i++) await s.decryptMessageFromRoom(ROOM, await messageUnder(stranger, `x${i}`), 'ann');
    // A different made-up id straight after: the room was read seconds ago.
    await s.decryptMessageFromRoom(ROOM, await messageUnder(other, 'y'), 'ann');
    expect(island.keyReads).toBe(1);
    expect(currentKid()).toBe(island.oldKid);
  });

  test('a message under a key we hold asks the island nothing', async () => {
    const t = await s.decryptMessageFromRoom(ROOM, await messageUnder(island.oldKey, 'plain day'), 'ann');
    expect(typeof t === 'string' ? t : t.text).toBe('plain day');
    expect(island.keyReads).toBe(0);
  });

  test('told the key changed: a room whose key we hold is read again, one we have not opened is left alone', async () => {
    const now = await rotatedElsewhere();
    expect(await s.refreshRoomKeyIfHeld(OTHER_ROOM)).toBe(false);
    expect(island.keyReads).toBe(0);

    expect(await s.refreshRoomKeyIfHeld(ROOM)).toBe(true);
    expect(island.keyReads).toBe(1);
    expect(currentKid()).toBe(now.kid);
  });

  test('the wake-up reaches the panel: the worker relays it and the panel acts on it', () => {
    const src = (f) => fs.readFileSync(path.join(EXT_DIR, f), 'utf8');
    expect(src('background.js')).toMatch(/NOTIFY_RELAY_TYPES = new Set\(\[[^\]]*"notify_room_key"/);
    expect(src('panel.js')).toMatch(/msg\.type === "notify_room_key"[\s\S]{0,400}refreshRoomKeyIfHeld\(rid\)/);
  });
});

describe('the sweep and a key it cannot be sure of', () => {
  test('the room\'s key not readable from the island: nothing is handed out from memory', async () => {
    island.gaps = [{ room_id: ROOM, room_name: 'r', username: 'ann' }];
    const shares = [];
    const inner = s.fetch;
    s.fetch = async (url, opts = {}) => {
      const p = new URL(String(url)).pathname;
      if (p === '/crypto/rooms/key-gaps') return reply(200, { gaps: island.gaps, truncated: false });
      if (p === `/crypto/room-key/${ROOM}`) return reply(503, { detail: 'down' });
      if (p === `/crypto/room/${ROOM}/share`) { shares.push(JSON.parse(opts.body)); return reply(200, { ok: true, written: true }); }
      return inner(url, opts);
    };
    try {
      const res = await s.sweepRoomKeyGaps({ reason: 'test' });
      expect(res).toMatchObject({ ran: true, shared: 0, failed: 1, incomplete: true });
      expect(shares).toHaveLength(0);
    } finally {
      s.fetch = inner;
    }
  });
});
