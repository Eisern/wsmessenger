// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Changing a room's key on Android (CryptoService.rotateRoomKey), and what a
 * member does when the key changes under them. The real CryptoService,
 * CryptoManager and StorageService, against a stubbed island that keeps every
 * request.
 *
 * This used to make the new key current on the phone first and then share it
 * member by member, counting failures and answering "ok" all the same: a
 * member whose share failed could read nothing written from then on, with
 * nothing to bring them back.
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import { CryptoUtils, cryptoManager } from '../../crypto';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import KeySweepService from '../KeySweepService';

const ROOM = 7;
const OTHER_ROOM = 8;
const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

function identity() {
  const priv = x25519.utils.randomSecretKey();
  const edSeed = CryptoUtils.deriveEd25519Seed(priv);
  return { priv, pubB64: b64(x25519.getPublicKey(priv)), edSeed, edPubB64: b64(CryptoUtils.ed25519GetPublicKey(edSeed)) };
}

async function privateKeyOf(who) {
  return CryptoUtils.importPrivateKey(Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(who.priv),
  ]).toString('base64'));
}

const island = {};
const people = {};
let owner;

function resetIsland() {
  Object.assign(island, {
    members: ['own', 'ann', 'bob'],
    keyStatus: {},
    rotations: [],
    rotateReplies: [],     // queue: a status, or 'throw'
    onRotate: null,
    keyReads: 0,
    gapCalls: 0,
  });
}

async function ownersCopy(keyB64) {
  const kid = await CryptoUtils.fingerprintRoomKeyBase64(keyB64);
  return {
    kid,
    encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(owner.pubB64, keyB64, {
      seed: owner.edSeed, signer: 'own', scope: 'room', scopeId: ROOM, recipient: 'own', keyId: kid,
    }),
  };
}

const newKey = async () => CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));

async function messageUnder(keyB64, text) {
  const kid = await CryptoUtils.fingerprintRoomKeyBase64(keyB64);
  const enc = await CryptoUtils.encryptMessage(
    await CryptoUtils.importRoomKey(keyB64), text, new TextEncoder().encode(kid));
  return JSON.stringify({ encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true });
}

const currentKid = () => cryptoManager.roomKeyIds.get(ROOM);
const textOf = (m) => (m && typeof m === 'object' ? m.text : m);

let realSetTimeout;

beforeAll(async () => {
  resetIsland();
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = new URL(String(url));
    const p = u.pathname;
    let m;
    if (p === `/rooms/${ROOM}/members`) {
      return reply(200, island.members.map((username) => ({ username, role: username === 'own' ? 'owner' : 'member' })));
    }
    if ((m = p.match(/^\/keys\/([^/]+)$/))) {
      const name = decodeURIComponent(m[1]);
      if (island.keyStatus[name]) return reply(island.keyStatus[name], { detail: 'no' });
      const a = people[name];
      return a ? reply(200, { username: name, public_key: a.pubB64, ed25519_public_key: a.edPubB64 }) : reply(404, { detail: 'no such user' });
    }
    if (p === `/crypto/room/${ROOM}/rotate` && opts.method === 'POST') {
      const body = JSON.parse(opts.body);
      island.rotations.push(body);
      if (island.onRotate) island.onRotate(body);
      const next = island.rotateReplies.length ? island.rotateReplies.shift() : 200;
      if (next === 'throw') throw new TypeError('Network request failed');
      if (typeof next === 'object') return reply(next.status, next.body);
      if (next !== 200) return reply(next, { detail: `refused with ${next}` });
      const mine = body.keys.find((k) => k.username === 'own');
      island.roomKey = { encrypted_room_key: mine.encrypted_room_key };
      return reply(200, { ok: true, rotated: body.keys.length, without: body.without.length });
    }
    if (p === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: [] });
    if (p === `/crypto/room-key/${ROOM}`) {
      island.keyReads += 1;
      return island.roomKey ? reply(200, island.roomKey) : reply(404, { detail: 'no key' });
    }
    if (p === '/crypto/rooms/key-gaps') {
      island.gapCalls += 1;
      return reply(200, { gaps: [], truncated: false });
    }
    return reply(200, { ok: true });
  });
  NetworkService.setServerConfig('https://island-r.test', 'wss://island-r.test');
  NetworkService._token = 'owner-token';
  await StorageService.setActiveUsername('own');
  owner = identity();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(owner.priv), owner.pubB64)).toBe(true);
  for (const name of ['ann', 'bob', 'carl', 'dan']) people[name] = identity();

  // The waits between attempts are real seconds; nothing here is about them.
  realSetTimeout = global.setTimeout;
});

beforeEach(async () => {
  resetIsland();
  CryptoService._forgetUnknownKeyIds();
  island.oldKey = await newKey();
  const copy = await ownersCopy(island.oldKey);
  island.oldKid = copy.kid;
  island.roomKey = { encrypted_room_key: copy.encrypted_room_key };
  expect((await CryptoService._loadRoomKey(ROOM)).ok).toBe(true);
  expect(currentKid()).toBe(island.oldKid);
  island.keyReads = 0;
});

afterAll(() => {
  KeySweepService.stop();
  CryptoService.lockSession();
});

/** Run with the waits between attempts collapsed. */
async function hurried(fn) {
  const spy = jest.spyOn(global, 'setTimeout').mockImplementation((cb, ms, ...a) => realSetTimeout(cb, ms >= 1000 ? 0 : ms, ...a));
  try {
    return await fn();
  } finally {
    spy.mockRestore();
  }
}

describe('changing the key', () => {
  test('every copy goes in one request, each signed for its member; only then is the key the one we write with', async () => {
    const kidWhileAsking = [];
    island.onRotate = () => kidWhileAsking.push(currentKid());

    const res = await CryptoService.rotateRoomKey(ROOM);
    expect(res).toEqual({ ok: true, shared: 2, failed: [] });

    expect(island.rotations).toHaveLength(1);
    const body = island.rotations[0];
    expect(body.keys.map((k) => k.username)).toEqual(['own', 'ann', 'bob']);
    expect(body.without).toEqual([]);
    expect(body.key_id).not.toBe(island.oldKid);

    const mine = await CryptoUtils.decryptRoomKeyForUser(await privateKeyOf(owner), body.keys[0].encrypted_room_key);
    expect(await CryptoUtils.fingerprintRoomKeyBase64(mine)).toBe(body.key_id);
    for (const name of ['ann', 'bob']) {
      const wrapped = body.keys.find((k) => k.username === name).encrypted_room_key;
      expect(await CryptoUtils.decryptRoomKeyForUser(await privateKeyOf(people[name]), wrapped)).toBe(mine);
      const info = CryptoUtils.inspectWrappedKey(wrapped, { scope: 'room', scopeId: ROOM, recipient: name, keyId: body.key_id });
      expect(info.signer).toBe('own');
      expect(CryptoUtils.ed25519Verify(CryptoUtils.ed25519GetPublicKey(owner.edSeed), info.sig, info.sigMessage)).toBe(true);
    }

    // It used to be current here before anybody else had it.
    expect(kidWhileAsking).toEqual([island.oldKid]);
    expect(currentKid()).toBe(body.key_id);
    expect(JSON.parse(await CryptoService.encryptMessage(ROOM, 'hello', 'own')).kid).toBe(body.key_id);
    // What was written before is still readable.
    expect(textOf(await CryptoService.decryptMessage(ROOM, await messageUnder(island.oldKey, 'before'), 'ann'))).toBe('before');
  });

  test('a member whose key cannot be trusted, or who has none, is left without - and the room still changes', async () => {
    island.members = ['own', 'ann', 'carl', 'ghost'];
    const scope = await CryptoService.pinScope();
    await StorageService.setKnownFingerprint(scope, 'own', 'carl', await CryptoUtils.fingerprintPublicKey(people.dan.pubB64));

    const res = await CryptoService.rotateRoomKey(ROOM);
    expect(res).toEqual({ ok: true, shared: 1, failed: ['carl', 'ghost'] });
    const body = island.rotations[0];
    expect(body.keys.map((k) => k.username)).toEqual(['own', 'ann']);
    expect(body.without).toEqual(['carl', 'ghost']);
    expect(currentKid()).toBe(body.key_id);
  });

  test('somebody left without is a gap: the sweep is asked to look at the room', async () => {
    jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });
    try {
      KeySweepService.start();
      jest.advanceTimersByTime(2500);
      for (let i = 0; i < 2000 && island.gapCalls < 1; i++) await new Promise((r) => setImmediate(r));
      const before = island.gapCalls;
      island.members = ['own', 'ann', 'ghost'];

      expect((await CryptoService.rotateRoomKey(ROOM)).failed).toEqual(['ghost']);
      jest.advanceTimersByTime(61_000);
      for (let i = 0; i < 2000 && island.gapCalls <= before; i++) await new Promise((r) => setImmediate(r));
      expect(island.gapCalls).toBe(before + 1);
    } finally {
      KeySweepService.stop();
      jest.useRealTimers();
    }
  });

  test('not being able to find out about a member stops it: nothing is sent and the old key stays', async () => {
    island.keyStatus.bob = 500;
    const res = await CryptoService.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.failed).toEqual(['bob']);
    expect(res.error).toMatch(/old key remains active/);
    expect(island.rotations).toHaveLength(0);
    expect(currentKid()).toBe(island.oldKid);
  });

  test('the member list changing under us: it is read again, and the same key goes to the new list', async () => {
    island.rotateReplies = [409];
    island.onRotate = () => { if (island.rotations.length === 1) island.members = ['own', 'ann', 'dan']; };

    const res = await CryptoService.rotateRoomKey(ROOM);
    expect(res).toEqual({ ok: true, shared: 2, failed: [] });
    expect(island.rotations).toHaveLength(2);
    expect(island.rotations[1].key_id).toBe(island.rotations[0].key_id);
    expect(island.rotations[1].keys.map((k) => k.username)).toEqual(['own', 'ann', 'dan']);
  });

  test('an island that does not answer is asked again with the very same request', async () => {
    island.rotateReplies = ['throw', 503, 200];
    const res = await hurried(() => CryptoService.rotateRoomKey(ROOM));
    expect(res.ok).toBe(true);
    expect(island.rotations).toHaveLength(3);
    for (const again of island.rotations.slice(1)) expect(again).toEqual(island.rotations[0]);
    expect(currentKid()).toBe(island.rotations[0].key_id);
  });

  test('never answered: the new key is not written with, but opens what may come under it', async () => {
    island.rotateReplies = ['throw', 'throw', 'throw', 'throw', 'throw'];
    const res = await hurried(() => CryptoService.rotateRoomKey(ROOM));
    expect(res.ok).toBe(false);
    expect(res.error).toMatch(/may or may not have changed/);
    expect(island.rotations).toHaveLength(4);
    expect(currentKid()).toBe(island.oldKid);
    expect(cryptoManager.roomKeyArchive.get(ROOM).has(island.rotations[0].key_id)).toBe(true);
  });

  test.each([
    [{ status: 403, body: { detail: 'Only the room owner can change the room key' } },
      'Only the room owner can change the room key; old key remains active'],
    [{ status: 404, body: { detail: 'Not Found' } }, expect.stringMatching(/needs an update/)],
  ])('the island refusing (%j) is not asked twice, and the old key stays', async (answer, message) => {
    island.rotateReplies = [answer];
    const res = await CryptoService.rotateRoomKey(ROOM);
    expect(res.ok).toBe(false);
    expect(res.error).toEqual(message);
    expect(island.rotations).toHaveLength(1);
    expect(currentKid()).toBe(island.oldKid);
    expect(cryptoManager.roomKeyArchive.get(ROOM).has(island.rotations[0].key_id)).toBe(false);
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
    const texts = await Promise.all([1, 2, 3].map(async (n) => CryptoService.decryptMessage(
      ROOM, await messageUnder(now.key, `after the change ${n}`), 'ann')));

    expect(texts.map(textOf)).toEqual(['after the change 1', 'after the change 2', 'after the change 3']);
    expect(island.keyReads).toBe(1);
    expect(currentKid()).toBe(now.kid);
    expect(JSON.parse(await CryptoService.encryptMessage(ROOM, 'hello', 'own')).kid).toBe(now.kid);
    expect(textOf(await CryptoService.decryptMessage(ROOM, await messageUnder(island.oldKey, 'before'), 'ann'))).toBe('before');
    expect(island.keyReads).toBe(1);
  });

  test('an id nobody will give us a key for is not a request per message', async () => {
    const stranger = await newKey();
    const other = await newKey();
    expect(await CryptoService.decryptMessage(ROOM, await messageUnder(stranger, 'x'), 'ann')).toBeNull();
    expect(island.keyReads).toBe(1);

    for (let i = 0; i < 5; i++) await CryptoService.decryptMessage(ROOM, await messageUnder(stranger, `x${i}`), 'ann');
    // A different made-up id straight after: the room was read seconds ago.
    await CryptoService.decryptMessage(ROOM, await messageUnder(other, 'y'), 'ann');
    expect(island.keyReads).toBe(1);
    expect(currentKid()).toBe(island.oldKid);
  });

  test('told the key changed: a room whose key we hold is read again, one we have not opened is left alone', async () => {
    const now = await rotatedElsewhere();
    expect(await CryptoService.refreshRoomKeyIfHeld(OTHER_ROOM)).toBe(false);
    expect(island.keyReads).toBe(0);

    KeySweepService.start();
    try {
      NetworkService._post({ type: 'notify_room_key', room_id: ROOM });
      for (let i = 0; i < 5000 && currentKid() !== now.kid; i++) await new Promise((r) => setImmediate(r));
      expect(currentKid()).toBe(now.kid);
      expect(island.keyReads).toBe(1);
    } finally {
      KeySweepService.stop();
    }
  });
});

describe('the sweep and a key it cannot be sure of', () => {
  test('the room\'s key not readable from the island: nothing is handed out from memory', async () => {
    const shares = [];
    const inner = global.fetch;
    global.fetch = jest.fn(async (url, opts = {}) => {
      const p = new URL(String(url)).pathname;
      if (p === '/crypto/rooms/key-gaps') return reply(200, { gaps: [{ room_id: ROOM, room_name: 'r', username: 'ann' }], truncated: false });
      if (p === `/crypto/room-key/${ROOM}`) return reply(404, { detail: 'no key' });
      if (p === `/crypto/room/${ROOM}/share`) { shares.push(JSON.parse(opts.body)); return reply(200, { ok: true, written: true }); }
      return inner(url, opts);
    });
    try {
      KeySweepService.stop();
      const res = await KeySweepService.run({ reason: 'test' });
      expect(res).toMatchObject({ ran: true, shared: 0, failed: 1, incomplete: true });
      expect(shares).toHaveLength(0);
    } finally {
      global.fetch = inner;
    }
  });
});
