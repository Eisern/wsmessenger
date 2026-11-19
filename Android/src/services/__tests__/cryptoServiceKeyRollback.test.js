// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * A room's key only moves forward, on Android (CryptoService._loadRoomKey and
 * ensureRoomKeyReady with room-key-guard.js). The real CryptoService,
 * CryptoManager and StorageService, against a stubbed island that keeps every
 * request. The extension's twin is extensionKeyRollback.test.js.
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import { CryptoUtils, cryptoManager } from '../../crypto';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import EP from '../endpoints';
import RKG from '../room-key-guard';

const ROOM = 7;
const MEMBER_ROOM = 9;
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

const island = {};
const people = {};
let owner;

function resetIsland() {
  Object.assign(island, {
    members: ['own', 'ann'],
    roomKey: { [ROOM]: null, [MEMBER_ROOM]: null },
    posted: [],
    rotations: [],
    gate: null,
  });
}

async function ownersCopy(keyB64, rid = ROOM) {
  const kid = await CryptoUtils.fingerprintRoomKeyBase64(keyB64);
  return {
    kid,
    encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(owner.pubB64, keyB64, {
      seed: owner.edSeed, signer: 'own', scope: 'room', scopeId: rid, recipient: 'own', keyId: kid,
    }),
  };
}

const newKey = async () => CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
const currentKid = (rid = ROOM) => cryptoManager.roomKeyIds.get(rid);

async function serve(keyB64, rid = ROOM) {
  const copy = await ownersCopy(keyB64, rid);
  island.roomKey[rid] = { encrypted_room_key: copy.encrypted_room_key };
  return copy.kid;
}

/** The app closed and opened again: nothing in memory, the disk as it was. */
async function restart() {
  CryptoService.lockSession();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(owner.priv), owner.pubB64)).toBe(true);
}

/** A phone with no history of the room at all. */
async function forget(rid = ROOM) {
  const island_ = EP.islandIdOf(NetworkService.getServerConfig());
  await StorageService.remove(`${RKG.PREFIX}${island_}:own:${rid}`);
  await StorageService.setRoomKeyArchive(rid, []);
  await restart();
}

const held = [];

beforeAll(async () => {
  resetIsland();
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = new URL(String(url));
    const p = u.pathname;
    const method = String(opts.method || 'GET').toUpperCase();
    let m;
    if ((m = p.match(/^\/rooms\/(\d+)\/members$/))) {
      return reply(200, island.members.map((username) => ({ username, role: username === 'own' ? 'owner' : 'member' })));
    }
    if ((m = p.match(/^\/keys\/([^/]+)$/))) {
      const a = people[decodeURIComponent(m[1])];
      return a ? reply(200, { username: m[1], public_key: a.pubB64, ed25519_public_key: a.edPubB64 }) : reply(404, { detail: 'no such user' });
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
      const mine = body.keys.find((k) => k.username === 'own');
      island.roomKey[Number(m[1])] = { encrypted_room_key: mine.encrypted_room_key };
      return reply(200, { ok: true, rotated: body.keys.length, without: body.without.length });
    }
    if ((m = p.match(/^\/crypto\/room-key\/(\d+)\/archive$/))) return reply(200, { keys: [] });
    if ((m = p.match(/^\/crypto\/room-key\/(\d+)$/))) {
      const answer = island.roomKey[Number(m[1])];
      if (island.gate) {
        const g = island.gate;
        island.gate = null;
        await g;
      }
      return answer ? reply(200, answer) : reply(404, { detail: 'no key' });
    }
    return reply(200, { ok: true });
  });
  NetworkService.setServerConfig('https://island-k.test', 'wss://island-k.test');
  NetworkService._token = 'owner-token';
  NetworkService._username = 'own';
  await StorageService.setActiveUsername('own');
  owner = identity();
  people.ann = identity();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(owner.priv), owner.pubB64)).toBe(true);
  CryptoService.on('room_key_held_back', ({ roomId }) => held.push(roomId));
});

let K1;
let K2;
let kid1;
let kid2;

beforeEach(async () => {
  resetIsland();
  held.length = 0;
  await forget(ROOM);
  await forget(MEMBER_ROOM);
  K1 = await newKey();
  K2 = await newKey();
  kid1 = await serve(K1);
  expect((await CryptoService._loadRoomKey(ROOM)).ok).toBe(true);
  kid2 = await serve(K2);
  expect((await CryptoService._loadRoomKey(ROOM)).ok).toBe(true);
  expect(currentKid()).toBe(kid2);
});

afterAll(() => {
  CryptoService.lockSession();
});

describe('the island offers a key this phone moved on from', () => {
  test('it is refused, the room stays on the newer key, and the screen is told once', async () => {
    await serve(K1);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ ok: true, heldBack: true });
    expect(currentKid()).toBe(kid2);
    expect(held).toEqual([ROOM]);
    await CryptoService._loadRoomKey(ROOM);
    expect(held).toEqual([ROOM]);
  });

  test('a key newer than both is still taken', async () => {
    await serve(K1);
    await CryptoService._loadRoomKey(ROOM);
    const K3 = await newKey();
    const kid3 = await serve(K3);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid3);
  });

  test('after a restart, from the stored archive: the newer key comes back', async () => {
    await restart();
    await serve(K1);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ ok: true, heldBack: true });
    expect(currentKid()).toBe(kid2);
  });

  test('with the newer key gone from storage, the room has no key - not the old one', async () => {
    await StorageService.setRoomKeyArchive(ROOM, []);
    await restart();
    await serve(K1);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ refused: true, heldBack: true });
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('a phone with no history of the room takes what the island says', async () => {
    // The limit of this protection, pinned so it is not mistaken for more.
    await forget();
    await serve(K1);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid1);
  });
});

describe('an answer that arrives after the key changed here', () => {
  test('is not applied, and does not retire the key that replaced it', async () => {
    let release;
    island.gate = new Promise((r) => { release = r; });
    const reading = CryptoService._loadRoomKey(ROOM);
    await new Promise((r) => setImmediate(r));
    const K3 = await newKey();
    const kid3 = await CryptoUtils.fingerprintRoomKeyBase64(K3);
    expect(await cryptoManager.loadRoomKey(ROOM, K3)).toBe(true);
    release();
    expect((await reading).ok).toBe(true);
    expect(currentKid()).toBe(kid3);

    await serve(K3);
    expect(await CryptoService._loadRoomKey(ROOM)).toEqual({ ok: true });
    expect(currentKid()).toBe(kid3);
  });
});

describe('the owner, with no copy on the island', () => {
  test('puts their copy of the key the room is on back - no new key', async () => {
    await restart();
    island.roomKey[ROOM] = null;
    await CryptoService.ensureRoomKeyReady(ROOM, { isOwner: true });
    expect(currentKid()).toBe(kid2);
    expect(island.rotations).toHaveLength(0);
    expect(island.posted).toHaveLength(1);
    expect(island.posted[0].key_id).toBe(kid2);
  });

  test('knowing no key, changes it for everybody - once in ten minutes', async () => {
    await forget();
    island.roomKey[ROOM] = null;
    await CryptoService.ensureRoomKeyReady(ROOM, { isOwner: true });
    expect(island.rotations).toHaveLength(1);
    expect(island.rotations[0].keys.map((k) => k.username).sort()).toEqual(['ann', 'own']);
    expect(island.posted).toHaveLength(0);
    expect(currentKid()).toBe(island.rotations[0].key_id);

    await forget();
    island.roomKey[ROOM] = null;
    await CryptoService.ensureRoomKeyReady(ROOM, { isOwner: true });
    expect(island.rotations).toHaveLength(1);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });
});

describe('a member, with no copy on the island', () => {
  test('waits for one: nothing is made, nothing is sent', async () => {
    await CryptoService.ensureRoomKeyReady(MEMBER_ROOM, { isOwner: false });
    expect(cryptoManager.roomKeys.has(MEMBER_ROOM)).toBe(false);
    expect(island.rotations).toHaveLength(0);
    expect(island.posted).toHaveLength(0);
  });
});
