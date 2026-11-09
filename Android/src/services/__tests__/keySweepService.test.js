// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Android handing out missing room keys (KeySweepService) over the real
 * CryptoService and StorageService, against a stubbed island. The rules of
 * when and how often are key-sweep.js's and tested there; this holds the
 * Android half: what goes over the wire, what the trust check stops, and that
 * the triggers the app hears actually start a run.
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import KeySweepService from '../KeySweepService';

const HOME = 'https://island-r.test';
const ROOM = 7;
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

const island = {
  gaps: [], gapsStatus: 200, accounts: {}, shares: [], written: true, roomKey: null, gapCalls: [],
};

let mod;
let roomKeyB64;
let roomKid;
const GUEST = 'Alice@island-g.test~ca2a4f';

const flush = async (n = 40) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = new URL(String(url));
    const p = u.pathname;
    if (p === '/crypto/rooms/key-gaps') {
      island.gapCalls.push(u.searchParams.get('room_id'));
      if (island.gapsStatus !== 200) return reply(island.gapsStatus, { detail: 'no' });
      return reply(200, { gaps: island.gaps, truncated: false });
    }
    if (p === `/crypto/room-key/${ROOM}`) return island.roomKey ? reply(200, island.roomKey) : reply(404, { detail: 'no key' });
    if (p.startsWith('/crypto/room-key-archive') || p === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: [] });
    let m;
    if ((m = p.match(/^\/keys\/([^/]+)$/))) {
      const a = island.accounts[decodeURIComponent(m[1])];
      return a ? reply(200, { username: decodeURIComponent(m[1]), public_key: a.pubB64, ed25519_public_key: a.edPubB64 }) : reply(404, { detail: 'no such user' });
    }
    if ((m = p.match(/^\/crypto\/room\/(\d+)\/share$/)) && opts.method === 'POST') {
      island.shares.push({ room: Number(m[1]), target: u.searchParams.get('target_username'), body: JSON.parse(opts.body) });
      return reply(200, { ok: true, written: island.written });
    }
    return reply(200, { ok: true });
  });
  NetworkService.setServerConfig(HOME, 'wss://island-r.test');
  NetworkService._token = 'mod-token';
  await StorageService.setActiveUsername('mod');
  mod = identity();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(mod.priv), mod.pubB64)).toBe(true);

  roomKeyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  roomKid = await CryptoUtils.fingerprintRoomKeyBase64(roomKeyB64);
  island.roomKey = {
    encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(mod.pubB64, roomKeyB64, {
      seed: mod.edSeed, signer: 'mod', scope: 'room', scopeId: ROOM, recipient: 'mod', keyId: roomKid,
    }),
  };
});

beforeEach(() => {
  KeySweepService.stop();   // a clean clock for each test
  island.shares = [];
  island.gapCalls = [];
  island.gapsStatus = 200;
  island.written = true;
});

afterAll(() => {
  KeySweepService.stop();
  CryptoService.lockSession();
});

test('closes a gap: the key goes to the member, signed for them, and only fills the gap', async () => {
  const alice = identity();
  island.accounts[GUEST] = alice;
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: GUEST }];

  const res = await KeySweepService.run({ reason: 'test' });
  expect(res).toMatchObject({ ran: true, shared: 1, failed: 0 });
  expect(island.shares).toHaveLength(1);
  const { target, body } = island.shares[0];
  expect(target).toBe(GUEST);
  expect(body.if_absent).toBe(true);

  // It opens for her, and says the moderator gave it - for her, in this room,
  // whichever way either side spells her name.
  const priv = await CryptoUtils.importPrivateKey(Buffer.concat([
    Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(alice.priv),
  ]).toString('base64'));
  expect(await CryptoUtils.decryptRoomKeyForUser(priv, body.encrypted_room_key)).toBe(roomKeyB64);
  const info = CryptoUtils.inspectWrappedKey(body.encrypted_room_key, {
    scope: 'room', scopeId: ROOM, recipient: GUEST.toLowerCase(), keyId: roomKid,
  });
  expect(info.signer).toBe('mod');
  expect(CryptoUtils.ed25519Verify(CryptoUtils.ed25519GetPublicKey(mod.edSeed), info.sig, info.sigMessage)).toBe(true);
});

test('another provider closing it first is a success, not a failure', async () => {
  island.accounts.bob = identity();
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: 'bob' }];
  island.written = false;
  expect(await KeySweepService.run()).toMatchObject({ ran: true, shared: 0, alreadyHad: 1, failed: 0 });
});

test('a key pinned from a card is not replaced by the one the island serves: nothing is sent, and the member waits for a verification', async () => {
  const carded = identity();
  const swapped = identity();
  const name = 'Bob@island-x.test~0b0b0b';
  const scope = await CryptoService.pinScope();
  await StorageService.setKnownFingerprint(scope, 'mod', name, await CryptoUtils.fingerprintPublicKey(carded.pubB64));
  island.accounts[name] = swapped;
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: name }];

  const res = await KeySweepService.run();
  expect(res).toMatchObject({ ran: true, shared: 0, skipped: 1, failed: 0 });
  expect(island.shares).toHaveLength(0);
  expect(KeySweepService.trustBlocked()).toEqual([{ username: name.toLowerCase(), reason: 'TRUST_CHANGED', rooms: [ROOM] }]);
});

test('not a provider of this room: the island\'s 403 is an answer, not a failure to back off from', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });
  try {
    island.gapsStatus = 403;
    expect(await KeySweepService.run({ roomId: ROOM })).toMatchObject({ ran: true, failed: 0 });
    // An answer costs the ordinary interval; a failure would cost five minutes.
    jest.advanceTimersByTime(61_000);
    expect((await KeySweepService.run({ roomId: ROOM })).ran).toBe(true);

    island.gapsStatus = 500;
    jest.advanceTimersByTime(61_000);
    expect((await KeySweepService.run({ roomId: ROOM })).ran).toBe(true);
    jest.advanceTimersByTime(61_000);
    expect((await KeySweepService.run({ roomId: ROOM })).ran).toBe(false);
  } finally {
    jest.useRealTimers();
  }
});

test('the start, the notify socket\'s key-gap wake-up and a membership change each start a run', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });
  try {
    island.gaps = [];
    KeySweepService.start();
    jest.advanceTimersByTime(2500);   // the start-up run, unlocked already
    await flush();
    expect(island.gapCalls).toEqual([null]);

    jest.advanceTimersByTime(60_000);  // past its interval
    NetworkService._post({ type: 'notify_key_gap', room_id: ROOM });
    jest.advanceTimersByTime(0);
    await flush();
    expect(island.gapCalls).toEqual([null, String(ROOM)]);

    jest.advanceTimersByTime(60_000);
    NetworkService._post({ type: 'members_changed', room_id: 9, action: 'invite_accepted', username: 'x' });
    jest.advanceTimersByTime(0);
    await flush();
    expect(island.gapCalls).toEqual([null, String(ROOM), '9']);

    // Somebody leaving is not a gap.
    jest.advanceTimersByTime(60_000);
    NetworkService._post({ type: 'members_changed', room_id: 9, action: 'left', username: 'x' });
    jest.advanceTimersByTime(0);
    await flush();
    expect(island.gapCalls).toEqual([null, String(ROOM), '9']);

    // Stopped, nothing more is heard.
    KeySweepService.stop();
    NetworkService._post({ type: 'notify_key_gap', room_id: ROOM });
    jest.advanceTimersByTime(120_000);
    await flush();
    expect(island.gapCalls).toEqual([null, String(ROOM), '9']);
  } finally {
    KeySweepService.stop();
    jest.useRealTimers();
  }
});

test('a verified peer is served again at once', async () => {
  jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });
  try {
    const carded = identity();
    const swapped = identity();
    const name = 'carl';
    const scope = await CryptoService.pinScope();
    await StorageService.setKnownFingerprint(scope, 'mod', name, await CryptoUtils.fingerprintPublicKey(carded.pubB64));
    island.accounts[name] = swapped;
    island.gaps = [{ room_id: ROOM, room_name: 'r', username: name }];
    KeySweepService.start();
    jest.advanceTimersByTime(2500);
    await flush();
    expect(KeySweepService.trustBlocked().map((x) => x.username)).toEqual([name]);
    expect(island.shares).toHaveLength(0);

    // The user compares safety numbers and accepts the new key.
    await CryptoService.verifyPeerKey('mod', name, await CryptoUtils.fingerprintPublicKey(swapped.pubB64));
    jest.advanceTimersByTime(60_000);
    await flush();
    expect(KeySweepService.trustBlocked()).toEqual([]);
    expect(island.shares.map((x) => x.target)).toEqual([name]);
  } finally {
    KeySweepService.stop();
    jest.useRealTimers();
  }
});

test('locked or signed out, nothing is asked', async () => {
  const token = NetworkService._token;
  NetworkService._token = null;
  try {
    expect(await KeySweepService.run()).toMatchObject({ ran: false });
  } finally {
    NetworkService._token = token;
  }
  expect(island.gapCalls).toEqual([]);
});
