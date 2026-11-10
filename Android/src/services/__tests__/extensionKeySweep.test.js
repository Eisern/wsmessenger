// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's half of the key sweep: chrome_extension/panel-crypto.js
 * wired to key-sweep.js, run headless (integration/helpers/panelHarness.js)
 * against a stubbed island. The rules are key-sweep.js's and tested in
 * keySweep.test.js; this holds the wiring - what goes over the wire, and that
 * a trust refusal comes back as one.
 */

const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const ROOM = 7;

function reply(status, body, headers = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k) => headers[String(k).toLowerCase()] ?? 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

const island = {
  gaps: [], gapsStatus: 200, retryAfter: null, accounts: {}, roomKey: null, shares: [], written: true, gapCalls: 0,
};

function route(url, opts = {}) {
  const u = new URL(url);
  const p = u.pathname;
  if (p === '/crypto/rooms/key-gaps') {
    island.gapCalls += 1;
    if (island.gapsStatus === 429) return reply(429, { detail: 'slow' }, { 'retry-after': island.retryAfter });
    if (island.gapsStatus !== 200) return reply(island.gapsStatus, { detail: 'no' });
    return reply(200, { gaps: island.gaps, truncated: false });
  }
  if (p === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: [] });
  if (p === `/crypto/room-key/${ROOM}`) return island.roomKey ? reply(200, island.roomKey) : reply(404, {});
  let m;
  if ((m = p.match(/^\/keys\/([^/]+)$/))) {
    const a = island.accounts[decodeURIComponent(m[1])];
    return a ? reply(200, { username: decodeURIComponent(m[1]), ...a }) : reply(404, { detail: 'no such user' });
  }
  if ((m = p.match(/^\/crypto\/room\/(\d+)\/share$/)) && opts.method === 'POST') {
    island.shares.push({ target: u.searchParams.get('target_username'), body: JSON.parse(opts.body) });
    return reply(200, { ok: true, written: island.written });
  }
  return reply(404, {});
}

let P;

async function member(CU) {
  const kp = await CU.generateIdentityKeyPair();
  const pub = await CU.exportPublicKey(kp.publicKey);
  return { pub, priv: kp.privateKey, account: { public_key: pub, ed25519_public_key: '' } };
}

beforeAll(async () => {
  P = makePanel({ apiBase: 'https://island.test', islandId: 'island.test', username: 'mod', token: 'tok' });
  P.sandbox.fetch = async (url, opts) => route(String(url), opts);
  P.sandbox.roomOwnerById = {};
  await unlockRealManager(P.sandbox, { username: 'mod', password: PASS });
  const keyB64 = await P.CU.exportRoomKey(await P.CU.generateRoomKey(true));
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  island.roomKey = {
    encrypted_room_key: await P.CU.encryptRoomKeyForUser(P.manager.userPublicKeyPem, keyB64, {
      seed: P.manager.ed25519Seed, signer: 'mod', scope: 'room', scopeId: ROOM, recipient: 'mod', keyId: kid,
    }),
  };
  island.keyB64 = keyB64;
  island.kid = kid;
}, 60000);

beforeEach(() => {
  vm.runInContext('_keySweep.reset()', P.sandbox);
  island.shares = [];
  island.gapCalls = 0;
  island.gapsStatus = 200;
  island.written = true;
});

test('a gap is filled - signed for the member, if absent only', async () => {
  const alice = await member(P.CU);
  island.accounts['Alice@island-g~ca2a4f'] = alice.account;
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: 'Alice@island-g~ca2a4f' }];

  const res = await P.sandbox.sweepRoomKeyGaps({ reason: 'test' });
  expect(res).toEqual({ ran: true, shared: 1, alreadyHad: 0, skipped: 0, failed: 0, incomplete: false });
  expect(island.shares).toHaveLength(1);
  const { target, body } = island.shares[0];
  expect(target).toBe('Alice@island-g~ca2a4f');
  expect(body.if_absent).toBe(true);
  expect(await P.CU.decryptRoomKeyForUser(alice.priv, body.encrypted_room_key)).toBe(island.keyB64);
  const info = P.CU.inspectWrappedKey(body.encrypted_room_key, {
    scope: 'room', scopeId: ROOM, recipient: 'alice@island-g~ca2a4f', keyId: island.kid,
  });
  expect(info.signer).toBe('mod');
  expect(await P.CU.ed25519Verify(await P.CU.ed25519GetPublicKey(P.manager.ed25519Seed), info.sig, info.sigMessage)).toBe(true);
});

test('somebody else filling it first is not a failure', async () => {
  island.accounts.bob = (await member(P.CU)).account;
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: 'bob' }];
  island.written = false;
  expect(await P.sandbox.sweepRoomKeyGaps()).toMatchObject({ ran: true, alreadyHad: 1, failed: 0 });
});

test('a member whose key changed since it was pinned gets nothing, and is listed for verification', async () => {
  const pinned = await member(P.CU);
  const served = await member(P.CU);
  const pin = await P.sandbox._fpBase('mod', 'carl');
  await P.sandbox.chrome.storage.local.set({ [pin]: await P.CU.fingerprintPublicKey(pinned.pub) });
  island.accounts.carl = served.account;
  island.gaps = [{ room_id: ROOM, room_name: 'r', username: 'carl' }];

  expect(await P.sandbox.sweepRoomKeyGaps()).toMatchObject({ ran: true, shared: 0, skipped: 1, failed: 0 });
  expect(island.shares).toHaveLength(0);
  expect(P.sandbox.getKeyShareTrustBlocked()).toEqual([{ username: 'carl', reason: 'TRUST_CHANGED', rooms: [ROOM] }]);
  P.sandbox.clearKeyShareTrustBlock('carl');
  expect(P.sandbox.getKeyShareTrustBlocked()).toEqual([]);
});

test('not a provider here: the island\'s 403 is an answer, not a failure', async () => {
  island.gapsStatus = 403;
  expect(await P.sandbox.sweepRoomKeyGaps({ roomId: ROOM })).toMatchObject({ ran: true, failed: 0 });
  expect(vm.runInContext('_keySweep.nextAllowedAt', P.sandbox) - Date.now()).toBeLessThanOrEqual(60_000);
});

test('a rate limit holds the sweep off for as long as the island says', async () => {
  island.gapsStatus = 429;
  island.retryAfter = '900';
  await P.sandbox.sweepRoomKeyGaps();
  expect(vm.runInContext('_keySweep.nextAllowedAt', P.sandbox) - Date.now()).toBeGreaterThan(850_000);
  expect((await P.sandbox.sweepRoomKeyGaps()).ran).toBe(false);
  expect(island.gapCalls).toBe(1);
});
