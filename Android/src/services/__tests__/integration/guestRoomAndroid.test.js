// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The Android app as a guest in a room on another island, end to end: the
 * room and its moderator are on island A (the extension's real panel-crypto.js),
 * the guest is the Android stack - ForeignService, GuestRoomService and the
 * shared feed, over the real CryptoService and StorageService - living on
 * island B. Two clients that never shared code for this until the shared
 * modules; this is where they meet.
 *
 * Requires both islands (integration/README.md).
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../../crypto/CryptoUtils';
import NetworkService from '../../NetworkService';
import CryptoService from '../../CryptoService';
import StorageService from '../../StorageService';
import ForeignService from '../../ForeignService';
import GuestRoomService from '../../GuestRoomService';

const WS = require('ws');
const { setUp, http, udDecode, PASS } = require('./helpers/panelHarness');

const ISLAND_A = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const ISLAND_B = process.env.TWO_ISLANDS_B || 'http://127.0.0.1:8001';

jest.setTimeout(120000);

let mod;          // extension, island A
let me;           // the Android guest's account on island B
let contact;      // the Android side's record of mod
let modSide;      // mod's record of the Android guest
let roomId;
let guestName;
let room;
let feed;
let items = [];
const notices = [];

function waitFor(pred, what, ms = 15000) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tick = () => {
      const v = pred();
      if (v) return resolve(v);
      if (Date.now() - t0 > ms) return reject(new Error(`timed out waiting for ${what}`));
      setTimeout(tick, 50);
    };
    tick();
  });
}

beforeAll(async () => {
  for (const [name, url] of [['A', ISLAND_A], ['B', ISLAND_B]]) {
    const h = await fetch(`${url}/health`).then((r) => r.json()).catch(() => null);
    if (!h || h.status !== 'ok') throw new Error(`island ${name} not reachable at ${url}`);
  }
  const stamp = Date.now().toString().slice(-7);
  mod = await setUp(ISLAND_A, 'island-test', `gra_m_${stamp}`);
  mod.sandbox.roomOwnerById = {};

  // The Android guest: an account on island B, the app unlocked with its key.
  const priv = x25519.utils.randomSecretKey();
  const pubB64 = CryptoUtils.arrayBufferToBase64(x25519.getPublicKey(priv));
  me = { username: `gra_g_${stamp}` };
  await http(ISLAND_B, '/auth/register', { method: 'POST', body: { username: me.username, password: PASS, public_key: pubB64 } });
  const login = await http(ISLAND_B, '/auth/login', { method: 'POST', body: { username: me.username, password: PASS } });
  if (!login.ok) throw new Error(`login on B: ${login.status}`);
  NetworkService.setServerConfig(ISLAND_B, ISLAND_B.replace(/^http/, 'ws'));
  NetworkService._token = login.data.access_token;
  me.token = login.data.access_token;
  await StorageService.setActiveUsername(me.username);
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(priv), pubB64)).toBe(true);
  await CryptoService.ensureEd25519KeyRegistered();
});

afterAll(() => {
  try { feed?.stop(); } catch { /* stopped */ }
  CryptoService.lockSession();
});

test('the Android guest and the extension moderator exchange cards', async () => {
  contact = await ForeignService.addContact(await mod.sandbox.buildMyContactBlobText());
  modSide = await mod.sandbox.addForeignContact(await ForeignService.buildMyCard());
  contact = await ForeignService.claimOutbox(contact);
  expect(contact.outbox?.keyB64).toBeTruthy();
  expect(modSide.outbox?.keyB64).toBeTruthy();
  expect(contact.island.islandId).toBe('island-test');
});

test('the moderator makes a room and invites the Android guest by card', async () => {
  const keyB64 = await mod.CU.exportRoomKey(await mod.CU.generateRoomKey(true));
  const created = await http(ISLAND_A, '/rooms', {
    method: 'POST',
    token: mod.token,
    body: {
      name: 'Room for Android', password: null, is_public: false, is_readonly: false,
      encrypted_room_key: await mod.CU.encryptRoomKeyForUser(mod.manager.userPublicKeyB64, keyB64),
    },
  });
  roomId = Number(created.data.id ?? created.data.room_id);
  await mod.manager.loadRoomKey(roomId, keyB64);
  await mod.sandbox.signCreatedRoomKey(roomId, keyB64);
  mod.sandbox.roomOwnerById[String(roomId)] = true;

  const res = await mod.sandbox.inviteForeignContactToRoom(roomId, modSide.kid, 'Room for Android');
  guestName = res.guestName;
  expect(res.status).toBe('invited');
});

test('Android reads the invitation from its mailbox and joins, through the card\'s island', async () => {
  await ForeignService.ensureKeysReady(contact);
  const hist = await http(ISLAND_B, `/dm/${contact.inbox.threadId}/history`, { token: me.token });
  const rows = hist.data.messages || hist.data;
  const dm = await CryptoService.decryptDm(contact.inbox.threadId, udDecode(rows.at(-1).text), contact.displayName);
  expect(dm.from).toBe(mod.username);
  expect(dm.sigValid).toBe(true);
  const invite = GuestRoomService.parseInvite(dm.text);
  expect(invite).toMatchObject({ islandId: 'island-test', roomId, guestName });

  room = await GuestRoomService.acceptInvite(contact.kid, invite, dm.from);
  expect(room).toMatchObject({ roomId, guestName, inviter: mod.username });
  // The inviter's keys, pinned in the Keychain under island A and the guest's name there.
  expect(await StorageService.getKnownEd25519('island-test', guestName, mod.username)).toBe(contact.ed25519PubB64);
});

test('the key arrives by the moderator\'s sweep, and Android accepts it', async () => {
  expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, notFound: true });
  expect(await mod.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test' })).toMatchObject({ shared: 1, failed: 0 });
  expect(await GuestRoomService.loadKey(room)).toEqual({ ok: true });
});

test('the feed shows what each writes, verified, in order', async () => {
  let online = false;
  feed = GuestRoomService.createFeed(room, {
    onReset: (list) => { items = [...list]; },
    onAppend: (it) => { items.push(it); },
    onNotice: (n) => { notices.push(n); },
    onStatus: (s) => { online = !!s.online; },
  });
  await feed.start();
  await waitFor(() => online, 'the room socket');

  feed.send(await GuestRoomService.encrypt(room, 'from Android'));
  await waitFor(() => items.find((i) => i.text === 'from Android'), 'its own message');

  const sock = new WS(`${ISLAND_A.replace(/^http/, 'ws')}/ws?room_id=${roomId}`, undefined,
    { headers: { Origin: 'chrome-extension://wsapp-integration-test' } });
  await new Promise((resolve, reject) => { sock.on('open', resolve); sock.on('error', reject); });
  sock.send(JSON.stringify({ type: 'auth', token: mod.token }));
  await new Promise((r) => setTimeout(r, 300));
  sock.send(await mod.sandbox.encryptMessageForRoom(roomId, 'from the extension'));
  await waitFor(() => items.find((i) => i.text === 'from the extension'), 'the moderator\'s message');
  sock.close();

  expect(items.map((i) => [i.user, i.text, i.mine, i.sigValid])).toEqual([
    [guestName, 'from Android', true, true],
    [mod.username, 'from the extension', false, true],
  ]);
  expect(notices).toEqual([]);

  // And the moderator verifies Android's signature under the key from its card.
  const hist = await http(ISLAND_A, `/rooms/${roomId}/history?limit=5`, { token: mod.token });
  const row = hist.data.messages.find((m) => m.username === guestName);
  expect(await mod.sandbox.decryptMessageFromRoom(roomId, row.text, row.username))
    .toEqual({ text: 'from Android', from: guestName, sigValid: true, mismatch: false });
});

test('leaving', async () => {
  feed.stop();
  feed = null;
  await GuestRoomService.leave(room);
  expect(await GuestRoomService.listRooms()).toEqual([]);
});
