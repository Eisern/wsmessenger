// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * A room on one island, with a guest from another - end to end, on two real
 * islands, with the extension's real panel-crypto.js on both sides.
 *
 * The offline suites (extensionGuestRooms, guestRoomService) hold each rule
 * against an island the test makes up. This one asks whether the pieces fit:
 * the card the guest hands over is one island A accepts, the invitation the
 * moderator sends arrives in the guest's mailbox on island B and reads as one,
 * the guest's signature opens a session on A, the key sweep wraps a key the
 * guest's client accepts, and a message each side writes - over a real room
 * socket - verifies on the other under a key pinned from a card.
 *
 * Requires both islands (integration/README.md): A at 127.0.0.1:8000 as
 * island-test, B at 127.0.0.1:8001 as island-b.
 */

const WS = require('ws');
const { setUp, http, lastMessage } = require('./helpers/panelHarness');

const ISLAND_A = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const ISLAND_B = process.env.TWO_ISLANDS_B || 'http://127.0.0.1:8001';
const ORIGIN = 'chrome-extension://wsapp-integration-test';

// The browser's WebSocket, as the island sees it: an extension origin.
class ExtensionWebSocket extends WS {
  constructor(url) {
    super(url, undefined, { headers: { Origin: ORIGIN } });
  }
}

jest.setTimeout(120000);

let mod;        // owns the room, on island A
let guest;      // lives on island B
let modSide;    // mod's contact record of the guest
let guestSide;  // guest's contact record of mod
let roomId;
let guestName;
let room;       // the guest's record of the room
let guestSock;
const live = []; // what the guest's room socket delivered

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
  mod = await setUp(ISLAND_A, 'island-test', `gr_m_${stamp}`);
  guest = await setUp(ISLAND_B, 'island-b', `gr_g_${stamp}`);
  mod.sandbox.roomOwnerById = {};
  guest.sandbox.WebSocket = ExtensionWebSocket;
});

afterAll(() => {
  try { guestSock?.close(); } catch { /* already closed */ }
});

test('the two exchange cards and can write to each other', async () => {
  guestSide = await guest.sandbox.addForeignContact(await mod.sandbox.buildMyContactBlobText());
  modSide = await mod.sandbox.addForeignContact(await guest.sandbox.buildMyContactBlobText());
  guestSide = await guest.sandbox.claimForeignOutbox(guestSide);
  expect(modSide.outbox?.keyB64).toBeTruthy();
  expect(guestSide.outbox?.keyB64).toBeTruthy();
  // What the invitation is checked against later: island A's own name.
  expect(guestSide.island.islandId).toBe('island-test');
  expect(modSide.card?.payload?.kid).toBe(modSide.kid);
});

test('the moderator creates a room on island A', async () => {
  const keyB64 = await mod.CU.exportRoomKey(await mod.CU.generateRoomKey(true));
  const created = await http(ISLAND_A, '/rooms', {
    method: 'POST',
    token: mod.token,
    body: {
      name: 'Книжный клуб', password: null, is_public: false, is_readonly: false,
      encrypted_room_key: await mod.CU.encryptRoomKeyForUser(mod.manager.userPublicKeyB64, keyB64),
    },
  });
  expect(created.ok).toBe(true);
  roomId = Number(created.data.id ?? created.data.room_id);
  expect(await mod.manager.loadRoomKey(roomId, keyB64)).toBe(true);
  await mod.sandbox.signCreatedRoomKey(roomId, keyB64);
  mod.sandbox.roomOwnerById[String(roomId)] = true;
});

test('the moderator invites the guest by card, and pins them from it', async () => {
  const res = await mod.sandbox.inviteForeignContactToRoom(roomId, modSide.kid, 'Книжный клуб');
  guestName = res.guestName;
  expect(guestName).toMatch(new RegExp(`^${guest.username}@island-b~`, 'i'));
  expect(res).toMatchObject({ status: 'invited', queued: false });

  const pin = await mod.sandbox._fpBase(mod.username, guestName);
  const got = await mod.sandbox.chrome.storage.local.get([pin, pin + ':ed']);
  expect(got[pin]).toBe(modSide.kid);
  expect(got[pin + ':ed']).toBe(modSide.ed25519PubB64);
});

test('the invitation arrives in the guest\'s mailbox on island B, signed by the moderator', async () => {
  await guest.sandbox.ensureForeignKeysReady(guestSide);
  const stored = await lastMessage(ISLAND_B, guestSide.inbox.threadId, guest.token);
  const dm = await guest.sandbox.decryptDm(guestSide.inbox.threadId, stored, '', Date.now());
  expect(dm.sealedFrom).toBe(mod.username);
  expect(dm.sigValid).toBe(true);
  const invite = guest.sandbox.WSGuestRooms.parseInvite(dm.text);
  expect(invite).toEqual({ islandId: 'island-test', roomId, roomName: 'Книжный клуб', guestName });

  // Island A's first two addresses answer nothing; the session walks past them.
  room = await guest.sandbox.acceptGuestInvite(guestSide.kid, invite, dm.sealedFrom);
  expect(room).toMatchObject({ islandId: 'island-test', roomId, guestName, inviter: mod.username });
  const members = await http(ISLAND_A, `/rooms/${roomId}/members`, { token: mod.token });
  expect(members.data.map((m) => m.username)).toContain(guestName);
});

test('the guest has no key until the moderator\'s sweep sends one, which the guest accepts', async () => {
  expect(await guest.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, notFound: true });

  const swept = await mod.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test' });
  expect(swept).toMatchObject({ ran: true, shared: 1, failed: 0, incomplete: false });

  expect(await guest.sandbox.loadGuestRoomKey(room)).toEqual({ ok: true });
});

test('what the guest writes over the room socket reads back verified - on both sides', async () => {
  let online = false;
  guestSock = guest.sandbox.openGuestRoomSocket(room, {
    onMessage: (m) => live.push(m),
    onStatus: (s) => { if (s.online) online = true; },
  });
  await waitFor(() => online, 'the guest\'s socket');

  const text = 'привет с острова B';
  guestSock.send(await guest.sandbox.encryptForGuestRoom(room, text));
  const echoed = await waitFor(() => live.find((m) => m.from === guestName), 'the broadcast');
  expect(await guest.sandbox.decryptFromGuestRoom(room, echoed.text, echoed.from))
    .toEqual({ text, from: guestName, sigValid: true, mismatch: false });

  // The moderator reads it through the island's history and checks the
  // signature against the key pinned from the guest's card.
  const hist = await http(ISLAND_A, `/rooms/${roomId}/history?limit=5`, { token: mod.token });
  const row = hist.data.messages.at(-1);
  expect(row.username).toBe(guestName);
  expect(await mod.sandbox.decryptMessageFromRoom(roomId, row.text, row.username))
    .toEqual({ text, from: guestName, sigValid: true, mismatch: false });
});

test('what the moderator writes reaches the guest live, verified under the key from the card', async () => {
  const sock = new ExtensionWebSocket(`${ISLAND_A.replace(/^http/, 'ws')}/ws?room_id=${roomId}`);
  await new Promise((resolve, reject) => { sock.on('open', resolve); sock.on('error', reject); });
  sock.send(JSON.stringify({ type: 'auth', token: mod.token }));
  try {
    const text = 'ответ с острова A';
    await waitFor(() => live.some((m) => m.type === 'message' && m.from === guestName), 'the earlier message');
    await new Promise((r) => setTimeout(r, 300));   // the server has taken the auth frame
    sock.send(await mod.sandbox.encryptMessageForRoom(roomId, text));
    const got = await waitFor(() => live.find((m) => m.from === mod.username), 'the moderator\'s message');
    expect(await guest.sandbox.decryptFromGuestRoom(room, got.text, got.from))
      .toEqual({ text, from: mod.username, sigValid: true, mismatch: false });
  } finally {
    sock.close();
  }
});

test('the guest\'s session on island A reaches the room and nothing else', async () => {
  const s = guest.sandbox.guestSessions().peek('island-test');
  expect(s?.username).toBe(guestName);
  const h = { token: s.token };
  expect((await http(ISLAND_A, `/rooms/${roomId}/history`, h)).status).toBe(200);
  expect((await http(ISLAND_A, '/dm/list', h)).status).toBe(403);
  expect((await http(ISLAND_A, '/auth/refresh', { ...h, method: 'POST', body: { refresh_token: 'x' } })).status).toBe(403);
});

test('an address of theirs that now leads to another island is passed over, not signed for', async () => {
  // Island A moved, and its old address now answers as island B. The session
  // must notice from the challenge and try the next door - not hand B a
  // signature, which B would refuse and end the search with.
  const c = await guest.sandbox.getForeignContact(guestSide.kid);
  await guest.sandbox.saveForeignContact({
    ...c,
    island: { ...c.island, entryPoints: [{ apiBase: ISLAND_B, wsBase: '', label: 'moved' }, ...c.island.entryPoints] },
  });
  try {
    guest.sandbox.guestSessions().forget();
    const page = await guest.sandbox.fetchGuestRoomHistory(room, { limit: 1 });
    expect(Array.isArray(page.messages)).toBe(true);
    expect(guest.sandbox.guestSessions().peek('island-test').apiBase).toBe(ISLAND_A);
  } finally {
    await guest.sandbox.saveForeignContact(c);
  }
});

test('leaving takes the guest out of the room there and off the list here', async () => {
  guestSock.close();
  guestSock = null;
  await guest.sandbox.leaveGuestRoom(room);
  expect(await guest.sandbox.listGuestRooms()).toEqual([]);
  const members = await http(ISLAND_A, `/rooms/${roomId}/members`, { token: mod.token });
  expect(members.data.map((m) => m.username)).not.toContain(guestName);
});
