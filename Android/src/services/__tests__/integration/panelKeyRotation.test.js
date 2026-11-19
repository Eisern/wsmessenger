// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Changing a room's key, against a real island, with somebody who stays.
 *
 * panelLocal covers rotation with nobody left but the owner, which is the case
 * where nothing can go wrong for anybody else. What a removal is for is the
 * member who STAYS: they must be able to read what is written under the new
 * key, and must themselves move on to it - with the room open, holding the old
 * key in memory, and nobody telling them anything but the message itself.
 * And a member whose key changed must be left out without holding the room
 * back on the removed member's key.
 *
 * The extension's own panel-crypto.js, the island from this checkout.
 * Requires island A; see integration/README.md.
 */

const { setUp, http } = require('./helpers/panelHarness');

const ISLAND = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';

jest.setTimeout(120000);

let alice; // owner
let bob;   // removed
let carol; // stays
let dave;  // stays, then gets a new key
let roomId;
let stamp;

async function readRoom(reader, wire, author) {
  const out = await reader.sandbox.decryptMessageFromRoom(roomId, wire, author.username);
  expect(out && typeof out).toBe('object');
  expect(out.from).toBe(author.username);
  expect(out.sigValid).toBe(true);
  return out.text;
}

const kidOf = (wire) => JSON.parse(wire).kid;

beforeAll(async () => {
  const h = await fetch(`${ISLAND}/health`).then((r) => r.json()).catch(() => null);
  if (!h || h.status !== 'ok') throw new Error(`island not reachable at ${ISLAND}`);

  stamp = Date.now().toString().slice(-7);
  alice = await setUp(ISLAND, 'island-local', `rot_a_${stamp}`);
  bob = await setUp(ISLAND, 'island-local', `rot_b_${stamp}`);
  carol = await setUp(ISLAND, 'island-local', `rot_c_${stamp}`);
  dave = await setUp(ISLAND, 'island-local', `rot_d_${stamp}`);
  for (const who of [bob, carol, dave]) {
    const r = await http(ISLAND, '/profile/me', {
      method: 'PUT', token: who.token,
      body: { privacy: { allow_group_invites_from_non_friends: true } },
    });
    if (!r.ok) throw new Error(`could not open ${who.username} to invites: ${r.status}`);
  }

  const keyB64 = await alice.CU.exportRoomKey(await alice.CU.generateRoomKey(true));
  const created = await http(ISLAND, '/rooms', {
    method: 'POST', token: alice.token,
    body: {
      name: `rot_${stamp}`, password: null, is_public: false, is_readonly: false,
      encrypted_room_key: await alice.CU.encryptRoomKeyForUser(alice.manager.userPublicKeyB64, keyB64),
    },
  });
  if (!created.ok) throw new Error(`room: ${created.status}`);
  roomId = Number(created.data.id ?? created.data.room_id);
  // The created key goes up unsigned; the panel signs it once the room has an id.
  await alice.manager.loadRoomKey(roomId, keyB64);
  await alice.sandbox.signCreatedRoomKey(roomId, keyB64);

  for (const who of [bob, carol, dave]) {
    const inv = await http(ISLAND, `/rooms/${roomId}/invite`, {
      method: 'POST', token: alice.token, body: { username: who.username },
    });
    if (!inv.ok) throw new Error(`invite ${who.username}: ${inv.status}`);
    const acc = await http(ISLAND, `/rooms/${roomId}/invites/accept`, {
      method: 'POST', token: who.token, body: {},
    });
    if (!acc.ok) throw new Error(`accept ${who.username}: ${acc.status}`);
  }
  const swept = await alice.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test' });
  if (swept.shared !== 3) throw new Error(`sweep shared ${swept.shared}, expected 3`);
  for (const who of [bob, carol, dave]) {
    const loaded = await who.sandbox.loadRoomKey(roomId);
    if (!loaded.ok) throw new Error(`${who.username} could not load the key`);
  }
});

describe('a removal, and the members who stay', () => {
  let before;
  let after;

  it('everybody is on one key to begin with', async () => {
    before = await alice.sandbox.encryptMessageForRoom(roomId, 'до удаления');
    expect(await readRoom(carol, before, alice)).toBe('до удаления');
    expect(await readRoom(bob, before, alice)).toBe('до удаления');
  });

  it('the owner removes one member and the key changes for everybody else in one step', async () => {
    const kicked = await http(ISLAND, `/rooms/${roomId}/kick`, {
      method: 'POST', token: alice.token, body: { username: bob.username },
    });
    expect(kicked.ok).toBe(true);

    const rotated = await alice.sandbox.rotateRoomKey(roomId, { kickedUsername: bob.username });
    expect(rotated).toEqual({ ok: true, shared: 2, failed: [] });

    after = await alice.sandbox.encryptMessageForRoom(roomId, 'после удаления');
    expect(kidOf(after)).not.toBe(kidOf(before));

    // Each who stays has a copy of exactly the key the owner now writes with.
    for (const who of [carol, dave]) {
      const k = await http(ISLAND, `/crypto/room-key/${roomId}`, { token: who.token });
      expect(k.ok).toBe(true);
      const info = alice.CU.inspectWrappedKey(k.data.encrypted_room_key);
      expect(info.signed).toBe(true);
    }
    expect((await http(ISLAND, `/crypto/room-key/${roomId}`, { token: bob.token })).ok).toBe(false);
  });

  it('a member with the room open reads the new key\'s first message, and from then on writes under it', async () => {
    // Carol still holds only the old key as current. Nothing told her about
    // the change: the message under a key id she never held is what does.
    expect(kidOf(await carol.sandbox.encryptMessageForRoom(roomId, 'probe'))).toBe(kidOf(before));

    expect(await readRoom(carol, after, alice)).toBe('после удаления');

    const reply = await carol.sandbox.encryptMessageForRoom(roomId, 'ответ после удаления');
    expect(kidOf(reply)).toBe(kidOf(after));
    expect(await readRoom(alice, reply, carol)).toBe('ответ после удаления');
    // History from before the change is still hers to read.
    expect(await readRoom(carol, before, alice)).toBe('до удаления');
  });

  it('told the key changed, a member reads it before any message arrives', async () => {
    // Dave is woken the way /ws-notify wakes him (notify_room_key).
    expect(await dave.sandbox.refreshRoomKeyIfHeld(roomId)).toBe(true);
    expect(kidOf(await dave.sandbox.encryptMessageForRoom(roomId, 'x'))).toBe(kidOf(after));
  });

  it('the removed member reads nothing under the new key, however they ask', async () => {
    const out = await bob.sandbox.decryptMessageFromRoom(roomId, after, alice.username);
    expect(typeof out).toBe('string');
    expect(out).toMatch(/^\[Encrypted message/);
  });
});

describe('a member whose key changed', () => {
  it('is left without the new key, and the room still moves on', async () => {
    // Dave's island now serves a different key for him. Alice pinned the old
    // one, so it cannot be handed a room key until somebody verifies it - and
    // that must not keep the room on a key a removed member holds.
    const fresh = await dave.CU.generateIdentityKeyPair();
    const pub = await dave.CU.exportPublicKey(fresh.publicKey);
    const kid = Buffer.from(await dave.CU.sha256Raw(Buffer.from(pub, 'base64'))).toString('hex').slice(0, 32);
    const published = await http(ISLAND, '/keys/me', {
      method: 'POST', token: dave.token, body: { kid, public_key: pub, alg: 'x25519' },
    });
    expect(published.ok).toBe(true);

    const rotated = await alice.sandbox.rotateRoomKey(roomId);
    expect(rotated.ok).toBe(true);
    expect(rotated.shared).toBe(1);
    expect(rotated.failed).toEqual([dave.username]);

    // His old copy is gone - not left behind as "current" - and he is a gap.
    expect((await http(ISLAND, `/crypto/room-key/${roomId}`, { token: dave.token })).ok).toBe(false);
    const gaps = await http(ISLAND, `/crypto/rooms/key-gaps?room_id=${roomId}`, { token: alice.token });
    expect((gaps.data.gaps || []).map((g) => g.username)).toContain(dave.username);

    // Carol, who stayed trusted, is on the newest key. She read the room's key
    // a moment ago, and a message is allowed to make her read it again only
    // every ten seconds (the key id is the sender's to write) - in a real
    // panel notify_room_key, which is not held back, would have woken her.
    const latest = await alice.sandbox.encryptMessageForRoom(roomId, 'третий ключ');
    await new Promise((r) => setTimeout(r, 10500));
    expect(await readRoom(carol, latest, alice)).toBe('третий ключ');
  });

  it('the sweep does not hand him the key while his new key is unverified', async () => {
    const swept = await alice.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test-after' });
    expect(swept.shared).toBe(0);
    expect((await http(ISLAND, `/crypto/room-key/${roomId}`, { token: dave.token })).ok).toBe(false);
  });
});
