// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Android as the moderator inviting somebody from another island into a room
 * here (GuestRoomService.inviteContact): the card goes to the island, the
 * guest's keys are pinned from the card under the name the island returns
 * before anything uses it, and the invitation goes out in the conversation.
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import ForeignService from '../ForeignService';
import GuestRoomService from '../GuestRoomService';
import GR from '../guest-rooms';

const HOME = 'https://island-r.test';
const R_ID = 'island-r.test';
const ROOM = 42;
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

const island = { invited: [], guestName: '', status: 201, detail: null };

function identity() {
  const priv = x25519.utils.randomSecretKey();
  const edSeed = CryptoUtils.deriveEd25519Seed(priv);
  return { priv, pubB64: b64(x25519.getPublicKey(priv)), edSeed, edPubB64: b64(CryptoUtils.ed25519GetPublicKey(edSeed)) };
}

let mod;
let alice;
let aliceKid;
let sent;
let claim;
const CARD = { payload: { v: 1, kid: 'x' }, sig_b64: 'c2ln' };

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = new URL(String(url));
    if (u.pathname === `/rooms/${ROOM}/guests` && opts.method === 'POST') {
      island.invited.push(JSON.parse(opts.body));
      if (island.detail) return reply(island.status, { detail: island.detail });
      return reply(201, { ok: true, room_id: ROOM, guest_username: island.guestName, status: 'pending', island_id: R_ID });
    }
    if (u.pathname === '/crypto/ed25519-key') return reply(200, { ok: true });
    return reply(404, { detail: 'Not found' });
  });
  NetworkService.setServerConfig(HOME, 'wss://island-r.test');
  NetworkService._token = 'mod-token';
  await StorageService.setActiveUsername('mod');
  mod = identity();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(mod.priv), mod.pubB64)).toBe(true);

  alice = identity();
  aliceKid = await CryptoUtils.fingerprintPublicKey(alice.pubB64);
  const contact = {
    v: 1, kid: aliceKid, displayName: 'Alice', x25519PubB64: alice.pubB64, ed25519PubB64: alice.edPubB64,
    island: { islandId: 'island-g.test', signingKeyB64: '', entryPoints: [{ apiBase: 'https://island-g.test', wsBase: '', label: '' }] },
    inbox: { threadId: 77, keyB64: null, keyId: null },
    outbox: { apiBase: 'https://island-g.test', threadId: 5, secretB64: 'c2VjcmV0', keyB64: 'a2V5', keyId: 'k1' },
    card: CARD,
    addedAt: Date.now(),
  };
  await ForeignService.saveContact(contact);
  await ForeignService.saveContact({ ...contact, kid: 'ab'.repeat(16), displayName: 'old', card: undefined });
  await ForeignService.saveContact({ ...contact, kid: 'cd'.repeat(16), displayName: 'silent', outbox: null });

  sent = [];
  jest.spyOn(ForeignService, 'sendMessage').mockImplementation(async (c, text) => { sent.push({ kid: c.kid, text }); return { ok: true }; });
  claim = jest.spyOn(ForeignService, 'claimOutbox').mockImplementation(async () => { throw new Error('Could not reach their server (no answer)'); });
});

afterAll(() => {
  jest.restoreAllMocks();
  CryptoService.lockSession();
  ForeignService.clearCache();
});

beforeEach(() => {
  island.guestName = `Alice@island-g.test~${aliceKid.slice(0, 6)}`;
  island.detail = null;
});

test('hands the card over, pins the guest from it under the island\'s name, and invites them in the DM', async () => {
  const res = await GuestRoomService.inviteContact(ROOM, aliceKid, 'Book club');
  expect(res).toEqual({ guestName: island.guestName, status: 'pending', queued: false });
  expect(island.invited.at(-1)).toEqual({ card: CARD });

  const scope = await CryptoService.pinScope();
  expect(await StorageService.getKnownFingerprint(scope, 'mod', island.guestName)).toBe(aliceKid);
  expect(await StorageService.getKnownEd25519(scope, 'mod', island.guestName)).toBe(alice.edPubB64);

  expect(sent).toHaveLength(1);
  expect(GR.parseInvite(sent[0].text)).toEqual({
    islandId: R_ID, roomId: ROOM, roomName: 'Book club', guestName: island.guestName,
  });
});

test('the key sweep then finds the card\'s key pinned, so the island cannot swap it in', async () => {
  // The same check every key share runs: a different key served for the
  // guest's name is a change, not a first contact.
  const other = identity();
  await expect(CryptoService.assertPeerKeyTrustedForSharing(island.guestName, 'sharing', { peerPublicKeyB64: other.pubB64 }))
    .rejects.toThrow(/changed/);
  await expect(CryptoService.assertPeerKeyTrustedForSharing(island.guestName, 'sharing', { peerPublicKeyB64: alice.pubB64 }))
    .resolves.toBeUndefined();
});

test('will not pin a name the island hands back to keys other than the card\'s', async () => {
  const other = identity();
  island.guestName = 'bob';
  const scope = await CryptoService.pinScope();
  await StorageService.setKnownFingerprint(scope, 'mod', 'bob', await CryptoUtils.fingerprintPublicKey(other.pubB64));
  const before = sent.length;
  await expect(GuestRoomService.inviteContact(ROOM, aliceKid, 'Book club')).rejects.toThrow(/already pinned/);
  expect(sent.length).toBe(before);
  expect(await StorageService.getKnownFingerprint(scope, 'mod', 'bob')).toBe(await CryptoUtils.fingerprintPublicKey(other.pubB64));
});

test('a contact added before cards were kept is not sent to the island', async () => {
  const before = island.invited.length;
  await expect(GuestRoomService.inviteContact(ROOM, 'ab'.repeat(16), 'Book club')).rejects.toThrow(/before cards were kept/);
  expect(island.invited.length).toBe(before);
});

test('somebody we cannot write to yet is not created on the island', async () => {
  const before = island.invited.length;
  await expect(GuestRoomService.inviteContact(ROOM, 'cd'.repeat(16), 'Book club')).rejects.toThrow(/cannot be told about it yet/);
  expect(island.invited.length).toBe(before);
  expect(claim).toHaveBeenCalled();
});

test('a message that did not go is reported as that, not as a failed invitation', async () => {
  ForeignService.sendMessage.mockImplementationOnce(async () => { throw new Error('Delivery refused (500)'); });
  const before = island.invited.length;
  await expect(GuestRoomService.inviteContact(ROOM, aliceKid, 'Book club'))
    .rejects.toThrow(/is invited on this server, but the message telling them did not go.*Invite them again/);
  expect(island.invited.length).toBe(before + 1);
});

test('an island with guests switched off says so; a missing room says that instead', async () => {
  island.status = 404;
  island.detail = 'Not found';
  await expect(GuestRoomService.inviteContact(ROOM, aliceKid, 'x')).rejects.toThrow(/does not take guests/);
  island.detail = 'Room not found';
  await expect(GuestRoomService.inviteContact(ROOM, aliceKid, 'x')).rejects.toThrow(/^Room not found$/);
});

test('two rooms saved at the same moment are both kept', async () => {
  const a = { v: 1, islandId: 'island-a.test', roomId: 1, roomName: 'a', guestName: 'x' };
  const b = { v: 1, islandId: 'island-b.test', roomId: 2, roomName: 'b', guestName: 'y' };
  await Promise.all([GuestRoomService.saveRoom(a), GuestRoomService.saveRoom(b)]);
  expect((await GuestRoomService.listRooms()).map((r) => r.roomName).sort()).toEqual(['a', 'b']);
  await Promise.all([GuestRoomService.dropRoom(a), GuestRoomService.dropRoom(b)]);
  expect(await GuestRoomService.listRooms()).toEqual([]);
});
