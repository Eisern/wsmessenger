// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension taking part in a room on another island, as a guest - and the
 * moderator on that island inviting it. Runs the REAL chrome_extension/
 * panel-crypto.js headless (integration/helpers/panelHarness.js) against a
 * stubbed island that, as in extensionKeyTrust.test.js, is the adversary:
 * every answer is whatever the test says, which is what a dishonest island
 * gets to say too.
 *
 * What has to hold:
 *
 *   - an invitation is followed only to the island of the person who sent it,
 *     as their card says - never to an address the invitation names;
 *   - the room key is accepted under the same rules as at home, with that
 *     island's names: a member must have signed it, under a key that island
 *     cannot swap - and the inviter's key comes from their card, so it cannot
 *     swap it even on first contact;
 *   - what the guest writes is signed as the name it has there, and members'
 *     signatures are checked against keys pinned under that island, never
 *     mixed with names at home;
 *   - the moderator pins the guest from the card before the island's answer
 *     can be used for anything, and refuses to re-pin a name to other keys.
 */

const crypto = require('crypto');
const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const R_ID = 'island-r.test';
const R_BASE = 'https://island-r.test';
const G_ID = 'island-g.test';
const ROOM = 42;
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

// The room's island, as the guest's panel sees it.
const R = {
  guests: new Map(),     // kid -> { edRaw, username }
  nonces: new Set(),
  tokens: new Map(),     // token -> username
  pending: new Set(),    // room ids with an open invitation
  joined: new Set(),
  members: [],
  accounts: {},          // name -> { public_key, ed25519_public_key }
  roomKey: null,
  archive: [],
  history: [],
  calls: [],
  invited: [],           // POST /rooms/{id}/guests bodies (moderator side)
};
let tokenN = 0;

function routeR(url, opts = {}) {
  const u = new URL(url);
  const method = opts.method || 'GET';
  const path = u.pathname;
  R.calls.push(`${method} ${path}`);

  if (path === '/foreign/challenge') {
    const nonce = crypto.randomBytes(32).toString('base64');
    R.nonces.add(nonce);
    return reply(200, { island_id: R.challengeIsland || R_ID, nonce_b64: nonce });
  }
  if (path === '/foreign/guest/session' && method === 'POST') {
    const b = JSON.parse(opts.body);
    if (!R.nonces.delete(b.nonce_b64)) return reply(403, { detail: 'forbidden' });
    const g = R.guests.get(b.kid);
    if (!g) return reply(403, { detail: 'forbidden' });
    const msg = Buffer.concat([
      Buffer.from('ws-guest-session-v1'), Buffer.from(R_ID, 'utf8'),
      Buffer.from(b.kid, 'ascii'), Buffer.from(b.nonce_b64, 'base64'),
    ]);
    const pub = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, g.edRaw]), format: 'der', type: 'spki' });
    if (!crypto.verify(null, msg, pub, Buffer.from(b.sig_b64, 'base64'))) return reply(403, { detail: 'forbidden' });
    const token = `guest-${++tokenN}`;
    R.tokens.set(token, g.username);
    return reply(200, { access_token: token, username: g.username, expires_in: 900, guest: true, island_id: R_ID });
  }

  const token = String((opts.headers || {}).Authorization || '').replace(/^Bearer /, '');
  if (token === 'modtok') {
    // The moderator, a local account here.
    let m;
    if ((m = path.match(/^\/rooms\/(\d+)\/guests$/)) && method === 'POST') {
      R.invited.push(JSON.parse(opts.body));
      return reply(201, {
        ok: true, room_id: Number(m[1]), guest_username: R.guestNameForInvite,
        status: 'pending', island_id: R_ID,
      });
    }
    return reply(404, {});
  }
  if (!R.tokens.has(token)) return reply(401, { detail: 'Invalid token' });

  let m;
  if ((m = path.match(/^\/rooms\/(\d+)\/invites\/accept$/)) && method === 'POST') {
    const rid = Number(m[1]);
    if (!R.pending.delete(rid)) return reply(404, { detail: 'Invite not found' });
    R.joined.add(rid);
    return reply(200, { ok: true, room_id: rid });
  }
  if (path === '/rooms/list') return reply(200, [...R.joined].map((id) => ({ id, name: 'Book club' })));
  if (path === `/rooms/${ROOM}/members`) {
    if (R.membersStatus) return reply(R.membersStatus, { detail: 'no' });
    return reply(200, R.members.map((username) => ({ username, role: 'member' })));
  }
  if ((m = path.match(/^\/keys\/([^/]+)$/))) {
    const a = R.accounts[decodeURIComponent(m[1])];
    return a ? reply(200, { username: decodeURIComponent(m[1]), ...a }) : reply(404, { detail: 'no such user' });
  }
  if (path === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: R.archive });
  if (path === `/crypto/room-key/${ROOM}`) return R.roomKey ? reply(200, R.roomKey) : reply(404, {});
  if (path === `/rooms/${ROOM}/history`) return reply(200, { room_id: ROOM, messages: R.history, has_more: false });
  return reply(404, {});
}

function makeRouter() {
  return async (url, opts) => {
    const u = new URL(String(url));
    if (u.host === new URL(R_BASE).host) return routeR(String(url), opts);
    throw new TypeError('Failed to fetch');   // nowhere else should be asked anything
  };
}

async function account(CU) {
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const edPub = await CU.ed25519GetPublicKey(seed);
  const x = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const xPubB64 = CU.arrayBufferToBase64(x);
  return {
    seed,
    edPubB64: CU.arrayBufferToBase64(edPub),
    xPubB64,
    kid: await CU.fingerprintPublicKey(xPubB64),
  };
}

let P;          // the guest: alice, at home on island G
let alice;      // { kid, edPubB64, xPubB64 }
let aliceThere; // her name on island R
let bob;        // the inviter, a member on R, a contact of alice's
let carol;      // another member on R
let mallory;    // has an account on R, is not in the room
let islandMade; // a signing key island R made up
let room;
let GR;

function slot() {
  return GR.slot(R_ID, ROOM);
}

function forgetSlot() {
  for (const map of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive']) {
    P.manager[map]?.delete?.(slot());
  }
}

async function freshKey() {
  const keyB64 = await P.CU.exportRoomKey(await P.CU.generateRoomKey(true));
  return { keyB64, kid: await P.CU.fingerprintRoomKeyBase64(keyB64) };
}

async function wrapForAlice(keyB64, by, signer) {
  const kid = await P.CU.fingerprintRoomKeyBase64(keyB64);
  const opts = by ? { seed: by.seed, signer, scope: 'room', scopeId: ROOM, recipient: aliceThere, keyId: kid } : null;
  return P.CU.encryptRoomKeyForUser(P.manager.userPublicKeyPem, keyB64, opts);
}

/** A room message as `who` writes it: signed envelope, encrypted under the slot's key. */
async function messageFrom(who, name, body) {
  const sig = await P.CU.ed25519Sign(who.seed, P.CU._roomSigMessage(ROOM, name, body));
  return P.manager.encryptMessage(slot(), JSON.stringify({ rs: 1, from: name, body, sig }));
}

beforeAll(async () => {
  P = makePanel({ apiBase: 'https://island-g.test', islandId: G_ID, username: 'alice', token: 'tok' });
  P.sandbox.fetch = makeRouter();
  await unlockRealManager(P.sandbox, { username: 'alice', password: PASS });
  GR = P.sandbox.WSGuestRooms;

  alice = {
    kid: await P.CU.fingerprintPublicKey(P.manager.userPublicKeyPem),
    xPubB64: P.manager.userPublicKeyPem,
    edPubB64: P.CU.arrayBufferToBase64(await P.CU.ed25519GetPublicKey(P.manager.ed25519Seed)),
  };
  aliceThere = `alice@${G_ID}~${alice.kid.slice(0, 6)}`;
  R.guests.set(alice.kid, { edRaw: Buffer.from(alice.edPubB64, 'base64'), username: aliceThere });
  R.pending.add(ROOM);

  bob = await account(P.CU);
  carol = await account(P.CU);
  mallory = await account(P.CU);
  islandMade = await account(P.CU);
  R.members = [aliceThere, 'bob', 'carol'];
  R.accounts.carol = { public_key: carol.xPubB64, ed25519_public_key: carol.edPubB64 };
  R.accounts.mallory = { public_key: mallory.xPubB64, ed25519_public_key: mallory.edPubB64 };
  // What the island says about bob is a key of its own: only his card is right.
  R.accounts.bob = { public_key: bob.xPubB64, ed25519_public_key: islandMade.edPubB64 };

  await P.sandbox.saveForeignContact({
    v: 1,
    kid: bob.kid,
    displayName: 'bob',
    x25519PubB64: bob.xPubB64,
    ed25519PubB64: bob.edPubB64,
    island: { islandId: R_ID, signingKeyB64: '', entryPoints: [{ apiBase: R_BASE, wsBase: 'wss://island-r.test', label: '' }] },
    inbox: { threadId: 900, keyB64: null, keyId: null },
    outbox: null,
    addedAt: Date.now(),
  });
}, 60000);

describe('following an invitation', () => {
  test('to anywhere but the inviter\'s own island is refused, before anything is asked', async () => {
    const before = R.calls.length;
    const elsewhere = GR.parseInvite(GR.buildInvite({ islandId: 'island-x.test', roomId: ROOM, roomName: 'x' }));
    await expect(P.sandbox.acceptGuestInvite(bob.kid, elsewhere, 'bob')).rejects.toThrow(/other than theirs/);
    expect(R.calls.length).toBe(before);
  });

  test('signs nothing for a server their address now leads to that is not their island', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club' }));
    R.challengeIsland = 'island-x.test';
    try {
      await expect(P.sandbox.acceptGuestInvite(bob.kid, invite, 'bob')).rejects.toThrow(/different server/);
    } finally {
      R.challengeIsland = '';
    }
    expect(R.calls).not.toContain('POST /foreign/guest/session');
    expect(R.joined.has(ROOM)).toBe(false);
  });

  test('signs in with the identity key, accepts, and pins the inviter from the card', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club', guestName: aliceThere }));
    room = await P.sandbox.acceptGuestInvite(bob.kid, invite, 'bob');
    expect(room).toMatchObject({
      islandId: R_ID, roomId: ROOM, roomName: 'Book club', guestName: aliceThere, inviter: 'bob', contactKid: bob.kid,
    });
    expect(R.joined.has(ROOM)).toBe(true);

    const pin = P.sandbox._fpBaseOn(R_ID, aliceThere, 'bob');
    const got = await P.sandbox.chrome.storage.local.get([pin, pin + ':ed']);
    expect(got[pin]).toBe(bob.kid);
    expect(got[pin + ':ed']).toBe(bob.edPubB64);

    expect(await P.sandbox.listGuestRooms()).toHaveLength(1);
  });

  test('pins nobody under a name the invitation gives that their card does not', async () => {
    // A second click on the same invitation, signed with somebody else's name
    // in the room: their keys must not become that person's here.
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club' }));
    await P.sandbox.acceptGuestInvite(bob.kid, invite, 'carol');
    const pin = P.sandbox._fpBaseOn(R_ID, aliceThere, 'carol');
    const got = await P.sandbox.chrome.storage.local.get([pin, pin + ':ed']);
    expect(got[pin]).toBeUndefined();
    expect(got[pin + ':ed']).toBeUndefined();
  });

  test('a second click on the same invitation is not an error', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club' }));
    await expect(P.sandbox.acceptGuestInvite(bob.kid, invite, 'bob')).resolves.toMatchObject({ roomId: ROOM });
    expect(await P.sandbox.listGuestRooms()).toHaveLength(1);
  });
});

describe('the list of rooms elsewhere', () => {
  test('two rooms saved at the same moment are both kept', async () => {
    const a = { v: 1, islandId: 'island-a.test', roomId: 1, roomName: 'a', guestName: 'x' };
    const b = { v: 1, islandId: 'island-b.test', roomId: 2, roomName: 'b', guestName: 'y' };
    await Promise.all([P.sandbox._saveGuestRoom(a), P.sandbox._saveGuestRoom(b)]);
    try {
      const list = await P.sandbox.listGuestRooms();
      expect(list.filter((r) => r.roomName === 'a' || r.roomName === 'b')).toHaveLength(2);
    } finally {
      await Promise.all([P.sandbox._dropGuestRoom(a), P.sandbox._dropGuestRoom(b)]);
    }
    expect(await P.sandbox.listGuestRooms()).toHaveLength(1);
  });
});

describe('the room key, from an island that is not ours', () => {
  afterEach(() => forgetSlot());

  test('opens when the inviter wrapped it, under the key on their card - not the one the island serves', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, bob, 'bob') };
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: true });
    expect(P.manager.roomKeys.has(slot())).toBe(true);
  });

  test('is refused when signed in the inviter\'s name with the key the island made up', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, islandMade, 'bob') };
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, refused: true });
    expect(P.manager.roomKeys.has(slot())).toBe(false);
  });

  test('is refused from somebody the room does not list, however valid their signature', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, mallory, 'mallory') };
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, refused: true });
  });

  test('cannot be introduced by an unsigned wrap', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, null, '') };
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, refused: true });
  });

  test('says "not yet" when there is none, rather than failing', async () => {
    R.roomKey = null;
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, notFound: true });
  });

  test('an island that will not say who is in the room is not reported as offering a bad key', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, bob, 'bob') };
    vm.runInContext('_guestSignerCache.clear()', P.sandbox);
    try {
      R.membersStatus = 502;
      expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: false, unreachable: true });
      R.membersStatus = 403;
      expect(await P.sandbox.loadGuestRoomKey(room)).toMatchObject({ ok: false, denied: true });
    } finally {
      R.membersStatus = 0;
    }
    expect(P.manager.roomKeys.has(slot())).toBe(false);
  });

  test('loads that overlap are one request; the decrypt path does not hammer a missing key', async () => {
    R.roomKey = null;
    const count = () => R.calls.filter((c) => c === `GET /crypto/room-key/${ROOM}`).length;

    let before = count();
    const both = await Promise.all([P.sandbox.loadGuestRoomKey(room), P.sandbox.loadGuestRoomKey(room)]);
    expect(both).toEqual([{ ok: false, notFound: true }, { ok: false, notFound: true }]);
    expect(count() - before).toBe(1);

    // A page of history before the key has arrived.
    const k = await freshKey();
    await P.manager.loadRoomKey(slot(), k.keyB64);
    const ct = await P.manager.encryptMessage(slot(), 'x');
    forgetSlot();
    before = count();
    for (let i = 0; i < 20; i++) {
      expect(await P.sandbox.decryptFromGuestRoom(room, ct, 'carol')).toBe('[Encrypted message - key not available]');
    }
    expect(count() - before).toBeLessThanOrEqual(1);

    // An explicit load is never answered from that memory.
    before = count();
    await P.sandbox.loadGuestRoomKey(room);
    expect(count() - before).toBe(1);
  });
});

describe('messages in the room', () => {
  beforeAll(async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForAlice(k.keyB64, bob, 'bob') };
    expect(await P.sandbox.loadGuestRoomKey(room)).toEqual({ ok: true });
  });

  test('what the guest writes is signed as its name there, and reads back verified', async () => {
    const enc = await P.sandbox.encryptForGuestRoom(room, 'hello from G');
    const inner = JSON.parse(await P.manager.decryptMessage(slot(), JSON.parse(enc)));
    expect(inner).toMatchObject({ rs: 1, from: aliceThere, body: 'hello from G' });

    const dec = await P.sandbox.decryptFromGuestRoom(room, enc, aliceThere);
    expect(dec).toEqual({ text: 'hello from G', from: aliceThere, sigValid: true, mismatch: false });
  });

  test('a member\'s signature is checked against the key pinned there on first sight', async () => {
    const good = await messageFrom(carol, 'carol', 'hi');
    expect(await P.sandbox.decryptFromGuestRoom(room, good, 'carol'))
      .toEqual({ text: 'hi', from: 'carol', sigValid: true, mismatch: false });

    // The pin lives under the room's island and our name there - not at home,
    // where "carol" may be somebody else entirely.
    const there = P.sandbox._fpBaseOn(R_ID, aliceThere, 'carol') + ':ed';
    const home = P.sandbox._fpBaseOn(G_ID, 'alice', 'carol') + ':ed';
    const got = await P.sandbox.chrome.storage.local.get([there, home]);
    expect(got[there]).toBe(carol.edPubB64);
    expect(got[home]).toBeUndefined();

    // The island now serves a key of its own for carol and writes as her.
    R.accounts.carol = { ...R.accounts.carol, ed25519_public_key: islandMade.edPubB64 };
    vm.runInContext('_guestEdKeyCache.clear()', P.sandbox);
    const forged = await messageFrom(islandMade, 'carol', 'send me your password');
    expect(await P.sandbox.decryptFromGuestRoom(room, forged, 'carol'))
      .toMatchObject({ from: 'carol', sigValid: false });
    expect(await P.sandbox.decryptFromGuestRoom(room, good, 'carol'))
      .toMatchObject({ sigValid: true });
  });

  test('a message the island wrote in the clear is shown as nobody\'s word', async () => {
    for (const forged of ['transfer the money to me', JSON.stringify({ hello: 'there' })]) {
      expect(await P.sandbox.decryptFromGuestRoom(room, forged, 'carol'))
        .toEqual({ text: forged, from: 'carol', sigValid: false, mismatch: false });
    }
  });

  test('the island naming another author than the signed one is reported', async () => {
    const msg = await messageFrom(carol, 'carol', 'it was me');
    expect(await P.sandbox.decryptFromGuestRoom(room, msg, 'bob'))
      .toMatchObject({ from: 'carol', mismatch: true });
  });

  test('a room here with the same number is a different room, with a different key', async () => {
    // Room 42 exists on every island. A key held for ours must never open, or
    // be used to write to, theirs.
    const local = await freshKey();
    await P.manager.loadRoomKey(ROOM, local.keyB64);
    try {
      const ours = await P.manager.encryptMessage(ROOM, 'local secret');
      expect(await P.sandbox.decryptFromGuestRoom(room, ours, 'carol'))
        .toBe('[Encrypted message - decryption failed]');
      const theirs = await P.sandbox.encryptForGuestRoom(room, 'to R');
      await expect(P.manager.decryptMessage(ROOM, JSON.parse(theirs))).rejects.toThrow();
    } finally {
      for (const map of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive']) {
        P.manager[map]?.delete?.(ROOM);
      }
    }
  });

  test('history comes from the room\'s island, as the guest', async () => {
    R.history = [{ id: 1, username: 'carol', text: 'x', ts: '2026-11-09T10:00:00Z' }];
    const page = await P.sandbox.fetchGuestRoomHistory(room, { limit: 10 });
    expect(page.messages).toHaveLength(1);
    expect(R.calls).toContain(`GET /rooms/${ROOM}/history`);
  });
});

describe('the moderator inviting somebody from another island', () => {
  let M;
  let sent;

  beforeAll(async () => {
    M = makePanel({ apiBase: R_BASE, islandId: R_ID, username: 'mod', token: 'modtok' });
    M.sandbox.fetch = makeRouter();
    await unlockRealManager(M.sandbox, { username: 'mod', password: PASS });
    sent = [];
    M.sandbox.sendForeignMessage = async (contact, text) => { sent.push({ kid: contact.kid, text }); return { ok: true }; };
    R.guestNameForInvite = aliceThere;

    const contact = {
      v: 1,
      kid: alice.kid,
      displayName: 'alice',
      x25519PubB64: alice.xPubB64,
      ed25519PubB64: alice.edPubB64,
      island: { islandId: G_ID, signingKeyB64: '', entryPoints: [{ apiBase: 'https://island-g.test', wsBase: '', label: '' }] },
      inbox: { threadId: 77, keyB64: null, keyId: null },
      outbox: { apiBase: 'https://island-g.test', threadId: 5, secretB64: 'c2VjcmV0', keyB64: 'a2V5', keyId: 'k1' },
      card: { payload: { v: 1, kid: alice.kid }, sig_b64: 'c2ln' },
      addedAt: Date.now(),
    };
    await M.sandbox.saveForeignContact(contact);
    await M.sandbox.saveForeignContact({ ...contact, kid: 'ab'.repeat(16), displayName: 'old', card: undefined });
    await M.sandbox.saveForeignContact({ ...contact, kid: 'cd'.repeat(16), displayName: 'silent', outbox: null });
  }, 60000);

  test('hands the card over, pins the guest from it, and invites them in the DM', async () => {
    const res = await M.sandbox.inviteForeignContactToRoom(ROOM, alice.kid, 'Book club');
    expect(res).toMatchObject({ guestName: aliceThere, status: 'pending', queued: false });
    expect(R.invited.at(-1)).toEqual({ card: { payload: { v: 1, kid: alice.kid }, sig_b64: 'c2ln' } });

    const pin = await M.sandbox._fpBase('mod', aliceThere);
    const got = await M.sandbox.chrome.storage.local.get([pin, pin + ':ed']);
    expect(got[pin]).toBe(alice.kid);
    expect(got[pin + ':ed']).toBe(alice.edPubB64);

    expect(sent).toHaveLength(1);
    expect(sent[0].kid).toBe(alice.kid);
    expect(GR.parseInvite(sent[0].text)).toEqual({
      islandId: R_ID, roomId: ROOM, roomName: 'Book club', guestName: aliceThere,
    });
  });

  test('will not pin a name the island hands back to keys other than the card\'s', async () => {
    const other = await account(M.CU);
    R.guestNameForInvite = 'bob';   // a name already known here with other keys
    const pin = await M.sandbox._fpBase('mod', 'bob');
    await M.sandbox.chrome.storage.local.set({ [pin]: other.kid, [pin + ':ed']: other.edPubB64 });
    try {
      await expect(M.sandbox.inviteForeignContactToRoom(ROOM, alice.kid, 'Book club'))
        .rejects.toThrow(/already pinned/);
      expect(sent).toHaveLength(1);
      const got = await M.sandbox.chrome.storage.local.get([pin]);
      expect(got[pin]).toBe(other.kid);
    } finally {
      R.guestNameForInvite = aliceThere;
    }
  });

  test('a contact added before cards were kept is not sent to the island', async () => {
    const before = R.invited.length;
    await expect(M.sandbox.inviteForeignContactToRoom(ROOM, 'ab'.repeat(16), 'Book club'))
      .rejects.toThrow(/before cards were kept/);
    expect(R.invited.length).toBe(before);
  });

  test('somebody we cannot write to yet is not created on the island', async () => {
    // Their island does not answer, so the mailbox they opened for us cannot
    // be claimed, and an invitation would sit on this island with nobody told.
    const before = R.invited.length;
    await expect(M.sandbox.inviteForeignContactToRoom(ROOM, 'cd'.repeat(16), 'Book club'))
      .rejects.toThrow(/cannot be told about it yet/);
    expect(R.invited.length).toBe(before);
  });

  test('a message that did not go is reported as that, not as a failed invitation', async () => {
    const real = M.sandbox.sendForeignMessage;
    M.sandbox.sendForeignMessage = async () => { throw new Error('Delivery refused (500)'); };
    const before = R.invited.length;
    try {
      await expect(M.sandbox.inviteForeignContactToRoom(ROOM, alice.kid, 'Book club'))
        .rejects.toThrow(/is invited on this server, but the message telling them did not go.*Invite them again/);
      expect(R.invited.length).toBe(before + 1);
    } finally {
      M.sandbox.sendForeignMessage = real;
    }
  });
});
