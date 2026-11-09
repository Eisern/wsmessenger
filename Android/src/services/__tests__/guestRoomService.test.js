// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Android as a guest in a room on another island: GuestRoomService over the
 * real CryptoService, StorageService (on the AsyncStorage / Keychain stubs)
 * and ForeignService, against a stubbed island that is the adversary - as
 * extensionGuestRooms.test.js holds the extension to the same rules.
 *
 * The guest's name there carries a capital, as most will: the island builds it
 * from the display name on the card, and a signed key wrap binds it.
 */

const crypto = require('crypto');
const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import ForeignService from '../ForeignService';
import GuestRoomService from '../GuestRoomService';
import GR from '../guest-rooms';

const HOME = 'https://island-g.test';
const G_ID = 'island-g.test';
const R_BASE = 'https://island-r.test';
const R_ID = 'island-r.test';
const ROOM = 42;
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');
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

const R = {
  guests: new Map(), nonces: new Set(), tokens: new Map(), pending: new Set(), joined: new Set(),
  members: [], accounts: {}, roomKey: null, archive: [], history: [], calls: [],
  challengeIsland: '', membersStatus: 0,
};
let tokenN = 0;

function routeR(path, opts) {
  const method = opts.method || 'GET';
  R.calls.push(`${method} ${path.split('?')[0]}`);
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
  if (!R.tokens.has(token)) return reply(401, { detail: 'Invalid token' });

  let m;
  const p = path.split('?')[0];
  if ((m = p.match(/^\/rooms\/(\d+)\/invites\/accept$/)) && method === 'POST') {
    const rid = Number(m[1]);
    if (!R.pending.delete(rid)) return reply(404, { detail: 'Invite not found' });
    R.joined.add(rid);
    return reply(200, { ok: true, room_id: rid });
  }
  if (p === '/rooms/list') return reply(200, [...R.joined].map((id) => ({ id, name: 'Book club' })));
  if (p === `/rooms/${ROOM}/members`) {
    if (R.membersStatus) return reply(R.membersStatus, { detail: 'no' });
    return reply(200, R.members.map((username) => ({ username, role: 'member' })));
  }
  if ((m = p.match(/^\/keys\/([^/]+)$/))) {
    const a = R.accounts[decodeURIComponent(m[1])];
    return a ? reply(200, { username: decodeURIComponent(m[1]), ...a }) : reply(404, { detail: 'no such user' });
  }
  if (p === `/crypto/room-key/${ROOM}/archive`) return reply(200, { keys: R.archive });
  if (p === `/crypto/room-key/${ROOM}`) return R.roomKey ? reply(200, R.roomKey) : reply(404, { detail: 'no key' });
  if (p === `/rooms/${ROOM}/history`) return reply(200, { room_id: ROOM, messages: R.history, has_more: false });
  if (p === `/rooms/${ROOM}/leave` && method === 'POST') { R.joined.delete(ROOM); return reply(200, { ok: true }); }
  return reply(404, { detail: 'Not found' });
}

function identity() {
  const priv = x25519.utils.randomSecretKey();
  const edSeed = CryptoUtils.deriveEd25519Seed(priv);
  return { priv, pubB64: b64(x25519.getPublicKey(priv)), edSeed, edPubB64: b64(CryptoUtils.ed25519GetPublicKey(edSeed)) };
}

let me;
let meKid;
let aliceThere;
let bob;
let bobKid;
let carol;
let mallory;
let islandMade;
let room;

const slot = () => GR.slot(R_ID, ROOM);
function forgetSlot() {
  for (const map of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive']) cryptoManager[map]?.delete?.(slot());
}
async function freshKey() {
  const keyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  return { keyB64, kid: await CryptoUtils.fingerprintRoomKeyBase64(keyB64) };
}
async function wrapForMe(keyB64, by, signer) {
  const kid = await CryptoUtils.fingerprintRoomKeyBase64(keyB64);
  const opts = by ? { seed: by.edSeed, signer, scope: 'room', scopeId: ROOM, recipient: aliceThere, keyId: kid } : null;
  return CryptoUtils.encryptRoomKeyForUser(me.pubB64, keyB64, opts);
}
async function messageFrom(who, name, body) {
  const sig = CryptoUtils.ed25519Sign(who.edSeed, CryptoUtils._roomSigMessage(ROOM, name, body));
  return cryptoManager.encryptMessage(slot(), JSON.stringify({ rs: 1, from: name, body, sig }));
}

beforeAll(async () => {
  global.fetch = jest.fn(async (url, opts = {}) => {
    const u = String(url);
    if (u.startsWith(R_BASE)) return routeR(u.slice(R_BASE.length), opts);
    if (u.startsWith(HOME)) return reply(404, { detail: 'Not found' });
    throw new TypeError(`unexpected host: ${u}`);
  });
  NetworkService.setServerConfig(HOME, 'wss://island-g.test');
  NetworkService._token = 'home-token';
  await StorageService.setActiveUsername('alice');

  me = identity();
  expect(await CryptoService.unlockWithRawKey(new Uint8Array(me.priv), me.pubB64)).toBe(true);
  meKid = await CryptoUtils.fingerprintPublicKey(me.pubB64);
  aliceThere = `Alice@${G_ID}~${meKid.slice(0, 6)}`;
  R.guests.set(meKid, { edRaw: Buffer.from(CryptoService.ed25519PublicKey()), username: aliceThere });
  R.pending.add(ROOM);

  bob = identity();
  carol = identity();
  mallory = identity();
  islandMade = identity();
  bobKid = await CryptoUtils.fingerprintPublicKey(bob.pubB64);
  R.members = [aliceThere, 'bob', 'carol'];
  R.accounts.carol = { public_key: carol.pubB64, ed25519_public_key: carol.edPubB64 };
  R.accounts.mallory = { public_key: mallory.pubB64, ed25519_public_key: mallory.edPubB64 };
  R.accounts.bob = { public_key: bob.pubB64, ed25519_public_key: islandMade.edPubB64 };   // a lie

  await ForeignService.saveContact({
    v: 1, kid: bobKid, displayName: 'bob', x25519PubB64: bob.pubB64, ed25519PubB64: bob.edPubB64,
    island: { islandId: R_ID, signingKeyB64: '', entryPoints: [{ apiBase: R_BASE, wsBase: 'wss://island-r.test', label: '' }] },
    inbox: { threadId: 900, keyB64: null, keyId: null }, outbox: null, addedAt: Date.now(),
  });
});

afterAll(() => {
  CryptoService.lockSession();
  ForeignService.clearCache();
  GuestRoomService.clearCache();
});

describe('following an invitation', () => {
  test('to anywhere but the inviter\'s own island is refused, before anything is asked', async () => {
    const before = R.calls.length;
    const elsewhere = GR.parseInvite(GR.buildInvite({ islandId: 'island-x.test', roomId: ROOM }));
    await expect(GuestRoomService.acceptInvite(bobKid, elsewhere, 'bob')).rejects.toThrow(/other than theirs/);
    expect(R.calls.length).toBe(before);
  });

  test('signs nothing for a server their address now leads to that is not their island', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM }));
    R.challengeIsland = 'island-x.test';
    try {
      await expect(GuestRoomService.acceptInvite(bobKid, invite, 'bob')).rejects.toThrow(/different server/);
    } finally {
      R.challengeIsland = '';
    }
    expect(R.calls).not.toContain('POST /foreign/guest/session');
    expect(R.joined.has(ROOM)).toBe(false);
  });

  test('signs in with the identity key, accepts, and pins the inviter from the card', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club', guestName: aliceThere }));
    room = await GuestRoomService.acceptInvite(bobKid, invite, 'bob');
    expect(room).toMatchObject({ islandId: R_ID, roomId: ROOM, guestName: aliceThere, inviter: 'bob', contactKid: bobKid });
    expect(R.joined.has(ROOM)).toBe(true);
    expect(await StorageService.getKnownFingerprint(R_ID, aliceThere, 'bob')).toBe(bobKid);
    expect(await StorageService.getKnownEd25519(R_ID, aliceThere, 'bob')).toBe(bob.edPubB64);
    expect(await GuestRoomService.listRooms()).toHaveLength(1);
  });

  test('pins nobody under a name the invitation gives that their card does not', async () => {
    const invite = GR.parseInvite(GR.buildInvite({ islandId: R_ID, roomId: ROOM, roomName: 'Book club' }));
    const again = await GuestRoomService.acceptInvite(bobKid, invite, 'carol');
    expect(await StorageService.getKnownEd25519(R_ID, aliceThere, 'carol')).toBeFalsy();
    expect(again.inviter).toBe('bob');   // the second tap did not erase what the first learned
    expect(await GuestRoomService.listRooms()).toHaveLength(1);
  });
});

describe('the room key, from an island that is not ours', () => {
  afterEach(() => forgetSlot());

  test('opens when the inviter wrapped it - for a name with a capital - under the key on their card', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, bob, 'bob') };
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: true });
    expect(cryptoManager.roomKeys.has(slot())).toBe(true);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);   // never under the bare id
  });

  test('is refused when signed in the inviter\'s name with the key the island made up', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, islandMade, 'bob') };
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, refused: true });
  });

  test('is refused from somebody the room does not list', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, mallory, 'mallory') };
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, refused: true });
  });

  test('cannot be introduced by an unsigned wrap', async () => {
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, null, '') };
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, refused: true });
  });

  test('"not yet", "could not say" and "not yours" are told apart from a bad key', async () => {
    R.roomKey = null;
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, notFound: true });
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, bob, 'bob') };
    GuestRoomService.clearCache();
    try {
      R.membersStatus = 502;
      expect(await GuestRoomService.loadKey(room)).toEqual({ ok: false, unreachable: true });
      GuestRoomService.clearCache();
      R.membersStatus = 403;
      expect(await GuestRoomService.loadKey(room)).toMatchObject({ ok: false, denied: true });
    } finally {
      R.membersStatus = 0;
      GuestRoomService.clearCache();
    }
  });

  test('loads that overlap are one request; the decrypt path does not hammer a missing key', async () => {
    R.roomKey = null;
    const count = () => R.calls.filter((c) => c === `GET /crypto/room-key/${ROOM}`).length;
    let before = count();
    const both = await Promise.all([GuestRoomService.loadKey(room), GuestRoomService.loadKey(room)]);
    expect(both).toEqual([{ ok: false, notFound: true }, { ok: false, notFound: true }]);
    expect(count() - before).toBe(1);

    const k = await freshKey();
    await cryptoManager.loadRoomKey(slot(), k.keyB64);
    const ct = await cryptoManager.encryptMessage(slot(), 'x');
    forgetSlot();
    before = count();
    for (let i = 0; i < 20; i++) {
      expect(await GuestRoomService.decrypt(room, ct, 'carol')).toBe('[Encrypted message - key not available]');
    }
    expect(count() - before).toBeLessThanOrEqual(1);
  });
});

describe('messages in the room', () => {
  beforeAll(async () => {
    GuestRoomService.clearCache();
    const k = await freshKey();
    R.roomKey = { encrypted_room_key: await wrapForMe(k.keyB64, bob, 'bob') };
    expect(await GuestRoomService.loadKey(room)).toEqual({ ok: true });
  });

  test('what the guest writes is signed as its name there, and reads back verified', async () => {
    const enc = await GuestRoomService.encrypt(room, 'hello from G');
    const inner = JSON.parse(await cryptoManager.decryptMessage(slot(), enc));
    expect(inner).toMatchObject({ rs: 1, from: aliceThere, body: 'hello from G' });
    expect(await GuestRoomService.decrypt(room, enc, aliceThere))
      .toEqual({ text: 'hello from G', from: aliceThere, sigValid: true, mismatch: false });
  });

  test('a member\'s signature is checked against the key pinned there; the island cannot swap it', async () => {
    const good = await messageFrom(carol, 'carol', 'hi');
    expect(await GuestRoomService.decrypt(room, good, 'carol'))
      .toEqual({ text: 'hi', from: 'carol', sigValid: true, mismatch: false });
    expect(await StorageService.getKnownEd25519(R_ID, aliceThere, 'carol')).toBe(carol.edPubB64);
    expect(await StorageService.getKnownEd25519(G_ID, 'alice', 'carol')).toBeFalsy();

    R.accounts.carol = { ...R.accounts.carol, ed25519_public_key: islandMade.edPubB64 };
    GuestRoomService.clearCache();
    await GuestRoomService.loadKey(room);
    const forged = await messageFrom(islandMade, 'carol', 'send me your password');
    expect(await GuestRoomService.decrypt(room, forged, 'carol')).toMatchObject({ from: 'carol', sigValid: false });
  });

  test('the island naming another author than the signed one is reported', async () => {
    const msg = await messageFrom(carol, 'carol', 'it was me');
    expect(await GuestRoomService.decrypt(room, msg, 'bob')).toMatchObject({ from: 'carol', mismatch: true });
  });

  test('a room here with the same number is a different room, with a different key', async () => {
    const local = await freshKey();
    await cryptoManager.loadRoomKey(ROOM, local.keyB64);
    try {
      const ours = await cryptoManager.encryptMessage(ROOM, 'local secret');
      expect(await GuestRoomService.decrypt(room, ours, 'carol')).toBe('[Encrypted message - decryption failed]');
    } finally {
      for (const map of ['roomKeys', 'roomKeysExportable', 'roomKeyIds', 'roomKeyArchive']) cryptoManager[map]?.delete?.(ROOM);
    }
  });
});

describe('the room socket', () => {
  function fakeSockets() {
    const made = [];
    GuestRoomService._setSocketFactory((url) => {
      const s = {
        url, sent: [], readyState: 0,
        send(t) { this.sent.push(t); },
        close() { this.readyState = 3; },
        open() { this.readyState = 1; this.onopen?.(); },
        frame(obj) { this.onmessage?.({ data: JSON.stringify(obj) }); },
        drop(code) { this.readyState = 3; this.onclose?.({ code }); },
      };
      made.push(s);
      return s;
    });
    return made;
  }
  const flush = async (n = 30) => { for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r)); };

  test('authenticates as the guest, takes only its room\'s messages, and says when it is up', async () => {
    const made = fakeSockets();
    const got = [];
    const statuses = [];
    const sock = GuestRoomService.openSocket(room, { onMessage: (m) => got.push(m.text), onStatus: (s) => statuses.push(s) });
    try {
      await flush();
      expect(made[0].url).toBe(`wss://island-r.test/ws?room_id=${ROOM}`);
      made[0].open();
      const auth = JSON.parse(made[0].sent[0]);
      expect(auth.type).toBe('auth');
      expect(R.tokens.get(auth.token)).toBe(aliceThere);

      made[0].frame({ type: 'presence', room_id: ROOM, online: [] });
      made[0].frame({ type: 'message', room_id: ROOM, from: 'carol', text: 'here' });
      made[0].frame({ type: 'message', room_id: ROOM + 1, from: 'carol', text: 'elsewhere' });
      expect(got).toEqual(['here']);
      expect(statuses[0]).toEqual({ online: true });
      expect(sock.online).toBe(true);
    } finally {
      sock.close();
    }
  });

  test('a refusal is tried once more with a fresh session, then given up', async () => {
    jest.useFakeTimers({ doNotFake: ['setImmediate', 'nextTick'] });
    const made = fakeSockets();
    const statuses = [];
    const sock = GuestRoomService.openSocket(room, { onStatus: (s) => statuses.push(s) });
    try {
      await flush();
      made[0].open();
      made[0].drop(1008);
      jest.advanceTimersByTime(2000);
      await flush();
      expect(made).toHaveLength(2);
      made[1].open();
      made[1].drop(1008);
      jest.advanceTimersByTime(60000);
      await flush();
      expect(made).toHaveLength(2);
      expect(statuses.at(-1)).toEqual({ online: false, error: 'refused' });
    } finally {
      sock.close();
      jest.useRealTimers();
    }
  });

  test('a feed shows the history through the same checks', async () => {
    const made = fakeSockets();
    R.history = [{ id: 1, username: 'carol', text: await messageFrom(carol, 'carol', 'from history'), ts: 1 }];
    let items = [];
    const feed = GuestRoomService.createFeed(room, {
      onReset: (list) => { items = list; },
      onAppend: (it) => { items.push(it); },
      onNotice: () => {},
    });
    try {
      const started = feed.start();
      await flush();
      made[0].open();
      made[0].frame({ type: 'presence', room_id: ROOM, online: [] });
      await started;
      expect(items.map((i) => [i.user, i.text, i.sigValid])).toEqual([['carol', 'from history', true]]);
    } finally {
      feed.stop();
    }
  });
});

describe('leaving', () => {
  test('drops the room here and leaves it there', async () => {
    await GuestRoomService.leave(room);
    expect(R.joined.has(ROOM)).toBe(false);
    expect(await GuestRoomService.listRooms()).toHaveLength(0);
  });
});
