// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * GuestRoomService.js — rooms on another island, taken part in as a guest.
 *
 * The protocol is guest-rooms.js and the feed ordering guest-room-feed.js, both
 * byte-identical to the extension's copies. This file is the Android half of
 * what the "Rooms on other islands, as a guest" section of panel-crypto.js does
 * around them, and holds to the same rules:
 *
 *   - An invitation is followed only to the inviter's island as their CARD says;
 *     the island id in it is a consistency check, never an address.
 *   - A guest room's keys and signatures go through the same checks as at home
 *     (CryptoService.acceptWrappedKeyIn / openRoomEnvelopeIn), with that
 *     island's names. Pins live under (that island, our name there, theirs),
 *     never mixed with this island's.
 *   - The moderator pins the guest's keys from the card under the name the
 *     island returns, before anything uses that name; the guest pins the
 *     inviter from their card - only under the name the card carries.
 *   - Sessions are signed for with the identity key and kept in memory only;
 *     a lock forgets them.
 *
 * See docs/internal/cross-island-rooms-assessment.md for the design.
 */

import NetworkService from './NetworkService';
import StorageService from './StorageService';
import CryptoService from './CryptoService';
import ForeignService from './ForeignService';
import EP from './endpoints';
import GR from './guest-rooms';
import GRF from './guest-room-feed';
import { CryptoUtils, cryptoManager } from '../crypto';

// The origin every socket of this app announces; the island checks it.
const _ORIGIN = 'react-native://com.wsmessenger';

const _SIGNER_SET_TTL_MS = 60 * 1000;
const _KEY_RETRY_MS = 15 * 1000;

// "<island>|<me there>|<name>" -> Uint8Array: the pinned signing key of a name
// in a room elsewhere.
const _edKeyCache = new Map();
// key slot -> { at, set }: who may hand out a guest room's key.
const _signerCache = new Map();
// key slot -> { promise } while a load runs, { at, res } after one failed.
const _keyLoads = new Map();

let _sessions = null;
let _listChain = Promise.resolve();

// Tests replace this; the app opens a real socket.
let _makeSocket = (url) => new WebSocket(url, null, { headers: { Origin: _ORIGIN } });

function _fetchJson() {
  return async (url, opts = {}) => {
    const r = await fetch(url, opts);
    let body = null;
    try { body = await r.json(); } catch (_e) { /* empty body */ }
    return { ok: r.ok, status: r.status, body };
  };
}

function sessions() {
  if (_sessions) return _sessions;
  _sessions = GR.createSessions({
    fetchJson: _fetchJson(),
    sign: async (bytes) => CryptoService.signEd25519(bytes),
    now: () => Date.now(),
    myKid: async () => {
      const pub = cryptoManager.userPublicKeyB64;
      if (!pub) throw new Error('Locked');
      return CryptoUtils.fingerprintPublicKey(pub);
    },
  });
  return _sessions;
}

/** Forget everything signed for, or learned under, the key being put away. */
function clearCache() {
  try { _sessions?.forget(); } catch (_e) { /* nothing to forget */ }
  _edKeyCache.clear();
  _signerCache.clear();
  _keyLoads.clear();
}

CryptoService.on?.('locked', clearCache);

function slotOf(room) {
  return GR.slot(room?.islandId, room?.roomId);
}

// ============================
// The list of rooms elsewhere
// ============================

async function _listKey() {
  try { await NetworkService.serverConfigReady(); } catch (_e) { /* keep what we have */ }
  const home = EP.islandIdOf(NetworkService.getServerConfig());
  return GR.listKey(home, await CryptoService.activeUsername());
}

/** Every room on another island this account takes part in as a guest. */
async function listRooms() {
  try {
    const got = await StorageService.get(await _listKey());
    return Array.isArray(got) ? got : [];
  } catch (e) {
    console.warn('[Guest] list failed:', e?.message || e);
    return [];
  }
}

// Read-modify-write, one at a time: two interleaved would each write back a
// list without the other's change.
function _listWrite(fn) {
  const run = _listChain.then(fn, fn);
  _listChain = run.catch(() => {});
  return run;
}

function saveRoom(room) {
  return _listWrite(async () => {
    const key = await _listKey();
    const list = await listRooms();
    const at = list.findIndex((r) => GR.sameRoom(r, room));
    // A second accept adds what it learned; it does not erase the inviter or
    // the date the first one recorded.
    const merged = at >= 0 ? { ...list[at], ...room, joinedAt: list[at].joinedAt || room.joinedAt } : room;
    if (at >= 0) list[at] = merged;
    else list.push(merged);
    await StorageService.set(key, list);
    return merged;
  });
}

function dropRoom(room) {
  return _listWrite(async () => {
    const key = await _listKey();
    await StorageService.set(key, (await listRooms()).filter((r) => !GR.sameRoom(r, room)));
    _signerCache.delete(slotOf(room));
    _keyLoads.delete(slotOf(room));
  });
}

/**
 * Where a guest room's island is: the contact's copy first, which follows
 * their island's signed list when it moves; the snapshot kept with the room
 * when the contact has been removed since.
 */
async function islandOf(room) {
  const want = String(room?.islandId || '').toLowerCase();
  if (room?.contactKid) {
    try {
      const c = await ForeignService.getContact(room.contactKid);
      if (c?.island?.islandId && String(c.island.islandId).toLowerCase() === want) return c.island;
    } catch (_e) { /* fall back to the snapshot */ }
  }
  return room?.island || { islandId: room?.islandId, entryPoints: [] };
}

// ============================
// Pins from a card
// ============================

/**
 * Pin both of someone's keys under a name, from their card rather than from an
 * island. An existing pin to other keys is never overwritten: that is either a
 * different person who held the name, or the island lying about who this is.
 */
async function _pinFromCard(island, me, name, contact, { strict }) {
  const x = await StorageService.getKnownFingerprint(island, me, name);
  const ed = await StorageService.getKnownEd25519(island, me, name);
  const clash = (x && x !== contact.kid) || (ed && ed !== contact.ed25519PubB64);
  if (clash) {
    if (strict) throw new Error('that name is already pinned to other keys on this device');
    console.warn(`[Guest] ${name} on ${island} is pinned to other keys; keeping them`);
    return false;
  }
  if (!x) await StorageService.setKnownFingerprint(island, me, name, contact.kid);
  if (!ed) await StorageService.setKnownEd25519(island, me, name, contact.ed25519PubB64);
  return true;
}

// ============================
// The moderator's half
// ============================

/**
 * Invite a cross-island contact into a room on this island, and tell them.
 *
 * The island creates (or finds) the guest from their card and names them;
 * their keys are pinned under that name from the card before anything else
 * uses it, so the key wrapped for them later is checked against what they
 * signed, not against what this island says.
 */
async function inviteContact(roomId, peerKid, roomName = '') {
  const rid = Number(roomId);
  if (!Number.isInteger(rid) || rid <= 0) throw new Error('Bad room');
  const contact = await ForeignService.getContact(peerKid);
  if (!contact) throw new Error('Contact not found');
  const name = contact.displayName || String(contact.kid).slice(0, 8);
  if (!contact.card?.payload) {
    throw new Error(`${name} was added before cards were kept. Remove them and add their card again, then invite.`);
  }
  if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: true, reason: 'Invite to room' });
  if (!CryptoService.isReady()) throw new Error('Unlock first');
  const me = await CryptoService.activeUsername();
  if (!me) throw new Error('Not signed in');

  // The invitation reaches them only through the conversation. If we cannot
  // write to them yet, say so before the island creates a guest nobody will
  // ever tell about it.
  let reachable = contact;
  if (!reachable.outbox?.keyB64) {
    try {
      reachable = await ForeignService.claimOutbox(contact);
    } catch (e) {
      throw new Error(`${name} cannot be told about it yet: ${e?.message || e}`);
    }
  }
  if (!reachable?.outbox?.keyB64) throw new Error(`${name} cannot be told about it yet: no key for them`);

  let body;
  try {
    body = await NetworkService.inviteGuestToRoom(rid, contact.card);
  } catch (e) {
    // 404 "Not found" is the island with guests switched off; a missing room
    // is 404 "Room not found", and says so itself.
    throw new Error(e?.status === 404 && e?.message === 'Not found'
      ? 'This server does not take guests from other servers'
      : (e?.message || 'Could not invite'));
  }
  const guestName = String(body?.guest_username || '').trim();
  if (!guestName) throw new Error('The server did not say who the guest is');

  try {
    await _pinFromCard(await CryptoService.pinScope(), me, guestName, contact, { strict: true });
  } catch (e) {
    throw new Error(`Not inviting ${name}: ${e.message}`);
  }

  // The room is on this island, which is the island their card for us names:
  // that is what the invitation is checked against on their side.
  const invite = GR.buildInvite({
    islandId: String(body.island_id || EP.islandIdOf(NetworkService.getServerConfig())),
    roomId: rid,
    roomName: String(roomName || '').trim(),
    guestName,
  });
  let sent;
  try {
    sent = await ForeignService.sendMessage(reachable, invite);
  } catch (e) {
    // The island has the invitation; only the message did not go. Inviting
    // again is safe - the island answers "already invited" - and resends it.
    throw new Error(
      `${name} is invited on this server, but the message telling them did not go ` +
      `(${e?.message || e}). Invite them again to resend it.`,
    );
  }
  return { guestName, status: body.status || 'pending', queued: !!sent?.queued };
}

// ============================
// The guest's half
// ============================

/**
 * Accept an invitation that arrived in a cross-island conversation.
 *
 * @param {string} peerKid      the contact whose conversation it arrived in
 * @param {object} invite       as GR.parseInvite returns it
 * @param {string} inviterName  who wrote it, by their name on their island
 */
async function acceptInvite(peerKid, invite, inviterName) {
  const contact = await ForeignService.getContact(peerKid);
  if (!contact) throw new Error('Contact not found');
  const island = contact.island || {};
  if (!island.islandId || String(island.islandId).toLowerCase() !== String(invite?.islandId || '').toLowerCase()) {
    throw new Error('This invitation names a server other than theirs, so it was not followed');
  }
  if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: true, reason: 'Join room' });
  if (!CryptoService.isReady()) throw new Error('Unlock first');

  const S = sessions();
  const s = await S.get(island, { force: true });
  if (!s.ok) {
    throw new Error(s.status === 403
      ? 'Their server does not know you as a guest. The invitation may have been withdrawn.'
      : (s.reason === 'cannot sign' || s.reason === 'locked')
        ? 'Unlock first: joining is signed with your key'
        : s.reason === 'wrong island'
          ? 'Their address now leads to a different server, so it was not signed in to'
          : `Could not sign in to their server (${s.status || 'no answer'})`);
  }
  if (invite.guestName && s.username.toLowerCase() !== invite.guestName.toLowerCase()) {
    console.warn(`[Guest] invited as ${invite.guestName}, signed in as ${s.username}`);
  }

  const acc = await S.request(island, `/rooms/${invite.roomId}/invites/accept`, { method: 'POST' });
  if (!acc.ok) {
    if (acc.status !== 404) throw new Error(`Could not accept (${acc.status || 'no answer'})`);
    // No pending invitation: fine if we are already in, which is what a second
    // tap on the same invitation looks like.
    const mine = await S.request(island, '/rooms/list');
    if (!mine.ok || !Array.isArray(mine.body)) {
      throw new Error(`Could not check the invitation (${mine.status || 'no answer'})`);
    }
    if (!mine.body.some((r) => Number(r?.id) === invite.roomId)) {
      throw new Error('The invitation is no longer open');
    }
  }

  // Their keys under their name THERE, from their card - only under the name
  // the card carries: the name on a message is theirs to write.
  const said = String(inviterName || '').trim();
  const carded = String(contact.displayName || '').trim();
  const inviter = (said && carded && said.toLowerCase() === carded.toLowerCase()) ? said : '';
  if (said && !inviter) {
    console.warn(`[Guest] the invitation is signed "${said}" but their card says "${carded}"; not pinning`);
  }
  if (inviter) {
    try {
      await _pinFromCard(island.islandId, s.username, inviter, contact, { strict: false });
    } catch (e) {
      console.warn('[Guest] could not pin the inviter:', e?.message || e);
    }
  }

  const record = {
    v: 1,
    islandId: island.islandId,
    roomId: invite.roomId,
    roomName: invite.roomName || `#${invite.roomId}`,
    guestName: s.username,
    contactKid: contact.kid,
    island: {
      islandId: island.islandId,
      signingKeyB64: island.signingKeyB64 || '',
      entryPoints: island.entryPoints || [],
    },
    joinedAt: Date.now(),
  };
  if (inviter) record.inviter = inviter;
  return saveRoom(record);
}

function _ctx(room) {
  return { me: room.guestName, edKeyOf: (name) => _edKey(room, name) };
}

/**
 * The signing key to check `name`'s signatures against, in a room elsewhere:
 * pinned on first sight under that island and our name there, and once
 * pinned, the island is not asked again.
 */
async function _edKey(room, name) {
  const who = String(name || '').trim();
  if (!who || !room?.guestName) return null;
  const cacheKey = [room.islandId, room.guestName, who].map((v) => String(v).toLowerCase()).join('|');
  if (_edKeyCache.has(cacheKey)) return _edKeyCache.get(cacheKey);

  let b64;
  try {
    b64 = await StorageService.getKnownEd25519(room.islandId, room.guestName, who);
  } catch (_e) {
    return null;
  }
  if (!b64) {
    let r;
    try {
      r = await sessions().request(await islandOf(room), `/keys/${encodeURIComponent(who)}`);
    } catch (_e) {
      return null;   // no answer is not "no key"
    }
    if (!r.ok) return null;
    b64 = String(r.body?.ed25519_public_key || '').trim();
    if (!b64) return null;
    try {
      await StorageService.setKnownEd25519(room.islandId, room.guestName, who, b64);
    } catch (_e) {
      return null;   // an unrecorded first contact would be re-decided next time
    }
  }
  let raw;
  try {
    raw = new Uint8Array(CryptoUtils.base64ToArrayBuffer(b64));
  } catch (_e) {
    return null;
  }
  if (raw.length !== 32) return null;
  _edKeyCache.set(cacheKey, raw);
  return raw;
}

/** `{ set }` of who may hand out the room's key, or `{ status }` when the island did not say. */
async function _signers(room) {
  const slot = slotOf(room);
  const hit = _signerCache.get(slot);
  if (hit && Date.now() - hit.at < _SIGNER_SET_TTL_MS) return { set: hit.set };
  let r;
  try {
    r = await sessions().request(await islandOf(room), `/rooms/${room.roomId}/members`);
  } catch (_e) {
    return { status: 0 };
  }
  if (!r.ok || !Array.isArray(r.body)) return { status: r.status || 0 };
  const set = new Set(r.body.map((m) => String(m?.username || '').toLowerCase()).filter(Boolean));
  _signerCache.set(slot, { at: Date.now(), set });
  return { set };
}

/**
 * Load a guest room's key - current and archived - under the room's own slot.
 * Loads of one room never overlap; `throttled` callers (the decrypt path) get a
 * failure from the last few seconds instead of asking again.
 */
function loadKey(room, { throttled = false } = {}) {
  const slot = slotOf(room);
  if (!slot) return Promise.resolve({ ok: false, error: true });
  const cur = _keyLoads.get(slot);
  if (cur?.promise) return cur.promise;
  if (throttled && cur?.res && Date.now() - cur.at < _KEY_RETRY_MS) return Promise.resolve(cur.res);

  const settle = (res) => {
    // A lock is not the island's answer; after unlocking, ask at once.
    if (res.ok || res.locked) _keyLoads.delete(slot);
    else _keyLoads.set(slot, { at: Date.now(), res });
    return res;
  };
  const promise = _loadKeyOnce(room, slot).then(settle, (e) => {
    console.warn('[Guest] key load failed:', e?.message || e);
    return settle({ ok: false, error: true });
  });
  _keyLoads.set(slot, { promise });
  return promise;
}

async function _loadKeyOnce(room, slot) {
  if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: false });
  if (!CryptoService.isReady()) return { ok: false, locked: true };
  const island = await islandOf(room);

  let r;
  try {
    r = await sessions().request(island, `/crypto/room-key/${room.roomId}`);
  } catch (_e) {
    return { ok: false, unreachable: true };
  }
  if (r.status === 404) return { ok: false, notFound: true };
  if (r.status === 401 || r.status === 403) return { ok: false, denied: true, status: r.status };
  if (!r.ok || !r.body?.encrypted_room_key) {
    return r.status ? { ok: false, error: true, status: r.status } : { ok: false, unreachable: true };
  }

  // Who may have wrapped it, asked once up front: "the island could not say"
  // must not be reported as "the island offered a key nobody could have given".
  const who = await _signers(room);
  if (!who.set) {
    return (who.status === 401 || who.status === 403)
      ? { ok: false, denied: true, status: who.status }
      : { ok: false, unreachable: true };
  }
  const opts = (keyId) => ({ scope: 'room', scopeId: room.roomId, keyId, rid: slot, signers: async () => who.set });
  const ctx = _ctx(room);

  const key = await CryptoService.acceptWrappedKeyIn(ctx, r.body.encrypted_room_key, opts(String(r.body.key_id || '')));
  if (!key) return { ok: false, refused: true };
  if (!await cryptoManager.loadRoomKey(slot, key)) return { ok: false, error: true };

  try {
    const a = await sessions().request(island, `/crypto/room-key/${room.roomId}/archive`);
    const entries = Array.isArray(a.body?.keys) ? a.body.keys : [];
    for (const entry of entries) {
      const enc = String(entry?.encrypted_room_key || '').trim();
      if (!enc) continue;
      const hint = String(entry?.key_id || '').trim().toLowerCase();
      if (hint && cryptoManager.roomKeyArchive.get(slot)?.has(hint)) continue;
      const old = await CryptoService.acceptWrappedKeyIn(ctx, enc, opts(hint));
      if (!old) continue;
      const kid = await CryptoUtils.fingerprintRoomKeyBase64(old);
      if (!cryptoManager.roomKeyArchive.get(slot)?.has(kid)) await cryptoManager.loadArchivedKey(slot, kid, old);
    }
  } catch (e) {
    console.warn('[Guest] archive load failed:', e?.message || e);
  }
  return { ok: true };
}

/** Encrypt and sign a message for a guest room, as our guest name there. */
async function encrypt(room, plaintext) {
  if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: false });
  if (!CryptoService.isReady()) throw new Error('Unlock first');
  const slot = slotOf(room);
  if (!cryptoManager.roomKeys.has(slot)) {
    const res = await loadKey(room);
    if (!res.ok) {
      throw new Error(res.notFound
        ? 'No key for this room yet. A moderator there has to open their client once.'
        : 'No key for this room');
    }
  }
  if (!cryptoManager.roomKeys.has(slot)) throw new Error('Room key unavailable (locked during send)');
  // Always signed: there is no history here from before signatures existed.
  const payload = JSON.stringify({
    rs: 1,
    from: room.guestName,
    body: plaintext,
    sig: CryptoService.signEd25519B64(CryptoUtils._roomSigMessage(room.roomId, room.guestName, plaintext)),
  });
  return cryptoManager.encryptMessage(slot, payload);
}

/** Decrypt a guest room message; the same answers as CryptoService.decryptMessage. */
async function decrypt(room, text, claimedAuthor = null) {
  // Not encrypted at all. At home that is history from before encryption; in
  // a room on another island it is something that island wrote under a
  // member's name, and nobody can be held to it - so it is shown as such.
  const unattributable = (t) => ({ text: String(t), from: String(claimedAuthor || ''), sigValid: false, mismatch: false });
  if (typeof text !== 'string') return unattributable(text);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (_e) {
    return unattributable(text);
  }
  if (!parsed?.encrypted || !parsed.iv || !parsed.data) return unattributable(text);
  if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: false });
  if (!CryptoService.isReady()) return null;

  const slot = slotOf(room);
  if (!cryptoManager.roomKeys.has(slot)) {
    const res = await loadKey(room, { throttled: true });
    if (!res.ok) return '[Encrypted message - key not available]';
  }
  try {
    const plain = await cryptoManager.decryptMessage(slot, text);
    return await CryptoService.openRoomEnvelopeIn(_ctx(room), room.roomId, plain, claimedAuthor);
  } catch (e) {
    console.warn('[Guest] decryption failed:', e?.message || e);
    return '[Encrypted message - decryption failed]';
  }
}

/** A page of a guest room's history, as the island stores it. */
async function history(room, { limit = 50, beforeId = null } = {}) {
  let path = `/rooms/${room.roomId}/history?limit=${encodeURIComponent(String(limit))}`;
  if (beforeId) path += `&before_id=${encodeURIComponent(String(beforeId))}`;
  const r = await sessions().request(await islandOf(room), path);
  if (!r.ok) {
    const err = new Error(`History unavailable (${r.status || 'no answer'})`);
    err.status = r.status;
    throw err;
  }
  return r.body || { messages: [] };
}

/** Leave a room on another island; "not a member" from the island is success. */
async function leave(room) {
  let r;
  try {
    r = await sessions().request(await islandOf(room), `/rooms/${room.roomId}/leave`, { method: 'POST' });
  } catch (_e) {
    r = { ok: false, status: 0 };
  }
  if (!r.ok && r.status !== 403 && r.status !== 404) {
    throw new Error(`Could not leave (${r.status || 'their server did not answer'})`);
  }
  await dropRoom(room);
  return true;
}

/**
 * The room socket on the room's island, held by the app itself: posting to a
 * room is only possible over it, so it is also what carries messages in.
 *
 * @returns {{ send(text), close(), readonly online: boolean }}
 */
function openSocket(room, { onMessage, onStatus } = {}) {
  let ws = null;
  let closed = false;
  let attempt = 0;
  let timer = null;
  let refusedOnce = false;
  const status = (s) => { try { onStatus?.(s); } catch (_e) { /* the view's problem */ } };

  const schedule = () => {
    if (closed) return;
    const delay = Math.min(30000, 1000 * (2 ** attempt)) + Math.floor(Math.random() * 500);
    attempt = Math.min(attempt + 1, 6);
    timer = setTimeout(connect, delay);
  };

  async function connect() {
    if (closed) return;
    let island;
    let s;
    try {
      island = await islandOf(room);
      s = await sessions().get(island);
    } catch (e) {
      s = { ok: false, status: 0, reason: e?.message || 'unreachable' };
    }
    if (closed) return;
    if (!s?.ok) {
      status({ online: false, error: s?.status === 403 ? 'refused' : 'unreachable' });
      if (s?.status === 403) return;   // not a guest there any more
      schedule();
      return;
    }
    const entry = (island.entryPoints || [])
      .find((e) => String(e?.apiBase || '').replace(/\/+$/, '') === s.apiBase) || { apiBase: s.apiBase };
    let sock;
    try {
      sock = _makeSocket(GR.socketUrl(entry, room.roomId));
    } catch (_e) {
      schedule();
      return;
    }
    ws = sock;
    sock.onopen = () => {
      try { sock.send(JSON.stringify({ type: 'auth', token: s.token })); } catch (_e) { /* onclose follows */ }
    };
    sock.onmessage = (ev) => {
      let m;
      try { m = JSON.parse(ev.data); } catch (_e) { return; }
      if (!m || typeof m !== 'object') return;
      if (m.type === 'presence') {
        attempt = 0;
        refusedOnce = false;
        status({ online: true });
      } else if (m.type === 'message') {
        if (Number(m.room_id) !== Number(room.roomId)) return;
        try { onMessage?.(m); } catch (e) { console.warn('[Guest] message handler failed:', e?.message || e); }
      } else if (m.type === 'error') {
        status({ online: true, error: String(m.message || 'error') });
      }
    };
    sock.onclose = (ev) => {
      if (ws === sock) ws = null;
      if (closed) return;
      status({ online: false });
      if (ev?.code === 1008) {
        // Refused: the token, or our membership. A fresh session settles the
        // first; refused again, it is the second, and we stop.
        if (refusedOnce) {
          status({ online: false, error: 'refused' });
          return;
        }
        refusedOnce = true;
        sessions().forget(room.islandId);
      }
      schedule();
    };
  }

  const keepalive = setInterval(() => {
    try { if (ws && ws.readyState === 1) ws.send('ping'); } catch (_e) { /* onclose follows */ }
  }, 25000);
  connect();

  return {
    send(text) {
      if (!ws || ws.readyState !== 1) throw new Error('Not connected to their server');
      ws.send(text);
    },
    close() {
      closed = true;
      clearTimeout(timer);
      clearInterval(keepalive);
      try { ws?.close(1000); } catch (_e) { /* already gone */ }
      ws = null;
    },
    get online() { return !!ws && ws.readyState === 1; },
  };
}

/**
 * The feed a screen draws a guest room from (guest-room-feed.js): what is
 * shown, in what order, wired to this room's island.
 */
function createFeed(room, handlers) {
  const me = String(room.guestName || '').trim().toLowerCase();
  return GRF.createFeed({
    openSocket: (h) => openSocket(room, h),
    loadKey: () => loadKey(room),
    fetchHistory: () => history(room, { limit: 100 }),
    decrypt: (ciphertext, user) => decrypt(room, ciphertext, user),
    isMe: (user) => String(user || '').trim().toLowerCase() === me,
    log: (...args) => console.warn('[Guest]', ...args),
    ...handlers,
  });
}

const GuestRoomService = {
  listRooms,
  saveRoom,
  dropRoom,
  inviteContact,
  acceptInvite,
  loadKey,
  encrypt,
  decrypt,
  history,
  leave,
  openSocket,
  createFeed,
  slotOf,
  clearCache,
  parseInvite: GR.parseInvite,
  sameRoom: GR.sameRoom,
  // Tests only: replace the socket the app would open.
  _setSocketFactory(fn) { _makeSocket = fn; },
  _resetSessions() { _sessions = null; },
};

export default GuestRoomService;
