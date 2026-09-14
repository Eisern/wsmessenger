// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ForeignService.js — direct messages with somebody on another island.
 *
 * The protocol is foreign-dm.js, which is byte-identical to the extension's
 * copy and knows nothing about either platform. This file is the Android half
 * of what the "Cross-island contacts" section of panel-crypto.js does around
 * it: where a contact lives on this device, which key goes into which slot,
 * what a refused delivery means, and how a message reaches a server this
 * client has no account on.
 *
 * The shape, restated because it is what every decision below follows from:
 * each direction is a one-way mailbox on the RECIPIENT's island, opened by the
 * recipient for one specific key. So we read only from our own island, over
 * the /ws-dm we already use, and we write to theirs by hand. A mailbox is an
 * ordinary DM thread whose only member is its owner - the read path does not
 * know this feature exists.
 *
 * See docs/internal/cross-island-dm-assessment.md for the design and its
 * threat model.
 */

import NetworkService from './NetworkService';
import StorageService from './StorageService';
import CryptoService from './CryptoService';
import EP from './endpoints';
import FD from './foreign-dm';
import IL from './island-list';
import OB from './outbox';
import { CryptoUtils, cryptoManager } from '../crypto';

const { hmac: _nobleHmac } = require('@noble/hashes/hmac');
const { sha256: _nobleSha256 } = require('@noble/hashes/sha2');

// Lazy proxy — reads globalThis.crypto at call time, not at module init time.
const crypto = {
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

const _INDEX_PREFIX = '__foreign_index:';
const _OUTBOX_PREFIX = '__foreign_outbox:';
const _ISLAND_RECHECK_MS = 6 * 60 * 60 * 1000;

// thread id -> contact, for the decrypt path: it runs per message and must not
// read storage to find out whether a thread is a cross-island one.
const _threadCache = new Map();

// ============================
// Who we are, and where
// ============================

/**
 * Who we are, for filing a contact and for signing what we send.
 *
 * Not NetworkService.username on its own: `/auth/login` answers with tokens and
 * no name, so that field stays empty for the whole first session after a fresh
 * sign-in. Contacts filed under an empty user vanish the moment the name comes
 * back, and an envelope sent with one names nobody. CryptoService resolves it
 * the same way every key path here does, falling back to the persisted active
 * user, which login writes.
 */
async function _me() {
  return CryptoService.activeUsername();
}

/**
 * The island every contact of ours is filed under.
 *
 * Waited for rather than read: a contact looked up before the stored server
 * config has been applied is looked up in the wrong drawer, comes back empty,
 * and "no cross-island contacts" is exactly the answer that sends a foreign
 * thread down the local key path.
 */
async function _island() {
  try { await NetworkService.serverConfigReady(); } catch (_e) { /* keep what we have */ }
  return EP.islandIdOf(NetworkService.getServerConfig());
}

async function _indexKey() {
  return _INDEX_PREFIX + (await _island()) + ':' + (await _me());
}

async function _contactKey(kid) {
  return FD.contactKey(await _island(), await _me(), kid);
}

// ============================
// What the protocol needs from a platform
// ============================

function _u8FromB64(s) {
  return new Uint8Array(CryptoUtils.base64ToArrayBuffer(String(s || '')));
}

function _u8FromB64url(s) {
  let b64 = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  return _u8FromB64(b64);
}

function _deps() {
  return {
    fetchJson: async (url, opts = {}) => {
      const r = await fetch(url, opts);
      let body = null;
      try { body = await r.json(); } catch (_e) { /* empty body */ }
      return { ok: r.ok, status: r.status, body };
    },
    sign: async (bytes) => CryptoService.signEd25519(bytes),
    verify: (pub, sig, msg) => CryptoUtils.ed25519Verify(pub, sig, msg),
    sha256: async (bytes) => CryptoUtils.sha256Raw(bytes),
    // quick-crypto does not do HMAC in subtle, which is why the whole client
    // signs transport tags with @noble - the same call NetworkService makes.
    hmacSha256: async (keyBytes, msgBytes) => _nobleHmac(_nobleSha256, keyBytes, msgBytes),
    randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
    // The relay answers with bytes, not JSON: the answer is sealed so the
    // relay cannot fake a delivery it did not make.
    fetchBytes: async (url, opts = {}) => {
      const r = await fetch(url, opts);
      let bytes = null;
      try { bytes = new Uint8Array(await r.arrayBuffer()); } catch (_e) { /* no body */ }
      return { ok: r.ok, status: r.status, bytes };
    },
    sealRelay: (transportKeyB64, inner) => CryptoUtils.sealRelayEnvelope(transportKeyB64, inner),
    openRelayResponse: (key, bytes) => CryptoUtils.openRelayResponse(key, bytes),
  };
}

// ============================
// Contacts on this device
// ============================

/** The thread a foreign contact's conversation is displayed under. */
function threadIdOf(contact) {
  return Number(contact?.inbox?.threadId || 0);
}

/** Every cross-island contact this account has on this island. */
async function listContacts() {
  try {
    const kids = await StorageService.get(await _indexKey());
    if (!Array.isArray(kids) || !kids.length) return [];
    const out = [];
    for (const kid of kids) {
      const c = await StorageService.get(await _contactKey(kid));
      if (!c) continue;
      out.push(c);
      _threadCache.set(threadIdOf(c), c);
    }
    return out;
  } catch (e) {
    console.warn('[Foreign] list failed:', e?.message || e);
    return [];
  }
}

async function getContact(peerKid) {
  if (!peerKid) return null;
  return (await StorageService.get(await _contactKey(peerKid))) || null;
}

async function saveContact(contact) {
  const idxKey = await _indexKey();
  const kids = (await StorageService.get(idxKey)) || [];
  const list = Array.isArray(kids) ? kids : [];
  if (!list.includes(contact.kid)) list.push(contact.kid);
  await StorageService.set(await _contactKey(contact.kid), contact);
  await StorageService.set(idxKey, list);
  _threadCache.set(threadIdOf(contact), contact);
  return contact;
}

/**
 * The cross-island contact a thread belongs to, if any.
 *
 * Warms from storage on a miss rather than trusting the cache to be populated.
 * Decryption can run before anything has listed the contacts - history arrives
 * as soon as the thread opens - and a miss there is not harmless: the verifier
 * falls back to asking THIS island for the sender's key, gets a 404 because
 * the sender has no account here, and marks an honest message unverified.
 */
async function forThread(threadId) {
  const tid = Number(threadId);
  if (!tid) return null;
  if (_threadCache.has(tid)) return _threadCache.get(tid);
  try { await listContacts(); } catch (_e) { /* stay with what we have */ }
  return _threadCache.get(tid) || null;
}

/**
 * The same lookup without the wait, for callers that cannot be async - a
 * notification arriving while the app is in the background, say. Answers only
 * from what has already been listed; `forThread` is what fills that in.
 */
function cachedForThread(threadId) {
  return _threadCache.get(Number(threadId)) || null;
}

// ============================
// Handing over a card, and taking one
// ============================

/**
 * The card this user hands to somebody on another island, out of band.
 *
 * It carries the island's signed entry points so the other side can reach this
 * island without being told where by a third party, and it is signed by this
 * user's own key, so nothing in it has to be taken on the island's word.
 */
async function buildMyCard() {
  const me = await _me();
  const myPub = cryptoManager.userPublicKeyB64;
  if (!me || !myPub) throw new Error('Unlock first');

  const kid = await CryptoUtils.fingerprintPublicKey(myPub);
  const edPub = CryptoUtils.arrayBufferToBase64(CryptoService.ed25519PublicKey());

  const cfg = NetworkService.getServerConfig();
  let islandId = await _island();
  let signingKey = '';
  let entryPoints = [{ apiBase: cfg.apiBase, wsBase: cfg.wsBase, label: '' }];
  try {
    const r = await fetch(cfg.apiBase + '/.well-known/wsapp-island');
    if (r.ok) {
      const doc = await r.json();
      if (doc?.payload?.island_id) {
        islandId = doc.payload.island_id;
        signingKey = doc.signing_key_b64 || '';
        if (Array.isArray(doc.payload.entry_points) && doc.payload.entry_points.length) {
          entryPoints = doc.payload.entry_points;
        }
      }
    }
  } catch (_e) {
    // An island that publishes no list still works: the card then carries the
    // address this client is actually using, which is what the peer needs.
  }

  const blob = await FD.buildContactBlob(
    { kid, x25519PubB64: myPub, ed25519PubB64: edPub, displayName: me },
    { islandId, signingKeyB64: signingKey, entryPoints },
    _deps().sign,
  );
  return JSON.stringify(blob);
}

/**
 * Take somebody's card, open a mailbox for them here, and pin their keys.
 *
 * Opening the mailbox IS the consent: until this runs, nothing on this island
 * will accept a message addressed to this user from that key.
 */
async function addContact(cardText) {
  const me = await _me();
  if (!me) throw new Error('Not logged in');
  if (!CryptoService.isReady()) {
    await CryptoService.ensureReady({ interactive: true, reason: 'Add contact' });
  }
  if (!CryptoService.isReady()) throw new Error('Unlock first');

  let blob;
  try {
    blob = JSON.parse(String(cardText || '').trim());
  } catch (_e) {
    throw new Error('That does not look like a contact card');
  }

  const seen = await FD.verifyContactBlob(blob, _deps());
  if (!seen.ok) throw new Error(`Card rejected: ${seen.reason}`);
  const c = seen.contact;

  const myPub = cryptoManager.userPublicKeyB64;
  if (c.kid === await CryptoUtils.fingerprintPublicKey(myPub)) {
    throw new Error('That is your own card');
  }

  // The key their messages to us will be encrypted with. We generate it
  // because we own the mailbox; they receive it when they claim.
  const keyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  const keyId = await CryptoUtils.fingerprintRoomKeyBase64(keyB64);

  const created = await NetworkService.createForeignBox({
    peerKid: c.kid,
    peerX25519Pub: c.x25519PubB64,
    peerEd25519Pub: c.ed25519PubB64,
    label: c.displayName,
    encryptedThreadKey: await CryptoUtils.encryptRoomKeyForUser(myPub, keyB64),
    keyId,
  });
  const threadId = Number(created?.thread_id);
  if (!threadId) throw new Error('The server did not open a mailbox');

  await NetworkService.putForeignPeerKey(threadId, {
    peerKid: c.kid,
    peerX25519Pub: c.x25519PubB64,
    peerEd25519Pub: c.ed25519PubB64,
    encryptedThreadKey: await CryptoUtils.encryptRoomKeyForUser(c.x25519PubB64, keyB64),
    keyId,
  });

  // Their keys are pinned by the contact record itself, and nothing else on
  // this device may answer "who is this" for them: the card bound both keys to
  // one kid, which is strictly stronger than anything a key server could say -
  // and neither island can be asked about a person who has no account there.
  const contact = {
    v: 1,
    kid: c.kid,
    displayName: c.displayName || c.kid.slice(0, 8),
    x25519PubB64: c.x25519PubB64,
    ed25519PubB64: c.ed25519PubB64,
    island: { islandId: c.islandId, signingKeyB64: c.islandSigningKeyB64, entryPoints: c.entryPoints },
    inbox: { threadId, keyB64, keyId },
    outbox: null,
    addedAt: Date.now(),
  };
  await saveContact(contact);

  // Their mailbox may not exist yet - they add us in their own time - so a
  // failure here is normal and retried whenever the conversation is opened.
  try {
    await claimOutbox(contact);
  } catch (e) {
    console.log('[Foreign] outbox not claimable yet:', e?.message || e);
  }
  return await getContact(c.kid);
}

/**
 * Forget a contact and close the mailbox their messages arrive in.
 *
 * Closing the mailbox is what actually stops them: the delivery secret they
 * hold opens nothing once the box is gone.
 */
async function removeContact(peerKid) {
  const contact = await getContact(peerKid);
  if (!contact) return false;

  const tid = threadIdOf(contact);
  if (tid) {
    try {
      await NetworkService.deleteForeignBox(tid);
    } catch (e) {
      // A mailbox already gone is the state we wanted; anything else is a real
      // failure and must not leave the local half pointing at a live box.
      if (e?.status !== 404) throw new Error(`Could not close the mailbox (${e?.status || e?.message})`);
    }
  }

  const idxKey = await _indexKey();
  const kids = (await StorageService.get(idxKey)) || [];
  await StorageService.set(
    idxKey,
    (Array.isArray(kids) ? kids : []).filter((k) => k !== peerKid),
  );
  await StorageService.remove(await _contactKey(peerKid));
  _threadCache.delete(tid);
  return true;
}

// ============================
// The mailbox they opened for us
// ============================

/**
 * Collect the address, delivery secret and thread key of the mailbox this
 * contact opened for us on their island.
 */
async function claimOutbox(contact, { retried = false } = {}) {
  const myKid = await CryptoUtils.fingerprintPublicKey(cryptoManager.userPublicKeyB64);
  const bases = (contact.island?.entryPoints || []).map((e) => e.apiBase).filter(Boolean);
  if (!bases.length) throw new Error('Contact card carries no address');

  let last = null;
  for (const base of bases) {
    // An address that cannot be reached at all - dead host, wrong scheme,
    // no route - throws rather than answering. Letting that escape would
    // abandon the remaining entry points, which is the whole reason a card
    // carries more than one.
    let r;
    try {
      r = await FD.claimMailbox(_deps(), base, myKid);
    } catch (e) {
      console.warn(`[Foreign] ${base} unreachable:`, e?.message || e);
      last = { status: 0 };
      continue;
    }
    if (r.ok) {
      let keyB64 = null;
      if (r.encryptedThreadKey) {
        try {
          keyB64 = await CryptoUtils.decryptRoomKeyForUser(
            cryptoManager.userPrivateKey, r.encryptedThreadKey,
          );
        } catch (e) {
          console.warn('[Foreign] their key did not unwrap:', e?.message || e);
        }
      }
      return await saveContact({
        ...contact,
        lastClaim: null,
        outbox: {
          apiBase: base,
          threadId: r.threadId,
          secretB64: r.deliverySecretB64,
          expiresAt: r.expiresAt,
          keyB64,
          keyId: r.keyId,
        },
      });
    }
    last = r;
    // 403 is the island's single answer to every refusal, including "no
    // mailbox here yet". Trying the next entry point is still worth it: this
    // one may simply be unreachable.
  }

  // Every address we know either refused us or did not answer. Before calling
  // it a failure, ask their island for its current list - that is the case the
  // signed list exists for, and the pin from their card is what makes the
  // answer safe to believe.
  if (!retried) {
    const moved = await refreshIsland(contact, { force: true }).catch(() => ({ ok: false }));
    if (moved.ok && moved.changed) {
      const fresh = await getContact(contact.kid);
      if (fresh) return await claimOutbox(fresh, { retried: true });
    }
  }

  // Remember why, so the list can say which of the two it was. They need
  // different things from the user - wait for the other person, or go and fix
  // the address - and one line for both says neither.
  const failure = {
    at: Date.now(),
    status: last?.status ?? null,
    kind: (last?.status === 403) ? 'not-added-yet'
      : (last?.status === 0 || last?.status == null) ? 'unreachable'
        : 'refused',
  };
  try { await saveContact({ ...contact, lastClaim: failure }); } catch (_e) { /* best effort */ }
  throw new Error(
    failure.kind === 'not-added-yet'
      ? 'They have not added your card yet'
      : `Could not reach their server (${last?.status || 'no answer'})`,
  );
}

/**
 * Put both directions' keys where decryption will find them.
 *
 * The conversation holds ciphertext under two keys - theirs for what they
 * wrote, ours for the copies we kept - and every message names the key it used,
 * so both simply go into the same slot's archive.
 *
 * Called once per message on the decrypt path, so it returns without doing
 * anything when there is nothing to do. Nothing is persisted: the contact
 * record already holds both keys, and it is what this reloads them from.
 */
async function ensureKeysReady(contact) {
  if (!contact) return;
  _threadCache.set(threadIdOf(contact), contact);
  const rid = CryptoService._dmRid(threadIdOf(contact));

  const archive = cryptoManager.roomKeyArchive?.get(rid);
  const inboxKid = contact.inbox?.keyId;
  const outboxKid = contact.outbox?.keyId;
  const haveInbox = !inboxKid || !!archive?.has(inboxKid);
  const haveOutbox = !outboxKid || !!archive?.has(outboxKid);
  if (cryptoManager.roomKeys?.has(rid) && haveInbox && haveOutbox) return;

  if (contact.inbox?.keyB64) {
    if (!cryptoManager.roomKeys?.has(rid)) {
      await cryptoManager.loadRoomKey(rid, contact.inbox.keyB64);
    }
    if (inboxKid && !cryptoManager.roomKeyArchive?.get(rid)?.has(inboxKid)) {
      await cryptoManager.loadArchivedKey(rid, inboxKid, contact.inbox.keyB64);
    }
  }
  if (contact.outbox?.keyB64 && outboxKid
      && !cryptoManager.roomKeyArchive?.get(rid)?.has(outboxKid)) {
    await cryptoManager.loadArchivedKey(rid, outboxKid, contact.outbox.keyB64);
  }
}

// ============================
// Sending
// ============================

/**
 * Encrypt for a cross-island contact and deliver it twice: to their island,
 * which is where they will read it, and to ours, so our own outgoing messages
 * survive a reinstall. Both copies are the same ciphertext under their
 * mailbox's key.
 *
 * @returns {Promise<{ok:boolean, queued?:boolean, ciphertext:string}>}
 */
async function sendMessage(contact, plaintext) {
  let c = contact;
  if (!c.outbox || !c.outbox.keyB64) c = await claimOutbox(c);
  if (!c.outbox?.keyB64) throw new Error('No key for this contact yet');

  const me = await _me();
  if (!me) throw new Error('Not signed in');
  const envelope = { ss: 1, from: me, body: plaintext };
  // v1 signature deliberately: the chain is not written yet on either client
  // (CHAIN_WRITE_ENABLED), and a v2 signature would be rejected outright by a
  // reader that only knows v1 - a forgery warning on an honest message.
  envelope.sig = CryptoService.signEd25519B64(
    CryptoUtils._dmSigMessage(c.outbox.threadId, me, plaintext),
  );

  // Built by hand rather than through cryptoManager.encryptMessage, because
  // that encrypts with the key in the slot - the inbox key - and this has to go
  // out under the mailbox key of the island it is addressed to. The shape must
  // match the manager's byte for byte: `encrypted: true` is what the receiving
  // client keys on, and the kid is bound as AAD, so a message cannot be
  // re-labelled with another key's id.
  const key = await CryptoUtils.importRoomKey(c.outbox.keyB64);
  const kid = c.outbox.keyId || await CryptoUtils.fingerprintRoomKeyBase64(c.outbox.keyB64);
  const aad = new TextEncoder().encode(String(kid));
  const enc = await CryptoUtils.encryptMessage(key, JSON.stringify(envelope), aad);
  const ciphertext = JSON.stringify({
    encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true,
  });

  const box = () => ({
    apiBase: c.outbox.apiBase,
    threadId: c.outbox.threadId,
    secretB64: c.outbox.secretB64,
  });

  let res;
  try {
    res = c.useRelay
      ? await deliverViaRelay(c, box(), ciphertext)
      : await FD.deliver(_deps(), box(), ciphertext);
  } catch (e) {
    // Their island did not answer at all. Nothing about this message is wrong,
    // so it goes in the queue rather than being announced as a failure.
    res = { ok: false, status: 0, nonceB64: null, transport: e?.message || 'unreachable' };
  }

  // A delivery secret lasts a day. An expired one is refused with the same
  // 403 as everything else, so re-claim once before believing it.
  if (!res.ok && (res.status === 403 || res.status === 401)) {
    try {
      c = await claimOutbox(c);
      res = await FD.deliver(_deps(), box(), ciphertext);
    } catch (_e) { /* fall through to the queue */ }
  }

  // Our own copy goes to our own island either way: if that is unreachable,
  // the user is looking at a client that cannot do anything at all, which is
  // the case the queue is explicitly NOT for.
  await _keepOwnCopy(c, ciphertext);

  if (res.ok) {
    // A successful send is also the best moment to try whatever is waiting:
    // their island is evidently up.
    drainOutbox().catch(() => {});
    return { ok: true, ciphertext };
  }

  const ob = _outbox();
  if (ob && (res.status === 0 || res.status === 429 || res.status >= 500)) {
    await ob.enqueue({
      threadId: c.outbox.threadId,
      // The envelope as it goes on the wire. deliver() encodes it; the field
      // name is the queue's, and it never looks inside.
      ciphertextB64: ciphertext,
      nonceB64: res.nonceB64 || FD._b64url(_deps().randomBytes(16)),
      meta: { kid: c.kid },
    });
    return { ok: false, queued: true, ciphertext };
  }

  throw new Error(`Delivery refused (${res.status})`);
}

/**
 * Keep our own half of the conversation on our own island.
 *
 * The mailbox is an ordinary thread we are the only member of, so this is the
 * ordinary sealed-sender send - the ciphertext is the one that went abroad,
 * which is what makes both halves decrypt from one archive.
 */
async function _keepOwnCopy(contact, ciphertext) {
  const tid = threadIdOf(contact);
  if (!tid) return false;
  try {
    const secret = await NetworkService.getDeliverySecret(tid, null, { openThread: false });
    await NetworkService.sendDmUd(tid, ciphertext, secret);
    return true;
  } catch (e) {
    // The socket is the fallback rather than the primary: it only exists while
    // the conversation is open, and this runs from the send path either way.
    if (NetworkService.sendDmViaWs(tid, ciphertext)) return true;
    console.warn('[Foreign] own copy not stored:', e?.message || e);
    return false;
  }
}

// ============================
// The queue of what could not be delivered
// ============================

let _foreignOutbox = null;
let _outboxKeyCache = null;

function _outbox() {
  if (_foreignOutbox) return _foreignOutbox;
  _foreignOutbox = OB.createOutbox({
    storage: {
      load: async () => {
        const key = await _outboxKey();
        const got = await StorageService.get(key);
        return Array.isArray(got) ? got : [];
      },
      save: async (items) => { await StorageService.set(await _outboxKey(), items); },
    },
    now: () => Date.now(),
    log: (msg, data) => console.log('[Outbox]', msg, data || ''),
  });
  return _foreignOutbox;
}

async function _outboxKey() {
  if (_outboxKeyCache) return _outboxKeyCache;
  _outboxKeyCache = _OUTBOX_PREFIX + (await _island()) + ':' + (await _me());
  return _outboxKeyCache;
}

/**
 * Try every queued message that is due.
 *
 * The nonce is the item's, never a fresh one: the island de-duplicates on
 * (thread_id, nonce), which is what makes repeating a message that already
 * arrived answer 409 instead of delivering it twice.
 */
async function drainOutbox() {
  const ob = _outbox();
  if (!ob) return null;
  try {
    return await ob.drain(async (item) => {
      const kid = item?.meta?.kid;
      const contact = kid ? await getContact(kid) : null;
      if (!contact) return { status: 400 };          // the contact is gone; drop it

      let c = contact;
      if (!c.outbox?.secretB64 || item.secretRefreshed) {
        try { c = await claimOutbox(c); } catch (_e) { return { status: 0 }; }
      }
      if (!c.outbox?.secretB64) return { status: 0 };

      try {
        return await FD.deliver(
          _deps(),
          { apiBase: c.outbox.apiBase, threadId: c.outbox.threadId, secretB64: c.outbox.secretB64 },
          item.ciphertextB64,
          { nonce: _u8FromB64url(item.nonceB64) },
        );
      } catch (e) {
        // Unreachable rather than refused: keep it and back off.
        return { name: e?.name || 'TypeError' };
      }
    });
  } catch (e) {
    console.warn('[Outbox] drain failed:', e?.message || e);
    return null;
  }
}

/** How many messages are still waiting, for the UI. */
async function outboxSize() {
  const ob = _outbox();
  if (!ob) return 0;
  try { return await ob.size(); } catch (_e) { return 0; }
}

// ============================
// Keeping a contact's island reachable
// ============================
//
// A card freezes the addresses of the other island at the moment it was handed
// over. Islands move: a domain changes, a bridge is added, the one address in
// the card stops answering - and the contact would then be lost for good, with
// no way back except meeting again in person.
//
// The card carries the island's signing key precisely so that need not happen.
// The island publishes a signed list of its own entry points; the key pinned
// from the card says whether a list we are handed is really theirs.

function _verifier() {
  return IL.createIslandListVerifier({
    ed25519Verify: (pub, sig, msg) => CryptoUtils.ed25519Verify(pub, sig, msg),
    b64decode: (s) => _u8FromB64url(s),
    utf8Encode: (s) => new TextEncoder().encode(s),
    now: () => Date.now(),
  });
}

/**
 * Ask a contact's island where it lives now, and believe the answer only if it
 * is signed by the key their card pinned.
 *
 * @param {object} contact
 * @param {object} [opts] { force } - skip the recheck interval
 * @returns {Promise<{ok:boolean, reason?:string, changed?:boolean}>}
 */
async function refreshIsland(contact, { force = false } = {}) {
  const verifier = _verifier();
  if (!verifier) return { ok: false, reason: 'verifier unavailable' };

  const last = Number(contact.island?.lastCheckedAt || 0);
  if (!force && last && Date.now() - last < _ISLAND_RECHECK_MS) {
    return { ok: true, reason: 'checked recently', changed: false };
  }

  // The pin starts as what the card said. `version: 0` because the card does
  // not carry one - the first list we verify sets the floor for every later
  // one, and the verifier refuses anything older afterwards.
  const pin = contact.island?.pin || {
    signingKeyB64: contact.island?.signingKeyB64 || '',
    islandId: contact.island?.islandId || '',
    version: 0,
  };
  if (!pin.signingKeyB64) return { ok: false, reason: 'card carried no signing key' };

  const bases = [];
  if (contact.outbox?.apiBase) bases.push(contact.outbox.apiBase);
  for (const e of contact.island?.entryPoints || []) {
    if (e.apiBase && !bases.includes(e.apiBase)) bases.push(e.apiBase);
  }

  let lastReason = 'unreachable';
  for (const base of bases) {
    let doc;
    try {
      const r = await fetch(String(base).replace(/\/+$/, '') + '/.well-known/wsapp-island');
      if (!r.ok) { lastReason = `http ${r.status}`; continue; }
      doc = await r.json();
    } catch (_e) {
      lastReason = 'unreachable';
      continue;
    }

    const res = await verifier.verify(doc, pin);
    if (!res.ok) {
      // Signed by the wrong key, or a replay of an older list. Not a network
      // problem and not something to shop around for at the next address: an
      // island that answers with somebody else's signature is exactly what the
      // pin exists to catch.
      console.warn(`[Foreign] ${base} served a list we cannot trust: ${res.reason}`);
      lastReason = res.reason;
      if (res.reason === 'bad signature' || res.reason === 'different island' || res.reason === 'rollback') {
        return { ok: false, reason: res.reason };
      }
      continue;
    }

    const fresh = res.payload.entryPoints.map((e) => ({
      apiBase: e.apiBase, wsBase: e.wsBase || '', label: e.label || '',
    }));
    const before = (contact.island?.entryPoints || []).map((e) => e.apiBase).join('|');
    const after = fresh.map((e) => e.apiBase).join('|');

    const updated = {
      ...contact,
      island: {
        ...contact.island,
        entryPoints: fresh,
        relays: res.payload.relays || [],
        // Only ever from the signed list: whoever substitutes that key reads
        // the metadata of every envelope sent through a relay.
        transportKeys: res.payload.transportKeys || [],
        pin: res.pin,
        lastCheckedAt: Date.now(),
      },
    };

    // If the address we have been delivering to is gone from their own list,
    // move to one that is there. The delivery secret is per mailbox, not per
    // address, so nothing else has to change.
    if (updated.outbox?.apiBase && !fresh.some((e) => e.apiBase === updated.outbox.apiBase)) {
      updated.outbox = { ...updated.outbox, apiBase: fresh[0].apiBase };
    }

    await saveContact(updated);
    if (before !== after) {
      console.log(`[Foreign] ${contact.displayName}: island now reachable at ${after}`);
    }
    return { ok: true, changed: before !== after };
  }

  return { ok: false, reason: lastReason };
}

/**
 * Send one message through one of the contact's island's relays.
 *
 * Direct delivery tells the recipient's island the sender's address and the
 * time they typed - to a server the sender does not trust and has no account
 * with. That is the metadata leak this design accepts by default, and the
 * relay is what closes it; the choice is per contact and made by the user,
 * because it is a trade against reliability, not a free win.
 *
 * Falls back to nothing: if the relays fail, the caller queues the message. A
 * silent fallback to direct delivery would hand over the address the user
 * asked to withhold.
 */
async function deliverViaRelay(contact, box, ciphertext, opts) {
  const relays = contact.island?.relays || [];
  const key = (contact.island?.transportKeys || [])[0]?.publicKeyB64;
  if (!relays.length || !key) {
    // Their island publishes no relay, or we have not verified its list yet.
    // Saying so beats quietly sending the thing the user asked not to send.
    throw new Error('No relay is available for this contact yet');
  }

  let last = { ok: false, status: 0 };
  for (const relay of relays) {
    last = await FD.deliverThroughRelay(
      _deps(),
      { url: relay.url, islandId: contact.island.islandId, transportKeyB64: key },
      box,
      ciphertext,
      opts,
    );
    // A relay that failed us says nothing about the island; try the next one.
    // An answer FROM the island - even a refusal - is final.
    if (!last.relayFailed) return last;
    console.warn(`[Foreign] relay ${relay.id} did not carry it (${last.status})`);
  }
  return last;
}

/**
 * Turn relaying on or off for one contact.
 *
 * Asking their island for its current list first when turning it on: the list
 * is re-read on a six-hour timer, so a relay added since the last read would
 * not show up until it expired, and the client would report that their server
 * lists none while it does.
 */
async function setUseRelay(contact, on) {
  let current = contact;
  if (on && !(current.island?.relays || []).length) {
    try {
      await refreshIsland(contact, { force: true });
      current = (await getContact(contact.kid)) || contact;
    } catch (_e) { /* fall through to the answer below */ }
    if (!(current.island?.relays || []).length) {
      throw new Error('Their server does not list a relay, so there is nothing to send through yet');
    }
  }
  return await saveContact({ ...current, useRelay: !!on });
}

/**
 * The safety number for a cross-island contact.
 *
 * v2 - keyed by the two X25519 keys ordered by kid, with no usernames in it at
 * all, because a name means nothing across the border and two people may share
 * one. Neither island is asked anything: their key came from the card, which
 * is exactly what this number confirms.
 */
async function safetyNumber(contact) {
  const myPub = cryptoManager.userPublicKeyB64;
  if (!myPub) throw new Error('Own public key not available (locked?)');
  return {
    safetyNumber: await CryptoUtils.computeSafetyNumberV2(myPub, contact.x25519PubB64),
    peerFingerprint: contact.kid,
    v2: true,
  };
}

/** Forget every cached contact — called on logout, when `me` stops meaning us. */
function clearCache() {
  _threadCache.clear();
  _foreignOutbox = null;
  _outboxKeyCache = null;
}

const ForeignService = {
  listContacts,
  getContact,
  saveContact,
  removeContact,
  threadIdOf,
  forThread,
  cachedForThread,
  buildMyCard,
  addContact,
  claimOutbox,
  ensureKeysReady,
  sendMessage,
  drainOutbox,
  outboxSize,
  refreshIsland,
  setUseRelay,
  safetyNumber,
  clearCache,
};

export default ForeignService;
