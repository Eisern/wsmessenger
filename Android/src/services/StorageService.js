// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * StorageService.js — замена chrome.storage.local / chrome.storage.session
 *
 * Маппинг:
 *   Чувствительные данные (tokens, passwords, keys) → react-native-keychain (Android Keystore)
 *   Обычные данные (история, кэш, метаданные)       → AsyncStorage
 *   Сессионные данные (token runtime, KEK)           → in-memory Map (в NetworkService)
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';

// ============================
// Helpers
// ============================

// react-native-keychain uses 'service' as the key namespace.
// We store JSON as the password field with a fixed username.
const KC_USER = 'wsapp';

// Per-user identity slot (mirrors extension LOCAL_IDENTITY_PREFIX = "e2ee_local_identity_v2:")
const _IDENTITY_PREFIX = 'identity_v2_';
const _ACTIVE_USER_KEY = 'active_user_v2';
const _PENDING_MNEMONIC_KEY = 'pending_mnemonic_v1';

function _normUser(u) {
  return String(u || '').trim().toLowerCase();
}

function _safeKey(k) {
  return `com.wsmessenger.${String(k).replace(/[^A-Za-z0-9._-]/g, '_')}`;
}

async function _secureGet(key) {
  try {
    const creds = await Keychain.getGenericPassword({ service: _safeKey(key) });
    if (!creds) return null;
    try { return JSON.parse(creds.password); } catch (_e) { return creds.password; }
  } catch (e) {
    console.warn('[StorageService] Keychain.get error:', e?.message);
    return null;
  }
}

async function _secureSet(key, value) {
  try {
    await Keychain.setGenericPassword(KC_USER, JSON.stringify(value), {
      service: _safeKey(key),
      // Prefer hardware-backed Android Keystore; falls back to software if unavailable
      securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
      accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  } catch (e) {
    // Retry without hardware requirement (some emulators / old devices lack TEE)
    try {
      await Keychain.setGenericPassword(KC_USER, JSON.stringify(value), {
        service: _safeKey(key),
        securityLevel: Keychain.SECURITY_LEVEL.SECURE_SOFTWARE,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      });
    } catch (e2) {
      console.warn('[StorageService] Keychain.set error:', e2?.message);
    }
  }
}

async function _secureRemove(key) {
  try {
    await Keychain.resetGenericPassword({ service: _safeKey(key) });
  } catch (e) {
    console.warn('[StorageService] Keychain.remove error:', e?.message);
  }
}

async function _asyncGet(key) {
  try {
    const raw = await AsyncStorage.getItem(key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (_e) { return raw; }
  } catch (e) {
    console.warn('[StorageService] AsyncStorage.get error:', key, e?.message);
    return null;
  }
}

async function _asyncSet(key, value) {
  try {
    await AsyncStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    console.warn('[StorageService] AsyncStorage.set error:', key, e?.message);
  }
}

async function _asyncRemove(key) {
  try {
    await AsyncStorage.removeItem(key);
  } catch (e) {
    console.warn('[StorageService] AsyncStorage.remove error:', key, e?.message);
  }
}

// Pin keys: `fp2_{island}_{me}_{peer}` with `_verified` / `_changed` suffixes.
// The v1 shape carried no island — see migrateFingerprintPins below.
const _FP_PREFIX = 'fp2_';
const _FP_PREFIX_V1 = 'fp_';
const _FP_INDEX_KEY = '_fp_index';

function _fpBase(island, me, peer) {
  return `${_FP_PREFIX}${String(island).toLowerCase()}_${String(me).toLowerCase()}_${String(peer).toLowerCase()}`;
}

/**
 * Track fingerprint Keychain keys in Keychain (not AsyncStorage) for clearAll() enumeration.
 * Prevents metadata leakage: peer list is NOT stored in unencrypted AsyncStorage.
 */
async function _addToFpIndex(fpKey) {
  try {
    const idx = (await _secureGet(_FP_INDEX_KEY)) || [];
    if (!idx.includes(fpKey)) {
      idx.push(fpKey);
      await _secureSet(_FP_INDEX_KEY, idx);
    }
  } catch (_e) { /* best-effort */ }
}

// ============================
// History encryption helpers
// ============================

// Room/DM history is AES-256-GCM encrypted before persisting to AsyncStorage.
// Each key version has a unique `kid` (8 hex chars from random bytes).
// The keyring (all versions) is stored in Keychain; each encrypted record
// references its kid so decryption uses the correct key even after rotation.
//
// Keychain entry: 'history_keyring' → { current: kid, keys: { kid: b64, ... } }

const _HISTORY_KEYRING_ID = 'history_keyring';

let _keyringCache = null; // in-memory cache to avoid repeated Keychain reads

function _u8ToBase64(u8) {
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

function _base64ToU8(b64) {
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function _generateKid() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16)); // 128-bit entropy
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

let _keyringInitPromise = null;

async function _getKeyring() {
  if (_keyringCache) return _keyringCache;
  // Mutex: prevent concurrent keyring creation from generating duplicate keys
  if (_keyringInitPromise) {
    await _keyringInitPromise;
    return _keyringCache;
  }
  _keyringInitPromise = _initKeyring();
  try {
    await _keyringInitPromise;
  } finally {
    _keyringInitPromise = null;
  }
  return _keyringCache;
}

async function _initKeyring() {
  // Re-check after acquiring "lock" — another caller may have populated the cache
  if (_keyringCache) return;
  const stored = await _secureGet(_HISTORY_KEYRING_ID);
  if (stored && stored.current && stored.keys && stored.keys[stored.current]) {
    _keyringCache = stored;
    return;
  }
  // First use or corrupted — create new keyring
  const kid = _generateKid();
  const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const b64 = _u8ToBase64(raw);
  raw.fill(0);
  const keyring = { current: kid, keys: { [kid]: b64 } };
  await _secureSet(_HISTORY_KEYRING_ID, keyring);
  _keyringCache = keyring;
}

/** Get the current key (for encryption). Returns { kid, b64 }. */
async function _getCurrentHistoryKey() {
  const kr = await _getKeyring();
  return { kid: kr.current, b64: kr.keys[kr.current] };
}

/** Get a key by kid (for decryption). Returns b64 or null. */
async function _getHistoryKeyByKid(kid) {
  const kr = await _getKeyring();
  return kr.keys[kid] || null;
}

async function _encryptHistory(plainJson) {
  try {
    const { kid, b64: keyB64 } = await _getCurrentHistoryKey();
    const keyBytes = _base64ToU8(keyB64);
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt'],
    );
    keyBytes.fill(0);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const plainBytes = new TextEncoder().encode(JSON.stringify(plainJson));
    const ciphertext = await globalThis.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, cryptoKey, plainBytes,
    );
    return {
      _enc: 1,
      kid,
      iv: _u8ToBase64(iv),
      ct: _u8ToBase64(new Uint8Array(ciphertext)),
    };
  } catch (e) {
    // NEVER fall back to plaintext — if encryption fails, refuse to store
    console.error('[StorageService] history encryption failed — refusing plaintext storage:', e?.message);
    throw new Error('History encryption failed; refusing to store plaintext');
  }
}

async function _decryptHistory(stored) {
  if (!stored || !stored._enc) return stored; // not encrypted (legacy)
  try {
    // Determine which key to use
    const kid = stored.kid;
    let keyB64;
    if (kid) {
      keyB64 = await _getHistoryKeyByKid(kid);
      if (!keyB64) {
        // Key not in keyring — might have been created before keyring migration
        // Try current key as fallback (covers _enc:1 without kid from first implementation)
        const current = await _getCurrentHistoryKey();
        keyB64 = current.b64;
      }
    } else {
      // No kid field — encrypted with the pre-keyring single key.
      // Try migrating: read old 'history_enc_key' if it exists, else use current.
      const legacyKey = await _secureGet('history_enc_key');
      if (legacyKey) {
        keyB64 = legacyKey;
      } else {
        const current = await _getCurrentHistoryKey();
        keyB64 = current.b64;
      }
    }

    const keyBytes = _base64ToU8(keyB64);
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt'],
    );
    keyBytes.fill(0);
    const iv = _base64ToU8(stored.iv);
    const ct = _base64ToU8(stored.ct);
    const plainBuf = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv }, cryptoKey, ct,
    );
    return JSON.parse(new TextDecoder().decode(plainBuf));
  } catch (_e) {
    // Decryption failed — key lost or data corrupt; return empty
    return [];
  }
}

// ============================
// StorageService
// ============================

const StorageService = {

  // --- Generic AsyncStorage access ---

  async get(key) { return _asyncGet(key); },
  async set(key, value) { return _asyncSet(key, value); },
  async remove(key) { return _asyncRemove(key); },

  // --- Auth (SecureStore) ← chrome.storage.session "auth" ---

  async getAuth() {
    return _secureGet('auth');
    // { username, token, refreshToken }
  },

  async setAuth({ username, token, refreshToken }) {
    await _secureSet('auth', { username, token, refreshToken });
  },

  async removeAuth() {
    await _secureRemove('auth');
  },

  // --- E2EE Identity (SecureStore) — per-username slot ---
  // Mirrors Chrome Extension login.js: LOCAL_IDENTITY_PREFIX + normUser(username).
  // Each user has their own Keychain entry so registering a second account on
  // the same device does NOT overwrite the first account's EPK.

  // Lazy migration from legacy single-slot 'identity_v1' happens on first
  // getIdentity(username) call: we attribute the legacy blob only if its
  // embedded username matches (or is missing — very old containers).

  async getIdentity(username) {
    const u = _normUser(username);
    if (!u) return null;
    const perUser = await _secureGet(_IDENTITY_PREFIX + u);
    if (perUser) return perUser;

    const legacy = await _secureGet('identity_v1');
    if (!legacy) return null;
    const legacyUser = _normUser(
      legacy?.username || legacy?.encrypted_private_key?.username || ''
    );
    if (legacyUser && legacyUser !== u) return null;
    await _secureSet(_IDENTITY_PREFIX + u, { ...legacy, username: u });
    await _secureRemove('identity_v1');
    return { ...legacy, username: u };
  },

  async setIdentity(username, identity) {
    const u = _normUser(username);
    if (!u) throw new Error('setIdentity: username required');
    await _secureSet(_IDENTITY_PREFIX + u, { ...identity, username: u });
  },

  async removeIdentity(username) {
    const u = _normUser(username);
    if (!u) return;
    await _secureRemove(_IDENTITY_PREFIX + u);
  },

  // --- Active username pointer (SecureStore) ---
  // Survives app restart; lets CryptoService resolve username when
  // NetworkService hasn't restored auth yet (cold start auto-unlock path).

  async getActiveUsername() {
    const v = await _secureGet(_ACTIVE_USER_KEY);
    return _normUser(typeof v === 'string' ? v : v?.username || '') || null;
  },

  async setActiveUsername(username) {
    const u = _normUser(username);
    if (!u) return;
    await _secureSet(_ACTIVE_USER_KEY, u);
  },

  async clearActiveUsername() {
    await _secureRemove(_ACTIVE_USER_KEY);
  },

  // --- Pending recovery-phrase acknowledgement ---
  // Set right after a successful registration, BEFORE showing the mnemonic
  // modal. Cleared only when the user confirms "I have saved my phrase".
  // If the app crashes between register and ack, the next unlock surfaces
  // the modal again (mnemonic re-derived from the in-memory raw private key).

  async getPendingMnemonicAck() {
    const v = await _secureGet(_PENDING_MNEMONIC_KEY);
    if (!v) return null;
    const u = _normUser(typeof v === 'string' ? v : v?.username || '');
    return u ? { username: u } : null;
  },

  async setPendingMnemonicAck(username) {
    const u = _normUser(username);
    if (!u) return;
    await _secureSet(_PENDING_MNEMONIC_KEY, { username: u, ts: Date.now() });
  },

  async clearPendingMnemonicAck() {
    await _secureRemove(_PENDING_MNEMONIC_KEY);
  },

  // --- Cached private key (Keychain) — for auto-unlock on app restart ---

  async getCachedPrivKey() {
    return _secureGet('cached_priv');
  },

  async setCachedPrivKey(data) {
    await _secureSet('cached_priv', data);
  },

  async removeCachedPrivKey() {
    await _secureRemove('cached_priv');
  },

  // --- Last connection (AsyncStorage) ← chrome.storage.local "conn" ---

  async getLastConn() {
    return _asyncGet('conn');
    // { room, roomName }
  },

  async setLastConn(conn) {
    await _asyncSet('conn', conn);
  },

  async removeLastConn() {
    await _asyncRemove('conn');
  },

  // --- Last DM thread (AsyncStorage) — for auto-reconnect DM WS on app start ---

  async getLastDm() {
    return _asyncGet('lastDm');
    // { threadId, peer }
  },

  async setLastDm(dm) {
    await _asyncSet('lastDm', dm);
  },

  // --- Room message history (AsyncStorage, AES-GCM encrypted) ---

  async getRoomHistory(roomId) {
    const stored = await _asyncGet(`room_history_${roomId}`);
    if (!stored) return [];
    return _decryptHistory(stored);
  },

  async setRoomHistory(roomId, messages) {
    const encrypted = await _encryptHistory(messages);
    await _asyncSet(`room_history_${roomId}`, encrypted);
  },

  // --- Room key archive (Keychain) — contains raw AES-256 keys, must be encrypted at rest ---

  async getRoomKeyArchive(roomId) {
    return (await _secureGet(`rka_${roomId}`)) || [];
    // [{ kid, b64 }]
  },

  async setRoomKeyArchive(roomId, entries) {
    await _secureSet(`rka_${roomId}`, entries);
  },

  // --- Known peer fingerprints (Keychain) — TOFU integrity requires tamper-resistant storage ---
  //
  // Addressed by (island, me, peer). A username identifies a person only
  // within one island: "bob" on one server and "bob" on another are two
  // different people, and one slot for both means either a false "this key
  // changed" warning on an honest peer or, worse, a stranger's key inheriting
  // the trust the user granted to someone else. The island comes from the
  // caller — this store resolves nothing on its own, the same way ChainStore
  // takes a slot rather than working out which thread the caller meant.

  async getKnownFingerprint(island, me, peer) {
    return _secureGet(_fpBase(island, me, peer));
    // fingerprint string or null
  },

  async setKnownFingerprint(island, me, peer, fingerprint) {
    const key = _fpBase(island, me, peer);
    await _secureSet(key, fingerprint);
    // Maintain an AsyncStorage index of fp keys so clearAll() can enumerate them
    await _addToFpIndex(key);
  },

  async isKeyVerified(island, me, peer) {
    return !!(await _secureGet(_fpBase(island, me, peer) + '_verified'));
  },

  async setKeyVerified(island, me, peer) {
    await _secureSet(_fpBase(island, me, peer) + '_verified', { ts: Date.now() });
  },

  async removeKeyVerified(island, me, peer) {
    const fpKey = _fpBase(island, me, peer);
    await _secureRemove(fpKey);
    await _secureRemove(fpKey + '_verified');
    await _secureRemove(fpKey + '_changed');
  },

  /** Remove ONLY the _verified flag, preserving fingerprint and _changed. */
  async clearVerifiedFlag(island, me, peer) {
    await _secureRemove(_fpBase(island, me, peer) + '_verified');
  },

  async getKeyChanged(island, me, peer) {
    return !!(await _secureGet(_fpBase(island, me, peer) + '_changed'));
  },

  async setKeyChanged(island, me, peer) {
    await _secureSet(_fpBase(island, me, peer) + '_changed', true);
  },

  async removeKeyChanged(island, me, peer) {
    await _secureRemove(_fpBase(island, me, peer) + '_changed');
  },

  /**
   * Move pins written before the address carried an island onto `island`.
   *
   * Such a pin belongs to whichever island this client was talking to when it
   * wrote it — it only ever talks to one at a time — so attributing them to the
   * current one is right for anyone who never changed servers, and anyone who
   * did already had both servers sharing the slot. Runs before any pin is read:
   * reading first would find nothing, record the key on offer as the trusted
   * baseline and call it first contact, which is the silent downgrade pins
   * exist to prevent.
   *
   * Returns the number of pins moved.
   */
  async migrateFingerprintPins(island) {
    let moved = 0;
    try {
      const index = (await _secureGet(_FP_INDEX_KEY)) || [];
      if (!Array.isArray(index) || !index.length) return 0;

      const kept = [];
      for (const legacyKey of index) {
        if (typeof legacyKey !== 'string' || !legacyKey.startsWith(_FP_PREFIX_V1)) {
          kept.push(legacyKey);
          continue;
        }
        const newKey = `${_FP_PREFIX}${String(island).toLowerCase()}_${legacyKey.slice(_FP_PREFIX_V1.length)}`;
        for (const suffix of ['', '_verified', '_changed']) {
          const value = await _secureGet(legacyKey + suffix);
          if (value === null || value === undefined) continue;
          await _secureSet(newKey + suffix, value);
          await _secureRemove(legacyKey + suffix).catch(() => {});
        }
        kept.push(newKey);
        moved++;
      }

      await _secureSet(_FP_INDEX_KEY, kept);
      if (moved) console.log(`[StorageService] Moved ${moved} pin(s) onto island ${island}`);
    } catch (e) {
      // Reported, not swallowed: the caller retries, and a pin that did not
      // move must never be read as "no pin".
      console.warn('[StorageService] pin migration failed:', e?.message);
      throw e;
    }
    return moved;
  },

  // --- Room passwords (SecureStore) ← chrome.storage.local "roomPassById" ---

  async getRoomPass(roomId) {
    return _secureGet(`room_pass_${roomId}`);
  },

  async setRoomPass(roomId, password) {
    await _secureSet(`room_pass_${roomId}`, password);
  },

  async removeRoomPass(roomId) {
    await _secureRemove(`room_pass_${roomId}`);
  },

  // --- Room metadata cache (AsyncStorage) ← chrome.storage.local "roomMetaCache" ---

  async getRoomMeta(roomId) {
    return _asyncGet(`room_meta_${roomId}`);
  },

  async setRoomMeta(roomId, meta) {
    await _asyncSet(`room_meta_${roomId}`, { ...meta, _cachedAt: Date.now() });
  },

  // --- Unread tracking (AsyncStorage) ← chrome.storage.local lastSeen keys ---

  async getLastSeen(kind, id) {
    // kind: 'room' | 'dm'
    return _asyncGet(`last_seen_${kind}_${id}`) || 0;
  },

  async setLastSeen(kind, id, ts) {
    await _asyncSet(`last_seen_${kind}_${id}`, ts);
  },

  // --- SW last error (AsyncStorage) ← chrome.storage.local "sw_last_error" ---

  async getLastError() {
    return _asyncGet('last_error');
  },

  async setLastError(err) {
    await _asyncSet('last_error', { ts: Date.now(), ...err });
  },

  // --- Utility: clear all app data (logout) ---

  async clearAll() {
    try {
      // --- Keychain: wipe session material (NOT identity — EPK must survive logout) ---
      await _secureRemove('auth');
      await _secureRemove('cached_priv');
      await _secureRemove(_ACTIVE_USER_KEY);
      await _secureRemove(_PENDING_MNEMONIC_KEY);
      // NOTE: per-user identity slots (identity_v2_<user>) are intentionally NOT removed
      // on logout. EPK is device-only (server returns 410 on GET /crypto/keys) —
      // deleting it would force recovery on every re-login. Matches Chrome Extension.

      // Wipe room key archives (rka_*) and fingerprints (fp_*) from Keychain.
      // These are now stored in Keychain (Android Keystore) — we must enumerate
      // and remove them. Also wipe room passwords (room_pass_*).
      //
      // react-native-keychain does not support listing all services, so we scan
      // AsyncStorage for room/DM/fingerprint keys that tell us which IDs exist,
      // then remove the corresponding Keychain entries.
      const allKeys = await AsyncStorage.getAllKeys();

      // Room key archives: rka_{roomId} in Keychain
      const roomIds = new Set();
      allKeys.forEach(k => {
        // room_history_{id}, room_meta_{id}, last_seen_room_{id}
        const m = k.match(/^(?:room_history_|room_meta_|last_seen_room_)(\d+)$/);
        if (m) roomIds.add(m[1]);
      });
      for (const rid of roomIds) {
        await _secureRemove(`rka_${rid}`).catch(() => {});
        await _secureRemove(`room_pass_${rid}`).catch(() => {});
      }

      // Fingerprints: fp_{me}_{peer}[_verified|_changed] in Keychain
      // Collect known me_peer pairs from AsyncStorage metadata
      // Since fp_* keys are now in Keychain, we need to track them.
      // Use a dedicated AsyncStorage index to enumerate Keychain fp entries.
      const fpIndex = (await _secureGet('_fp_index')) || [];
      if (Array.isArray(fpIndex)) {
        for (const fpKey of fpIndex) {
          await _secureRemove(fpKey).catch(() => {});
          await _secureRemove(fpKey + '_verified').catch(() => {});
          await _secureRemove(fpKey + '_changed').catch(() => {});
        }
        await _secureRemove('_fp_index');
      }
      // Also clean legacy AsyncStorage _fp_index if it exists (migration)
      await _asyncRemove('_fp_index').catch(() => {});

      // History encryption keyring + legacy key
      await _secureRemove(_HISTORY_KEYRING_ID).catch(() => {});
      await _secureRemove('history_enc_key').catch(() => {}); // legacy single key
      _keyringCache = null;

      // --- AsyncStorage: wipe all session/room/DM data ---
      // Collect all keys that should be removed on logout.
      // Preserve only identity-related and server config keys.
      const keysToRemove = allKeys.filter(k =>
        // Legacy Keychain-migrated keys
        k.startsWith('rka_') || k.startsWith('fp_') || k.startsWith('fp2_') ||
        // Room data (history, metadata, last seen)
        k.startsWith('room_history_') || k.startsWith('room_meta_') || k.startsWith('last_seen_room_') ||
        // Saved connections
        k === 'conn' || k === 'lastDm' ||
        // Crypto idle lock setting (user preference — survives logout by design)
        // k === 'crypto_idle_lock_ms' // intentionally NOT removed
        // Catch-all for any other room/DM data
        k.startsWith('dm_')
      );
      if (keysToRemove.length) {
        await AsyncStorage.multiRemove(keysToRemove);
      }
    } catch (e) {
      console.warn('[StorageService] clearAll error:', e?.message);
    }
  },

  /**
   * Rotate the history encryption key. Old keys are preserved in the keyring
   * so existing encrypted history can still be decrypted.
   * Call this after security-sensitive events (e.g., password change).
   */
  async rotateHistoryKey() {
    const kr = await _getKeyring();
    const newKid = _generateKid();
    const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const b64 = _u8ToBase64(raw);
    raw.fill(0);
    kr.keys[newKid] = b64;
    kr.current = newKid;
    _keyringCache = kr;
    await _secureSet(_HISTORY_KEYRING_ID, kr);
  },
};

export default StorageService;
