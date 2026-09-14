// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * CryptoService.js — замена panel-crypto.js
 *
 * Управляет жизненным циклом крипто-сессии:
 *   - Разблокировка (пароль → KEK → расшифровка приватного ключа)
 *   - Авто-блокировка через 20 минут бездействия
 *   - Шифрование/дешифрование сообщений и DM
 *   - Управление ключами комнат (load, rotate, archive)
 *   - Safety numbers
 */

import { Alert } from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import NetworkService from './NetworkService';
import EP from './endpoints';
import StorageService from './StorageService';
import { CryptoUtils, cryptoManager } from '../crypto';
import TC from './thread-chain';
import ChainStore from './chainStore';

const { x25519 } = require('@noble/curves/ed25519');

// Lazy proxy — reads globalThis.crypto at call time, not at module init time.
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

// Constant-time base64 key comparison — used by BIP39 recovery to match server pubkey.
function _pubKeysEqual(aB64, bB64) {
  try {
    const a = new Uint8Array(CryptoUtils.base64ToArrayBuffer(String(aB64 || '')));
    const b = new Uint8Array(CryptoUtils.base64ToArrayBuffer(String(bB64 || '')));
    if (a.length !== 32 || b.length !== 32) return false;
    let diff = 0;
    for (let i = 0; i < 32; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  } catch (_e) {
    return false;
  }
}

let _cryptoIdleLockMs = 20 * 60 * 1000; // 20 minutes (default, configurable)

// Available timeout options (matches extension CRYPTO_IDLE_LOCK_UI_OPTIONS)
const CRYPTO_IDLE_LOCK_OPTIONS = [
  { label: '5 minutes', value: 5 * 60 * 1000 },
  { label: '10 minutes', value: 10 * 60 * 1000 },
  { label: '20 minutes', value: 20 * 60 * 1000 },
  { label: '30 minutes', value: 30 * 60 * 1000 },
  { label: '1 hour', value: 60 * 60 * 1000 },
];

// TOFU cooldown: avoid hammering the server for peer key checks
const _KC_CHECK_TTL_MS = 60_000; // 1 minute

// Which island a peer name belongs to. A username identifies a person only
// within one island, so it is half the address of a pin — StorageService holds
// the other half and resolves nothing itself.
//
// Pins written before the address carried an island are moved onto the current
// one before the first read. Reading first would find nothing, record the key
// on offer as the trusted baseline and call it first contact, which is the
// silent downgrade pins exist to prevent — so a failed migration propagates and
// the caller either blocks the action or reports "unverified", never "trusted".
let _pinsMigrated = null;

async function _pinScope() {
  const island = EP.islandIdOf(NetworkService.getServerConfig());
  if (!_pinsMigrated) {
    _pinsMigrated = StorageService.migrateFingerprintPins(island).catch((e) => {
      _pinsMigrated = null;
      throw e;
    });
  }
  await _pinsMigrated;
  return island;
}
const _kcLastChecked = new Map(); // peerLower -> timestamp
const _kcAlerted = new Set(); // peerLower — session dedup for key change alerts

// ==============================
// Rate limiter (password unlock)
// ==============================

class _RateLimiter {
  constructor(maxAttempts, windowMs, lockoutMs) {
    this._max      = maxAttempts;
    this._window   = windowMs;
    this._lockout  = lockoutMs ?? windowMs;
    this._attempts = [];
    this._lockedUntil = 0;
  }
  allow() {
    const now = Date.now();
    if (now < this._lockedUntil) return false;
    this._attempts = this._attempts.filter(t => now - t < this._window);
    if (this._attempts.length >= this._max) {
      this._lockedUntil = now + this._lockout;
      this._attempts = [];
      return false;
    }
    this._attempts.push(now);
    return true;
  }
  secondsRemaining() {
    const rem = this._lockedUntil - Date.now();
    return rem > 0 ? Math.ceil(rem / 1000) : 0;
  }
  reset() { this._attempts = []; this._lockedUntil = 0; }
}

// 5 password attempts per 60 s; lockout 5 min
const _unlockRateLimit = new _RateLimiter(5, 60_000, 5 * 60_000);

// ==============================
// Internal state
// ==============================

let _initialized = false;
let _unlocked = false;
let _lockTimer = null;
// _cachedPassword removed: storing plaintext password in JS memory is a security risk
// (extractable via memory dump on rooted devices). Keychain-based auto-unlock
// (_tryAutoUnlockFromKeychain) handles all re-unlock scenarios safely.
let _ensureReadyPromise = null; // mutex: prevents concurrent unlock races
let _promptPasswordFn = null; // set by UI: (reason: string) => Promise<string|null>
let _promptPasswordFnStack = []; // stack-based: multiple screens can push/pop
let _listeners = [];          // [{event, fn}]
const _dmKeyLocks = new Map();   // dmRid -> Promise (prevent concurrent key ops)
const _roomKeyLocks = new Map(); // roomId -> Promise (prevent concurrent key ops)

// Ed25519 signing state (derived from X25519 private key on every unlock)
let _ed25519Seed = null;                  // Uint8Array(32) | null — cleared on lock
// Emitting chained signatures is OFF until readers are deployed on both
// clients. A reader that only knows v1 rejects a v2 signature outright, which
// would show a forgery warning for an honest message. Flip this only after
// both clients ship the reader that landed in a3f7d33.
const CHAIN_WRITE_ENABLED = false;

// Signing ROOM messages is OFF until readers are deployed on both clients, for
// the same reason: a client that has not learned the envelope would show the
// JSON of it as the message text. Readers first (this build), then this flag.
//
// What it is for: a room message is encrypted under a key every member holds,
// so the key proves membership and nothing more. The author is whatever the
// server wrote in the row - which means a dishonest server can move one
// member's words under another member's name, and nothing in the message can
// contradict it. The signature is what makes the claim checkable.
const ROOM_SIG_WRITE_ENABLED = false;

// Signing the key WRAP is staged the same way, and for a harder reason than the
// others: a signed wrap is a new blob format (v3), and a client that only knows
// v2 cannot open it at all - it would see a room it can no longer read. Readers
// ship first (this build understands both), then this flag.
//
// What it is for: the wrap derives from an ephemeral key, so it says only that
// somebody who knew your public key made it. The rows are written by the
// server, so the server can hand you a key it made itself and read everything
// you write under it. A signature inside the blob is what makes "who gave me
// this key" a question with an answer.
const KEY_WRAP_SIG_WRITE_ENABLED = false;

const _threadChain = TC.createThreadChain({
  sha256: async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)),
});

const _ed25519PubKeyCache = new Map();    // username_lower → { key: Uint8Array(32)|null, ts }
const _ED25519_ABSENT_TTL_MS = 5 * 60 * 1000;

// Cross-island contacts, required at call time rather than imported.
// ForeignService is built on this module - it signs cards and claims with the
// identity held here - so a static import back would be a cycle, and the decrypt
// path is the only thing on this side that needs it.
function _foreign() {
  return require('./ForeignService').default;
}

// ==============================
// Public API
// ==============================

const CryptoService = {

  // ---- Setup ----

  /**
   * Register the password-prompt function from UI layer (stack-based).
   * Multiple screens can push/pop their prompt functions without racing.
   * The most recently pushed function is used for prompts.
   *
   * @param {function(string): Promise<string|null>} fn — pass null to pop
   */
  setPromptPasswordFn(fn) {
    if (fn) {
      _promptPasswordFnStack = _promptPasswordFnStack || [];
      _promptPasswordFnStack.push(fn);
      _promptPasswordFn = fn;
    } else {
      if (_promptPasswordFnStack && _promptPasswordFnStack.length) {
        _promptPasswordFnStack.pop();
        _promptPasswordFn = _promptPasswordFnStack.length
          ? _promptPasswordFnStack[_promptPasswordFnStack.length - 1]
          : null;
      } else {
        _promptPasswordFn = null;
      }
    }
  },

  isReady() {
    return _unlocked && _initialized && cryptoManager.isReady();
  },

  isInitialized() {
    return _initialized;
  },

  // ---- Session lifecycle ----

  /**
   * Try to unlock crypto. If non-interactive: try KEK from NetworkService session.
   * If interactive: prompt for password.
   *
   * @param {{ interactive?: boolean, reason?: string }} opts
   * @returns {Promise<boolean>}
   */
  async ensureReady({ interactive = false, reason = '' } = {}) {
    if (CryptoService.isReady()) return true;

    // Mutex: if another ensureReady() is already in progress, wait for it
    if (_ensureReadyPromise) {
      await _ensureReadyPromise.catch(() => {});
      if (CryptoService.isReady()) return true;
      // Previous attempt failed and we're non-interactive — don't retry
      if (!interactive) return false;
    }

    const run = async () => {
      if (CryptoService.isReady()) return true;

      // Try auto-unlock from in-memory KEK
      const kekKey = NetworkService.getMasterKey?.() || null;
      if (kekKey) {
        const ok = await _initWithKek(kekKey);
        if (ok) return true;
      }

      // Try auto-unlock from Keychain (cached raw private key from previous session)
      {
        const ok = await _tryAutoUnlockFromKeychain();
        if (ok) return true;
      }

      if (!interactive) return false;

      // Check for local identity BEFORE prompting password — gives actionable error if missing.
      const u = await _resolveUsername();
      const identity = u ? await StorageService.getIdentity(u) : null;
      if (!identity) {
        Alert.alert(
          'Encryption not set up',
          'No encryption key found on this device.\n\nSign out and use "Import existing account" on the login screen to set up E2EE for your account.',
          [{ text: 'OK' }],
        );
        return false;
      }

      // Check rate limit before showing the password prompt
      if (!_unlockRateLimit.allow()) {
        const s = _unlockRateLimit.secondsRemaining();
        Alert.alert('Too many attempts', `Too many unlock attempts. Try again in ${s} seconds.`);
        return false;
      }
      // Reserve the slot back — _initWithPassword will consume its own slot
      _unlockRateLimit._attempts.pop();

      // Prompt user for password
      const password = await _promptPassword(reason);
      if (!password) return false;

      try {
        const ok = await _initWithPassword(password);
        return ok;
      } catch (e) {
        if (e?.code === 'RATE_LIMITED') {
          Alert.alert('Too many attempts', e.message);
          return false;
        }
        throw e;
      }
    };

    _ensureReadyPromise = run();
    try {
      return await _ensureReadyPromise;
    } finally {
      _ensureReadyPromise = null;
    }
  },

  /**
   * Derive unlock key from password + local encrypted private key,
   * cache it in NetworkService, and try non-interactive unlock.
   * Mirrors extension "login handoff" behavior for RN.
   *
   * @param {{ password: string }} opts
   * @returns {Promise<boolean>}
   */
  async bootstrapAfterAuth({ password } = {}) {
    try {
      const pwd = String(password || '');
      if (!pwd) return false;

      const u = await _resolveUsername();
      const identity = u ? await StorageService.getIdentity(u) : null;
      const epk = identity?.encrypted_private_key;
      if (!epk?.salt) return false;

      const kdf = epk.kdf || {};
      const kekKey = await CryptoUtils.deriveKeyFromPassword(pwd, epk.salt, {
        name:         kdf.name,
        preferArgon2: !!kdf.name && /^argon2id$/i.test(kdf.name),
        // Argon2id params
        time_cost:    kdf.time_cost,
        memory_kib:   kdf.memory_kib,
        parallelism:  kdf.parallelism,
        version:      kdf.version,
        // PBKDF2 params
        iterations:   kdf.iterations,
        hash:         kdf.hash,
      });
      NetworkService.setMasterKey?.(kekKey);
      return await CryptoService.ensureReady({ interactive: false });
    } catch (e) {
      console.warn('[CryptoService] bootstrapAfterAuth failed:', e?.message || e);
      return false;
    }
  },

  /**
   * Directly unlock crypto with a plain password (bypasses KEK cache path).
   * Use after login/register/import when the password is known.
   *
   * @param {string} password
   * @returns {Promise<boolean>}
   */
  async unlockWithPassword(password) {
    if (CryptoService.isReady()) return true;
    const pwd = String(password || '');
    if (!pwd) return false;
    const ok = await _initWithPassword(pwd);
    return ok;
  },

  /**
   * Directly unlock crypto from raw X25519 private key bytes.
   * Use after BIP39 import where privRaw is already in memory.
   *
   * @param {Uint8Array} privRaw  32-byte raw X25519 private key
   * @param {string} pubB64       base64 public key
   * @returns {Promise<boolean>}
   */
  async unlockWithRawKey(privRaw, pubB64) {
    if (CryptoService.isReady()) return true;
    try {
      // Derive Ed25519 seed BEFORE initializeUserKeyFromRaw — caller may wipe privRaw afterwards.
      const privRawCopy = new Uint8Array(privRaw);
      const newEd25519Seed = CryptoUtils.deriveEd25519Seed(privRawCopy);

      const ok = await cryptoManager.initializeUserKeyFromRaw(privRaw, pubB64);
      if (!ok) return false;
      _ed25519Seed = newEd25519Seed;
      _initialized = true;
      _unlocked = true;
      try { Clipboard.setString(''); } catch (_e) { /* ignore */ }
      CryptoService.resetIdleTimer();
      // Persist active-user pointer so cold-start auto-unlock can find the per-user EPK slot.
      try {
        const uNow = String(NetworkService.username || '').trim().toLowerCase();
        if (uNow) await StorageService.setActiveUsername(uNow);
      } catch (_e) { /* best-effort */ }
      // Await cache — caller may .fill(0) privRaw after we return
      await _cachePrivKeyToKeychain().catch(e => console.warn('[CryptoService] Keychain cache failed:', e?.message));
      _emit('unlocked');
      // Register Ed25519 public key with server (fire-and-forget, non-blocking).
      CryptoService.ensureEd25519KeyRegistered().catch(() => {});
      return true;
    } catch (e) {
      console.warn('[CryptoService] unlockWithRawKey error:', e?.message || e);
      return false;
    }
  },

  /** Get current idle lock timeout in ms. */
  getCryptoIdleLockMs() { return _cryptoIdleLockMs; },

  /** Set idle lock timeout in ms. Resets the timer immediately. */
  setCryptoIdleLockMs(ms) {
    const val = Number(ms);
    if (!val || val < 60_000) return; // minimum 1 minute
    _cryptoIdleLockMs = val;
    if (_unlocked) CryptoService.resetIdleTimer();
    // Persist to AsyncStorage
    StorageService.set('crypto_idle_lock_ms', String(val)).catch(() => {});
  },

  /** Available timeout options for UI picker. */
  CRYPTO_IDLE_LOCK_OPTIONS,

  /** Restore persisted timeout setting. Call once on app init. */
  async restoreIdleLockSetting() {
    try {
      const saved = await StorageService.get('crypto_idle_lock_ms');
      if (saved) {
        const val = Number(saved);
        if (val >= 60_000) _cryptoIdleLockMs = val;
      }
    } catch (_e) { /* ignore */ }
  },

  lockSession() {
    _unlocked = false;
    _initialized = false;
    cryptoManager.clear();
    _clearLockTimer();
    _ed25519Seed = null;
    _ed25519PubKeyCache.clear();
    _emit('locked');
  },

  resetIdleTimer() {
    _clearLockTimer();
    _lockTimer = setTimeout(async () => {
      // Instead of hard-locking, try to silently re-unlock from Keychain.
      // This keeps crypto available after idle timeout without user interaction.
      _clearLockTimer();
      const ok = await _tryAutoUnlockFromKeychain().catch(() => false);
      if (ok) {
        // Successfully re-unlocked — just reset the timer
        CryptoService.resetIdleTimer();
      } else {
        // Keychain unlock failed — actually lock the session
        CryptoService.lockSession();
      }
    }, _cryptoIdleLockMs);
  },

  // ---- Room key management ----

  /**
   * Load a room key from base64 and store in archive.
   * @param {number|string} roomId
   * @param {string} keyB64
   * @returns {Promise<boolean>}
   */
  async loadRoomKey(roomId, keyB64) {
    try {
      const ok = await cryptoManager.loadRoomKey(roomId, keyB64);
      if (ok) await _persistRoomKeyArchive(roomId);
      return ok;
    } catch (_e) {
      return false;
    }
  },

  /**
   * Generate a room key and return the encrypted blob for the owner.
   * Does NOT post to server — caller includes it in room creation request.
   * After room is created, caller should call loadRoomKey() to store locally.
   * @returns {Promise<{encrypted_room_key: string, rawB64: string}|null>}
   */
  async generateRoomKeyForCreation() {
    if (!CryptoService.isReady()) return null;
    try {
      const myPubB64 = cryptoManager.userPublicKeyB64;
      if (!myPubB64) throw new Error('No user public key');
      const roomKey = await CryptoUtils.generateRoomKey(true);
      const rawB64 = await CryptoUtils.exportRoomKey(roomKey);
      const encrypted_room_key = await CryptoUtils.encryptRoomKeyForUser(myPubB64, rawB64);
      return { encrypted_room_key, rawB64 };
    } catch (_e) {
      console.warn('[CryptoService] generateRoomKeyForCreation error:', _e?.message);
      return null;
    }
  },

  /**
   * Create a new room key and upload it to the server (wrapped for current user).
   * @param {number|string} roomId
   * @param {string} ownerPubB64
   * @returns {Promise<string|null>} raw room key b64 or null
   */
  /**
   * The signing options for a key wrap, or null when that is switched off.
   *
   * Kept in one place so every path that hands out a room key signs the same
   * thing: a wrap that binds to a different room, member or key version is a
   * wrap that cannot be moved there.
   */
  async _wrapSignOpts(scopeId, recipient, keyId, scope = 'room') {
    if (!KEY_WRAP_SIG_WRITE_ENABLED) return null;
    const signer = await _resolveUsername();
    if (!signer || !_ed25519Seed) return null;
    return { seed: _ed25519Seed, signer, scope, scopeId, recipient, keyId };
  },

  async createAndShareRoomKey(roomId, ownerPubB64) {
    if (!CryptoService.isReady()) return null;
    try {
      const rawB64 = await cryptoManager.createRoomKey(roomId);
      const keyId = await CryptoUtils.fingerprintRoomKeyBase64(rawB64);
      const me = await _resolveUsername();
      const wrapped = await CryptoUtils.encryptRoomKeyForUser(
        ownerPubB64, rawB64, await CryptoService._wrapSignOpts(roomId, me, keyId),
      );
      await NetworkService.postRoomKey(roomId, wrapped, keyId);
      await _persistRoomKeyArchive(roomId);
      _emit('room_key_loaded', { roomId });
      return rawB64;
    } catch (_e) {
      console.warn('[CryptoService] createAndShareRoomKey error:', _e?.message);
      return null;
    }
  },

  /**
   * Rotate room key: create new key, re-encrypt for all members.
   * @param {number|string} roomId
   * @param {Array<{username: string, public_key: string}>} members
   * @returns {Promise<boolean>}
   */
  async rotateRoomKey(roomId, members) {
    if (!CryptoService.isReady()) return { ok: false, shared: 0, failed: [], error: 'Crypto not ready' };
    try {
      const newRawB64 = await cryptoManager.createRoomKey(roomId);
      const keyId = await CryptoUtils.fingerprintRoomKeyBase64(newRawB64);
      const failed = [];
      let shared = 0;

      for (const m of members) {
        if (!m.public_key) { failed.push(m.username); continue; }
        try {
          // TOFU: verify peer key before sharing room key
          await _assertPeerKeyTrustedForSharing(
            m.username, 'sharing room key', { peerPublicKeyB64: m.public_key },
          );
          const wrapped = await CryptoUtils.encryptRoomKeyForUser(
            m.public_key, newRawB64, await CryptoService._wrapSignOpts(roomId, m.username, keyId),
          );
          await NetworkService.shareRoomKey(roomId, m.username, wrapped, keyId);
          shared++;
        } catch (_e) {
          console.warn(`[rotateRoomKey] skip ${m.username}:`, _e?.message);
          failed.push(m.username);
        }
      }
      await _persistRoomKeyArchive(roomId);
      if (failed.length > 0) {
        console.warn('[rotateRoomKey] failed for:', failed.join(', '));
      }
      return { ok: true, shared, failed };
    } catch (_e) {
      console.warn('[CryptoService] rotateRoomKey error:', _e?.message);
      return { ok: false, shared: 0, failed: [], error: _e?.message || 'Unknown error' };
    }
  },

  /**
   * Share the current room key with a specific user (for invite flow).
   * Fetches the user's public key, validates via TOFU, encrypts room key, shares via API.
   * @param {number|string} roomId
   * @param {string} targetUsername
   * @returns {Promise<boolean>}
   */
  async shareRoomKeyToUser(roomId, targetUsername) {
    if (!CryptoService.isReady()) return false;
    try {
      const rawB64 = await cryptoManager.exportRoomKeyForSharing(roomId);
      if (!rawB64) throw new Error('No room key to share');
      const keyId = await CryptoUtils.fingerprintRoomKeyBase64(rawB64);

      const peerData = await NetworkService.fetchPeerKey(targetUsername);
      const peerPubB64 = peerData?.public_key;
      if (!peerPubB64) throw new Error(`No public key for ${targetUsername}`);

      // Validate 32-byte X25519 key
      const raw = CryptoUtils.base64ToArrayBuffer(peerPubB64);
      if (raw.byteLength !== 32) throw new Error(`Invalid key length for ${targetUsername}: ${raw.byteLength}`);

      // TOFU: verify peer key before sharing
      await _assertPeerKeyTrustedForSharing(
        targetUsername, 'sharing room key (invite)', { peerPublicKeyB64: peerPubB64 },
      );

      const wrapped = await CryptoUtils.encryptRoomKeyForUser(
        peerPubB64, rawB64, await CryptoService._wrapSignOpts(roomId, targetUsername, keyId),
      );
      await NetworkService.shareRoomKey(roomId, targetUsername, wrapped, keyId);
      return true;
    } catch (_e) {
      console.warn('[CryptoService] shareRoomKeyToUser error:', _e?.message);
      throw _e;
    }
  },

  /**
   * Restore room key archive from StorageService into CryptoManager.
   * @param {number|string} roomId
   */
  async restoreRoomKeyArchive(roomId) {
    try {
      const archive = await StorageService.getRoomKeyArchive(roomId);
      for (const entry of (archive || [])) {
        await cryptoManager.loadArchivedKey(roomId, entry.kid, entry.b64);
      }
    } catch (_e) { /* ignore */ }
  },

  // ---- Message encryption ----

  /**
   * Encrypt a plaintext message for a room.
   * @param {number|string} roomId
   * @param {string} text
   * @returns {Promise<string|null>} JSON string or null
   */
  async encryptMessage(roomId, text, senderUsername) {
    if (!CryptoService.isReady()) {
      await CryptoService.ensureReady({ interactive: false });
    }
    if (!CryptoService.isReady()) return null;
    try {
      CryptoService.resetIdleTimer();
      // Auto-fetch room key from server if not in memory
      if (!cryptoManager.roomKeys.has(roomId)) {
        await CryptoService.ensureRoomKeyReady(roomId).catch(() => {});
      }

      let payload = text;
      if (ROOM_SIG_WRITE_ENABLED) {
        const me = senderUsername || NetworkService.username || await _resolveUsername();
        if (!me) throw new Error('Cannot sign a room message without knowing who is sending it');
        payload = JSON.stringify({
          rs: 1,
          from: me,
          body: text,
          sig: CryptoService.signEd25519B64(CryptoUtils._roomSigMessage(roomId, me, text)),
        });
      }
      return await cryptoManager.encryptMessage(roomId, payload);
    } catch (_e) {
      console.warn('[CryptoService] encryptMessage error:', _e?.message);
      return null;
    }
  },

  /**
   * Decrypt a room message JSON string.
   * @param {number|string} roomId
   * @param {string} encryptedJson
   * @returns {Promise<string|null>}
   */
  /**
   * Decrypt a room message.
   *
   * Answers a plain string for a message with no envelope - everything written
   * before signing existed - and an object when there is one to report on:
   * `{ text, from, sigValid, mismatch }`. `claimedAuthor` is who the SERVER
   * says wrote it; a signature that verifies over a different name is the
   * server moving somebody's words, and is reported rather than accepted.
   */
  async decryptMessage(roomId, encryptedJson, claimedAuthor = null) {
    if (!CryptoService.isReady()) {
      // Auto-re-unlock from Keychain (handles idle lock transparently)
      await CryptoService.ensureReady({ interactive: false });
    }
    if (!CryptoService.isReady()) return null;
    try {
      CryptoService.resetIdleTimer();
      // Auto-fetch room key from server if not in memory
      if (!cryptoManager.roomKeys.has(roomId)) {
        await CryptoService.ensureRoomKeyReady(roomId).catch(() => {});
      }
      const plain = await cryptoManager.decryptMessage(roomId, encryptedJson);
      return await _openRoomEnvelope(roomId, plain, claimedAuthor);
    } catch (_e) {
      console.warn('[decryptMessage] decrypt failed for room', roomId, ':', _e?.message);
      return null;
    }
  },

  // ---- DM key management ----

  /**
   * Key slot for a DM thread, scoped by island — `threadRid` in endpoints.js
   * carries the reasoning, and the extension derives the same slot the same
   * way. Rooms keep their bare numeric id.
   * @param {number|string} threadId
   * @returns {string}
   */
  _dmRid(threadId) {
    const rid = EP.threadRid(EP.islandIdOf(NetworkService.getServerConfig()), threadId);
    if (!rid) throw new Error(`Bad threadId ${threadId} or unknown island`);
    return rid;
  },

  /** Check whether the DM thread key is loaded in memory (no I/O). */
  isDmKeyLoaded(threadId) {
    // A slot that cannot be derived is a slot that cannot hold a key. Callers
    // use this to decide what to render, so it answers instead of throwing.
    try {
      return cryptoManager.roomKeys.has(CryptoService._dmRid(threadId));
    } catch (_e) {
      return false;
    }
  },

  /** Check whether a room key is loaded in memory (no I/O). */
  isRoomKeyLoaded(roomId) {
    return cryptoManager.roomKeys.has(roomId);
  },

  /**
   * Fetch and decrypt the room key from the server.
   * Mirrors _loadDmKey but for regular rooms.
   */
  async _loadRoomKey(roomId) {
    try {
      const data = await NetworkService.getRoomKey(roomId);
      if (!data?.encrypted_room_key) return { notFound: true };
      const ok = await _checkWrapSignature(data.encrypted_room_key, {
        scope: 'room', scopeId: roomId, keyId: data.key_id || '',
      });
      if (!ok) return { refused: true };
      const keyB64 = await CryptoUtils.decryptRoomKeyForUser(
        cryptoManager.userPrivateKey,
        data.encrypted_room_key,
      );
      await cryptoManager.loadRoomKey(roomId, keyB64);
      await _persistRoomKeyArchive(roomId);
      _emit('room_key_loaded', { roomId });
      return { ok: true };
    } catch (e) {
      console.warn('[_loadRoomKey] ERROR:', e?.message, 'status:', e?.status);
      if (e?.status === 404 || String(e?.message || '').includes('404')) {
        return { notFound: true };
      }
      throw e;
    }
  },

  /**
   * Ensure the room key is loaded into cryptoManager.
   * Uses a lock to prevent concurrent fetches for the same room.
   * Mirrors extension panel-crypto.js loadRoomKey():
   *   - Tries to fetch encrypted room key from server
   *   - If 404 and user is room owner → auto-creates room key
   *   - Also loads key archive from server for old key versions
   */
  async ensureRoomKeyReady(roomId, { isOwner = false } = {}) {
    if (cryptoManager.roomKeys.has(roomId)) return;
    // Cannot load keys without a decrypted private key — wait for unlock first
    if (!CryptoService.isReady()) {
      console.warn('[ensureRoomKeyReady] CryptoService not ready yet, skipping room', roomId);
      return;
    }
    if (_roomKeyLocks.has(roomId)) return _roomKeyLocks.get(roomId);

    const p = (async () => {
      const got = await CryptoService._loadRoomKey(roomId).catch((e) => {
        console.warn('[ensureRoomKeyReady] _loadRoomKey threw:', e?.message);
        return { notFound: true };
      });

      if (got?.ok) {
        // Also load archived keys from server (for old messages)
        await _loadRoomKeyArchiveFromServer(roomId).catch(() => {});
        return;
      }

      if (got?.notFound) {
        // Try loading key archive from server — may have archived keys even if primary returns 404
        await _loadRoomKeyArchiveFromServer(roomId).catch(() => {});
        if (cryptoManager.roomKeys.has(roomId)) return;

        // If owner, auto-create room key (mirrors extension behavior)
        if (isOwner && CryptoService.isReady()) {
          console.log('[ensureRoomKeyReady] Owner of room', roomId, '— auto-creating room key');
          const pubB64 = cryptoManager.userPublicKeyB64;
          if (pubB64) {
            const created = await CryptoService.createAndShareRoomKey(roomId, pubB64);
            if (created) {
              console.log('[ensureRoomKeyReady] Room key auto-created for room', roomId);
              return;
            }
          }
        }
      }
    })().finally(() => _roomKeyLocks.delete(roomId));

    _roomKeyLocks.set(roomId, p);
    return p;
  },

  /**
   * Fetch and decrypt the DM thread key from the server.
   * @returns {Promise<{ok?:boolean, notFound?:boolean}>}
   */
  async _loadDmKey(threadId) {
    try {
      const data = await NetworkService.getDmKey(threadId);
      if (!data?.encrypted_thread_key) return { notFound: true };
      const ok = await _checkWrapSignature(data.encrypted_thread_key, {
        scope: 'dm', scopeId: threadId, keyId: data.key_id || '',
      });
      if (!ok) return { refused: true };
      const keyB64 = await CryptoUtils.decryptRoomKeyForUser(
        cryptoManager.userPrivateKey,
        data.encrypted_thread_key,
      );
      await cryptoManager.loadRoomKey(CryptoService._dmRid(threadId), keyB64);
      _emit('dm_key_loaded', { threadId });
      return { ok: true };
    } catch (e) {
      if (__DEV__) console.warn('[_loadDmKey] ERROR:', e?.message, 'status:', e?.status);
      if (e?.status === 404 || String(e?.message || '').includes('404')) {
        return { notFound: true };
      }
      throw e;
    }
  },

  /**
   * Generate a new DM thread key, encrypt for both parties, upload to server.
   * Mirrors panel-crypto.js createAndShareDmKey().
   */
  async _createAndShareDmKey(threadId, peerUsername) {
    const rid    = CryptoService._dmRid(threadId);
    const rawB64 = await cryptoManager.createRoomKey(rid);

    // Compute key_id (fingerprint) — required by server and Chrome Extension
    const kid = await CryptoUtils.fingerprintRoomKeyBase64(rawB64);

    const myPubB64 = cryptoManager.userPublicKeyB64;
    if (!myPubB64) throw new Error('No user public key');

    // Use keyring endpoint (not legacy /crypto/user/)
    const peerData  = await NetworkService.fetchPeerKey(peerUsername);
    const peerPubB64 = peerData?.public_key;
    if (!peerPubB64) throw new Error(`No public key for ${peerUsername}`);

    // TOFU: verify peer key is trusted before sharing
    await _assertPeerKeyTrustedForSharing(peerUsername, 'sharing DM key', { peerPublicKeyB64: peerPubB64 });

    const me = await _resolveUsername();
    const encForMe = await CryptoUtils.encryptRoomKeyForUser(
      myPubB64, rawB64, await CryptoService._wrapSignOpts(threadId, me, kid, 'dm'),
    );
    const encForPeer = await CryptoUtils.encryptRoomKeyForUser(
      peerPubB64, rawB64, await CryptoService._wrapSignOpts(threadId, peerUsername, kid, 'dm'),
    );

    await NetworkService.postDmKey(threadId, encForMe, kid);
    await NetworkService.shareDmKey(threadId, peerUsername, encForPeer, kid);
    _emit('dm_key_loaded', { threadId });
  },

  /**
   * Ensure the DM thread key is loaded into cryptoManager.
   * If not found on server, creates and shares a new one.
   * Uses per-rid lock to prevent concurrent operations.
   */
  async ensureDmKeyReady(threadId, peerUsername) {
    const rid = CryptoService._dmRid(threadId);
    if (cryptoManager.roomKeys.has(rid)) return;
    if (!CryptoService.isReady()) {
      // Instead of silently returning, wait for Keychain auto-unlock to finish.
      // This prevents the race where a WS message arrives during idle-to-unlock transition.
      const ready = await _waitForReady(5000);
      if (!ready) {
        console.warn('[ensureDmKeyReady] CryptoService not ready after 5 s, skipping');
        return;
      }
      // Re-check: another concurrent call may have loaded the key while we waited
      if (cryptoManager.roomKeys.has(rid)) return;
    }

    if (_dmKeyLocks.has(rid)) {
      return _dmKeyLocks.get(rid);
    }

    const p = (async () => {
      let got;
      try {
        got = await CryptoService._loadDmKey(threadId);
      } catch (e) {
        console.warn('[CryptoService] loadDmKey failed:', e?.message);
        return;
      }

      if (got?.ok) return;

      if (got?.notFound && peerUsername) {
        try {
          await CryptoService._createAndShareDmKey(threadId, peerUsername);
          // Reload after create
          await CryptoService._loadDmKey(threadId);
        } catch (e) {
          console.warn('[CryptoService] createAndShareDmKey failed:', e?.message);
        }
      }
    })().finally(() => _dmKeyLocks.delete(rid));

    _dmKeyLocks.set(rid, p);
    return p;
  },

  // ---- DM encryption ----

  /**
   * Encrypt a DM message using the shared DM thread key (room key approach).
   * Produces a "sealed sender" envelope: { ss:1, from, body } → encrypt → JSON string.
   * Output is compatible with the Chrome Extension panel-crypto.js encryptDm().
   *
   * @param {number|string} threadId
   * @param {string} text
   * @param {string} peerUsername   — needed to create key if not yet established
   * @param {string} [senderUsername] — caller-supplied username for the sealed sender `from` field;
   *                                    falls back to NetworkService.username. Pass explicitly to
   *                                    guarantee attribution even if NetworkService hasn't synced yet.
   * @returns {Promise<string|null>} JSON string {encrypted,iv,data,kid} or null
   */
  async encryptDm(threadId, text, peerUsername, senderUsername) {
    if (!CryptoService.isReady()) {
      await CryptoService.ensureReady({ interactive: false });
    }
    if (!CryptoService.isReady()) return null;
    try {
      CryptoService.resetIdleTimer();
      await CryptoService.ensureDmKeyReady(threadId, peerUsername);
      const rid = CryptoService._dmRid(threadId);
      if (!cryptoManager.roomKeys.has(rid)) {
        console.warn('[CryptoService] encryptDm: DM key not ready');
        return null;
      }
      const myUsername = senderUsername || NetworkService.username || await _resolveUsername();
      const envelopeObj = { ss: 1, from: myUsername, body: text };
      // Sign the envelope so the recipient can verify the sender identity.
      // Signature covers (threadId, from, body) — prevents peer from forging `from`.
      // With the chain enabled it also covers the message's place in this
      // sender's run, so a message cannot be deleted or re-filed unnoticed.
      if (_ed25519Seed && myUsername) {
        try {
          let sigMsg;
          let chained = null;
          if (CHAIN_WRITE_ENABLED) {
            const head = await ChainStore.get(rid, 'out');
            chained = { seq: head.seq + 1, prev: head.hash };
            envelopeObj.sq = chained.seq;
            envelopeObj.pv = chained.prev;
            sigMsg = CryptoUtils._dmSigMessageV2(threadId, chained.seq, chained.prev, myUsername, text);
          } else {
            sigMsg = CryptoUtils._dmSigMessage(threadId, myUsername, text);
          }
          envelopeObj.sig = CryptoUtils.ed25519Sign(_ed25519Seed, sigMsg);

          if (chained) {
            // Advance at signing time, not at delivery: a failed send is
            // queued with this exact ciphertext and retried unchanged, so the
            // seq it carries must already be spoken for. An abandoned send
            // leaves a hole, which the peer reports as a GAP - the survivable
            // verdict, not an accusation.
            await ChainStore.set(rid, 'out', {
              seq: chained.seq,
              hash: await _threadChain.linkFor(sigMsg),
            });
          }
        } catch (sigErr) {
          // Having a seed and failing to sign with it is not a normal
          // condition; the "no signing key" case never reaches here, it is the
          // guard above. Sending unsigned anyway downgraded authenticity where
          // only the recipient could notice, as a quiet "unverified" marker.
          console.warn('[CryptoService] Ed25519 sign failed:', sigErr?.message);
          const err = new Error('Could not sign this message. Nothing was sent — unlock and try again.');
          err.signingFailed = true;
          throw err;
        }
      }
      return await cryptoManager.encryptMessage(rid, JSON.stringify(envelopeObj));
    } catch (e) {
      // A signing failure must reach the sender: returning null here would put
      // it in the same bucket as "key not ready", and the UI would report a
      // generic send error for what is an authenticity downgrade.
      if (e?.signingFailed) throw e;
      console.warn('[CryptoService] encryptDm error:', e?.message);
      return null;
    }
  },

  /**
   * Decrypt a DM message.
   * Expects JSON string {encrypted,iv,data,kid} from encryptDm / Chrome Extension.
   * Returns plain text after unwrapping sealed sender envelope.
   *
   * @param {number|string} threadId
   * @param {string} encryptedJson
   * @param {string} [peerUsername]
   * @returns {Promise<string|null>}
   */
  async decryptDm(threadId, encryptedJson, _peerUsername) {
    if (!CryptoService.isReady()) {
      await CryptoService.ensureReady({ interactive: false });
    }
    if (!CryptoService.isReady()) return null;
    try {
      CryptoService.resetIdleTimer();
      const rid = CryptoService._dmRid(threadId);

      // A cross-island thread has no key on this island and no peer here to
      // share one with. Left to the local path, a missing key becomes "the
      // server has none, so create and share one" - which would mint a key for
      // a mailbox the other side cannot read, addressed to a display name that
      // is not a username here. Its keys came with the contact instead.
      const foreign = await _foreign().forThread(threadId);
      if (foreign) {
        try {
          await _foreign().ensureKeysReady(foreign);
        } catch (e) {
          console.warn('[decryptDm] foreign keys not ready:', e?.message);
        }
      }

      // Pass null for peerUsername — on RECEIVE path we must NOT create a new key.
      // Creating a new key here would replace the key the sender used, making decryption impossible.
      // Key creation only happens on the SEND path (encryptDm passes peerUsername).
      if (!foreign && !cryptoManager.roomKeys.has(rid)) {
        await CryptoService.ensureDmKeyReady(threadId, null).catch((e) => {
          console.warn('[decryptDm] ensureDmKeyReady threw:', e?.message);
        });
      }
      if (!cryptoManager.roomKeys.has(rid)) return null;

      let decrypted;
      try {
        decrypted = await cryptoManager.decryptMessage(rid, encryptedJson);
      } catch (decryptErr) {
        // Key mismatch — force-reload from server and retry.
        // Happens when Extension used a different key version than what Android has in memory.
        // Never for a cross-island thread: this island holds no key for a
        // mailbox, so the reload would 404 and the retry would fail anyway.
        if (foreign) return null;
        if (__DEV__) console.warn('[decryptDm] decryptMessage failed:', decryptErr?.message, '— force-reloading key from server');
        try {
          await CryptoService._loadDmKey(threadId);
          decrypted = await cryptoManager.decryptMessage(rid, encryptedJson);
          if (__DEV__) console.warn('[decryptDm] force-reload retry succeeded');
        } catch (retryErr) {
          if (__DEV__) console.warn('[decryptDm] force-reload retry also failed:', retryErr?.message);
          return null;
        }
      }

      // Unwrap sealed sender envelope { ss:1, from, body, sig? }
      try {
        const inner = JSON.parse(decrypted);
        if (inner?.ss === 1 && inner.body !== undefined) {
          const from = inner.from || null;
          const sig  = inner.sig  || null;

          // Verify Ed25519 signature when present.
          // sigValid: true = verified OK, false = bad sig (forgery), null = not checked.
          let sigValid = null;
          let sigMsgBytes = null;
          if (sig && from) {
            try {
              // Resolved, not read off NetworkService: after a fresh sign-in
              // that field is empty (the login response carries no name), and
              // taking it at face value here would make our own copies look
              // like somebody else's - verified against the contact's key, and
              // reported as forged.
              const mine = String(from).trim().toLowerCase() === await _resolveUsername();
              // A cross-island contact has no entry in this island's key store,
              // and should not need one: their signing key came from the card,
              // out of band. Verifying against that is strictly stronger than
              // verifying against whatever a key server hands over - it is what
              // stops a dishonest island forging messages from them. Our own
              // key needs no lookup at all; it is already unlocked.
              const peerPubKey = (foreign && !mine && foreign.ed25519PubB64)
                ? new Uint8Array(CryptoUtils.base64ToArrayBuffer(foreign.ed25519PubB64))
                : (mine && CryptoService.isReady())
                  ? CryptoService.ed25519PublicKey()
                  : await CryptoService._fetchPeerEd25519PubKey(from);
              if (peerPubKey) {
                // v2 when the envelope carries its place in the sender's chain,
                // v1 otherwise. Which one was signed is inside the signature
                // (the domain prefix differs), so stripping sq/pv to force a v1
                // check does not downgrade anything - it just fails.
                const chained = Number.isInteger(inner.sq) && /^[0-9a-f]{64}$/.test(inner.pv || '');

                // A signature covers the thread the message was DELIVERED to.
                // In a cross-island conversation that is not always the thread
                // it is read in: our own copy of what we sent went to the
                // peer's mailbox on their island and is kept here only so the
                // history is whole. Verifying it against this thread's number
                // fails - correctly, on the wrong question - and accuses us of
                // forging our own messages. Both numbers are tried, because not
                // every message of ours went abroad; anybody who could produce
                // either signature already holds our signing key.
                const tids = [];
                if (foreign && mine && foreign.outbox?.threadId) tids.push(foreign.outbox.threadId);
                tids.push(threadId);

                const sigBytes = new Uint8Array(CryptoUtils.base64ToArrayBuffer(sig));
                let sigMsg = null;
                for (const tid of tids) {
                  sigMsg = chained
                    ? CryptoUtils._dmSigMessageV2(tid, inner.sq, inner.pv, from, String(inner.body))
                    : CryptoUtils._dmSigMessage(tid, from, String(inner.body));
                  sigValid = CryptoUtils.ed25519Verify(peerPubKey, sigBytes, sigMsg);
                  if (sigValid === true) break;
                }
                sigMsgBytes = chained ? sigMsg : null;
                if (!sigValid) {
                  if (__DEV__) console.warn('[CryptoService] DM Ed25519 signature INVALID — from:', from, 'thread:', threadId);
                }
              }
            } catch (verifyErr) {
              if (__DEV__) console.warn('[CryptoService] Ed25519 verify error:', verifyErr?.message);
            }
          }

          // Chain position travels with the message. Deliberately reported
          // rather than checked here: history arrives in pages and in no
          // particular order, so verifying message by message would invent a
          // gap on every load. The caller sorts a sender's run and checks it
          // with verifyRun. The link is computed only for a message whose
          // signature verified - otherwise a forgery could drag the chain
          // forward.
          let chain = null;
          if (Number.isInteger(inner.sq) && /^[0-9a-f]{64}$/.test(inner.pv || '')) {
            chain = { seq: inner.sq, prev: inner.pv, link: null };
            if (sigValid === true && sigMsgBytes) {
              try {
                chain.link = await _threadChain.linkFor(sigMsgBytes);
              } catch (_e) { /* leave link null; the run reports it as unchained */ }
            }
          }
          return { text: String(inner.body), from, sigValid, chain };
        }
      } catch (_e) {}

      // Non-sealed messages should not appear in DMs — treat as opaque text
      if (__DEV__) console.warn('[decryptDm] message lacks sealed sender envelope');
      return { text: decrypted, from: null, sigValid: null };
    } catch (_e) {
      if (__DEV__) console.warn('[decryptDm] outer catch:', _e?.message);
      return null;
    }
  },

  // ---- Safety numbers ----

  /**
   * Compute safety number between two users.
   * @param {string} myUsername
   * @param {string} peerUsername
   * @param {string} peerPubB64
   * @returns {Promise<string|null>}
   */
  async getSafetyNumber(myUsername, peerUsername, peerPubB64) {
    if (!CryptoService.isReady() || !cryptoManager.userPublicKeyB64) return null;
    try {
      return await CryptoUtils.computeSafetyNumber(
        myUsername, cryptoManager.userPublicKeyB64,
        peerUsername, peerPubB64,
      );
    } catch (_e) {
      return null;
    }
  },

  /**
   * Get my public key fingerprint.
   * @returns {Promise<string|null>} hex fingerprint
   */
  async getMyFingerprint() {
    if (!cryptoManager.userPublicKeyB64) return null;
    return CryptoUtils.fingerprintPublicKey(cryptoManager.userPublicKeyB64);
  },

  /**
   * Get fingerprint of a peer's public key.
   * @param {string} peerPubB64
   * @returns {Promise<string|null>} hex fingerprint
   */
  async fingerprintPeerKey(peerPubB64) {
    if (!peerPubB64) return null;
    return CryptoUtils.fingerprintPublicKey(peerPubB64);
  },

  /**
   * Mark a peer key as verified.
   * @param {string} me
   * @param {string} peer
   * @param {string} fingerprint
   */
  async verifyPeerKey(me, peer, fingerprint) {
    const island = await _pinScope();
    await StorageService.setKnownFingerprint(island, me, peer, fingerprint);
    await StorageService.setKeyVerified(island, me, peer);
  },

  /**
   * Check if peer key is verified.
   * @param {string} me
   * @param {string} peer
   * @returns {Promise<boolean>}
   */
  /**
   * Whether this peer's key changed since it was pinned and still needs
   * re-verification. Screens go through here rather than touching
   * StorageService: the island is half a pin's address, and resolving it in
   * one place is what keeps two servers' `bob` apart.
   * @returns {Promise<boolean>}
   */
  async getPeerKeyChanged(me, peer) {
    try {
      return await StorageService.getKeyChanged(await _pinScope(), me, peer);
    } catch (_e) {
      return false;
    }
  },

  /** Clear that flag once the user has confirmed the new key. */
  async clearPeerKeyChanged(me, peer) {
    await StorageService.removeKeyChanged(await _pinScope(), me, peer);
  },

  async isPeerKeyVerified(me, peer) {
    // Answers rather than throws: callers use it to decide what to render, and
    // "cannot tell" must render as not verified.
    try {
      return await StorageService.isKeyVerified(await _pinScope(), me, peer);
    } catch (_e) {
      return false;
    }
  },

  // ---- Identity & key publishing ----

  getUserPublicKeyB64() {
    return cryptoManager.userPublicKeyB64 || null;
  },

  /**
   * Compute kid (key ID) from base64 public key.
   * SHA-256(publicKeyB64 raw bytes) → first 32 hex chars.
   * Matches extension's kidFromPublicKeyB64().
   */
  async kidFromPublicKeyB64(publicKeyB64) {
    return _kidFromPublicKeyB64(publicKeyB64);
  },

  /**
   * Publish current user's identity key to server keyring (POST /keys/me).
   * Called after unlock when the public key is available.
   */
  async publishIdentityKey() {
    const pubB64 = cryptoManager.userPublicKeyB64;
    if (!pubB64) return;
    try {
      const kid = await _kidFromPublicKeyB64(pubB64);
      await NetworkService.publishMyKey({ kid, publicKeyB64: pubB64 });
    } catch (e) {
      console.warn('[CryptoService] publishIdentityKey error:', e?.message);
    }
  },

  // ---- Recovery phrase ----

  /**
   * Export 24-word BIP39 recovery phrase.
   * Requires password re-entry for security (matches extension panel-ui.js).
   * Decrypts EPK with the given password to extract raw key, then encodes as mnemonic.
   *
   * @param {string} password — user's current password
   * @returns {Promise<string>} 24-word mnemonic
   */
  async getRecoveryPhrase(password) {
    if (!password) throw new Error('Password is required');
    const u = await _resolveUsername();
    const identity = u ? await StorageService.getIdentity(u) : null;
    if (!identity?.encrypted_private_key) throw new Error('No identity found');

    // Use the same decryptPrivateKey path as login — guarantees identical KDF + AAD logic.
    // Returns { _x25519: true, priv: Uint8Array(32) }.
    let privKey;
    try {
      privKey = await CryptoUtils.decryptPrivateKey(
        identity.encrypted_private_key, password,
        { expectedUsername: identity.username || u }
      );
    } catch (_e) {
      throw new Error('Incorrect password');
    }

    const mnemonic = CryptoUtils.bip39Encode(privKey.priv);
    privKey.priv.fill(0);
    return mnemonic;
  },

  /**
   * Re-derive the BIP39 recovery phrase from the currently unlocked private
   * key — no password required (session is already unlocked).
   *
   * Used by the pending-mnemonic-ack flow: if the user crashed before
   * confirming the recovery phrase shown after registration, we surface it
   * again on the next unlock without re-prompting for the password.
   */
  exportCurrentMnemonic() {
    const priv = cryptoManager.userPrivateKey?.priv;
    if (!priv || priv.length !== 32) return null;
    return CryptoUtils.bip39Encode(priv);
  },

  /**
   * Change the user's password:
   *   1. Verify old password by decrypting EPK locally.
   *   2. Re-encrypt EPK with new password → new v3 container.
   *   3. Update server password hash via POST /auth/change-password.
   *   4. Save new EPK to Keychain only after server confirms.
   *
   * The current JWT stays valid. cached_priv (raw key) is unaffected.
   */
  async changePassword(oldPassword, newPassword) {
    if (!oldPassword || !newPassword) throw new Error('Both passwords are required');
    if (newPassword.length < 8) throw new Error('New password must be at least 8 characters');

    const u = await _resolveUsername();
    if (!u) throw new Error('No active user on this device');
    const identity = await StorageService.getIdentity(u);
    if (!identity?.encrypted_private_key) throw new Error('No identity found on this device');

    // 1. Verify old password
    let privKey;
    try {
      privKey = await CryptoUtils.decryptPrivateKey(
        identity.encrypted_private_key, oldPassword,
        { expectedUsername: identity.username || u },
      );
    } catch (_e) {
      throw new Error('Current password is incorrect');
    }

    // 2. Re-encrypt with new password
    let newEpk;
    try {
      newEpk = await CryptoUtils.encryptPrivateKey(
        privKey.priv, newPassword,
        { username: identity.username || u },
      );
    } finally {
      privKey.priv.fill(0);
    }

    // 3. Update server — throws on wrong old password or network error.
    // Server also revokes ALL refresh tokens (all sessions on all devices).
    await NetworkService.changePassword(oldPassword, newPassword);

    // 4. Server confirmed → persist new EPK.
    // Caller is responsible for logging out after showing success to the user.
    await StorageService.setIdentity(u, { ...identity, encrypted_private_key: newEpk, updated_at: Date.now() });
  },

  /**
   * Recover account from 24-word BIP39 mnemonic after password loss.
   *
   * Flow (mirrors extension login.js showRecoveryForm):
   *   1. Decode phrase (checksum verified client-side).
   *   2. Derive recovery auth token via HKDF.
   *   3. Derive public key from raw private key; fetch server public key and
   *      compare — abort if mismatch (wrong phrase for this username).
   *   4. Build new v3 EPK container encrypted with the new password.
   *   5. POST /auth/recover-start → get single-use nonce.
   *   6. POST /auth/recover (nonce + recovery_auth + new_password) →
   *      server verifies auth token, updates password_hash, returns ok.
   *   7. On success: persist new EPK to Keychain device-only.
   *
   * Does NOT log the user in — caller navigates back to LoginScreen on success.
   */
  async recoverFromBip39(username, phrase, newPassword) {
    const u = String(username || '').trim();
    const ph = String(phrase || '').trim().toLowerCase();
    if (!u) throw new Error('Username is required');
    if (!ph) throw new Error('Recovery phrase is required');
    if (!newPassword || newPassword.length < 8) {
      throw new Error('New password must be at least 8 characters');
    }
    const wordCount = ph.split(/\s+/).filter(Boolean).length;
    if (wordCount !== 24) throw new Error(`Recovery phrase must be exactly 24 words (got ${wordCount})`);

    let privRaw;
    try {
      privRaw = CryptoUtils.bip39Decode(ph);
    } catch (e) {
      throw new Error('Invalid recovery phrase: ' + (e?.message || 'checksum mismatch'));
    }

    try {
      const pubRaw = x25519.getPublicKey(privRaw);
      const derivedPubB64 = CryptoUtils.arrayBufferToBase64(pubRaw);

      let serverPubB64 = null;
      try {
        const keyData = await NetworkService.fetchPeerKey(u);
        serverPubB64 = keyData?.public_key;
      } catch (fetchErr) {
        if (__DEV__) console.warn('[recoverFromBip39] fetchPeerKey error:', fetchErr?.message);
      }
      if (!serverPubB64) {
        throw new Error('Could not fetch public key from server. Check your connection.');
      }
      if (!_pubKeysEqual(derivedPubB64, serverPubB64)) {
        throw new Error('Recovery phrase does not match this account. Double-check the 24 words.');
      }

      const recoveryAuth = CryptoUtils.deriveRecoveryAuth(privRaw);
      const recoveryAuthB64 = CryptoUtils.arrayBufferToBase64(recoveryAuth);

      const newEpk = await CryptoUtils.encryptPrivateKey(privRaw, newPassword, { username: u });

      const { nonce } = await NetworkService.recoverStart(u);
      if (!nonce) throw new Error('Server did not return a recovery nonce');

      await NetworkService.recover(u, nonce, recoveryAuthB64, newPassword);

      const uLower = u.toLowerCase();
      await StorageService.setIdentity(uLower, {
        encrypted_private_key: newEpk,
        public_key: serverPubB64,
        username: uLower,
        updated_at: Date.now(),
      });
      await StorageService.setActiveUsername(uLower).catch(() => {});
    } finally {
      try { privRaw.fill(0); } catch (_e) { /* best effort */ }
    }
  },

  // ---- TOFU (Trust On First Use) ----

  /**
   * Check if a peer's public key fingerprint has changed since last known.
   * Returns { changed: true/false, username } or null if skipped.
   */
  async checkPeerKeyChanged(peerUsername, { force = false, peerPublicKeyB64 = null } = {}) {
    return _checkPeerKeyChanged(peerUsername, { force, peerPublicKeyB64 });
  },

  /**
   * Assert that the peer's key is trusted before sharing encrypted keys.
   * Throws if the key has changed and hasn't been re-verified.
   */
  async assertPeerKeyTrustedForSharing(peerUsername, actionLabel = 'sharing encrypted key', { peerPublicKeyB64 = null } = {}) {
    return _assertPeerKeyTrustedForSharing(peerUsername, actionLabel, { peerPublicKeyB64 });
  },

  /**
   * Register the current user's Ed25519 signing public key with the server.
   * Called fire-and-forget after every unlock. Idempotent — re-registers if key changed.
   */
  async ensureEd25519KeyRegistered() {
    if (!_ed25519Seed) return;
    try {
      const pubKey = CryptoUtils.ed25519GetPublicKey(_ed25519Seed);
      const pubB64 = CryptoUtils.arrayBufferToBase64(pubKey);
      await NetworkService.registerEd25519Key(pubB64);
    } catch (e) {
      console.warn('[CryptoService] Ed25519 key registration failed:', e?.message);
    }
  },

  /**
   * Who is signed in, resolved the way every key path here resolves it.
   *
   * `/auth/login` answers with tokens and no name, so NetworkService.username
   * is empty for the whole first session after a fresh sign-in - the same race
   * that once put an empty `from` into sealed envelopes. The persisted active
   * user is the fallback, and it is written at login.
   */
  async activeUsername() {
    return _resolveUsername();
  },

  /**
   * Sign with this identity's Ed25519 key.
   *
   * The seed itself stays in this module. A cross-island contact card, and the
   * claim that proves possession of the key a mailbox was opened for, are both
   * signed with it - and the protocol that builds them must stay free of any
   * key handling of its own, so it gets these two calls instead of the seed.
   *
   * @param {Uint8Array} msgBytes
   * @returns {Uint8Array} 64-byte signature
   */
  signEd25519(msgBytes) {
    if (!_ed25519Seed) throw new Error('Locked: no signing key');
    return new Uint8Array(
      CryptoUtils.base64ToArrayBuffer(CryptoUtils.ed25519Sign(_ed25519Seed, msgBytes)),
    );
  },

  /** The same signature, base64url — the form a sealed envelope carries. */
  signEd25519B64(msgBytes) {
    if (!_ed25519Seed) throw new Error('Locked: no signing key');
    return CryptoUtils.ed25519Sign(_ed25519Seed, msgBytes);
  },

  /** This identity's Ed25519 public key, Uint8Array(32). Throws when locked. */
  ed25519PublicKey() {
    if (!_ed25519Seed) throw new Error('Locked: no signing key');
    return CryptoUtils.ed25519GetPublicKey(_ed25519Seed);
  },

  /**
   * Fetch and cache a peer's Ed25519 signing public key.
   * Returns Uint8Array(32) or null if the peer has no registered key.
   */
  async _fetchPeerEd25519PubKey(username) {
    const lower = (username || '').toLowerCase();
    if (!lower) return null;

    const cached = _ed25519PubKeyCache.get(lower);
    if (cached) {
      if (cached.key) return cached.key;
      // "No key" is a real answer, but only for a while: the peer may register
      // one at any moment, and a stale negative silently downgrades every DM
      // from them to unverified for the rest of the session.
      if (Date.now() - cached.ts < _ED25519_ABSENT_TTL_MS) return null;
    }

    try {
      const data = await NetworkService.fetchPeerKey(username);
      if (!data) return null;                     // a failed request is not an answer
      const b64 = data.ed25519_public_key;
      const bytes = b64 ? new Uint8Array(CryptoUtils.base64ToArrayBuffer(b64)) : null;
      const pubKey = bytes && bytes.length === 32 ? bytes : null;
      _ed25519PubKeyCache.set(lower, { key: pubKey, ts: Date.now() });
      return pubKey;
    } catch (_e) {
      return null;
    }
  },

  /**
   * Per-message entry point for key change alerts.
   * Deduplicates within a session so the user is only alerted once per peer.
   * Mirrors extension's checkAndAlertKeyChange() in panel-crypto.js.
   * @returns {string|null} username if changed (first detection), null otherwise
   */
  async checkAndAlertKeyChange(peerUsername) {
    const peer = String(peerUsername || '').trim();
    if (!peer) return null;
    const peerLower = peer.toLowerCase();
    if (_kcAlerted.has(peerLower)) return null;

    const result = await _checkPeerKeyChanged(peer, {});
    if (result?.changed) {
      _kcAlerted.add(peerLower);
      Alert.alert(
        'Key Changed',
        `The encryption key for "${peer}" has changed. ` +
        'Verify safety numbers to ensure your communication is secure.',
      );
      _emit('key_changed', { username: peer });
      return peer;
    }
    return null;
  },

  /**
   * Batch check for all room members. Used when entering a room.
   * Mirrors extension's checkRoomPeersKeyChanges().
   */
  async checkRoomPeersKeyChanges(usernames) {
    if (!Array.isArray(usernames) || !usernames.length) return;
    const me = await _resolveUsername();
    for (const u of usernames) {
      if (String(u || '').toLowerCase() === me) continue;
      try { await CryptoService.checkAndAlertKeyChange(u); } catch (_e) { /* ignore */ }
    }
  },

  /**
   * Reset session alert state. Called on room/thread navigation change.
   * Mirrors extension's resetKeyChangeAlerts().
   */
  resetKeyChangeAlerts() {
    _kcAlerted.clear();
    _kcLastChecked.clear();
  },

  // ---- Events ----

  on(event, fn) {
    _listeners.push({ event, fn });
    return () => CryptoService.off(event, fn);
  },

  off(event, fn) {
    _listeners = _listeners.filter(l => !(l.event === event && l.fn === fn));
  },

};

// ==============================
// Internal helpers
// ==============================

/**
 * Resolve current username for per-user identity slot lookup.
 * Tries NetworkService first (live session), falls back to the active-user
 * pointer in Keychain (cold start before auth restore).
 */
/**
 * Derive the Ed25519 signing seed from the identity key that was just unlocked.
 *
 * Every unlock path has to do this, and until now only the BIP39 import did: a
 * password sign-in and a Keychain auto-unlock both left the seed null. An
 * unsigned DM is not a small thing - the recipient shows it as unverified, and
 * once they have seen a signed message from the same person, as FORGED. The
 * same null also made ensureEd25519KeyRegistered() return early, so the key a
 * peer would verify against was never published either.
 *
 * The seed is deterministic (HKDF of the X25519 private key), so this stores no
 * new key material; it re-derives what the identity already implies.
 */
function _deriveSigningSeed() {
  try {
    const raw = cryptoManager.userPrivateKey && cryptoManager.userPrivateKey.priv;
    _ed25519Seed = (raw && raw.length === 32) ? CryptoUtils.deriveEd25519Seed(raw) : null;
  } catch (e) {
    _ed25519Seed = null;
    console.warn('[CryptoService] signing seed derivation failed:', e?.message);
  }
}

/**
 * Unwrap a room message and say what its signature proves.
 *
 * Unsigned messages stay exactly what they were - a string - because that is
 * every message written before this existed, and a reader that turned them into
 * "unverified" noise would cry wolf over the whole history.
 */
async function _openRoomEnvelope(roomId, plain, claimedAuthor) {
  if (typeof plain !== 'string' || !plain.startsWith('{')) return plain;
  let inner;
  try {
    inner = JSON.parse(plain);
  } catch (_e) {
    return plain;
  }
  if (!inner || inner.rs !== 1 || inner.body === undefined) return plain;

  const from = String(inner.from || '');
  const body = String(inner.body);
  const claimed = String(claimedAuthor || '').trim().toLowerCase();
  // The server said one name, the signed envelope says another: exactly the
  // move this signature exists to expose.
  const mismatch = !!claimed && !!from && claimed !== from.toLowerCase();

  let sigValid = null;
  if (inner.sig && from) {
    try {
      const me = await _resolveUsername();
      const pub = (me && from.toLowerCase() === me)
        ? CryptoService.ed25519PublicKey()
        : await CryptoService._fetchPeerEd25519PubKey(from);
      if (pub) {
        sigValid = CryptoUtils.ed25519Verify(
          pub,
          new Uint8Array(CryptoUtils.base64ToArrayBuffer(inner.sig)),
          CryptoUtils._roomSigMessage(roomId, from, body),
        );
      }
    } catch (e) {
      if (__DEV__) console.warn('[room] signature check failed to run:', e?.message);
    }
  }
  return { text: body, from, sigValid, mismatch };
}

/**
 * Decide whether a wrapped key may be used at all.
 *
 * An unsigned wrap (v2) is everything handed out before signing existed, so it
 * passes - refusing those would lock people out of their own rooms. A signed
 * one has to hold up: the signature is checked against the ed25519 key of
 * whoever the blob names, over bytes that bind this room, this recipient and
 * this key version. A wrap that fails is not "unverified", it is a key from
 * somebody who could not have wrapped it, and it is refused.
 *
 * What this cannot do is tell whether a genuine member should have been giving
 * you a key at all: room membership is the server's word. It stops the server
 * minting keys of its own and attributing them to people.
 */
async function _checkWrapSignature(encryptedB64, { scope, scopeId, keyId }) {
  let info;
  try {
    info = CryptoUtils.inspectWrappedKey(encryptedB64, {
      scope, scopeId, keyId, recipient: await _resolveUsername(),
    });
  } catch (e) {
    console.warn('[keywrap] unreadable wrapped key:', e?.message);
    return false;
  }
  if (!info.signed) return true;                       // v2: nothing to check

  try {
    const me = await _resolveUsername();
    const pub = (me && info.signer.toLowerCase() === me)
      ? CryptoService.ed25519PublicKey()
      : await CryptoService._fetchPeerEd25519PubKey(info.signer);
    if (!pub) {
      console.warn(`[keywrap] no signing key known for ${info.signer} - refusing the key`);
      return false;
    }
    const ok = CryptoUtils.ed25519Verify(pub, info.sig, info.sigMessage);
    if (!ok) console.warn(`[keywrap] signature from ${info.signer} does not hold - refusing the key`);
    return ok;
  } catch (e) {
    console.warn('[keywrap] signature check could not run:', e?.message);
    return false;
  }
}

async function _resolveUsername() {
  const fromNs = String(NetworkService.username || '').trim().toLowerCase();
  if (fromNs) return fromNs;
  try {
    const fromActive = await StorageService.getActiveUsername();
    return String(fromActive || '').trim().toLowerCase();
  } catch (_e) {
    return '';
  }
}

async function _initWithPassword(password) {
  if (!_unlockRateLimit.allow()) {
    const s = _unlockRateLimit.secondsRemaining();
    throw Object.assign(new Error(`Too many unlock attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
  }
  try {
    // Load encrypted private key from local storage (server never stores it — 410 deprecated)
    const u = await _resolveUsername();
    const keysData = await StorageService.getIdentity(u);
    if (!keysData) return false;

    const { encrypted_private_key, public_key } = keysData;

    const ok = await cryptoManager.initializeUserKey(encrypted_private_key, password, public_key);
    if (!ok) return false;

    if (u) await StorageService.setActiveUsername(u).catch(() => {});

    _deriveSigningSeed();
    _initialized = true;
    _unlocked = true;
    _unlockRateLimit.reset();
    try { Clipboard.setString(''); } catch (_e) { /* ignore */ }
    CryptoService.resetIdleTimer();
    // Cache raw private key in Keychain for auto-unlock on app restart
    // Must await — matches unlockWithRawKey() invariant; crash before write = key loss
    await _cachePrivKeyToKeychain().catch(e => console.warn('[CryptoService] Keychain cache failed:', e?.message));
    _emit('unlocked');
    CryptoService.publishIdentityKey().catch(() => {});
    CryptoService.ensureEd25519KeyRegistered().catch(() => {});
    return true;
  } catch (e) {
    if (e?.code === 'RATE_LIMITED') throw e;
    console.warn('[CryptoService] _initWithPassword error:', e?.message || e);
    return false;
  }
}

async function _initWithKek(kekKey) {
  try {
    const u = await _resolveUsername();
    const keysData = await StorageService.getIdentity(u);
    if (!keysData) return false;

    const { encrypted_private_key, public_key } = keysData;
    if (!encrypted_private_key) return false;

    // Reuse CryptoManager path so key fields are set consistently.
    const ok = await cryptoManager.initializeUserKeyWithKek(
      encrypted_private_key,
      kekKey,
      public_key,
    );
    if (!ok) return false;

    _deriveSigningSeed();
    _initialized = true;
    _unlocked = true;
    CryptoService.resetIdleTimer();
    _emit('unlocked');
    // Auto-publish identity key to server keyring (fire-and-forget)
    CryptoService.publishIdentityKey().catch(() => {});
    CryptoService.ensureEd25519KeyRegistered().catch(() => {});
    return true;
  } catch (_e) {
    return false;
  }
}

/**
 * Cache raw private key in Keychain for auto-unlock on app restart.
 * The key is protected by Android Keystore (hardware-backed on most devices).
 */
async function _cachePrivKeyToKeychain() {
  const pk = cryptoManager.userPrivateKey?.priv;
  const pub = cryptoManager.userPublicKeyB64;
  if (!pk || !pub) return;
  const b64 = CryptoUtils.arrayBufferToBase64(pk);
  await StorageService.setCachedPrivKey({ b64, pub });
}

/**
 * Try to restore crypto from cached private key in Keychain.
 * Returns true if unlock succeeded.
 */
async function _tryAutoUnlockFromKeychain() {
  let raw = null;
  try {
    const cached = await StorageService.getCachedPrivKey();
    if (!cached?.b64 || !cached?.pub) return false;
    raw = new Uint8Array(CryptoUtils.base64ToArrayBuffer(cached.b64));
    if (raw.length !== 32) { raw.fill(0); return false; }
    const ok = await cryptoManager.initializeUserKeyFromRaw(raw, cached.pub);
    raw.fill(0); // wipe temporary copy — initializeUserKeyFromRaw makes its own copy
    if (!ok) return false;
    _deriveSigningSeed();
    _initialized = true;
    _unlocked = true;
    CryptoService.resetIdleTimer();
    _emit('unlocked');
    CryptoService.publishIdentityKey().catch(() => {});
    CryptoService.ensureEd25519KeyRegistered().catch(() => {});
    return true;
  } catch (_e) {
    if (raw) raw.fill(0);
    return false;
  }
}

async function _promptPassword(reason) {
  if (_promptPasswordFn) {
    return _promptPasswordFn(reason);
  }
  // Fallback: show native Alert (no input; user must implement _promptPasswordFn)
  return new Promise((resolve) => {
    Alert.alert(
      'Unlock required',
      reason || 'Enter your password to decrypt messages.',
      [{ text: 'Cancel', onPress: () => resolve(null), style: 'cancel' }],
    );
  });
}

/**
 * Load room key archive from server (all key versions for a room).
 * Mirrors extension's loadRoomKeyArchiveFromServer().
 */
async function _loadRoomKeyArchiveFromServer(roomId) {
  if (!CryptoService.isReady()) return;
  try {
    const archive = await NetworkService.getRoomKeyArchive(roomId);
    if (!Array.isArray(archive) || !archive.length) return;

    let loaded = 0;
    for (const entry of archive) {
      const encKey = entry.encrypted_room_key;
      const kid = entry.key_id;
      if (!encKey) continue;
      // An archived key opens old messages, so a forged one is just as useful
      // to an attacker as a current one.
      if (!await _checkWrapSignature(encKey, { scope: 'room', scopeId: roomId, keyId: kid || '' })) continue;
      try {
        const keyB64 = await CryptoUtils.decryptRoomKeyForUser(
          cryptoManager.userPrivateKey,
          encKey,
        );
        if (kid) {
          await cryptoManager.loadArchivedKey(roomId, kid, keyB64);
        } else {
          await cryptoManager.loadRoomKey(roomId, keyB64);
        }
        loaded++;
      } catch (_e) {
        // Skip keys we can't decrypt (e.g. encrypted for a different public key version)
      }
    }
    if (loaded > 0) {
      console.log(`[KeyArchive] Restored ${loaded} key(s) from server for room ${roomId}`);
      await _persistRoomKeyArchive(roomId);
      _emit('room_key_loaded', { roomId });
    }
  } catch (e) {
    if (e?.status !== 404) {
      console.warn('[KeyArchive] server load failed:', e?.message);
    }
  }
}

async function _persistRoomKeyArchive(roomId) {
  try {
    const archiveB64 = cryptoManager.roomKeyArchiveB64.get(roomId);
    if (!archiveB64) return;
    const entries = [];
    archiveB64.forEach((b64, kid) => {
      if (b64) entries.push({ kid, b64 });
    });
    await StorageService.setRoomKeyArchive(roomId, entries);
  } catch (_e) { /* ignore */ }
}

function _clearLockTimer() {
  if (_lockTimer) {
    clearTimeout(_lockTimer);
    _lockTimer = null;
  }
}

function _emit(event, data) {
  _listeners.forEach(l => {
    if (l.event === event) {
      try { l.fn(data); } catch (_e) { /* ignore */ }
    }
  });
}

/**
 * Wait for CryptoService to become ready (e.g. Keychain auto-unlock in progress).
 * Resolves true when ready, false on timeout. Uses a bounded timeout to prevent
 * indefinite hangs — callers must handle the false case gracefully.
 * @param {number} timeoutMs — max wait time (capped at 10 000 ms for safety)
 * @returns {Promise<boolean>}
 */
function _waitForReady(timeoutMs = 5000) {
  if (CryptoService.isReady()) return Promise.resolve(true);
  const cap = Math.min(Math.max(timeoutMs, 0), 10000);
  return new Promise(resolve => {
    let timer = null;
    const unsub = CryptoService.on('unlocked', () => {
      if (timer) clearTimeout(timer);
      unsub();
      resolve(true);
    });
    timer = setTimeout(() => {
      unsub();
      resolve(false);
    }, cap);
  });
}

// ==============================
// kid computation (identity key ID)
// ==============================

async function _kidFromPublicKeyB64(publicKeyB64) {
  const raw = CryptoUtils.base64ToArrayBuffer(publicKeyB64);
  const digest = await crypto.subtle.digest('SHA-256', raw);
  const u8 = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, '0');
  return hex.slice(0, 32); // first 16 bytes → 32 hex chars
}

// ==============================
// TOFU — Trust On First Use
// ==============================

/**
 * Check if peer's public key fingerprint has changed since last known.
 * Returns { changed: true/false, username } or null if skipped.
 */
async function _checkPeerKeyChanged(peerUsername, { force = false, peerPublicKeyB64 = null } = {}) {
  // Resolved, never read straight off NetworkService: that field is empty until
  // a server answers the login with a name, and every pin is addressed by it.
  // Returning null here is not "no problem" - it is "cannot tell", and the
  // caller that shares keys treats it as a refusal.
  const me = await _resolveUsername();
  if (!me) return null;
  const peer = String(peerUsername || '').trim();
  if (!peer || peer.toLowerCase() === me.toLowerCase()) return null;

  const peerLower = peer.toLowerCase();
  const now = Date.now();
  const lastTs = _kcLastChecked.get(peerLower) || 0;
  if (!force && (now - lastTs < _KC_CHECK_TTL_MS)) return null;
  _kcLastChecked.set(peerLower, now);

  if (!CryptoService.isReady()) return null;

  try {
    const peerPub = String(peerPublicKeyB64 || '').trim()
      || (await NetworkService.fetchPeerKey(peer))?.public_key;
    if (!peerPub) return null;

    const peerFp = await CryptoUtils.fingerprintPublicKey(peerPub);
    const island = await _pinScope();
    const knownFp = await StorageService.getKnownFingerprint(island, me, peer);

    if (!knownFp) {
      // First time seeing this peer — store fingerprint, no alert
      await StorageService.setKnownFingerprint(island, me, peer, peerFp);
      return { changed: false, username: peer };
    }

    if (knownFp === peerFp) {
      // Same key — clear any stale :changed flag
      try { await StorageService.removeKeyChanged(island, me, peer); } catch (_e) {}
      return { changed: false, username: peer };
    }

    // Silent migration from the legacy fingerprint format. Every pin written
    // by an older build hashed the base64 text rather than the key bytes; if
    // the stored value is the legacy hash of THIS key, nothing changed but the
    // format. Alerting here would cry wolf for every existing contact at once,
    // which is the fastest way to teach users to ignore the warning.
    const legacyFp = await CryptoUtils._fingerprintPublicKeyLegacy(peerPub);
    if (knownFp === legacyFp) {
      await StorageService.setKnownFingerprint(island, me, peer, peerFp);
      try { await StorageService.removeKeyChanged(island, me, peer); } catch (_e) {}
      return { changed: false, username: peer, migrated: true };
    }

    // *** KEY CHANGED ***
    // The pin is deliberately NOT advanced to the new key. Advancing it makes
    // the very next check say "same key", which cleared the flag below and let
    // the next attempt through - one refusal, then the door opens. The user has
    // to confirm the new key (verifyPeerKey) before anything is wrapped for it,
    // and until they do, every check re-detects the change. The extension
    // carries the same rule, and says so in a comment this port dropped.
    await StorageService.setKeyChanged(island, me, peer);
    // Reset verification status only (keep fingerprint + _changed intact)
    try { await StorageService.clearVerifiedFlag(island, me, peer); } catch (_e) {}

    return { changed: true, username: peer };
  } catch (e) {
    console.warn('[checkPeerKeyChanged] failed:', e?.message);
    return null;
  }
}

/**
 * Assert that the peer's key is trusted before sharing encrypted keys.
 * Throws if the key has changed and hasn't been re-verified.
 * Mirrors extension's assertPeerKeyTrustedForSharing().
 */
async function _assertPeerKeyTrustedForSharing(peerUsername, actionLabel = 'sharing encrypted key', { peerPublicKeyB64 = null } = {}) {
  const peer = String(peerUsername || '').trim();
  if (!peer) throw new Error('Missing peer username');

  const me = await _resolveUsername();
  // Self-sharing is OK (e.g. wrapping room key for own account).
  //
  // Not knowing who we are is NOT one of those cases, and it used to be: the
  // guard returned here when the name was missing, which on this client was
  // always - so a key went out wrapped for whatever public key the server
  // offered, unpinned and unannounced. That is precisely the substitution this
  // function exists to stop, so an unknown name now falls through to the
  // check, where `null` means refuse.
  if (me && peer.toLowerCase() === me.toLowerCase()) return;

  const keyCheck = await _checkPeerKeyChanged(peer, { force: true, peerPublicKeyB64 });

  if (keyCheck === null) {
    throw new Error(
      `Unable to verify trust state for "${peer}". ` +
      `Open Safety Number and verify before ${actionLabel}.`
    );
  }

  if (keyCheck.changed) {
    throw new Error(
      `Public key for "${peer}" has changed since last known. ` +
      `Verify safety numbers before ${actionLabel}.`
    );
  }

  // Check persistent :changed flag — without this check, the block above only fires
  // in the narrow window of first detection. Once the fingerprint is updated,
  // keyCheck.changed becomes false and sharing would be allowed even without re-verification.
  try {
    const stillChanged = await StorageService.getKeyChanged(await _pinScope(), me || keyCheck.username, peer);
    if (stillChanged) {
      throw new Error(
        `Public key for "${peer}" has recently changed and requires re-verification. ` +
        `Open Safety Numbers and verify before ${actionLabel}.`
      );
    }
  } catch (e) {
    if (String(e?.message || '').includes('re-verification')) throw e;
    // Storage error — fail closed: do NOT allow key sharing without verification
    console.warn('[CryptoService] TOFU storage check failed — blocking key share:', e?.message);
    throw new Error(`Cannot verify trust state for "${peer}" due to storage error. Retry or re-verify safety numbers.`);
  }
}

export default CryptoService;
