// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * CryptoManager.js — адаптация crypto-manager.js для React Native
 *
 * Изменения vs оригинал:
 *  - Добавлен import CryptoUtils из локального модуля
 *  - Добавлен ES-module export (export default CryptoManager)
 *  - Убран globalThis.__wsCrypto (синглтон создаётся через src/crypto/index.js)
 *
 * Identity key: X25519 (32-byte public key, stored as base64)
 * Room/DM keys: AES-256-GCM (wrapped via X25519 ECDH)
 */

import CryptoUtils from './CryptoUtils';

class CryptoManager {
  constructor() {
    this.userPrivateKey = null;      // CryptoKey (X25519 private)
    this.userPublicKey = null;       // CryptoKey (X25519 public)
    this.userPublicKeyB64 = null;    // base64 string of raw 32-byte public key

    // --- Current (latest) keys ---
    this.roomKeys = new Map();            // room_id -> CryptoKey (AES, non-extractable)
    this.roomKeysExportable = new Map();  // room_id -> CryptoKey (AES, extractable)

    // --- Key versioning ---
    this.roomKeyIds = new Map();          // room_id -> kid string (latest key's fingerprint)
    this.roomKeyArchive = new Map();      // room_id -> Map<kid, CryptoKey> (all known keys)
    this.roomKeyArchiveB64 = new Map();   // room_id -> Map<kid, base64> (for persistence)
  }

  async initializeUserKey(encrypted, password, publicKeyB64) {
    try {
      this.userPrivateKey = await CryptoUtils.decryptPrivateKey(encrypted, password);

      if (publicKeyB64) {
        this.userPublicKeyB64 = publicKeyB64;
        this.userPublicKey = await CryptoUtils.importPublicKey(publicKeyB64);
      }

      return true;
    } catch (error) {
      console.warn('[CryptoManager] initializeUserKey failed:', error?.message);
      this.userPrivateKey = null;
      this.userPublicKey = null;
      this.userPublicKeyB64 = null;
      return false;
    }
  }

  async initializeUserKeyWithKek(encrypted, aesKey, publicKeyB64) {
    try {
      this.userPrivateKey = await CryptoUtils.decryptPrivateKeyWithAesKey(encrypted, aesKey);

      if (publicKeyB64) {
        this.userPublicKeyB64 = publicKeyB64;
        this.userPublicKey = await CryptoUtils.importPublicKey(publicKeyB64);
      }

      return true;
    } catch (error) {
      console.warn('[CryptoManager] initializeUserKeyWithKek failed:', error?.message);
      this.userPrivateKey = null;
      this.userPublicKey = null;
      this.userPublicKeyB64 = null;
      return false;
    }
  }

  async initializeUserKeyFromRaw(privRaw, publicKeyB64) {
    try {
      // COPY privRaw — caller may .fill(0) the original after this returns.
      const privCopy = new Uint8Array(privRaw);
      // Make priv non-enumerable to reduce exposure (won't appear in JSON.stringify/Object.keys)
      const key = { _x25519: true };
      Object.defineProperty(key, 'priv', { value: privCopy, enumerable: false, configurable: false, writable: false });
      this.userPrivateKey = key;
      if (publicKeyB64) {
        this.userPublicKeyB64 = publicKeyB64;
        this.userPublicKey = await CryptoUtils.importPublicKey(publicKeyB64);
      }
      return true;
    } catch (error) {
      console.warn('[CryptoManager] initializeUserKeyFromRaw failed:', error?.message);
      this.userPrivateKey = null;
      this.userPublicKey = null;
      this.userPublicKeyB64 = null;
      return false;
    }
  }

  // ============================
  // Key archiving helpers
  // ============================

  async _archiveCurrentKey(roomId) {
    const oldKid = this.roomKeyIds.get(roomId);
    const oldKey = this.roomKeys.get(roomId);
    const oldExportable = this.roomKeysExportable.get(roomId);

    if (!oldKid || !oldKey) return;

    if (!this.roomKeyArchive.has(roomId)) this.roomKeyArchive.set(roomId, new Map());
    this.roomKeyArchive.get(roomId).set(oldKid, oldKey);

    if (oldExportable) {
      try {
        const oldB64 = await CryptoUtils.exportRoomKey(oldExportable);
        if (!this.roomKeyArchiveB64.has(roomId)) this.roomKeyArchiveB64.set(roomId, new Map());
        this.roomKeyArchiveB64.get(roomId).set(oldKid, oldB64);
      } catch (e) {
        console.warn('[CryptoManager] exportOldKey failed:', e?.message);
      }
    }
  }

  async _registerInArchive(roomId, kid, nonExtractableKey, base64) {
    if (!this.roomKeyArchive.has(roomId)) this.roomKeyArchive.set(roomId, new Map());
    if (!this.roomKeyArchiveB64.has(roomId)) this.roomKeyArchiveB64.set(roomId, new Map());

    this.roomKeyArchive.get(roomId).set(kid, nonExtractableKey);
    if (base64) {
      this.roomKeyArchiveB64.get(roomId).set(kid, base64);
    }
  }

  // ============================
  // Room key management
  // ============================

  async createRoomKey(roomId) {
    await this._archiveCurrentKey(roomId);

    const tmp = await CryptoUtils.generateRoomKey(true);
    const rawB64 = await CryptoUtils.exportRoomKey(tmp);
    const roomKey = await CryptoUtils.importRoomKey(rawB64);
    const kid = await CryptoUtils.fingerprintRoomKeyBase64(rawB64);

    this.roomKeys.set(roomId, roomKey);
    this.roomKeysExportable.set(roomId, tmp);
    this.roomKeyIds.set(roomId, kid);

    await this._registerInArchive(roomId, kid, roomKey, rawB64);

    return rawB64;
  }

  async loadRoomKey(roomId, roomKeyBase64) {
    try {
      const kid = await CryptoUtils.fingerprintRoomKeyBase64(roomKeyBase64);

      const oldKid = this.roomKeyIds.get(roomId);
      if (oldKid && oldKid !== kid) {
        await this._archiveCurrentKey(roomId);
      }

      const roomKey = await CryptoUtils.importRoomKey(roomKeyBase64);
      const exportable = await CryptoUtils.importRoomKeyExportable(roomKeyBase64);

      this.roomKeys.set(roomId, roomKey);
      this.roomKeysExportable.set(roomId, exportable);
      this.roomKeyIds.set(roomId, kid);

      await this._registerInArchive(roomId, kid, roomKey, roomKeyBase64);

      return true;
    } catch (error) {
      console.warn(`[CryptoManager] loadRoomKey failed for room ${roomId}:`, error?.message);
      return false;
    }
  }

  async loadArchivedKey(roomId, kid, keyBase64) {
    try {
      const roomKey = await CryptoUtils.importRoomKey(keyBase64);
      await this._registerInArchive(roomId, kid, roomKey, keyBase64);
      return true;
    } catch (e) {
      console.warn(`[CryptoManager] loadArchivedKey failed kid=${kid} room=${roomId}:`, e?.message);
      return false;
    }
  }

  async exportRoomKeyForSharing(roomId) {
    const exportable = this.roomKeysExportable.get(roomId);
    if (!exportable) return null;
    return await CryptoUtils.exportRoomKey(exportable);
  }

  // ============================
  // Encrypt / Decrypt with key versioning
  // ============================

  async encryptMessage(roomId, plaintext) {
    const roomKey = this.roomKeys.get(roomId);
    if (!roomKey) throw new Error(`No room key for room ${roomId}`);

    const kid = this.roomKeyIds.get(roomId) || undefined;
    // Bind kid to the ciphertext via AES-GCM AAD.
    // This prevents the server from swapping the kid field to point to a different
    // (e.g., weaker or previously rotated) key version.
    // aad_v1 flag lets older clients fall back gracefully to no-AAD decryption.
    const kidBytes = kid != null ? new TextEncoder().encode(String(kid)) : undefined;
    const encrypted = await CryptoUtils.encryptMessage(roomKey, plaintext, kidBytes);

    return JSON.stringify({
      encrypted: true,
      iv: encrypted.iv,
      data: encrypted.data,
      kid,
      ...(kidBytes ? { aad_v1: true } : {}),
    });
  }

  async decryptMessage(roomId, encryptedText, ivBase64, kid) {
    let iv, data, aad_v1 = false;

    if (typeof ivBase64 === 'string' && ivBase64.length) {
      iv = ivBase64;
      data = encryptedText;
    } else {
      let payload = encryptedText;
      if (typeof payload === 'string') {
        const s = payload.trim();
        if (s.startsWith('{')) {
          try { payload = JSON.parse(s); } catch (_e) {}
        }
      }

      if (payload && typeof payload === 'object' && payload.iv && payload.data) {
        iv = payload.iv;
        data = payload.data;
        if (!kid && payload.kid) kid = payload.kid;
        if (payload.aad_v1) aad_v1 = true;
      } else {
        throw new Error('Unsupported encrypted message format');
      }
    }

    // Reconstruct AAD: same derivation as encryptMessage (kid bytes).
    // Messages without aad_v1 are old-format — decrypt without AAD.
    const kidBytes = (aad_v1 && kid != null) ? new TextEncoder().encode(String(kid)) : undefined;

    let primaryKey = null;

    if (kid) {
      const archive = this.roomKeyArchive.get(roomId);
      if (archive) primaryKey = archive.get(kid);
    }

    if (!primaryKey) {
      primaryKey = this.roomKeys.get(roomId);
    }

    if (!primaryKey) throw new Error(`No room key for room ${roomId}`);

    try {
      return await CryptoUtils.decryptMessage(primaryKey, { iv, data }, kidBytes);
    } catch (primaryError) {
      const archive = this.roomKeyArchive.get(roomId);
      if (archive && archive.size > 0) {
        // Scan the full archive — AES-GCM decrypt is ~5ms per try, and this only runs
        // on decrypt failures for messages without a valid kid (rare).
        for (const [, archKey] of archive) {
          if (archKey === primaryKey) continue;
          try {
            return await CryptoUtils.decryptMessage(archKey, { iv, data }, kidBytes);
          } catch (_e) {}
        }
      }
      throw primaryError;
    }
  }

  isReady() {
    return !!this.userPrivateKey;
  }

  clearUnlocked() {
    this.clear();
  }

  _wipeMap(map) {
    for (const [k, v] of map) {
      if (v instanceof Map) {
        this._wipeMap(v);
      }
      map.set(k, null);
    }
    map.clear();
  }

  flushArchiveB64(roomId) {
    const sub = this.roomKeyArchiveB64.get(roomId);
    if (sub) {
      for (const k of sub.keys()) sub.set(k, null);
      sub.clear();
    }
    this.roomKeyArchiveB64.delete(roomId);
  }

  clear() {
    // Zeroize raw private key bytes before dropping the reference
    if (this.userPrivateKey?.priv instanceof Uint8Array) {
      this.userPrivateKey.priv.fill(0);
    }
    this.userPrivateKey = null;
    this.userPublicKey = null;
    this.userPublicKeyB64 = null;
    this._wipeMap(this.roomKeys);
    this._wipeMap(this.roomKeysExportable);
    this._wipeMap(this.roomKeyIds);
    this._wipeMap(this.roomKeyArchive);
    this._wipeMap(this.roomKeyArchiveB64);
    console.log('Crypto state cleared (wiped)');
  }

  // Backward-compat alias
  get userPublicKeyPem() { return this.userPublicKeyB64; }
}

export default CryptoManager;
