// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * crypto-manager.js
 *
 * Manages encryption state for the current user.
 * Supports key versioning: multiple keys per room for backward-compatible decryption.
 *
 * Identity key: X25519 (32-byte public key, stored as base64)
 * Room/DM keys: AES-256-GCM (wrapped via X25519 ECDH)
 */

class CryptoManager {
  constructor() {
    this.userPrivateKey = null;      // CryptoKey (X25519 private)
    this.userPublicKey = null;       // CryptoKey (X25519 public)
    this.userPublicKeyB64 = null;    // base64 string of raw 32-byte public key
    this.ed25519Seed = null;         // Uint8Array(32) — Ed25519 signing seed (derived from X25519 priv via HKDF)

    // --- Current (latest) keys ---
    this.roomKeys = new Map();            // room_id -> CryptoKey (AES, non-extractable)
    this.roomKeysExportable = new Map();  // room_id -> CryptoKey (AES, extractable)

    // --- Key versioning ---
    this.roomKeyIds = new Map();          // room_id -> kid string (latest key's fingerprint)
    this.roomKeyArchive = new Map();      // room_id -> Map<kid, CryptoKey> (all known keys)
    this.roomKeyArchiveB64 = new Map();   // room_id -> Map<kid, base64> (for persistence)
  }

  async initializeUserKey(encrypted, password, publicKeyB64, expectedUsername = "") {
    try {
      this.userPrivateKey = await CryptoUtils.decryptPrivateKey(encrypted, password, { expectedUsername });

      if (publicKeyB64) {
        this.userPublicKeyB64 = publicKeyB64;
        this.userPublicKey = await CryptoUtils.importPublicKey(publicKeyB64);
      }

      console.log("User private key decrypted");
      return true;
    } catch (error) {
      console.error("Failed to decrypt user private key:", error);
      this.userPrivateKey = null;
      this.userPublicKey = null;
      this.userPublicKeyB64 = null;
      return false;
    }
  }

  /**
   * Initialize user keys using a pre-derived AES key (KEK) instead of a password string.
   */
  async initializeUserKeyWithKek(encrypted, aesKey, publicKeyB64, expectedUsername = "") {
    try {
      const { privateKey, ed25519Seed } = await CryptoUtils.decryptPrivateKeyWithAesKeyAll(
        encrypted, aesKey, { expectedUsername }
      );
      this.userPrivateKey = privateKey;
      this.ed25519Seed = ed25519Seed;

      if (publicKeyB64) {
        this.userPublicKeyB64 = publicKeyB64;
        this.userPublicKey = await CryptoUtils.importPublicKey(publicKeyB64);
      }

      console.log("User private key decrypted (KEK)");
      return true;
    } catch (error) {
      console.error("Failed to decrypt user private key (KEK):", error);
      this.userPrivateKey = null;
      this.userPublicKey = null;
      this.userPublicKeyB64 = null;
      this.ed25519Seed = null;
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
        console.warn("Failed to export old key for archive:", e);
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

  /**
   * Create a new room key. Archives the previous key if one exists.
   * Returns raw base64 for ECDH-wrapping and server upload.
   */
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

  /**
   * Load existing room key (raw base64).
   */
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

      console.log(`Room key loaded for room ${roomId} (kid: ${kid})`);
      return true;
    } catch (error) {
      console.error(`Failed to load room key for room ${roomId}:`, error);
      return false;
    }
  }

  async loadArchivedKey(roomId, kid, keyBase64) {
    try {
      const roomKey = await CryptoUtils.importRoomKey(keyBase64);
      await this._registerInArchive(roomId, kid, roomKey, keyBase64);
      return true;
    } catch (e) {
      console.warn(`Failed to load archived key ${kid} for room ${roomId}:`, e);
      return false;
    }
  }

  /**
   * Get raw base64 room key (for ECDH-wrapping / sharing)
   */
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
    const aad = kid ? new TextEncoder().encode(String(kid)) : undefined;
    const encrypted = await CryptoUtils.encryptMessage(roomKey, plaintext, aad);

    const out = { encrypted: true, iv: encrypted.iv, data: encrypted.data, kid };
    if (aad) out.aad_v1 = true;
    return JSON.stringify(out);
  }

  async decryptMessage(roomId, encryptedText, ivBase64, kid) {
    let iv, data;
    // NOTE: we intentionally do NOT read an aad_v1 flag from the payload
    // anymore. AAD policy is decided locally based on whether a `kid` is
    // present: that way the server cannot strip a flag and force us down
    // the unauthenticated path. aad_v1 remains in the wire format purely
    // as a legacy hint and is ignored on the decrypt side.

    if (typeof ivBase64 === "string" && ivBase64.length) {
      iv = ivBase64;
      data = encryptedText;
    } else {
      let payload = encryptedText;
      if (typeof payload === "string") {
        const s = payload.trim();
        if (s.startsWith("{")) {
          try { payload = JSON.parse(s); } catch {}
        }
      }

      if (payload && typeof payload === "object" && payload.iv && payload.data) {
        iv = payload.iv;
        data = payload.data;
        if (!kid && payload.kid) kid = payload.kid;
      } else {
        throw new Error("Unsupported encrypted message format");
      }
    }

    // Client-controlled AAD policy: if a kid is present, the sender was
    // running the versioned protocol (encryptMessage always binds AAD=kid
    // when a kid exists). Try the AAD-bound decryption first. Only on
    // failure do we fall back to the no-AAD path for truly legacy messages
    // that predated the kid field entirely.
    const aad = kid ? new TextEncoder().encode(String(kid)) : undefined;

    let primaryKey = null;
    if (kid) {
      const archive = this.roomKeyArchive.get(roomId);
      if (archive) primaryKey = archive.get(kid);
    }
    if (!primaryKey) {
      primaryKey = this.roomKeys.get(roomId);
    }
    if (!primaryKey) throw new Error(`No room key for room ${roomId}`);

    // Path 1: kid present → enforce AAD binding. On failure, do NOT try
    // other keys or strip AAD: aad_v1 binds this ciphertext to THIS kid,
    // and any other result would mean a forgery/mis-routing attempt.
    if (aad) {
      try {
        return await CryptoUtils.decryptMessage(primaryKey, { iv, data }, aad);
      } catch (err) {
        // Narrow legacy-compat exception: the sender might have been an
        // old client that used kid-in-envelope but NOT AAD-bound encrypt.
        // Retry the same primary key without AAD — still only that key,
        // still only because we can't tell the two formats apart on wire.
        try {
          return await CryptoUtils.decryptMessage(primaryKey, { iv, data });
        } catch {
          throw err;
        }
      }
    }

    // Path 2: no kid at all → this is an ancient message from before the
    // kid field existed. Try every archived key without AAD.
    try {
      return await CryptoUtils.decryptMessage(primaryKey, { iv, data });
    } catch (primaryError) {
      const archive = this.roomKeyArchive.get(roomId);
      if (archive && archive.size > 0) {
        for (const [, archKey] of archive) {
          if (archKey === primaryKey) continue;
          try {
            return await CryptoUtils.decryptMessage(archKey, { iv, data });
          } catch {}
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

  /**
   * Drop references to all values inside a Map (or Map of Maps) and clear it.
   *
   * IMPORTANT: This is *not* a cryptographic wipe. JS strings are immutable
   * and CryptoKey contents are opaque to JS, so we cannot zero the underlying
   * bytes. All this does is remove references so the GC is free to reclaim
   * the memory at some unspecified later time. Treat this as best-effort
   * accelerated GC, not as secure erasure.
   */
  _dropMapRefs(map) {
    for (const [k, v] of map) {
      if (v instanceof Map) {
        this._dropMapRefs(v);
      }
      map.set(k, null);
    }
    map.clear();
  }

  /**
   * Flush in-memory base64 key material for a room after it has been
   * persisted to chrome.storage.local. Keeps CryptoKey objects intact
   * for decryption, but removes raw key strings from memory.
   */
  flushArchiveB64(roomId) {
    const sub = this.roomKeyArchiveB64.get(roomId);
    if (sub) {
      for (const k of sub.keys()) sub.set(k, null);
      sub.clear();
    }
    this.roomKeyArchiveB64.delete(roomId);
  }

  clear() {
    this.userPrivateKey = null;
    this.userPublicKey = null;
    this.userPublicKeyB64 = null;
    if (this.ed25519Seed) { this.ed25519Seed.fill(0); this.ed25519Seed = null; }
    this._dropMapRefs(this.roomKeys);
    this._dropMapRefs(this.roomKeysExportable);
    this._dropMapRefs(this.roomKeyIds);
    this._dropMapRefs(this.roomKeyArchive);
    this._dropMapRefs(this.roomKeyArchiveB64);
    console.log("Crypto state cleared (wiped)");
  }
}

// Create isolated instance + expose minimal facade
(() => {
  const g = globalThis;
  const root = (g.__wsCrypto = g.__wsCrypto || {});

  const manager = new CryptoManager();

  const facade = Object.freeze({
    initializeUserKey: manager.initializeUserKey.bind(manager),
    initializeUserKeyWithKek: manager.initializeUserKeyWithKek?.bind(manager),

    createRoomKey: manager.createRoomKey.bind(manager),
    loadRoomKey: manager.loadRoomKey.bind(manager),
    loadArchivedKey: manager.loadArchivedKey.bind(manager),
    exportRoomKeyForSharing: manager.exportRoomKeyForSharing.bind(manager),

    encryptMessage: manager.encryptMessage.bind(manager),
    decryptMessage: manager.decryptMessage.bind(manager),

    isReady: manager.isReady.bind(manager),
    clearUnlocked: manager.clearUnlocked.bind(manager),
    clear: manager.clear?.bind(manager),
    flushArchiveB64: manager.flushArchiveB64?.bind(manager),

    get roomKeys() { return manager.roomKeys; },
    get roomKeysExportable() { return manager.roomKeysExportable; },

    get roomKeyIds() { return manager.roomKeyIds; },
    get roomKeyArchive() { return manager.roomKeyArchive; },
    get roomKeyArchiveB64() { return manager.roomKeyArchiveB64; },

    get userPrivateKey() { return manager.userPrivateKey; },
    // X25519 public key as base64 (primary name)
    get userPublicKeyB64() { return manager.userPublicKeyB64; },
    // Backward-compat alias (panel-crypto.js / panel-ui.js may still reference this)
    get userPublicKeyPem() { return manager.userPublicKeyB64; },
    // Ed25519 signing seed (Uint8Array, 32 bytes) — null when locked
    get ed25519Seed() { return manager.ed25519Seed; },
  });

  Object.defineProperty(root, "manager", {
    value: facade,
    writable: false,
    configurable: false,
    enumerable: false,
  });
})();
