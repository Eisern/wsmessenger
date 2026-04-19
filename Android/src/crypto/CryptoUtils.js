// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * CryptoUtils.js — адаптация crypto-utils.js для React Native
 *
 * Изменения vs оригинал:
 *  - Добавлен ES-module export (export default CryptoUtils)
 *  - globalThis.__wsCrypto сохранён для обратной совместимости
 *  - crypto.subtle берётся из react-native-quick-crypto (глобальный polyfill)
 *
 * Key wrapping format (version 0x02):
 *   [0]      : 0x02 — version tag (X25519 ECDH)
 *   [1..32]  : ephemeral X25519 public key (32 bytes)
 *   [33..44] : AES-GCM IV (12 bytes)
 *   [45..]   : AES-GCM ciphertext (plaintext + 16-byte auth tag)
 */

// Lazy proxy — reads globalThis.crypto at call time, not at module init time.
// (react-native-quick-crypto polyfill is installed after module evaluation)
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

// Pure-JS X25519: react-native-quick-crypto does not implement subtle.generateKey/deriveBits
// for X25519, so we use @noble/curves which works in any JS runtime.
const { x25519, ed25519 } = require('@noble/curves/ed25519');

// TextDecoder polyfill: Hermes (RN) may not expose TextDecoder globally.
function _utf8Decode(buffer) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder('utf-8').decode(
      buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    );
  }
  // Manual UTF-8 decode — handles all Unicode including emoji (4-byte sequences)
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let str = '';
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    if (b < 0x80) {
      str += String.fromCharCode(b);
      i += 1;
    } else if ((b & 0xE0) === 0xC0) {
      str += String.fromCharCode(((b & 0x1F) << 6) | (bytes[i + 1] & 0x3F));
      i += 2;
    } else if ((b & 0xF0) === 0xE0) {
      str += String.fromCharCode(((b & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F));
      i += 3;
    } else {
      // 4-byte sequence → surrogate pair
      const cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
      str += String.fromCodePoint(cp);
      i += 4;
    }
  }
  return str;
}

// Pure-JS HKDF: react-native-quick-crypto does not implement subtle.deriveKey for HKDF.
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256: _sha256 } = require('@noble/hashes/sha2');

// Argon2id: prefer native react-native-argon2 (C library, ~100x faster),
// fall back to pure-JS @noble/hashes/argon2 if native module unavailable.
const { argon2id: _argon2id_js } = require('@noble/hashes/argon2');
let _nativeArgon2 = null;
try {
  _nativeArgon2 = require('react-native-argon2').default;
} catch (_) { /* native module not linked — will use pure-JS fallback */ }

// BIP39: @scure/bip39 provides mnemonic decode without embedding the 2048-word list inline.
const { mnemonicToEntropy, entropyToMnemonic } = require('@scure/bip39');
const { wordlist: _BIP39_ENGLISH } = require('@scure/bip39/wordlists/english');

// KDF self-test state — set once at startup by runKdfSelfTest().
// If the test failed, derivation is blocked (fail-closed, matches extension argon2-selftest.js).
let _kdfSelfTestResult = null; // null = not run yet; { ok: true, ... } | { ok: false, error }

const CryptoUtils = {

  // ============================
  // Constants
  // ============================
  _WRAP_VERSION: 0x02,
  _WRAP_EPHEM_LEN: 32,
  _WRAP_IV_LEN: 12,
  _WRAP_HEADER: 1 + 32 + 12,  // 45 bytes before ciphertext

  // ============================
  // KDF self-test (fail-closed — mirrors extension argon2-selftest.js)
  // ============================

  /**
   * Run the KDF self-test with fixed inputs. Blocks subsequent KDF use on failure.
   * Checks (in order):
   *   1. @noble/hashes/argon2 produces a 32-byte non-trivial output.
   *   2. If native react-native-argon2 is present, its output equals the JS output
   *      byte-for-byte (detects a backdoored/misconfigured native module — e.g., wrong
   *      params, reduced rounds, or returning the password itself).
   * Call once at startup before any password derivation.
   */
  async runKdfSelfTest() {
    if (_kdfSelfTestResult) return _kdfSelfTestResult;
    try {
      const TEST_PASS = 'wsapp-argon2-selftest';
      const TEST_SALT = new TextEncoder().encode('wsapp-selftest-salt-16b');
      // Light params for quick smoke-test — still exercises the full Argon2id state machine.
      // Cross-verify native↔JS on matching params is what catches a tampered native module;
      // production KDF uses real params (t=3, m=65536) elsewhere.
      const PARAMS = { t: 1, m: 4096, p: 1, dkLen: 32 };

      const passU8 = new TextEncoder().encode(TEST_PASS);
      const jsOut = _argon2id_js(passU8, TEST_SALT, PARAMS);
      if (!(jsOut instanceof Uint8Array) || jsOut.byteLength !== 32) {
        throw new Error('Argon2id JS output shape invalid');
      }
      // Reject trivial outputs (all zeros, echo of password, echo of salt).
      let nonZero = 0;
      for (let i = 0; i < jsOut.length; i++) nonZero |= jsOut[i];
      if (!nonZero) throw new Error('Argon2id JS output is all zeros');
      if (jsOut.length === TEST_SALT.length) {
        let eq = 1;
        for (let i = 0; i < jsOut.length; i++) if (jsOut[i] !== TEST_SALT[i]) { eq = 0; break; }
        if (eq) throw new Error('Argon2id JS output equals salt');
      }

      if (_nativeArgon2) {
        try {
          const saltHex = Array.from(TEST_SALT).map(b => b.toString(16).padStart(2, '0')).join('');
          const nativeRes = await _nativeArgon2(TEST_PASS, saltHex, {
            iterations: PARAMS.t,
            memory: PARAMS.m,
            parallelism: PARAMS.p,
            hashLength: PARAMS.dkLen,
            mode: 'argon2id',
            saltEncoding: 'hex',
          });
          const hex = nativeRes.rawHash;
          if (typeof hex !== 'string' || hex.length !== jsOut.length * 2) {
            throw new Error('Native Argon2id output shape invalid');
          }
          let diff = 0;
          for (let i = 0; i < jsOut.length; i++) {
            const nb = parseInt(hex.substr(i * 2, 2), 16);
            diff |= nb ^ jsOut[i];
          }
          if (diff) throw new Error('Native Argon2id output does not match JS reference');
        } catch (nativeErr) {
          // Native present but mismatched/broken → fail-closed; don't silently fall back.
          throw new Error('Native Argon2id self-test failed: ' + (nativeErr?.message || nativeErr));
        }
      }

      _kdfSelfTestResult = { ok: true, hasNative: !!_nativeArgon2 };
    } catch (e) {
      _kdfSelfTestResult = { ok: false, error: String(e?.message || e) };
    }
    return _kdfSelfTestResult;
  },

  /** Returns the cached self-test result; null if not yet run. */
  getKdfSelfTestResult() {
    return _kdfSelfTestResult;
  },

  // ============================
  // Password-based key derivation (Argon2id preferred, PBKDF2 fallback)
  // ============================

  /**
   * Check whether Argon2id is available in this runtime.
   * Native module preferred; pure-JS fallback always available.
   */
  isArgon2Available() {
    return !!_nativeArgon2 || typeof _argon2id_js === 'function';
  },

  /**
   * Derive 32 raw bytes from password using configured KDF.
   * Supports Argon2id (preferred) and PBKDF2 (fallback / legacy containers).
   *
   * @param {string} password
   * @param {string} saltBase64
   * @param {object} opts  — { name, time_cost, memory_kib, parallelism, version,
   *                           iterations, hash, preferArgon2 }
   * @returns {Promise<{raw: Uint8Array, kdf: object}>}
   */
  async deriveRawKeyFromPassword(password, saltBase64, opts = {}) {
    if (_kdfSelfTestResult && !_kdfSelfTestResult.ok) {
      throw new Error('KDF self-test failed: ' + (_kdfSelfTestResult.error || 'unknown'));
    }
    const saltU8 = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
    const pass = String(password || '');
    if (!pass) throw new Error('Password is required');
    if (saltU8.byteLength < 16) throw new Error('KDF salt too short (minimum 16 bytes)');

    const requestedNameRaw = String(opts?.name || '').trim();
    const requestedName =
      /^argon2id$/i.test(requestedNameRaw) ? 'Argon2id' :
      /^pbkdf2$/i.test(requestedNameRaw)   ? 'PBKDF2'  :
      requestedNameRaw;
    const preferArgon2 = opts?.preferArgon2 !== false;
    const kdfName = requestedName || (preferArgon2 ? 'Argon2id' : 'PBKDF2');

    // --- Argon2id path ---
    if (kdfName === 'Argon2id') {
      if (!this.isArgon2Available()) {
        throw new Error('Argon2id runtime is not available in this client');
      }

      const t = Number(opts?.time_cost)  > 0 ? Number(opts.time_cost)  : 3;
      const m = Number(opts?.memory_kib) > 0 ? Number(opts.memory_kib) : 65536;
      const p = Number(opts?.parallelism) > 0 ? Number(opts.parallelism) : 1;

      if (t < 2)         throw new Error(`Argon2id time_cost too low: ${t} (minimum 2)`);
      if (m < 32768)     throw new Error(`Argon2id memory_kib too low: ${m} (minimum 32768)`);
      if (p < 1 || p > 8) throw new Error(`Argon2id parallelism out of range: ${p}`);

      let rawOut;

      // Try native Argon2id first (C library, ~100x faster than pure JS)
      if (_nativeArgon2) {
        try {
          const saltHex = Array.from(saltU8).map(b => b.toString(16).padStart(2, '0')).join('');
          const result = await _nativeArgon2(pass, saltHex, {
            iterations: t,
            memory: m,
            parallelism: p,
            hashLength: 32,
            mode: 'argon2id',
            saltEncoding: 'hex',
          });
          // result.rawHash is a hex string
          const hex = result.rawHash;
          rawOut = new Uint8Array(hex.length / 2);
          for (let i = 0; i < rawOut.length; i++) {
            rawOut[i] = parseInt(hex.substr(i * 2, 2), 16);
          }
        } catch (nativeErr) {
          console.warn('[CryptoUtils] Native Argon2id failed, falling back to JS:', nativeErr?.message);
          rawOut = null;
        }
      }

      // Fallback to pure-JS @noble/hashes/argon2
      if (!rawOut) {
        const passU8 = new TextEncoder().encode(pass);
        rawOut = _argon2id_js(passU8, saltU8, { t, m, p, dkLen: 32 });
      }

      if (!(rawOut instanceof Uint8Array) || rawOut.byteLength !== 32) {
        throw new Error(`Argon2id output length is ${rawOut?.byteLength}, expected 32`);
      }

      return {
        raw: rawOut,
        kdf: { name: 'Argon2id', time_cost: t, memory_kib: m, parallelism: p, version: 19 },
      };
    }

    // --- PBKDF2 path (fallback / legacy) ---
    const MIN_ITERATIONS = 600_000;
    const ALLOWED_HASHES = new Set(['SHA-256', 'SHA-384', 'SHA-512']);
    const iterations = Math.max(
      Number(opts?.iterations) > 0 ? Number(opts.iterations) : 620_000,
      MIN_ITERATIONS,
    );
    let hash = String(opts?.hash || 'SHA-256').trim().toUpperCase();
    if (hash === 'SHA256') hash = 'SHA-256';
    if (hash === 'SHA384') hash = 'SHA-384';
    if (hash === 'SHA512') hash = 'SHA-512';
    if (!ALLOWED_HASHES.has(hash)) throw new Error(`KDF hash not allowed: ${hash}`);

    const passwordBuffer = new TextEncoder().encode(pass);
    const keyMaterial = await crypto.subtle.importKey(
      'raw', passwordBuffer, 'PBKDF2', false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltU8, iterations, hash },
      keyMaterial,
      256,
    );

    return {
      raw: new Uint8Array(bits),
      kdf: { name: 'PBKDF2', hash, iterations },
    };
  },

  /**
   * Derive AES-256-GCM CryptoKey from password (Argon2id preferred, PBKDF2 fallback).
   * Delegates to deriveRawKeyFromPassword and imports the result.
   */
  async deriveKeyFromPassword(password, saltBase64, opts = {}) {
    const { raw } = await this.deriveRawKeyFromPassword(password, saltBase64, opts);
    const key = await crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
    raw.fill(0); // wipe intermediate key material
    return key;
  },

  // ============================
  // X25519 Identity Key — generate / export / import
  // ============================

  async generateIdentityKeyPair() {
    const privRaw = x25519.utils.randomSecretKey();
    const pubRaw = x25519.getPublicKey(privRaw);
    return {
      publicKey: { _x25519: true, pub: pubRaw },
      privateKey: { _x25519: true, priv: privRaw },
    };
  },

  async exportPublicKey(publicKey) {
    if (publicKey?._x25519) return this.arrayBufferToBase64(publicKey.pub);
    // Fallback: CryptoKey (legacy path, not used in RN)
    const raw = await crypto.subtle.exportKey('raw', publicKey);
    return this.arrayBufferToBase64(raw);
  },

  async exportPrivateKey(privateKey) {
    if (privateKey?._x25519) return this.arrayBufferToBase64(privateKey.priv);
    // Fallback: CryptoKey (legacy path, not used in RN)
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    return this.arrayBufferToBase64(pkcs8);
  },

  async importPublicKey(base64) {
    const raw = new Uint8Array(this.base64ToArrayBuffer(base64));
    if (raw.byteLength !== 32) {
      throw new Error(
        `Invalid X25519 public key: expected 32 bytes, got ${raw.byteLength}. ` +
        'The peer may need to re-register to generate X25519 keys.'
      );
    }
    return { _x25519: true, pub: raw };
  },

  async importPrivateKey(base64) {
    const raw = new Uint8Array(this.base64ToArrayBuffer(base64));
    let privRaw;
    if (raw.byteLength === 32) {
      privRaw = raw; // raw format (new)
    } else {
      // PKCS8 format (48 bytes): header is 16 bytes, key is bytes 16-47
      privRaw = raw.slice(16);
    }
    return { _x25519: true, priv: privRaw };
  },

  // ============================
  // Encrypted private key storage (password → AES-GCM)
  // ============================

  /**
   * Deterministic JSON serialization (sorted keys, no spaces).
   */
  _stableJson(value) {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map((v) => this._stableJson(v)).join(',')}]`;
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${this._stableJson(v)}`);
    }
    return `{${parts.join(',')}}`;
  },

  _normalizePrivateKeyKdfForAad(kdf) {
    const src = kdf || {};
    const name = String(src.name || '').trim();
    const out = { name };
    if (name === 'Argon2id') {
      out.time_cost = Number(src.time_cost || 0);
      out.memory_kib = Number(src.memory_kib || 0);
      out.parallelism = Number(src.parallelism || 0);
      out.version = Number(src.version || 0);
      return out;
    }
    if (name === 'PBKDF2') {
      out.hash = String(src.hash || 'SHA-256');
      out.iterations = Number(src.iterations || 0);
      return out;
    }
    if (src.hash !== undefined) out.hash = String(src.hash);
    if (src.iterations !== undefined) out.iterations = Number(src.iterations || 0);
    return out;
  },

  /**
   * Build deterministic AAD string for key-container v3.
   */
  buildPrivateKeyContainerAAD(container) {
    const payload = {
      v: Number(container?.v || 0),
      alg: String(container?.alg || ''),
      username: String(container?.username || '').trim().toLowerCase(),
      ext_version: String(container?.ext_version || ''),
      created_at: Number(container?.created_at || 0),
      kdf: this._normalizePrivateKeyKdfForAad(container?.kdf),
    };
    return this._stableJson(payload);
  },

  /**
   * AES-GCM params for private-key container decrypt/encrypt.
   * v2: no AAD (legacy)
   * v3+: AAD is mandatory
   */
  buildPrivateKeyContainerGcmParams(container, ivBuffer) {
    const v = Number(container?.v || 0);
    const params = { name: 'AES-GCM', iv: ivBuffer };
    if (v >= 3) {
      const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(container));
      params.additionalData = aad;
    }
    return params;
  },

  /**
   * One-time migration helper: v2(no AAD) -> v3(with AAD) using already-derived AES key.
   */
  async migrateLegacyPrivateKeyContainerV2ToV3WithAesKey(encrypted, aesKey, opts = {}) {
    const v = Number(encrypted?.v || 2);
    if (v === 3) return encrypted;
    if (v !== 2) throw new Error(`Unsupported legacy private key container version: ${v}`);
    if (!encrypted?.iv || !encrypted?.data || !encrypted?.salt || !encrypted?.kdf) {
      throw new Error('Malformed legacy private key container');
    }

    const legacyIv = this.base64ToArrayBuffer(encrypted.iv);
    const legacyData = this.base64ToArrayBuffer(encrypted.data);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: legacyIv }, aesKey, legacyData
    );
    const pkcs8B64 = _utf8Decode(decryptedBuffer);

    const containerV3 = {
      v: 3,
      alg: 'AES-256-GCM',
      kdf: encrypted.kdf,
      salt: encrypted.salt,
      iv: this.arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(12))),
      created_at: Number(opts?.createdAt || Date.now()),
      username: String(opts?.username || '').trim().toLowerCase(),
      ext_version: String(opts?.appVersion || '0'),
    };
    const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(containerV3));
    const reIv = this.base64ToArrayBuffer(containerV3.iv);
    const reEncoded = new TextEncoder().encode(pkcs8B64);
    const reCipher = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: reIv, additionalData: aad },
      aesKey,
      reEncoded
    );

    return {
      ...containerV3,
      data: this.arrayBufferToBase64(reCipher),
    };
  },

  async decryptPrivateKey(encrypted, password, opts = {}) {
    // Validate EPK container fields
    if (!encrypted?.salt || !encrypted?.iv || !encrypted?.data) {
      throw new Error('Invalid EPK container: missing salt, iv, or data');
    }
    const saltBytes = this.base64ToArrayBuffer(encrypted.salt);
    if (saltBytes.byteLength < 16) throw new Error('EPK salt too short (minimum 16 bytes)');
    const ivBytes = this.base64ToArrayBuffer(encrypted.iv);
    if (ivBytes.byteLength !== 12) throw new Error(`EPK IV must be 12 bytes, got ${ivBytes.byteLength}`);

    const v = Number(encrypted?.v || 2);
    if (v >= 3) {
      const expectedUsername = String(opts?.expectedUsername || '').trim().toLowerCase();
      if (expectedUsername) {
        const actualUsername = String(encrypted?.username || '').trim().toLowerCase();
        if (!actualUsername || actualUsername !== expectedUsername) {
          throw new Error('Encrypted private key container username mismatch');
        }
      }
    }
    const kdf = encrypted?.kdf || {};
    // When decrypting, use the KDF that was used to encrypt — do NOT prefer Argon2id
    // if the container doesn't explicitly specify it (backwards compatibility with PBKDF2 containers).
    const aesKey = await this.deriveKeyFromPassword(password, encrypted.salt, {
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

    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    let decryptedBuffer;
    try {
      decryptedBuffer = await crypto.subtle.decrypt(
        this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
      );
    } catch (primaryErr) {
      // Fallback: retry WITHOUT AAD for v3 containers whose AAD fields may have
      // been lost or altered during Keychain JSON serialization round-trip.
      if (v >= 3) {
        try {
          if (__DEV__) console.warn('[CryptoUtils] v3 AAD decrypt failed, retrying without AAD');
          decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, aesKey, encryptedData
          );
        } catch (_fallbackErr) {
          throw primaryErr;
        }
      } else {
        throw primaryErr;
      }
    }

    const pkcs8B64 = _utf8Decode(decryptedBuffer);
    return this.importPrivateKey(pkcs8B64);
  },

  async importAesKeyFromRaw(base64, extractable = false, usages = ['decrypt']) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, !!extractable, usages
    );
  },

  async decryptPrivateKeyWithAesKey(encrypted, aesKey, opts = {}) {
    const v = Number(encrypted?.v || 2);
    if (v >= 3) {
      const expectedUsername = String(opts?.expectedUsername || '').trim().toLowerCase();
      if (expectedUsername) {
        const actualUsername = String(encrypted?.username || '').trim().toLowerCase();
        if (!actualUsername || actualUsername !== expectedUsername) {
          throw new Error('Encrypted private key container username mismatch');
        }
      }
    }
    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const encryptedData = this.base64ToArrayBuffer(encrypted.data);

    let decryptedBuffer;
    try {
      decryptedBuffer = await crypto.subtle.decrypt(
        this.buildPrivateKeyContainerGcmParams(encrypted, iv), aesKey, encryptedData
      );
    } catch (primaryErr) {
      if (v >= 3) {
        try {
          if (__DEV__) console.warn('[CryptoUtils] v3 AAD decrypt (AesKey) failed, retrying without AAD');
          decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv }, aesKey, encryptedData
          );
        } catch (_fallbackErr) {
          throw primaryErr;
        }
      } else {
        throw primaryErr;
      }
    }

    const pkcs8B64 = _utf8Decode(decryptedBuffer);
    return this.importPrivateKey(pkcs8B64);
  },

  // ============================
  // Room key generation / import / export (AES-256-GCM)
  // ============================

  async generateRoomKey(exportable = false) {
    return crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      !!exportable,
      ['encrypt', 'decrypt']
    );
  },

  async exportRoomKey(key) {
    const exported = await crypto.subtle.exportKey('raw', key);
    return this.arrayBufferToBase64(exported);
  },

  async importRoomKey(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  },

  async importRoomKeyExportable(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    return crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
  },

  async fingerprintRoomKeyBase64(base64) {
    const raw = this.base64ToArrayBuffer(base64);
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const arr = new Uint8Array(hash);
    let hex = '';
    for (let i = 0; i < 8; i++) hex += arr[i].toString(16).padStart(2, '0');
    return hex;
  },

  // ============================
  // X25519 ECDH key wrapping / unwrapping
  // ============================

  async _deriveWrappingKey(sharedBits, ephemeralPubRaw) {
    // react-native-quick-crypto does not implement HKDF in subtle — use @noble/hashes/hkdf
    const rawKey = hkdf(
      _sha256,
      new Uint8Array(sharedBits),
      new Uint8Array(ephemeralPubRaw),
      new TextEncoder().encode('ws-e2ee-wrap-v2'),
      32
    );
    const key = await crypto.subtle.importKey(
      'raw', rawKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    rawKey.fill(0); // wipe HKDF output from heap
    return key;
  },

  async encryptRoomKeyForUser(peerPublicKeyBase64, roomKeyBase64) {
    const peerKey = await this.importPublicKey(peerPublicKeyBase64);

    // Ephemeral X25519 keypair (pure JS, no crypto.subtle needed)
    const ephPrivRaw = x25519.utils.randomSecretKey();
    const ephPubRaw = x25519.getPublicKey(ephPrivRaw);

    // ECDH shared secret
    const sharedRaw = x25519.getSharedSecret(ephPrivRaw, peerKey.pub);
    ephPrivRaw.fill(0); // wipe ephemeral private key

    const wrappingKey = await this._deriveWrappingKey(sharedRaw, ephPubRaw);
    sharedRaw.fill(0); // wipe ECDH shared secret

    const iv = crypto.getRandomValues(new Uint8Array(this._WRAP_IV_LEN));
    const roomKeyBytes = this.base64ToArrayBuffer(roomKeyBase64);

    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      wrappingKey,
      roomKeyBytes
    );

    const ctBytes = new Uint8Array(ciphertext);
    const blob = new Uint8Array(this._WRAP_HEADER + ctBytes.length);
    blob[0] = this._WRAP_VERSION;
    blob.set(ephPubRaw, 1);
    blob.set(iv, 1 + this._WRAP_EPHEM_LEN);
    blob.set(ctBytes, this._WRAP_HEADER);

    return this.arrayBufferToBase64(blob.buffer);
  },

  async decryptRoomKeyForUser(privateKey, encryptedBase64) {
    const blob = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

    if (blob.length < this._WRAP_HEADER + 1 || blob[0] !== this._WRAP_VERSION) {
      throw new Error('Unsupported wrapped key format (expected v2 X25519)');
    }

    const ephemPubRaw = blob.slice(1, 1 + this._WRAP_EPHEM_LEN);
    const iv = blob.slice(1 + this._WRAP_EPHEM_LEN, this._WRAP_HEADER);
    const ciphertext = blob.slice(this._WRAP_HEADER);

    // ECDH shared secret (pure JS)
    const sharedRaw = x25519.getSharedSecret(privateKey.priv, ephemPubRaw);

    const unwrappingKey = await this._deriveWrappingKey(sharedRaw, ephemPubRaw);
    sharedRaw.fill(0); // wipe ECDH shared secret

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      unwrappingKey,
      ciphertext
    );

    return this.arrayBufferToBase64(plaintext);
  },

  // ============================
  // Safety Numbers (fingerprints)
  // ============================

  async computeSafetyNumber(myUsername, myPublicKeyB64, peerUsername, peerPublicKeyB64) {
    const normKey = (b64) => String(b64 || '').trim();
    const idA = String(myUsername || '').toLowerCase();
    const idB = String(peerUsername || '').toLowerCase();
    const keyA = normKey(myPublicKeyB64);
    const keyB = normKey(peerPublicKeyB64);

    let first, second;
    if (idA < idB) {
      first = idA + '|' + keyA;
      second = idB + '|' + keyB;
    } else if (idA > idB) {
      first = idB + '|' + keyB;
      second = idA + '|' + keyA;
    } else {
      first = idA + '|' + (keyA < keyB ? keyA : keyB);
      second = idB + '|' + (keyA < keyB ? keyB : keyA);
    }

    const payload = first + '||' + second;
    const hashBuf = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(payload)
    );
    const hashBytes = new Uint8Array(hashBuf);

    // First 30 bytes → 60 decimal digits via BigInt (no entropy loss).
    // Previous byte-by-byte .padStart(2,"0").slice(-2) dropped the leading
    // digit for bytes ≥ 100, causing ~60% collision rate.
    let n = 0n;
    for (let i = 0; i < 30; i++) {
      n = n * 256n + BigInt(hashBytes[i]);
    }
    // 2^240 fits in at most 73 decimal digits; pad and take the first 60.
    const dec = n.toString(10).padStart(73, '0').slice(0, 60);
    const groups = [];
    for (let i = 0; i < 60; i += 5) {
      groups.push(dec.slice(i, i + 5));
    }
    return groups.join(' ');
  },

  async fingerprintPublicKey(publicKeyB64) {
    const normalized = String(publicKeyB64 || '').trim();
    const bytes = new TextEncoder().encode(normalized);
    const hash = await crypto.subtle.digest('SHA-256', bytes);
    const arr = new Uint8Array(hash);
    let hex = '';
    for (let i = 0; i < 16; i++) {
      hex += arr[i].toString(16).padStart(2, '0');
    }
    return hex;
  },

  // ============================
  // Message padding (v1)
  // ============================

  _PAD_HEADER: 5,
  _PAD_VERSION: 0x01,
  _PAD_MIN_BUCKET: 64,

  _padBucket(totalBytes) {
    const MAX_BUCKET = 2 ** 24; // 16 MB — sane upper limit for a chat message
    if (totalBytes > MAX_BUCKET) throw new Error('Message too large for padding');
    let bucket = this._PAD_MIN_BUCKET;
    while (bucket < totalBytes) bucket *= 2;
    return bucket;
  },

  _padPlaintext(msgBytes) {
    const msgLen = msgBytes.byteLength;
    const needed = this._PAD_HEADER + msgLen;
    const bucket = this._padBucket(needed);
    const padded = new Uint8Array(bucket);
    crypto.getRandomValues(padded);
    padded[0] = this._PAD_VERSION;
    padded[1] = (msgLen >>> 24) & 0xff;
    padded[2] = (msgLen >>> 16) & 0xff;
    padded[3] = (msgLen >>>  8) & 0xff;
    padded[4] =  msgLen         & 0xff;
    padded.set(msgBytes, this._PAD_HEADER);
    return padded;
  },

  _unpadPlaintext(decryptedBuf) {
    const bytes = new Uint8Array(decryptedBuf);
    if (bytes.length < this._PAD_HEADER || bytes[0] !== this._PAD_VERSION) {
      // Legacy unpadded plaintext (pre-padding era) or too short for header.
      // Safe: AES-GCM authentication already verified ciphertext integrity.
      return _utf8Decode(decryptedBuf);
    }
    const msgLen =
      (bytes[1] << 24) | (bytes[2] << 16) | (bytes[3] << 8) | bytes[4];
    if (msgLen < 0 || this._PAD_HEADER + msgLen > bytes.length) {
      throw new Error('Invalid padded message: length out of bounds');
    }
    return _utf8Decode(
      bytes.subarray(this._PAD_HEADER, this._PAD_HEADER + msgLen)
    );
  },

  // ============================
  // Message encrypt / decrypt (AES-GCM)
  // ============================

  async encryptMessage(roomKey, plaintext, additionalData) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const msgBytes = new TextEncoder().encode(plaintext);
    const padded = this._padPlaintext(msgBytes);
    const params = additionalData
      ? { name: 'AES-GCM', iv, additionalData }
      : { name: 'AES-GCM', iv };
    const ciphertext = await crypto.subtle.encrypt(params, roomKey, padded);
    return {
      iv: this.arrayBufferToBase64(iv),
      data: this.arrayBufferToBase64(ciphertext),
    };
  },

  async decryptMessage(roomKey, encrypted, additionalData) {
    const iv = this.base64ToArrayBuffer(encrypted.iv);
    const ciphertext = this.base64ToArrayBuffer(encrypted.data);
    const params = additionalData
      ? { name: 'AES-GCM', iv, additionalData }
      : { name: 'AES-GCM', iv };
    const decrypted = await crypto.subtle.decrypt(params, roomKey, ciphertext);
    return this._unpadPlaintext(decrypted);
  },

  // ============================
  // Helpers
  // ============================

  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  },

  base64ToArrayBuffer(base64) {
    let b64 = String(base64 || '').replace(/-/g, '+').replace(/_/g, '/').trim();
    const pad = b64.length % 4;
    if (pad) b64 += '='.repeat(4 - pad);
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  },

  // ============================
  // EPK re-encryption (password change)
  // ============================

  /**
   * Encrypt raw X25519 private key bytes into a v3 AES-256-GCM container with a new password.
   * Mirrors the Extension's encryptPrivateKey() in login.js.
   * @param {Uint8Array} privRaw  — 32-byte raw private key (will NOT be zeroed here; caller must)
   * @param {string}     password — new password
   * @param {string}     username — stored in container AAD for key-commitment
   * @returns {Promise<object>} v3 EPK container {v,alg,kdf,salt,iv,data,created_at,username,...}
   */
  async encryptPrivateKey(privRaw, password, { username = '' } = {}) {
    if (!(privRaw instanceof Uint8Array) || privRaw.byteLength !== 32) {
      throw new Error('encryptPrivateKey: expected Uint8Array(32)');
    }
    const privB64 = this.arrayBufferToBase64(privRaw);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = this.arrayBufferToBase64(salt);

    const { raw, kdf } = await this.deriveRawKeyFromPassword(password, saltB64, { preferArgon2: true });
    const aesKey = await crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
    );
    raw.fill(0);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const container = {
      v: 3,
      alg: 'AES-256-GCM',
      kdf,
      salt: saltB64,
      iv: this.arrayBufferToBase64(iv),
      created_at: Date.now(),
      username: String(username || '').trim().toLowerCase(),
      ext_version: '0',
    };
    const aad = new TextEncoder().encode(this.buildPrivateKeyContainerAAD(container));
    const encoded = new TextEncoder().encode(privB64);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, aesKey, encoded,
    );
    return { ...container, data: this.arrayBufferToBase64(ciphertext) };
  },

  // ============================
  // BIP39 Recovery Phrase
  // ============================

  /**
   * Encode 32 raw bytes as a 24-word BIP39 mnemonic.
   * 256-bit entropy + 8-bit SHA-256 checksum = 264 bits → 24 × 11-bit words.
   */
  bip39Encode(rawBytes) {
    const b = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
    if (b.length !== 32) throw new Error(`bip39Encode: expected 32 bytes, got ${b.length}`);
    return entropyToMnemonic(b, _BIP39_ENGLISH);
  },

  /**
   * Decode a 24-word BIP39 mnemonic to the raw 32-byte X25519 private key.
   * Throws if phrase is invalid or checksum fails.
   * @param {string} phrase
   * @returns {Uint8Array} 32 bytes of raw private key
   */
  bip39Decode(phrase) {
    const entropy = mnemonicToEntropy(String(phrase || '').trim().toLowerCase(), _BIP39_ENGLISH);
    if (!(entropy instanceof Uint8Array) || entropy.length !== 32) {
      throw new Error('Invalid BIP39 phrase: expected 24 words (256-bit entropy)');
    }
    return entropy;
  },

  /**
   * Derive a 32-byte recovery auth token from raw X25519 private key bytes.
   * recovery_auth = HKDF-SHA256(ikm=rawKey, salt=0x00*32, info="ws-messenger-recovery-v1")
   */
  deriveRecoveryAuth(rawKeyBytes) {
    const raw = rawKeyBytes instanceof Uint8Array ? rawKeyBytes : new Uint8Array(rawKeyBytes);
    const salt = new Uint8Array(32); // zero salt
    const info = new TextEncoder().encode('ws-messenger-recovery-v1');
    return hkdf(_sha256, raw, salt, info, 32);
  },

  /** SHA-256 of bytes → hex string (synchronous, uses @noble/hashes). */
  sha256Hex(bytes) {
    const hash = _sha256(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
    return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /** SHA-256 of bytes → Uint8Array (synchronous, uses @noble/hashes). */
  sha256Raw(bytes) {
    return _sha256(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  },

  // ============================
  // PKCS8 helpers
  // ============================

  /** Extract the 32-byte raw private key from a 48-byte X25519 PKCS8 blob. */
  extractRawKeyFromPkcs8(pkcs8Bytes) {
    const b = pkcs8Bytes instanceof Uint8Array ? pkcs8Bytes : new Uint8Array(pkcs8Bytes);
    if (b.length !== 48) throw new Error(`PKCS8 length ${b.length} != 48`);
    return b.slice(16, 48);
  },

  // ============================
  // Ed25519 signing (sealed-sender from-field authentication)
  // ============================

  /**
   * Derive a 32-byte Ed25519 seed from the X25519 private key via HKDF-SHA256.
   * The seed is deterministic — no new key material is stored; it is re-derived
   * from the existing identity key on every unlock.
   *
   * @param {Uint8Array} x25519PrivRaw — raw 32-byte X25519 private scalar
   * @returns {Uint8Array} 32-byte Ed25519 seed
   */
  deriveEd25519Seed(x25519PrivRaw) {
    const ikm = x25519PrivRaw instanceof Uint8Array ? x25519PrivRaw : new Uint8Array(x25519PrivRaw);
    const info = new TextEncoder().encode('ws-id-signing-v1');
    return hkdf(_sha256, ikm, new Uint8Array(32), info, 32);
  },

  /**
   * Compute Ed25519 public key from seed (32 bytes).
   * @param {Uint8Array} seed
   * @returns {Uint8Array} 32-byte public key
   */
  ed25519GetPublicKey(seed) {
    return ed25519.getPublicKey(seed);
  },

  /**
   * Build the canonical byte-string that is signed/verified for a DM envelope.
   * Format: [12b domain] [4b threadId big-endian uint32] [2b from_len] [from utf8] [body utf8]
   * Length-prefixed fields prevent injection across field boundaries.
   *
   * @param {number|string} threadId
   * @param {string} from  — sender username
   * @param {string} body  — plaintext message body
   * @returns {Uint8Array}
   */
  _dmSigMessage(threadId, from, body) {
    const enc = new TextEncoder();
    const domainB = enc.encode('ws-dm-sig-v1');   // 12 bytes exactly
    const fromB   = enc.encode(from  || '');
    const bodyB   = enc.encode(body  || '');
    const tid = (Number(threadId) >>> 0);          // clamp to uint32
    const buf = new Uint8Array(12 + 4 + 2 + fromB.length + bodyB.length);
    let off = 0;
    buf.set(domainB, off); off += 12;
    buf[off++] = (tid >>> 24) & 0xff;
    buf[off++] = (tid >>> 16) & 0xff;
    buf[off++] = (tid >>>  8) & 0xff;
    buf[off++] =  tid         & 0xff;
    buf[off++] = (fromB.length >> 8) & 0xff;
    buf[off++] =  fromB.length       & 0xff;
    buf.set(fromB, off); off += fromB.length;
    buf.set(bodyB, off);
    return buf;
  },

  /**
   * Sign a DM envelope byte-string with the Ed25519 seed.
   * Returns base64url-encoded 64-byte signature.
   *
   * @param {Uint8Array} seed      — 32-byte Ed25519 seed
   * @param {Uint8Array} msgBytes  — output of _dmSigMessage()
   * @returns {string} base64url signature
   */
  ed25519Sign(seed, msgBytes) {
    const sig = ed25519.sign(msgBytes, seed);
    return this.arrayBufferToBase64(sig).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },

  /**
   * Verify an Ed25519 signature over a DM envelope byte-string.
   * Returns true if valid, false if invalid or on any error.
   *
   * @param {Uint8Array} pubKeyBytes — 32-byte Ed25519 public key
   * @param {Uint8Array} sigBytes    — 64-byte signature
   * @param {Uint8Array} msgBytes    — output of _dmSigMessage()
   * @returns {boolean}
   */
  ed25519Verify(pubKeyBytes, sigBytes, msgBytes) {
    try {
      return ed25519.verify(sigBytes, msgBytes, pubKeyBytes);
    } catch (_e) {
      return false;
    }
  },
};

export default CryptoUtils;
