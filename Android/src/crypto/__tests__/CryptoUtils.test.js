// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * @jest-environment node
 *
 * CryptoUtils.test.js — порт test-x25519-crypto.mjs в Jest
 *
 * Требования: Node 20+ (globalThis.crypto встроен)
 * PBKDF2 620k iterations медленный — timeout 60s
 */

// @ts-nocheck
import CryptoUtils from '../CryptoUtils';

jest.setTimeout(60_000);

describe('CryptoUtils — X25519 + AES-GCM', () => {

  test('X25519 keypair generation', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    expect(kp.publicKey).toBeTruthy();
    expect(kp.privateKey).toBeTruthy();

    const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);
    expect(typeof pubB64).toBe('string');
    const pubBytes = CryptoUtils.base64ToArrayBuffer(pubB64);
    expect(pubBytes.byteLength).toBe(32);

    const privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);
    expect(typeof privB64).toBe('string');
    expect(privB64.length).toBeGreaterThan(0);
  });

  test('X25519 key import/export roundtrip', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();

    const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);
    const reimported = await CryptoUtils.importPublicKey(pubB64);
    const reexported = await CryptoUtils.exportPublicKey(reimported);
    expect(pubB64).toBe(reexported);

    const privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);
    const privReimported = await CryptoUtils.importPrivateKey(privB64);
    expect(privReimported).toBeTruthy();
  });

  test('Room key generation and roundtrip', async () => {
    const rk = await CryptoUtils.generateRoomKey(true);
    expect(rk).toBeTruthy();

    const rkB64 = await CryptoUtils.exportRoomKey(rk);
    expect(rkB64.length).toBeGreaterThan(0);

    const reimported = await CryptoUtils.importRoomKey(rkB64);
    expect(reimported).toBeTruthy();

    const fp = await CryptoUtils.fingerprintRoomKeyBase64(rkB64);
    expect(fp).toHaveLength(16);
  });

  test('ECDH key wrapping (encryptRoomKeyForUser → decryptRoomKeyForUser)', async () => {
    const alice = await CryptoUtils.generateIdentityKeyPair();
    const bob = await CryptoUtils.generateIdentityKeyPair();
    const bobPubB64 = await CryptoUtils.exportPublicKey(bob.publicKey);

    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);

    const wrapped = await CryptoUtils.encryptRoomKeyForUser(bobPubB64, rkB64);
    expect(typeof wrapped).toBe('string');

    // version byte = 0x02
    const blobBytes = new Uint8Array(CryptoUtils.base64ToArrayBuffer(wrapped));
    expect(blobBytes[0]).toBe(0x02);
    expect(blobBytes.length).toBeGreaterThanOrEqual(45 + 32);

    const unwrapped = await CryptoUtils.decryptRoomKeyForUser(bob.privateKey, wrapped);
    expect(unwrapped).toBe(rkB64);
  });

  test('ECDH wrapping — wrong private key fails', async () => {
    const bob = await CryptoUtils.generateIdentityKeyPair();
    const eve = await CryptoUtils.generateIdentityKeyPair();
    const bobPubB64 = await CryptoUtils.exportPublicKey(bob.publicKey);

    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);
    const wrapped = await CryptoUtils.encryptRoomKeyForUser(bobPubB64, rkB64);

    await expect(
      CryptoUtils.decryptRoomKeyForUser(eve.privateKey, wrapped)
    ).rejects.toThrow();
  });

  test('ECDH wrapping — self-encrypt/decrypt', async () => {
    const user = await CryptoUtils.generateIdentityKeyPair();
    const userPubB64 = await CryptoUtils.exportPublicKey(user.publicKey);

    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);

    const wrapped = await CryptoUtils.encryptRoomKeyForUser(userPubB64, rkB64);
    const unwrapped = await CryptoUtils.decryptRoomKeyForUser(user.privateKey, wrapped);
    expect(unwrapped).toBe(rkB64);
  });

  test('ECDH wrapping — multiple recipients', async () => {
    const owner = await CryptoUtils.generateIdentityKeyPair();
    const user1 = await CryptoUtils.generateIdentityKeyPair();
    const user2 = await CryptoUtils.generateIdentityKeyPair();

    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);

    const ownerPubB64 = await CryptoUtils.exportPublicKey(owner.publicKey);
    const u1PubB64 = await CryptoUtils.exportPublicKey(user1.publicKey);
    const u2PubB64 = await CryptoUtils.exportPublicKey(user2.publicKey);

    const w0 = await CryptoUtils.encryptRoomKeyForUser(ownerPubB64, rkB64);
    const w1 = await CryptoUtils.encryptRoomKeyForUser(u1PubB64, rkB64);
    const w2 = await CryptoUtils.encryptRoomKeyForUser(u2PubB64, rkB64);

    // ephemeral keys differ — blobs must differ
    expect(w0).not.toBe(w1);
    expect(w1).not.toBe(w2);

    // all recover same room key
    const r0 = await CryptoUtils.decryptRoomKeyForUser(owner.privateKey, w0);
    const r1 = await CryptoUtils.decryptRoomKeyForUser(user1.privateKey, w1);
    const r2 = await CryptoUtils.decryptRoomKeyForUser(user2.privateKey, w2);
    expect(r0).toBe(rkB64);
    expect(r1).toBe(rkB64);
    expect(r2).toBe(rkB64);
  });

  test('Password-based private key encryption (PBKDF2)', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    const privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);
    const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);

    const password = 'testPassword123!';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const km = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 620000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(privB64)
    );

    const encrypted = {
      salt: CryptoUtils.arrayBufferToBase64(salt),
      iv: CryptoUtils.arrayBufferToBase64(iv),
      data: CryptoUtils.arrayBufferToBase64(ct),
      kdf: { iterations: 620000, hash: 'SHA-256' },
    };

    const recovered = await CryptoUtils.decryptPrivateKey(encrypted, password);
    expect(recovered).toBeTruthy();

    // Verify recovered key works for ECDH
    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);
    const wrapped = await CryptoUtils.encryptRoomKeyForUser(pubB64, rkB64);
    const unwrapped = await CryptoUtils.decryptRoomKeyForUser(recovered, wrapped);
    expect(unwrapped).toBe(rkB64);
  }, 120_000); // PBKDF2 slow — extra timeout

  test('Password-based — wrong password fails', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    const privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const km = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode('correct_password'), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 620000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(privB64)
    );

    const encrypted = {
      salt: CryptoUtils.arrayBufferToBase64(salt),
      iv: CryptoUtils.arrayBufferToBase64(iv),
      data: CryptoUtils.arrayBufferToBase64(ct),
      kdf: { iterations: 620000, hash: 'SHA-256' },
    };

    await expect(
      CryptoUtils.decryptPrivateKey(encrypted, 'wrong_password')
    ).rejects.toThrow();
  }, 120_000);

  test('Message encryption/decryption (AES-GCM)', async () => {
    const rk = await CryptoUtils.generateRoomKey(false);
    const plaintext = 'Hello, encrypted world! Привет мир! 🔐';

    const encrypted = await CryptoUtils.encryptMessage(rk, plaintext);
    expect(encrypted.iv).toBeTruthy();
    expect(encrypted.data).toBeTruthy();

    const decrypted = await CryptoUtils.decryptMessage(rk, encrypted);
    expect(decrypted).toBe(plaintext);
  });

  test('Message padding works', async () => {
    const rk = await CryptoUtils.generateRoomKey(false);

    const short = 'Hi';
    const enc1 = await CryptoUtils.encryptMessage(rk, short);

    const medium = 'Hello, this is a medium-length message for testing.';
    const enc2 = await CryptoUtils.encryptMessage(rk, medium);

    expect(await CryptoUtils.decryptMessage(rk, enc1)).toBe(short);
    expect(await CryptoUtils.decryptMessage(rk, enc2)).toBe(medium);
  });

  test('Safety numbers — symmetric, 60 digits', async () => {
    const alice = await CryptoUtils.generateIdentityKeyPair();
    const bob = await CryptoUtils.generateIdentityKeyPair();

    const alicePubB64 = await CryptoUtils.exportPublicKey(alice.publicKey);
    const bobPubB64 = await CryptoUtils.exportPublicKey(bob.publicKey);

    const sn1 = await CryptoUtils.computeSafetyNumber('alice', alicePubB64, 'bob', bobPubB64);
    const sn2 = await CryptoUtils.computeSafetyNumber('bob', bobPubB64, 'alice', alicePubB64);

    expect(sn1).toBe(sn2);
    expect(sn1.replace(/ /g, '')).toHaveLength(60);

    // Different key → different safety number
    const eve = await CryptoUtils.generateIdentityKeyPair();
    const evePubB64 = await CryptoUtils.exportPublicKey(eve.publicKey);
    const sn3 = await CryptoUtils.computeSafetyNumber('alice', alicePubB64, 'bob', evePubB64);
    expect(sn1).not.toBe(sn3);
  });

  test('Public key fingerprint — deterministic, 32 hex chars', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);

    const fp = await CryptoUtils.fingerprintPublicKey(pubB64);
    expect(fp).toHaveLength(32);

    const fp2 = await CryptoUtils.fingerprintPublicKey(pubB64);
    expect(fp).toBe(fp2);

    const kp2 = await CryptoUtils.generateIdentityKeyPair();
    const pubB64_2 = await CryptoUtils.exportPublicKey(kp2.publicKey);
    const fp3 = await CryptoUtils.fingerprintPublicKey(pubB64_2);
    expect(fp).not.toBe(fp3);
  });

  test('Full registration + login flow simulation', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    const publicKeyB64 = await CryptoUtils.exportPublicKey(kp.publicKey);
    const privateKeyB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);

    const password = 'MyStrongP@ss123';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const km = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 620000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(privateKeyB64)
    );

    const serverUser = {
      public_key: publicKeyB64,
      encrypted_private_key: {
        salt: CryptoUtils.arrayBufferToBase64(salt),
        iv: CryptoUtils.arrayBufferToBase64(iv),
        data: CryptoUtils.arrayBufferToBase64(ct),
      },
    };

    // public key should be compact (32 bytes in base64 = ~44 chars, not ~400 PEM)
    expect(serverUser.public_key.length).toBeLessThan(60);

    const recovered = await CryptoUtils.decryptPrivateKey(serverUser.encrypted_private_key, password);
    expect(recovered).toBeTruthy();

    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);
    const wrappedForSelf = await CryptoUtils.encryptRoomKeyForUser(publicKeyB64, rkB64);
    const rkRecovered = await CryptoUtils.decryptRoomKeyForUser(recovered, wrappedForSelf);
    expect(rkRecovered).toBe(rkB64);

    const roomKey = await CryptoUtils.importRoomKey(rkRecovered);
    const msg = 'Secret message in room 🔐';
    const enc = await CryptoUtils.encryptMessage(roomKey, msg);
    const dec = await CryptoUtils.decryptMessage(roomKey, enc);
    expect(dec).toBe(msg);
  }, 120_000);

  // ============================
  // Argon2id KDF tests
  // ============================

  test('isArgon2Available returns true', () => {
    expect(CryptoUtils.isArgon2Available()).toBe(true);
  });

  test('deriveRawKeyFromPassword — Argon2id (preferred)', async () => {
    const password = 'testArgon2id!';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    const { raw, kdf } = await CryptoUtils.deriveRawKeyFromPassword(password, saltB64, {
      preferArgon2: true,
    });

    expect(raw).toBeInstanceOf(Uint8Array);
    expect(raw.byteLength).toBe(32);
    expect(kdf.name).toBe('Argon2id');
    expect(kdf.time_cost).toBe(3);
    expect(kdf.memory_kib).toBe(65536);
    expect(kdf.parallelism).toBe(1);
    expect(kdf.version).toBe(19);
  }, 30_000);

  test('deriveRawKeyFromPassword — Argon2id deterministic', async () => {
    const password = 'deterministic_test';
    const salt = new Uint8Array(16).fill(0xAB);
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    const { raw: r1 } = await CryptoUtils.deriveRawKeyFromPassword(password, saltB64, {
      preferArgon2: true, time_cost: 2, memory_kib: 32768,
    });
    const { raw: r2 } = await CryptoUtils.deriveRawKeyFromPassword(password, saltB64, {
      preferArgon2: true, time_cost: 2, memory_kib: 32768,
    });

    expect(Buffer.from(r1).toString('hex')).toBe(Buffer.from(r2).toString('hex'));
  }, 30_000);

  test('deriveRawKeyFromPassword — wrong password gives different key', async () => {
    const salt = new Uint8Array(16).fill(0xCC);
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    const { raw: r1 } = await CryptoUtils.deriveRawKeyFromPassword('password1', saltB64, {
      preferArgon2: true, time_cost: 2, memory_kib: 32768,
    });
    const { raw: r2 } = await CryptoUtils.deriveRawKeyFromPassword('password2', saltB64, {
      preferArgon2: true, time_cost: 2, memory_kib: 32768,
    });

    expect(Buffer.from(r1).toString('hex')).not.toBe(Buffer.from(r2).toString('hex'));
  }, 30_000);

  test('deriveRawKeyFromPassword — PBKDF2 fallback when name=PBKDF2', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    const { raw, kdf } = await CryptoUtils.deriveRawKeyFromPassword('test', saltB64, {
      name: 'PBKDF2', iterations: 620000, hash: 'SHA-256',
    });

    expect(raw.byteLength).toBe(32);
    expect(kdf.name).toBe('PBKDF2');
    expect(kdf.iterations).toBe(620000);
  }, 120_000);

  test('deriveRawKeyFromPassword — rejects weak Argon2id params', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    await expect(
      CryptoUtils.deriveRawKeyFromPassword('test', saltB64, {
        name: 'Argon2id', time_cost: 1,
      })
    ).rejects.toThrow(/time_cost too low/);

    await expect(
      CryptoUtils.deriveRawKeyFromPassword('test', saltB64, {
        name: 'Argon2id', memory_kib: 1024,
      })
    ).rejects.toThrow(/memory_kib too low/);
  });

  test('Argon2id encrypt + decrypt private key roundtrip', async () => {
    const kp = await CryptoUtils.generateIdentityKeyPair();
    const privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);
    const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);

    // Encrypt with Argon2id
    const password = 'argon2id_roundtrip_test!';
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

    const { raw, kdf: kdfObj } = await CryptoUtils.deriveRawKeyFromPassword(password, saltB64, {
      preferArgon2: true, time_cost: 2, memory_kib: 32768,
    });
    const aesKey = await crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
    );
    raw.fill(0);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const container = {
      v: 3, alg: 'AES-256-GCM', kdf: kdfObj,
      salt: saltB64,
      iv: CryptoUtils.arrayBufferToBase64(iv),
      created_at: Date.now(), username: 'testuser', ext_version: '0',
    };
    const aad = new TextEncoder().encode(CryptoUtils.buildPrivateKeyContainerAAD(container));
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad }, aesKey, new TextEncoder().encode(privB64),
    );
    const encrypted = { ...container, data: CryptoUtils.arrayBufferToBase64(ct) };

    // Decrypt — should detect Argon2id from kdf.name and derive correctly
    const recovered = await CryptoUtils.decryptPrivateKey(encrypted, password);
    expect(recovered).toBeTruthy();

    // Verify recovered key works for ECDH
    const rk = await CryptoUtils.generateRoomKey(true);
    const rkB64 = await CryptoUtils.exportRoomKey(rk);
    const wrapped = await CryptoUtils.encryptRoomKeyForUser(pubB64, rkB64);
    const unwrapped = await CryptoUtils.decryptRoomKeyForUser(recovered, wrapped);
    expect(unwrapped).toBe(rkB64);
  }, 60_000);

});
