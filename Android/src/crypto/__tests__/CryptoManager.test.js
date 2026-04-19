// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * @jest-environment node
 *
 * CryptoManager.test.js — порт test-integration.mjs в Jest
 *
 * Требования: Node 20+ (globalThis.crypto встроен)
 */

// @ts-nocheck
import CryptoUtils from '../CryptoUtils';
import CryptoManager from '../CryptoManager';

jest.setTimeout(120_000); // PBKDF2 медленный

// ============================
// Вспомогательная функция: создать зашифрованный приватный ключ
// ============================
async function encryptPrivateKey(privB64, password) {
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
    { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(privB64)
  );
  return {
    salt: CryptoUtils.arrayBufferToBase64(salt),
    iv: CryptoUtils.arrayBufferToBase64(iv),
    data: CryptoUtils.arrayBufferToBase64(ct),
    kdf: { iterations: 620000, hash: 'SHA-256' },
  };
}

// ============================
// Тесты с общим состоянием (как оригинальный test-integration.mjs)
// ============================
describe('CryptoManager — интеграционные тесты', () => {
  let CM;
  let CU = CryptoUtils;
  const ROOM_ID = 42;
  const PASSWORD = 'test1234';

  // Инициализация CryptoManager перед первым тестом
  beforeAll(async () => {
    CM = new CryptoManager();
    const kp = await CU.generateIdentityKeyPair();
    const pubB64 = await CU.exportPublicKey(kp.publicKey);
    const privB64 = await CU.exportPrivateKey(kp.privateKey);
    const encrypted = await encryptPrivateKey(privB64, PASSWORD);

    const ok = await CM.initializeUserKey(encrypted, PASSWORD, pubB64);
    if (!ok) throw new Error('beforeAll: initializeUserKey failed');
  });

  test('initializeUserKey — возвращает true, isReady() = true', async () => {
    expect(CM.isReady()).toBe(true);
    expect(CM.userPublicKeyB64).toBeTruthy();
    expect(CM.userPublicKeyPem).toBe(CM.userPublicKeyB64); // alias
    expect(CM.userPrivateKey).not.toBeNull();
  });

  test('createRoomKey + encryptMessage/decryptMessage', async () => {
    const rawB64 = await CM.createRoomKey(ROOM_ID);
    expect(typeof rawB64).toBe('string');
    expect(rawB64.length).toBeGreaterThan(0);
    expect(CM.roomKeys.has(ROOM_ID)).toBe(true);

    const msg = 'Hello room 42! 🔐';
    const encryptedStr = await CM.encryptMessage(ROOM_ID, msg);
    expect(typeof encryptedStr).toBe('string');

    const parsed = JSON.parse(encryptedStr);
    expect(parsed.encrypted).toBe(true);
    expect(parsed.kid).toBeTruthy();

    const decrypted = await CM.decryptMessage(ROOM_ID, encryptedStr);
    expect(decrypted).toBe(msg);
  });

  test('exportRoomKeyForSharing + ECDH wrap/unwrap', async () => {
    const pubB64 = CM.userPublicKeyPem;
    const rawB64 = await CM.exportRoomKeyForSharing(ROOM_ID);
    expect(rawB64).toBeTruthy();

    const wrapped = await CU.encryptRoomKeyForUser(pubB64, rawB64);
    expect(wrapped.length).toBeGreaterThan(0);

    const unwrapped = await CU.decryptRoomKeyForUser(CM.userPrivateKey, wrapped);
    expect(unwrapped).toBe(rawB64);
  });

  test('key rotation — новый kid, старый ключ в архиве', async () => {
    const oldKid = CM.roomKeyIds.get(ROOM_ID);
    expect(oldKid).toBeTruthy();

    await CM.createRoomKey(ROOM_ID); // ротация
    const newKid = CM.roomKeyIds.get(ROOM_ID);
    expect(newKid).not.toBe(oldKid);

    const archive = CM.roomKeyArchive.get(ROOM_ID);
    expect(archive).toBeTruthy();
    expect(archive.has(oldKid)).toBe(true);

    // Новые сообщения шифруются и дешифруются новым ключом
    const msg = 'Post-rotation message';
    const encrypted = await CM.encryptMessage(ROOM_ID, msg);
    const decrypted = await CM.decryptMessage(ROOM_ID, encrypted);
    expect(decrypted).toBe(msg);
  });

  test('loadRoomKey — загружает внешний ключ, архивирует старый', async () => {
    // Генерируем новый ключ «снаружи» (как если бы пришёл с сервера)
    const externalKey = await CU.generateRoomKey(true);
    const externalB64 = await CU.exportRoomKey(externalKey);

    const prevKid = CM.roomKeyIds.get(ROOM_ID);
    const ok = await CM.loadRoomKey(ROOM_ID, externalB64);
    expect(ok).toBe(true);

    const newKid = CM.roomKeyIds.get(ROOM_ID);
    expect(newKid).not.toBe(prevKid);

    // Архив содержит предыдущий ключ
    const archive = CM.roomKeyArchive.get(ROOM_ID);
    expect(archive.has(prevKid)).toBe(true);

    // Сообщение шифруется новым ключом
    const msg = 'Message with loaded external key';
    const encrypted = await CM.encryptMessage(ROOM_ID, msg);
    const decrypted = await CM.decryptMessage(ROOM_ID, encrypted);
    expect(decrypted).toBe(msg);
  });

  test('loadArchivedKey + decryptMessage по kid из архива', async () => {
    // Генерируем отдельный «архивный» ключ
    const archiveKey = await CU.generateRoomKey(true);
    const archiveB64 = await CU.exportRoomKey(archiveKey);
    const archiveKid = await CU.fingerprintRoomKeyBase64(archiveB64);

    // Шифруем сообщение этим ключом напрямую
    const msg = 'Old archived message';
    const { iv, data } = await CU.encryptMessage(archiveKey, msg);
    const encryptedJson = JSON.stringify({ encrypted: true, iv, data, kid: archiveKid });

    // Загружаем ключ в архив CryptoManager
    const ok = await CM.loadArchivedKey(ROOM_ID, archiveKid, archiveB64);
    expect(ok).toBe(true);

    // CryptoManager должен найти ключ по kid и расшифровать
    const decrypted = await CM.decryptMessage(ROOM_ID, encryptedJson);
    expect(decrypted).toBe(msg);
  });

  test('clear — сбрасывает всё состояние', () => {
    CM.clear();
    expect(CM.isReady()).toBe(false);
    expect(CM.userPrivateKey).toBeNull();
    expect(CM.userPublicKeyPem).toBeNull();
    expect(CM.roomKeys.size).toBe(0);
    expect(CM.roomKeyArchive.size).toBe(0);
  });

  test('decryptMessage — неверный формат бросает ошибку', async () => {
    const freshCM = new CryptoManager();
    await expect(
      freshCM.decryptMessage(99, 'not json at all')
    ).rejects.toThrow();
  });

  test('encryptMessage — без ключа бросает ошибку', async () => {
    const freshCM = new CryptoManager();
    await expect(
      freshCM.encryptMessage(99, 'test')
    ).rejects.toThrow('No room key');
  });

});
