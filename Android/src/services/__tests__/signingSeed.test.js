// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Whether this client can sign at all after each way of unlocking.
 *
 * The Ed25519 seed is derived from the identity key, and for a long time only
 * the BIP39 import path derived it: after a password sign-in or a Keychain
 * auto-unlock the seed was null, `encryptDm` skipped the signature without
 * saying so, and `ensureEd25519KeyRegistered` returned early — so the peer had
 * nothing to verify against and nothing to verify. An unsigned message reads as
 * "unverified", and to anyone who has already seen a signed one from the same
 * person, as FORGED.
 *
 * The check is the same in every case: the key the client would sign with must
 * be the one its identity implies.
 */
const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import StorageService from '../StorageService';
import CryptoService from '../CryptoService';

const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);

let privRaw;
let pubB64;
let expectedEdPubB64;

beforeAll(async () => {
  // No network in this test: registering the signing key is fire-and-forget and
  // must not be what decides whether unlocking succeeded.
  global.fetch = jest.fn(async () => ({
    ok: true, status: 200, headers: { get: () => 'application/json' },
    async json() { return {}; }, async text() { return '{}'; },
  }));
  privRaw = x25519.utils.randomSecretKey();
  pubB64 = b64(x25519.getPublicKey(privRaw));
  expectedEdPubB64 = b64(CryptoUtils.ed25519GetPublicKey(CryptoUtils.deriveEd25519Seed(privRaw)));
  await StorageService.setActiveUsername('seeduser');
});

beforeEach(() => {
  CryptoService.lockSession();
});

test('a Keychain auto-unlock can sign — the path every app restart takes', async () => {
  await StorageService.setCachedPrivKey({ b64: b64(privRaw), pub: pubB64 });
  const ok = await CryptoService.ensureReady({ interactive: false });
  expect(ok).toBe(true);
  expect(b64(CryptoService.ed25519PublicKey())).toBe(expectedEdPubB64);
});

test('the signature it produces verifies under that key', async () => {
  await StorageService.setCachedPrivKey({ b64: b64(privRaw), pub: pubB64 });
  await CryptoService.ensureReady({ interactive: false });

  const msg = CryptoUtils._dmSigMessage(7, 'seeduser', 'hello');
  const sig = CryptoService.signEd25519(msg);
  expect(sig).toHaveLength(64);
  expect(CryptoUtils.ed25519Verify(
    new Uint8Array(CryptoUtils.base64ToArrayBuffer(expectedEdPubB64)), sig, msg,
  )).toBe(true);
});

test('locking takes the signing key away again', async () => {
  await StorageService.setCachedPrivKey({ b64: b64(privRaw), pub: pubB64 });
  await CryptoService.ensureReady({ interactive: false });
  CryptoService.lockSession();
  expect(() => CryptoService.ed25519PublicKey()).toThrow(/Locked/);
});

test('a DM is signed, not quietly sent bare', async () => {
  await StorageService.setCachedPrivKey({ b64: b64(privRaw), pub: pubB64 });
  await CryptoService.ensureReady({ interactive: false });

  const rid = CryptoService._dmRid(7);
  const keyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  await cryptoManager.loadRoomKey(rid, keyB64);

  const wire = await CryptoService.encryptDm(7, 'hello', null, 'seeduser');
  const parsed = JSON.parse(wire);
  const plain = await CryptoUtils.decryptMessage(
    await CryptoUtils.importRoomKey(keyB64), parsed,
    parsed.kid ? new TextEncoder().encode(String(parsed.kid)) : undefined,
  );
  const envelope = JSON.parse(plain);
  expect(envelope.from).toBe('seeduser');
  expect(typeof envelope.sig).toBe('string');
  expect(CryptoUtils.ed25519Verify(
    new Uint8Array(CryptoUtils.base64ToArrayBuffer(expectedEdPubB64)),
    new Uint8Array(CryptoUtils.base64ToArrayBuffer(envelope.sig)),
    CryptoUtils._dmSigMessage(7, 'seeduser', 'hello'),
  )).toBe(true);
});
