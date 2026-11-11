// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Who wrote a direct message, on Android (CryptoService.decryptDm).
 *
 * The server attaches no author to a direct message - the sender's name lives
 * inside the ciphertext - so the envelope is the only claim, and its signature
 * the only proof. Only somebody holding the thread key can write one, but
 * that is exactly who these checks are for: an envelope no client writes
 * (no name, a body that is not text, a signature that cannot be read) is a
 * forgery, and a message without a signature, or without an envelope at all,
 * says so instead of passing quietly as the peer's.
 */
const { x25519, ed25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

// A local thread: no cross-island contact owns it. That path has its own
// suite (crossIslandClient.test.js); here it would only list contacts.
jest.mock('../ForeignService', () => ({
  __esModule: true,
  default: { forThread: async () => null, ensureKeysReady: async () => {} },
}));

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import StorageService from '../StorageService';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';

const THREAD = 77;
const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);
let bob;

async function dm(envelope) {
  const rid = CryptoService._dmRid(THREAD);
  return cryptoManager.encryptMessage(rid, typeof envelope === 'string' ? envelope : JSON.stringify(envelope));
}
const signed = (from, body, seed) => ({
  ss: 1, from, body, sig: b64(ed25519.sign(CryptoUtils._dmSigMessage(THREAD, from, body), seed)),
});

beforeAll(async () => {
  bob = { priv: x25519.utils.randomSecretKey() };
  bob.edSeed = CryptoUtils.deriveEd25519Seed(bob.priv);
  const bobEdPub = b64(CryptoUtils.ed25519GetPublicKey(bob.edSeed));
  global.fetch = jest.fn(async (url) => {
    const body = String(url).includes('/keys/bob')
      ? { username: 'bob', public_key: b64(x25519.getPublicKey(bob.priv)), ed25519_public_key: bobEdPub }
      : {};
    return {
      ok: true, status: 200, headers: { get: () => 'application/json' },
      async json() { return body; }, async text() { return JSON.stringify(body); },
    };
  });

  const mine = x25519.utils.randomSecretKey();
  await StorageService.setActiveUsername('alice');
  await StorageService.setCachedPrivKey({ b64: b64(mine), pub: b64(x25519.getPublicKey(mine)) });
  await CryptoService.ensureReady({ interactive: false });
  NetworkService._username = 'alice';
  NetworkService._token = 'tok';
  const key = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  await cryptoManager.loadRoomKey(CryptoService._dmRid(THREAD), key);
});

afterAll(() => {
  NetworkService._clearSession();
  CryptoService.lockSession();
});

const open = async (wire) => CryptoService.decryptDm(THREAD, wire, 'bob');

test('signed by the peer whose name is on it', async () => {
  const out = await open(await dm(signed('bob', 'hello', bob.edSeed)));
  expect(out).toMatchObject({ text: 'hello', from: 'bob', sigValid: true });
  expect(out.unsigned).toBeUndefined();
});

test('somebody else signing under the name fails', async () => {
  const impostor = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
  expect((await open(await dm(signed('bob', 'hi', impostor)))).sigValid).toBe(false);
});

test('an envelope no client writes is forged: no name, a body that is not text, an unreadable signature', async () => {
  expect((await open(await dm({ ss: 1, body: 'no name' }))).sigValid).toBe(false);
  const objBody = await open(await dm({ ss: 1, from: 'bob', body: { not: 'text' } }));
  expect(objBody.sigValid).toBe(false);
  expect(typeof objBody.text).toBe('string');
  for (const sig of ['not base64 at all!!', b64(new Uint8Array(10))]) {
    expect((await open(await dm({ ss: 1, from: 'bob', body: 'x', sig }))).sigValid).toBe(false);
  }
});

test('a signer with no key known anywhere is unverified, and not called unsigned', async () => {
  const carol = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
  const out = await open(await dm(signed('carol', 'hi', carol)));
  expect(out.sigValid).toBeNull();
  expect(out.unsigned).toBeUndefined();
});

test('an envelope without a signature says it is unsigned', async () => {
  const out = await open(await dm({ ss: 1, from: 'bob', body: 'no sig' }));
  expect(out).toMatchObject({ text: 'no sig', from: 'bob', sigValid: null, unsigned: true });
});

test('a message with no envelope at all says so, its text intact', async () => {
  const out = await open(await dm('plain words'));
  expect(out).toEqual({ text: 'plain words', from: null, sigValid: null, unsigned: true });
});
