// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Recovering an account on Android (CryptoService.recoverFromBip39) and moving
 * an account from before to a recovery key after an unlock. The real
 * CryptoService and CryptoUtils, against a stubbed island that keeps every
 * request. The extension's side runs against a live island in
 * integration/recovery.test.js.
 */

const { x25519, ed25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import { CryptoUtils } from '../../crypto';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';

const AR = require('../account-recovery');

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

const island = {};
function reset() {
  Object.assign(island, { recover: [], recoverReplies: [], state: 'key', keyPosts: [], nonces: 0, pub: '' });
}

const unb64 = (s) => new Uint8Array(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const sha256 = async (b) => CryptoUtils.sha256Raw(b);

let priv;
let phrase;

beforeAll(async () => {
  reset();
  global.fetch = jest.fn(async (url, opts = {}) => {
    const p = new URL(String(url)).pathname;
    const method = String(opts.method || 'GET').toUpperCase();
    if (p.startsWith('/keys/')) return reply(200, { public_key: island.pub });
    if (p === '/auth/recover-start') return reply(200, { nonce: `nonce${++island.nonces}` });
    if (p === '/auth/recover') {
      island.recover.push(JSON.parse(opts.body));
      const next = island.recoverReplies.shift() ?? 200;
      return next === 200 ? reply(200, { ok: true }) : reply(next, { detail: 'refused' });
    }
    if (p === '/auth/recovery-key' && method === 'GET') return reply(200, { state: island.state });
    if (p === '/auth/recovery-key' && method === 'POST') {
      island.keyPosts.push(JSON.parse(opts.body));
      return reply(200, { state: 'key' });
    }
    return reply(200, { ok: true });
  });
  NetworkService.setServerConfig('https://island-rc.test', 'wss://island-rc.test');
  NetworkService._token = 'tok';
  NetworkService._username = 'alice';
  await StorageService.setActiveUsername('alice');
  priv = x25519.utils.randomSecretKey();
  island.pub = CryptoUtils.arrayBufferToBase64(x25519.getPublicKey(priv));
  phrase = CryptoUtils.bip39Encode(priv);
  // The new container is Argon2id in pure JS - a minute a call, and not what
  // is under test here.
  jest.spyOn(CryptoUtils, 'encryptPrivateKey').mockResolvedValue({ v: 3, stub: true });
});

beforeEach(() => {
  reset();
  island.pub = CryptoUtils.arrayBufferToBase64(x25519.getPublicKey(priv));
  CryptoService.lockSession();
});

afterAll(() => CryptoService.lockSession());

describe('recoverFromBip39', () => {
  test('signs the nonce, the name and the new password - and sends no secret', async () => {
    await CryptoService.recoverFromBip39('alice', phrase, 'Newpass!67890');
    expect(island.recover).toHaveLength(1);
    const body = island.recover[0];
    expect(body.recovery_auth_b64).toBeUndefined();
    const pub = CryptoUtils.ed25519GetPublicKey(CryptoUtils.deriveRecoverySigningSeed(priv));
    const msg = await AR.challengeBytes(sha256, 'alice', body.nonce, 'Newpass!67890');
    expect(ed25519.verify(unb64(body.signature_b64), msg, pub)).toBe(true);
  });

  test('an account from before: refused, then the old secret, with a fresh nonce', async () => {
    island.recoverReplies = [401, 200];
    await CryptoService.recoverFromBip39('alice', phrase, 'Newpass!67890');
    expect(island.recover).toHaveLength(2);
    expect(island.recover[1].nonce).not.toBe(island.recover[0].nonce);
    expect(Buffer.from(unb64(island.recover[1].recovery_auth_b64)).toString('hex'))
      .toBe(Buffer.from(CryptoUtils.deriveRecoveryAuth(priv)).toString('hex'));
  });

  test('refused both ways: it says so, and nothing is saved', async () => {
    island.recoverReplies = [401, 401];
    await expect(CryptoService.recoverFromBip39('alice', phrase, 'Newpass!67890')).rejects.toThrow(/refused/);
  });
});

describe('after an unlock', () => {
  async function unlock() {
    expect(await CryptoService.unlockWithRawKey(new Uint8Array(priv), island.pub)).toBe(true);
    // The migration runs on the back of the unlock; let it finish.
    for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  }

  test('an account from before moves to a recovery key, once', async () => {
    island.state = 'hash';
    await unlock();
    expect(island.keyPosts).toHaveLength(1);
    const pub = CryptoUtils.ed25519GetPublicKey(CryptoUtils.deriveRecoverySigningSeed(priv));
    expect(Buffer.from(unb64(island.keyPosts[0].recovery_pub)).toString('hex')).toBe(Buffer.from(pub).toString('hex'));
    expect(Buffer.from(unb64(island.keyPosts[0].recovery_auth_b64)).toString('hex'))
      .toBe(Buffer.from(CryptoUtils.deriveRecoveryAuth(priv)).toString('hex'));
  });

  test.each(['key', 'none'])('an account that is "%s" sends no secret', async (st) => {
    island.state = st;
    await unlock();
    expect(island.keyPosts).toHaveLength(0);
  });
});
