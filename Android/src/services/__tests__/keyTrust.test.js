// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The one check that stands between this client and a server that lies about
 * who somebody is.
 *
 * Every key this client sends out - a room key, a DM key - is wrapped for a
 * public key the server handed over. If the server hands over its own instead,
 * it reads the conversation from that moment on, and nothing else in the design
 * would notice. `assertPeerKeyTrustedForSharing` is the whole defence: it pins
 * the key on first sight and refuses to wrap for a different one later.
 *
 * It was not working. The guard opened with `if (!me) return`, and `me` came
 * straight off NetworkService.username - a field this client never filled,
 * because `/auth/login` answered with tokens and no name and the empty value
 * was written over the stored one. So the guard returned before it checked
 * anything, for every account, for the life of the install.
 *
 * These tests drive the real CryptoService. The first one fails on that code.
 */
const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import StorageService from '../StorageService';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';

const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);
const somebodysKey = () => b64(x25519.getPublicKey(x25519.utils.randomSecretKey()));

beforeAll(async () => {
  // Registering the signing key is fire-and-forget; nothing here needs a server.
  global.fetch = jest.fn(async () => ({
    ok: true, status: 200, headers: { get: () => 'application/json' },
    async json() { return {}; }, async text() { return '{}'; },
  }));
  const priv = x25519.utils.randomSecretKey();
  await StorageService.setActiveUsername('alice');
  await StorageService.setCachedPrivKey({ b64: b64(priv), pub: b64(x25519.getPublicKey(priv)) });
  await CryptoService.ensureReady({ interactive: false });
});

afterAll(() => {
  // _setSession arms the token-refresh timer; without this the run hangs on to
  // the event loop for as long as that timer says.
  NetworkService._clearSession();
  CryptoService.lockSession();
});

describe('sharing a key with somebody whose key changed', () => {
  test('is refused when the session never learned our own name', async () => {
    // Exactly the state after a fresh sign-in against a server that answers
    // with tokens only: authenticated, and nameless.
    NetworkService._username = '';
    NetworkService._token = 'tok';

    const peer = 'bob';
    await CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
      peerPublicKeyB64: somebodysKey(),
    });

    await expect(
      CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
        peerPublicKeyB64: somebodysKey(),   // the server swaps the key
      }),
    ).rejects.toThrow(/changed/i);
  });

  test('is refused when it does know the name', async () => {
    NetworkService._username = 'alice';
    const peer = 'carol';
    await CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
      peerPublicKeyB64: somebodysKey(),
    });
    await expect(
      CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
        peerPublicKeyB64: somebodysKey(),
      }),
    ).rejects.toThrow(/changed/i);
  });

  test('stays refused on every later attempt, not just the first', async () => {
    // The refusal used to hold for exactly one call: detecting the change
    // advanced the pin, so the next check said "same key" and let it through.
    // Tapping send twice was the whole exploit.
    NetworkService._username = 'alice';
    const peer = 'dave';
    await CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
      peerPublicKeyB64: somebodysKey(),
    });
    const swapped = somebodysKey();
    for (let attempt = 0; attempt < 3; attempt++) {
      await expect(
        CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', { peerPublicKeyB64: swapped }),
      ).rejects.toThrow(/changed|re-verification/i);
    }
  });

  test('opens again only when the user confirms the new key', async () => {
    NetworkService._username = 'alice';
    const peer = 'frank';
    await CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', {
      peerPublicKeyB64: somebodysKey(),
    });
    const swapped = somebodysKey();
    await expect(
      CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', { peerPublicKeyB64: swapped }),
    ).rejects.toThrow();

    // What the safety-number screen does when the user says they compared it.
    await CryptoService.verifyPeerKey('alice', peer, await CryptoService.fingerprintPeerKey(swapped));
    await CryptoService.clearPeerKeyChanged('alice', peer);

    await expect(
      CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', { peerPublicKeyB64: swapped }),
    ).resolves.toBeUndefined();
  });

  test('the same key twice is fine', async () => {
    NetworkService._username = 'alice';
    const peer = 'erin';
    const key = somebodysKey();
    await CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', { peerPublicKeyB64: key });
    await expect(
      CryptoService.assertPeerKeyTrustedForSharing(peer, 'sharing DM key', { peerPublicKeyB64: key }),
    ).resolves.toBeUndefined();
  });
});

describe('what a session keeps after signing in', () => {
  test('the name survives a server that answers with tokens only', async () => {
    NetworkService._username = '';
    await NetworkService._setSession(
      { access_token: 'a', refresh_token: 'r' },   // no username in the answer
      'Alice',
    );
    expect(NetworkService.username).toBe('Alice');
    // and it is what gets persisted, or no restart could recover it
    expect((await StorageService.getAuth())?.username).toBe('Alice');
  });

  test('a later answer never blanks a name we already have', async () => {
    await NetworkService._setSession({ access_token: 'a', username: 'alice' });
    await NetworkService._setSession({ access_token: 'b' });
    expect(NetworkService.username).toBe('alice');
  });
});
