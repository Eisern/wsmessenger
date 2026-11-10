// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The island id on a contact card must be the island's own name.
 *
 * A peer's client checks a room invitation, and the guest sign-in's challenge,
 * against the id on the card. Without a signed island list the card used to
 * carry this client's guess - the host it happens to connect through - and a
 * user on a second domain handed out a card nobody could join their rooms
 * with. Both clients now ask the island (its challenge says) when there is no
 * list to read it from.
 */

const { x25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';
import StorageService from '../StorageService';
import ForeignService from '../ForeignService';

const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => 'application/json' },
    async json() { return body; },
    async text() { return JSON.stringify(body); },
  };
}

// Reached through its second domain; calls itself by its first.
const island = { list: null, challenges: 0 };
function route(url) {
  const p = new URL(String(url)).pathname;
  if (p === '/.well-known/wsapp-island') return island.list ? reply(200, island.list) : reply(404, { detail: 'island list not configured' });
  if (p === '/foreign/challenge') {
    island.challenges += 1;
    return reply(200, { island_id: 'messenger.example.com', nonce_b64: Buffer.alloc(32, 1).toString('base64') });
  }
  if (p === '/crypto/ed25519-key') return reply(200, { ok: true });
  return reply(404, {});
}

beforeEach(() => {
  island.list = null;
  island.challenges = 0;
});

describe('the extension\'s card', () => {
  let P;
  beforeAll(async () => {
    P = makePanel({ apiBase: 'https://chat.example.org', islandId: 'chat.example.org', username: 'ann', token: 't' });
    P.sandbox.fetch = async (url) => route(url);
    await unlockRealManager(P.sandbox, { username: 'ann', password: PASS });
  }, 60000);

  test('without a signed list, carries what the island calls itself', async () => {
    const card = JSON.parse(await P.sandbox.buildMyContactBlobText());
    expect(card.payload.island_id).toBe('messenger.example.com');
    expect(island.challenges).toBe(1);
  });

  test('with a signed list, the list says - the island is not asked again', async () => {
    island.list = {
      payload: { island_id: 'messenger.example.com', entry_points: [{ apiBase: 'https://messenger.example.com', wsBase: 'wss://messenger.example.com', label: '' }] },
      signing_key_b64: Buffer.alloc(32, 2).toString('base64'),
    };
    const card = JSON.parse(await P.sandbox.buildMyContactBlobText());
    expect(card.payload.island_id).toBe('messenger.example.com');
    expect(island.challenges).toBe(0);
  });
});

describe('the Android card', () => {
  beforeAll(async () => {
    global.fetch = jest.fn(async (url) => route(url));
    NetworkService.setServerConfig('https://chat.example.org', 'wss://chat.example.org');
    NetworkService._token = 't';
    await StorageService.setActiveUsername('ann');
    const priv = x25519.utils.randomSecretKey();
    expect(await CryptoService.unlockWithRawKey(new Uint8Array(priv), CryptoUtils.arrayBufferToBase64(x25519.getPublicKey(priv)))).toBe(true);
  });
  afterAll(() => CryptoService.lockSession());

  test('without a signed list, carries what the island calls itself', async () => {
    const card = JSON.parse(await ForeignService.buildMyCard());
    expect(card.payload.island_id).toBe('messenger.example.com');
    expect(island.challenges).toBe(1);
  });

  test('with a signed list, the list says', async () => {
    island.list = {
      payload: { island_id: 'messenger.example.com', entry_points: [{ apiBase: 'https://messenger.example.com', wsBase: 'wss://messenger.example.com', label: '' }] },
      signing_key_b64: Buffer.alloc(32, 2).toString('base64'),
    };
    const card = JSON.parse(await ForeignService.buildMyCard());
    expect(card.payload.island_id).toBe('messenger.example.com');
    expect(island.challenges).toBe(0);
  });
});
