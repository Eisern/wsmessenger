// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Who wrote a room message.
 *
 * A room message is encrypted under a key every member holds, so the key proves
 * membership and nothing else: the author is whatever the server put in the
 * row. A server that wanted to could move one member's words under another
 * member's name, and no amount of encryption would contradict it.
 *
 * The signature is what makes the claim checkable. This covers the reading
 * side, which ships first - a client has to understand the envelope before
 * anybody starts writing one, or it would show the JSON as the message text.
 * The writer stays behind ROOM_SIG_WRITE_ENABLED until then, and the last test
 * here is what makes flipping that flag a deliberate act rather than an
 * accident.
 */
const { x25519, ed25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import StorageService from '../StorageService';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';

const ROOM = 42;
const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);

let roomKeyB64;
let bob;

/** What a signing client puts on the wire, built the way the writer builds it. */
async function roomMessage({ from, body, signWith, claimBody = null }) {
  const envelope = { rs: 1, from, body };
  if (signWith) {
    envelope.sig = b64(ed25519.sign(
      CryptoUtils._roomSigMessage(ROOM, from, claimBody === null ? body : claimBody),
      signWith,
    ));
  }
  return cryptoManager.encryptMessage(ROOM, JSON.stringify(envelope));
}

beforeAll(async () => {
  bob = { username: 'bob' };
  bob.priv = x25519.utils.randomSecretKey();
  bob.edSeed = CryptoUtils.deriveEd25519Seed(bob.priv);
  bob.edPubB64 = b64(CryptoUtils.ed25519GetPublicKey(bob.edSeed));

  // The island's key store, as far as this client can see it.
  global.fetch = jest.fn(async (url) => {
    const body = String(url).includes('/keys/bob')
      ? { username: 'bob', public_key: b64(x25519.getPublicKey(bob.priv)), ed25519_public_key: bob.edPubB64 }
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

  roomKeyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  await cryptoManager.loadRoomKey(ROOM, roomKeyB64);
});

afterAll(() => {
  NetworkService._clearSession();
  CryptoService.lockSession();
});

describe('reading a signed room message', () => {
  test('a message signed by the peer whose name is on it', async () => {
    const wire = await roomMessage({ from: 'bob', body: 'hello room', signWith: bob.edSeed });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.text).toBe('hello room');
    expect(out.from).toBe('bob');
    expect(out.sigValid).toBe(true);
    expect(out.mismatch).toBe(false);
  });

  test('our own message, verified against the key we hold rather than fetched', async () => {
    const me = 'alice';
    const body = 'mine';
    const envelope = {
      rs: 1, from: me, body,
      sig: CryptoService.signEd25519B64(CryptoUtils._roomSigMessage(ROOM, me, body)),
    };
    const wire = await cryptoManager.encryptMessage(ROOM, JSON.stringify(envelope));
    const out = await CryptoService.decryptMessage(ROOM, wire, me);
    expect(out.sigValid).toBe(true);
  });

  test('a body changed after signing is reported, not shown as authentic', async () => {
    const wire = await roomMessage({
      from: 'bob', body: 'transfer 10', signWith: bob.edSeed, claimBody: 'transfer 1',
    });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.text).toBe('transfer 10');
    expect(out.sigValid).toBe(false);
  });

  test('a signature from somebody else fails under the named author', async () => {
    const impostor = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
    const wire = await roomMessage({ from: 'bob', body: 'not bob', signWith: impostor });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.sigValid).toBe(false);
  });

  test('the server naming a different author than the envelope is caught', async () => {
    // The move this whole thing exists to expose: bob's words, carol's name.
    const wire = await roomMessage({ from: 'bob', body: 'said by bob', signWith: bob.edSeed });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'carol');
    expect(out.mismatch).toBe(true);
    expect(out.from).toBe('bob');
    expect(out.sigValid).toBe(true);   // the signature is bob's and holds
  });

  test('an envelope with no signature reads as unverified, not as forged', async () => {
    const wire = await roomMessage({ from: 'bob', body: 'unsigned', signWith: null });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.text).toBe('unsigned');
    expect(out.sigValid).toBeNull();
  });
});

describe('what came before signing existed', () => {
  test('a plain message is returned untouched, with nothing to warn about', async () => {
    const wire = await cryptoManager.encryptMessage(ROOM, 'just text');
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out).toBe('just text');
  });

  test('a reply payload is still a plain string to the caller', async () => {
    const payload = JSON.stringify({ v: 2, t: 'hi', reply: { author: 'bob', text: 'yo' } });
    const wire = await cryptoManager.encryptMessage(ROOM, payload);
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out).toBe(payload);
  });
});

describe('the writer stays off until both clients can read', () => {
  test('nothing signed goes out yet', async () => {
    const wire = await CryptoService.encryptMessage(ROOM, 'plain for now', 'alice');
    const plain = await CryptoUtils.decryptMessage(
      await CryptoUtils.importRoomKey(roomKeyB64),
      JSON.parse(wire),
      JSON.parse(wire).kid ? new TextEncoder().encode(String(JSON.parse(wire).kid)) : undefined,
    );
    // Flipping ROOM_SIG_WRITE_ENABLED changes this line, and should be done
    // only once readers are out - a client without them shows the JSON.
    expect(plain).toBe('plain for now');
  });
});
