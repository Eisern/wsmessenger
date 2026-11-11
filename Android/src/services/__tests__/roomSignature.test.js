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
 * The signature is what makes the claim checkable. The reading side shipped
 * first (0.4.0) - a client has to understand the envelope before anybody
 * starts writing one, or it would show the JSON as the message text. The
 * writer (ROOM_SIG_WRITE_ENABLED) is on from 0.5.0; the last tests pin that it
 * signs, and that what it signs is what the reader accepts.
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
// How the island fails to answer /keys/*: false (it answers), '503', or
// 'empty' - a 200 with nothing readable in it. Neither says anything about anybody.
let keysDown = false;

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
    if (keysDown && String(url).includes('/keys/')) {
      const empty = keysDown === 'empty';
      return {
        ok: empty, status: empty ? 200 : 503, headers: { get: () => 'text/plain' },
        async json() { throw new Error('not json'); }, async text() { return empty ? '' : 'unavailable'; },
      };
    }
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

  test('an envelope with no signature is one no client writes: it reads as forged', async () => {
    // Every writer signs. An envelope without a signature was made up to look
    // like one, and "unknown" would have let it pass quietly.
    const wire = await roomMessage({ from: 'bob', body: 'unsigned', signWith: null });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.text).toBe('unsigned');
    expect(out.sigValid).toBe(false);
  });

  test('so does a signature that cannot even be read', async () => {
    for (const sig of ['not base64 at all!!', b64(new Uint8Array(10))]) {
      const wire = await cryptoManager.encryptMessage(ROOM, JSON.stringify({ rs: 1, from: 'bob', body: 'x', sig }));
      const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
      expect(out.sigValid).toBe(false);
    }
  });

  test('a signer with no key known anywhere is unverified, not forged', async () => {
    const dave = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
    const wire = await roomMessage({ from: 'dave', body: 'hi', signWith: dave });
    const out = await CryptoService.decryptMessage(ROOM, wire, 'dave');
    expect(out).toEqual({ text: 'hi', from: 'dave', sigValid: null, mismatch: false });
  });
});

describe('an island that stops answering for a pinned peer', () => {
  // A fresh session: nothing cached, but bob's signing key stays pinned.
  async function freshSession() {
    CryptoService.lockSession();
    await CryptoService.ensureReady({ interactive: false });
    await cryptoManager.loadRoomKey(ROOM, roomKeyB64);
  }

  afterEach(() => { keysDown = false; });

  test.each(['503', 'empty'])('does not switch the check off (%s): the pinned key still decides', async (how) => {
    // Pinned on first sight.
    const first = await CryptoService.decryptMessage(
      ROOM, await roomMessage({ from: 'bob', body: 'pin me', signWith: bob.edSeed }), 'bob');
    expect(first.sigValid).toBe(true);

    await freshSession();
    keysDown = how;

    const genuine = await CryptoService.decryptMessage(
      ROOM, await roomMessage({ from: 'bob', body: 'still bob', signWith: bob.edSeed }), 'bob');
    expect(genuine.sigValid).toBe(true);

    // The point: a forgery under bob's name is caught, not waved through as
    // "could not be checked" because the island went quiet about bob.
    const impostor = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
    const forged = await CryptoService.decryptMessage(
      ROOM, await roomMessage({ from: 'bob', body: 'send money', signWith: impostor }), 'bob');
    expect(forged.sigValid).toBe(false);
  });

  test('and a name never pinned stays unverified - silence pins nothing', async () => {
    await freshSession();
    keysDown = '503';
    const erin = CryptoUtils.deriveEd25519Seed(x25519.utils.randomSecretKey());
    const out = await CryptoService.decryptMessage(
      ROOM, await roomMessage({ from: 'erin', body: 'hello', signWith: erin }), 'erin');
    expect(out.sigValid).toBeNull();
  });
});

describe('what came before signing existed', () => {
  test('a message with no envelope comes back marked unsigned, its text intact', async () => {
    const wire = await cryptoManager.encryptMessage(ROOM, 'just text');
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out).toEqual({ text: 'just text', from: null, sigValid: null, mismatch: false, unsigned: true });
  });

  test('so is a reply payload without one, the payload untouched', async () => {
    const payload = JSON.stringify({ v: 2, t: 'hi', reply: { author: 'bob', text: 'yo' } });
    const wire = await cryptoManager.encryptMessage(ROOM, payload);
    const out = await CryptoService.decryptMessage(ROOM, wire, 'bob');
    expect(out.unsigned).toBe(true);
    expect(out.text).toBe(payload);
  });
});

describe('the writer is on (0.5.0): readers shipped in 0.4.0', () => {
  test('what goes out is a signed envelope, and it verifies under our key', async () => {
    const wire = await CryptoService.encryptMessage(ROOM, 'signed now', 'alice');
    const parsed = JSON.parse(wire);
    const plain = await CryptoUtils.decryptMessage(
      await CryptoUtils.importRoomKey(roomKeyB64),
      parsed,
      parsed.kid ? new TextEncoder().encode(String(parsed.kid)) : undefined,
    );
    // A client older than 0.4.0 shows exactly this JSON as the message text -
    // the cost CHANGELOG.md names for 0.5.0.
    const envelope = JSON.parse(plain);
    expect(envelope).toMatchObject({ rs: 1, from: 'alice', body: 'signed now' });
    expect(CryptoUtils.ed25519Verify(
      CryptoService.ed25519PublicKey(),
      new Uint8Array(CryptoUtils.base64ToArrayBuffer(envelope.sig)),
      CryptoUtils._roomSigMessage(ROOM, 'alice', 'signed now'),
    )).toBe(true);
  });

  test('and the reader accepts what the writer wrote', async () => {
    const wire = await CryptoService.encryptMessage(ROOM, 'round trip', 'alice');
    const out = await CryptoService.decryptMessage(ROOM, wire, 'alice');
    expect(out.text).toBe('round trip');
    expect(out.from).toBe('alice');
    expect(out.sigValid).toBe(true);
    expect(out.mismatch).toBe(false);
  });
});
