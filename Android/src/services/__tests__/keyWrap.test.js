// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Who gave me this key.
 *
 * A room key arrives wrapped for this client's public key, and the row it comes
 * from is written by the server. The wrap derives from an EPHEMERAL key, so it
 * proves only that somebody knew that public key - which the server does. So a
 * server could hand a member a key it made itself, watch them encrypt under it,
 * and read the room. Nothing in the old format could contradict that.
 *
 * The signed wrap (v3) carries the sharer's name and their signature over bytes
 * that bind this room, this recipient and this key version. These tests drive
 * the real CryptoService loading a key off a stubbed island, and check the two
 * things that matter: a wrap that does not hold up is refused outright, and
 * everything handed out before signing existed still works.
 */
const { x25519, ed25519 } = require('@noble/curves/ed25519');

globalThis.__DEV__ = false;

import CryptoUtils from '../../crypto/CryptoUtils';
import { cryptoManager } from '../../crypto';
import StorageService from '../StorageService';
import NetworkService from '../NetworkService';
import CryptoService from '../CryptoService';

const ROOM = 77;
const b64 = (u8) => CryptoUtils.arrayBufferToBase64(u8);

let me;         // this client
let owner;      // the member who hands out the key
let roomKeyB64;
let keyId;
let served;     // what the island answers for GET /crypto/room-key/{id}

function identity() {
  const priv = x25519.utils.randomSecretKey();
  const edSeed = CryptoUtils.deriveEd25519Seed(priv);
  return {
    priv,
    pubB64: b64(x25519.getPublicKey(priv)),
    edSeed,
    edPubB64: b64(CryptoUtils.ed25519GetPublicKey(edSeed)),
  };
}

beforeAll(async () => {
  me = identity();
  owner = identity();

  global.fetch = jest.fn(async (url) => {
    const u = String(url);
    let body = {};
    if (u.includes('/keys/owner')) {
      body = { username: 'owner', public_key: owner.pubB64, ed25519_public_key: owner.edPubB64 };
    } else if (u.includes(`/crypto/room-key/${ROOM}`)) {
      body = served;
    } else if (u.includes('/crypto/room-key-archive')) {
      body = [];
    }
    return {
      ok: true, status: 200, headers: { get: () => 'application/json' },
      async json() { return body; }, async text() { return JSON.stringify(body); },
    };
  });

  await StorageService.setActiveUsername('alice');
  await StorageService.setCachedPrivKey({ b64: b64(me.priv), pub: me.pubB64 });
  await CryptoService.ensureReady({ interactive: false });
  NetworkService._username = 'alice';
  NetworkService._token = 'tok';

  roomKeyB64 = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
  keyId = await CryptoUtils.fingerprintRoomKeyBase64(roomKeyB64);
});

afterEach(() => {
  cryptoManager.roomKeys.delete(ROOM);
  cryptoManager.roomKeyArchive.delete(ROOM);
});

afterAll(() => {
  NetworkService._clearSession();
  CryptoService.lockSession();
});

/** What the owner would upload for us. */
async function wrapFromOwner(overrides = {}) {
  return CryptoUtils.encryptRoomKeyForUser(me.pubB64, overrides.key || roomKeyB64, {
    seed: overrides.seed || owner.edSeed,
    signer: overrides.signer || 'owner',
    scope: 'room',
    scopeId: overrides.scopeId || ROOM,
    recipient: overrides.recipient || 'alice',
    keyId: overrides.keyId || keyId,
  });
}

describe('a key that says who wrapped it', () => {
  test('is accepted when the signature holds', async () => {
    served = { encrypted_room_key: await wrapFromOwner(), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
  });

  test('is refused when somebody else signed it', async () => {
    // The server mints a key of its own and signs with a key it controls, then
    // puts a real member's name on it.
    const impostor = identity();
    served = { encrypted_room_key: await wrapFromOwner({ seed: impostor.edSeed }), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('is refused when it was wrapped for another room', async () => {
    // A genuine wrap, signed by the owner - for a different room. Re-filing it
    // here must not work, or one room's key could be moved into another.
    served = { encrypted_room_key: await wrapFromOwner({ scopeId: ROOM + 1 }), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('is refused when it was wrapped for another member', async () => {
    served = { encrypted_room_key: await wrapFromOwner({ recipient: 'carol' }), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('is refused when the key version it claims is not the one it carries', async () => {
    served = { encrypted_room_key: await wrapFromOwner(), key_id: 'deadbeefdeadbeef' };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('is refused when the signer has no key we can check against', async () => {
    served = { encrypted_room_key: await wrapFromOwner({ signer: 'nobody' }), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });
});

describe('what came before signing existed', () => {
  test('an unsigned wrap still opens the room', async () => {
    served = {
      encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(me.pubB64, roomKeyB64),
      key_id: keyId,
    };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
  });
});

describe('the blob itself', () => {
  test('a signed wrap opens to the same key as an unsigned one', async () => {
    const signed = await wrapFromOwner();
    const opened = await CryptoUtils.decryptRoomKeyForUser(
      { _x25519: true, priv: me.priv }, signed,
    );
    expect(opened).toBe(roomKeyB64);
  });

  test('it names its signer without being decrypted', async () => {
    const info = CryptoUtils.inspectWrappedKey(await wrapFromOwner(), {
      scope: 'room', scopeId: ROOM, recipient: 'alice', keyId,
    });
    expect(info.version).toBe(3);
    expect(info.signer).toBe('owner');
    expect(ed25519.verify(
      info.sig,
      info.sigMessage,
      new Uint8Array(CryptoUtils.base64ToArrayBuffer(owner.edPubB64)),
    )).toBe(true);
  });

  test('a byte changed anywhere in it breaks the signature', async () => {
    const wrapped = await wrapFromOwner();
    const bytes = new Uint8Array(CryptoUtils.base64ToArrayBuffer(wrapped));
    bytes[bytes.length - 1] ^= 0x01;              // last byte of the ciphertext
    const info = CryptoUtils.inspectWrappedKey(b64(bytes), {
      scope: 'room', scopeId: ROOM, recipient: 'alice', keyId,
    });
    expect(ed25519.verify(
      info.sig,
      info.sigMessage,
      new Uint8Array(CryptoUtils.base64ToArrayBuffer(owner.edPubB64)),
    )).toBe(false);
  });
});
