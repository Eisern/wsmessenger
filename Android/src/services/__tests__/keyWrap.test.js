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
let mallory;    // a real account with a real signing key, not in the room
let roomKeyB64;
let keyId;
let served;     // what the island answers for GET /crypto/room-key/{id}
let members;    // who the island says is in ROOM
let edServed;   // username -> the Ed25519 key the island serves for them
let dmServed;   // what the island answers for GET /crypto/dm-key/{DM}
const DM = 501;

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
  mallory = identity();
  members = ['alice', 'owner'];
  edServed = { owner: owner.edPubB64, mallory: mallory.edPubB64 };
  const accounts = { owner, mallory };

  global.fetch = jest.fn(async (url) => {
    const u = String(url);
    let body = {};
    const keyFor = u.match(/\/keys\/([^/?]+)$/);
    if (keyFor && accounts[keyFor[1]]) {
      const name = keyFor[1];
      body = { username: name, public_key: accounts[name].pubB64, ed25519_public_key: edServed[name] };
    } else if (u.includes(`/rooms/${ROOM}/members`)) {
      body = members.map((username) => ({ username, role: 'member', is_owner: username === 'owner' }));
    } else if (u.includes(`/crypto/room-key/${ROOM}`)) {
      body = served;
    } else if (u.includes('/crypto/room-key-archive')) {
      body = [];
    } else if (u.includes(`/crypto/dm-key/${DM}`)) {
      body = dmServed;
    } else if (u.endsWith('/dm/list')) {
      body = [{ thread_id: DM, peer_username: 'owner' }];
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

  test('is filed under the id of the key inside, whatever version the island claims', async () => {
    // The key_id beside a wrap is the island's word. Re-filing a genuine key
    // as another version cannot work, because the claim is never used: the
    // signature is checked, and the key filed, under the id of what is inside.
    served = { encrypted_room_key: await wrapFromOwner(), key_id: 'deadbeefdeadbeef' };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
    expect(cryptoManager.roomKeyIds.get(ROOM)).toBe(keyId);
  });

  test('opens when the island sends no key_id at all - which is what it does for a current key', async () => {
    // GET /crypto/room-key/{id} answers with the blob alone. Checking the
    // signature against that missing claim refused every signed current key;
    // the offline suite never noticed because this stub always sent one.
    served = { encrypted_room_key: await wrapFromOwner() };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
  });

  test('is refused when the signer has no key we can check against', async () => {
    served = { encrypted_room_key: await wrapFromOwner({ signer: 'nobody' }), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });
});

describe('an unsigned wrap (everything handed out before 0.5.0)', () => {
  // An unsigned wrap is exactly what an island would forge: it proves only
  // that somebody knew our public key, which the island does. So it may hand
  // back a key this device already held, and never introduce a new one.
  test('opens the room with a key this device already held', async () => {
    await cryptoManager.loadArchivedKey(ROOM, keyId, roomKeyB64);
    served = {
      encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(me.pubB64, roomKeyB64),
      key_id: keyId,
    };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
  });

  test('is refused when it brings a key this device never held', async () => {
    // A fresh key on a fresh room: nothing in memory, nothing persisted.
    const ROOM3 = ROOM + 7;
    const islandKey = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
    const prev = global.fetch;
    global.fetch = jest.fn(async (url) => {
      const u = String(url);
      const body = u.includes(`/crypto/room-key/${ROOM3}`) && !u.includes('archive')
        ? { encrypted_room_key: await CryptoUtils.encryptRoomKeyForUser(me.pubB64, islandKey),
          key_id: await CryptoUtils.fingerprintRoomKeyBase64(islandKey) }
        : [];
      return {
        ok: true, status: 200, headers: { get: () => 'application/json' },
        async json() { return body; }, async text() { return JSON.stringify(body); },
      };
    });
    try {
      await CryptoService.ensureRoomKeyReady(ROOM3);
      expect(cryptoManager.roomKeys.has(ROOM3)).toBe(false);
    } finally {
      global.fetch = prev;
    }
  });
});

describe('who may sign a key', () => {
  test('a valid signature from somebody the room does not list is refused', async () => {
    // Mallory is a real account with a real key the island serves - the shape
    // of an account an island mints for itself. Signing proves who she is,
    // not that she may hand out this room's key.
    served = {
      encrypted_room_key: await wrapFromOwner({ seed: mallory.edSeed, signer: 'mallory' }),
      key_id: keyId,
    };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);
  });

  test('the same signature is accepted in a room that does list her', async () => {
    // The control for the test above: it is membership that decided, not her
    // key. The attack then needs her in the member list, where people see her.
    const ROOM_M = ROOM + 9;
    const wrap = await CryptoUtils.encryptRoomKeyForUser(me.pubB64, roomKeyB64, {
      seed: mallory.edSeed, signer: 'mallory', scope: 'room', scopeId: ROOM_M,
      recipient: 'alice', keyId,
    });
    const prev = global.fetch;
    global.fetch = jest.fn(async (url) => {
      const u = String(url);
      let body = [];
      if (u.includes(`/rooms/${ROOM_M}/members`)) {
        body = ['alice', 'mallory'].map((username) => ({ username, role: 'member' }));
      } else if (u.includes(`/crypto/room-key/${ROOM_M}`) && !u.includes('archive')) {
        body = { encrypted_room_key: wrap, key_id: keyId };
      } else {
        return prev(url);
      }
      return {
        ok: true, status: 200, headers: { get: () => 'application/json' },
        async json() { return body; }, async text() { return JSON.stringify(body); },
      };
    });
    try {
      await CryptoService.ensureRoomKeyReady(ROOM_M);
      expect(cryptoManager.roomKeys.has(ROOM_M)).toBe(true);
    } finally {
      global.fetch = prev;
      cryptoManager.roomKeys.delete(ROOM_M);
      cryptoManager.roomKeyArchive.delete(ROOM_M);
    }
  });

  test('the island cannot swap a signer\'s key once it is pinned', async () => {
    // Pin the owner's real key.
    served = { encrypted_room_key: await wrapFromOwner(), key_id: keyId };
    await CryptoService.ensureRoomKeyReady(ROOM);
    expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);

    // The island now serves a key of its own for "owner" and signs with it.
    const islandKey = identity();
    edServed.owner = islandKey.edPubB64;
    try {
      // Lock and unlock, so nothing is answered from the session cache.
      CryptoService.lockSession();
      await CryptoService.ensureReady({ interactive: false });
      NetworkService._username = 'alice';

      served = { encrypted_room_key: await wrapFromOwner({ seed: islandKey.edSeed }), key_id: keyId };
      await CryptoService.ensureRoomKeyReady(ROOM);
      expect(cryptoManager.roomKeys.has(ROOM)).toBe(false);

      // The real owner's signature still holds against the pinned key.
      cryptoManager.roomKeys.delete(ROOM);
      served = { encrypted_room_key: await wrapFromOwner(), key_id: keyId };
      await CryptoService.ensureRoomKeyReady(ROOM);
      expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);

      // Verifying the peer is what lets a new signing key in.
      cryptoManager.roomKeys.delete(ROOM);
      await CryptoService.verifyPeerKey('alice', 'owner', 'fp-the-user-confirmed');
      served = { encrypted_room_key: await wrapFromOwner({ seed: islandKey.edSeed }), key_id: keyId };
      await CryptoService.ensureRoomKeyReady(ROOM);
      expect(cryptoManager.roomKeys.has(ROOM)).toBe(true);
    } finally {
      edServed.owner = owner.edPubB64;
      const island = require('../endpoints').islandIdOf(NetworkService.getServerConfig());
      await StorageService.setKnownEd25519(island, 'alice', 'owner', owner.edPubB64);
      CryptoService.lockSession();
      await CryptoService.ensureReady({ interactive: false });
      NetworkService._username = 'alice';
    }
  });
});

describe('a DM key', () => {
  async function dmWrap({ seed, signer }) {
    const dmKey = await CryptoUtils.exportRoomKey(await CryptoUtils.generateRoomKey(true));
    const kid = await CryptoUtils.fingerprintRoomKeyBase64(dmKey);
    return {
      encrypted_thread_key: await CryptoUtils.encryptRoomKeyForUser(me.pubB64, dmKey, {
        seed, signer, scope: 'dm', scopeId: DM, recipient: 'alice', keyId: kid,
      }),
      key_id: kid,
    };
  }

  test('is accepted from the other person in the thread', async () => {
    dmServed = await dmWrap({ seed: owner.edSeed, signer: 'owner' });
    // The receive path: no peer passed, so the island's thread list says who.
    const got = await CryptoService._loadDmKey(DM);
    expect(got).toEqual({ ok: true });
    expect(cryptoManager.roomKeys.has(CryptoService._dmRid(DM))).toBe(true);
    cryptoManager.roomKeys.delete(CryptoService._dmRid(DM));
  });

  test('is refused from anybody else, however valid their signature', async () => {
    dmServed = await dmWrap({ seed: mallory.edSeed, signer: 'mallory' });
    const got = await CryptoService._loadDmKey(DM, 'owner');
    expect(got).toEqual({ refused: true });
  });
});

describe('the writer', () => {
  test('refuses to hand out a key it cannot sign, rather than sign nothing', async () => {
    CryptoService.lockSession();
    try {
      await expect(CryptoService._wrapSignOpts(ROOM, 'bob', keyId)).rejects.toThrow(/unlock/i);
    } finally {
      await CryptoService.ensureReady({ interactive: false });
      NetworkService._username = 'alice';
    }
  });
});

describe('what this client writes (0.5.0: the writer is on)', () => {
  // The tests above feed the reader blobs built by hand. This one closes the
  // loop the flag opens: the writer's own output, served back by the island,
  // must open the room. If it did not, switching KEY_WRAP_SIG_WRITE_ENABLED on
  // would lock every room creator out of the room they just made.
  test('a key it hands out is signed by it, and opens again on the way back', async () => {
    const ROOM2 = ROOM + 1;
    let uploaded = null;
    const prev = global.fetch;
    global.fetch = jest.fn(async (url, opts = {}) => {
      const u = String(url);
      if (u.endsWith('/crypto/room-key') && String(opts.method).toUpperCase() === 'POST') {
        uploaded = JSON.parse(opts.body);
      }
      let body = {};
      if (u.includes(`/crypto/room-key/${ROOM2}`) && uploaded) {
        body = { encrypted_room_key: uploaded.encrypted_room_key, key_id: uploaded.key_id };
      } else if (u.includes('/crypto/room-key-archive')) {
        body = [];
      }
      return {
        ok: true, status: 200, headers: { get: () => 'application/json' },
        async json() { return body; }, async text() { return JSON.stringify(body); },
      };
    });
    try {
      expect(await CryptoService.createAndShareRoomKey(ROOM2, me.pubB64)).toBeTruthy();
      expect(uploaded?.room_id).toBe(ROOM2);

      const info = CryptoUtils.inspectWrappedKey(uploaded.encrypted_room_key, {
        scope: 'room', scopeId: ROOM2, recipient: 'alice', keyId: uploaded.key_id,
      });
      expect(info.version).toBe(3);
      expect(info.signer).toBe('alice');

      cryptoManager.roomKeys.delete(ROOM2);
      cryptoManager.roomKeyArchive.delete(ROOM2);
      await CryptoService.ensureRoomKeyReady(ROOM2);
      expect(cryptoManager.roomKeys.has(ROOM2)).toBe(true);
    } finally {
      global.fetch = prev;
      cryptoManager.roomKeys.delete(ROOM2);
      cryptoManager.roomKeyArchive.delete(ROOM2);
    }
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
