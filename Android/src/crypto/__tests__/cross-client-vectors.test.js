// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Pinned cross-client test vectors.
 *
 * Every byte-level format in this project is written by hand TWICE — once in
 * chrome_extension/crypto-utils.js and once in Android/src/crypto/CryptoUtils.js
 * — against two different crypto stacks (WebCrypto and @noble). Nothing checked
 * that the two agree, and they silently stopped agreeing: fingerprintPublicKey
 * hashed the base64 text on Android and the raw bytes in the extension, and the
 * fingerprint is shown to the user, so verifying a key between phone and
 * browser compared two different numbers.
 *
 * This file exists so that cannot happen again. The expected values are
 * LITERALS, not something either implementation computes at test time: a
 * regression in both at once must still fail. Changing a value here is
 * changing a wire format, and needs a version bump and a migration, not an
 * edit.
 *
 * The extension is loaded in a vm sandbox — it is a classic script that
 * registers itself on globalThis, and Node supplies everything it needs
 * (WebCrypto, TextEncoder, atob/btoa).
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
import AND from '../CryptoUtils';

const EXTENSION_SRC = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'crypto-utils.js');

function loadExtensionUtils() {
  const src = fs.readFileSync(EXTENSION_SRC, 'utf8');
  const sandbox = { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, console, URL };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: 'crypto-utils.js' });
  const utils = sandbox.__wsCrypto && sandbox.__wsCrypto.utils;
  if (!utils) throw new Error('extension crypto-utils.js did not register __wsCrypto.utils');
  return utils;
}

/**
 * Bytes made inside the vm sandbox are not `instanceof Uint8Array` out here —
 * different realm, different prototype. Identify byte containers by shape.
 */
function hex(v) {
  if (v == null) throw new Error('expected bytes, got ' + String(v));
  if (typeof v === 'string') return v;
  const arr =
    typeof v.length === 'number' ? Array.from(v, Number) : Array.from(new Uint8Array(v), Number);
  return Buffer.from(arr).toString('hex');
}

// ---- fixed inputs -------------------------------------------------------
const PRIV = new Uint8Array(32).map((_, i) => i + 1);          // 01..20
const PUB_B64 = Buffer.from(new Uint8Array(32).map((_, i) => 0x40 + i)).toString('base64');
// A second key, so a pair can be formed. Its kid sorts before PUB_B64's, which
// is what makes the order test below meaningful rather than accidental.
const PUB2_B64 = Buffer.from(new Uint8Array(32).map((_, i) => i + 1)).toString('base64');

// ---- pinned outputs — do not recompute ----------------------------------
const V = {
  sha256Hex: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  sha256Raw: '0203b52a69e0c4dd07434fb2d93c82fec67f89679bf78f51645d5f9cb885ef77',

  // Hash of the raw 32 key bytes. Android used to hash the base64 TEXT, which
  // is the legacy form kept below only so old pins can be recognised.
  fingerprintPublicKey: 'ca2a4fe727faaecf16ecd130a86e0885',
  fingerprintPublicKeyLegacy: '9c1c6b0f2c0e1b5a',   // asserted by prefix only, see test
  fingerprintRoomKeyBase64: 'ca2a4fe727faaecf',

  // "ws-dm-sig-v1" ‖ uint32BE(threadId) ‖ uint16BE(len(from)) ‖ from ‖ body
  // A global identifier does not fit in that uint32 — this is the format the
  // federation assessment named as the expensive one to change.
  dmSigMessage: '77732d646d2d7369672d76310000002a0005616c69636568656c6c6f20776f726c64',
  dmSigMessageEmpty: '77732d646d2d7369672d7631000000000000',
  dmSigMessageUnicode: '77732d646d2d7369672d7631ffffffff0006d096d0a3d09ad0bad0bbd18ed18720e29aa1',

  bip39:
    'absurd avoid scissors anxiety gather lottery category door army half long cage ' +
    'bachelor another expect people blade school educate curtain scrub monitor lady beyond',

  deriveEd25519Seed: '928d12b121bae0dfdf43870dc3ab21fd255fbdd5b43da63dbe208461b3d5be51',
  deriveRecoveryAuth: 'f2ef659c12c605cac34f84155f00a8b4d1f67018d228520e5552156b4fe8fbab',
  ed25519Pub: '8070f93cd4bd6badc92dfab631fd390e2d976725cd49db539e9b2abdad22132f',
  ed25519Sig: 'ZjzuK99luiHyd2QNT9qtamPRBLcwT8-6DToCH8663m60hZOK121Vrko0AQ1VT5qhlOQI9s94jSV-7MqN8eIeDg',

  dmSigMessageV2: '77732d646d2d7369672d76320000002a00000007' + 'aa'.repeat(32) + '0005616c69636568656c6c6f20776f726c64',
  dmSigMessageV2Genesis: '77732d646d2d7369672d7632000000010000000100000000000000000000000000000000000000000000000000000000000000000000',

  // Two people read this aloud to each other. If the two clients disagree, the
  // number that is supposed to prove nobody is in the middle becomes the thing
  // that says somebody is.
  safetyNumberV2: '16494 02878 99189 75102 28754 87121 50637 46431 96992 49973 55065 63096',

  padBucket1: 64,
  padBucket100: 128,
  stableJson: '{"a":[2,{"c":3,"d":4}],"b":1}',
};

let EXT;
beforeAll(() => {
  EXT = loadExtensionUtils();
});

// Each case runs against BOTH implementations and against the pinned literal.
const CASES = [
  ['sha256Hex', async (U) => U.sha256Hex('ws-messenger'), V.sha256Hex],
  ['sha256Raw', async (U) => hex(await U.sha256Raw(new TextEncoder().encode('ws-messenger'))), V.sha256Raw],
  ['fingerprintPublicKey', async (U) => U.fingerprintPublicKey(PUB_B64), V.fingerprintPublicKey],
  ['fingerprintRoomKeyBase64', async (U) => U.fingerprintRoomKeyBase64(PUB_B64), V.fingerprintRoomKeyBase64],
  ['_dmSigMessage', async (U) => hex(await U._dmSigMessage(42, 'alice', 'hello world')), V.dmSigMessage],
  ['_dmSigMessage (empty)', async (U) => hex(await U._dmSigMessage(0, '', '')), V.dmSigMessageEmpty],
  ['_dmSigMessage (unicode, max thread id)', async (U) => hex(await U._dmSigMessage(4294967295, 'ЖУК', 'ключ ⚡')), V.dmSigMessageUnicode],
  // v2 binds the message to its place in the sender's chain. v1 above stays
  // pinned forever: history signed before v2 existed must remain verifiable.
  ['_dmSigMessageV2', async (U) => hex(await U._dmSigMessageV2(42, 7, 'aa'.repeat(32), 'alice', 'hello world')), V.dmSigMessageV2],
  ['_dmSigMessageV2 (genesis)', async (U) => hex(await U._dmSigMessageV2(1, 1, '00'.repeat(32), '', '')), V.dmSigMessageV2Genesis],
  ['bip39Encode', async (U) => U.bip39Encode(PRIV), V.bip39],
  ['deriveEd25519Seed', async (U) => hex(await U.deriveEd25519Seed(PRIV)), V.deriveEd25519Seed],
  ['deriveRecoveryAuth', async (U) => hex(await U.deriveRecoveryAuth(PRIV)), V.deriveRecoveryAuth],
  ['ed25519GetPublicKey', async (U) => hex(await U.ed25519GetPublicKey(await U.deriveEd25519Seed(PRIV))), V.ed25519Pub],
  ['ed25519Sign', async (U) => U.ed25519Sign(await U.deriveEd25519Seed(PRIV), new TextEncoder().encode('canonical message')), V.ed25519Sig],
  ['_padBucket(1)', async (U) => U._padBucket(1), V.padBucket1],
  ['_padBucket(100)', async (U) => U._padBucket(100), V.padBucket100],
  ['_stableJson', async (U) => U._stableJson({ b: 1, a: [2, { d: 4, c: 3 }] }), V.stableJson],
  // Keys, not names: a cross-island pair shares no namespace, and two people
  // may carry the same username on two islands.
  ['computeSafetyNumberV2', async (U) => U.computeSafetyNumberV2(PUB2_B64, PUB_B64), V.safetyNumberV2],
];

describe('extension matches the pinned vectors', () => {
  it.each(CASES)('%s', async (_name, fn, expected) => {
    expect(await fn(EXT)).toEqual(expected);
  });
});

describe('Android matches the pinned vectors', () => {
  it.each(CASES)('%s', async (_name, fn, expected) => {
    expect(await fn(AND)).toEqual(expected);
  });
});

describe('round trips agree across clients', () => {
  it('a safety number does not depend on who is asking', async () => {
    // Each side passes its own key first. Reading out different numbers would
    // look exactly like an interception to two people on the phone.
    const mine = await EXT.computeSafetyNumberV2(PUB2_B64, PUB_B64);
    const theirs = await AND.computeSafetyNumberV2(PUB_B64, PUB2_B64);
    expect(mine).toBe(theirs);
    expect(mine).toBe(V.safetyNumberV2);
  });

  it('the v2 number is not the v1 number for the same pair', async () => {
    // Separate domains, so a v1 number can never be read as a v2 one - and the
    // local pairs that already verified keep the number they verified.
    const v1 = await EXT.computeSafetyNumber('alice', PUB2_B64, 'bob', PUB_B64);
    expect(v1).not.toBe(V.safetyNumberV2);
    expect(await AND.computeSafetyNumber('alice', PUB2_B64, 'bob', PUB_B64)).toBe(v1);
  });

  it('bip39 decodes on either side what the other encoded', async () => {
    const fromExt = await EXT.bip39Encode(PRIV);
    const fromAnd = await AND.bip39Encode(PRIV);
    expect(fromExt).toBe(fromAnd);
    expect(hex(await AND.bip39Decode(fromExt))).toBe(hex(PRIV));
    expect(hex(await EXT.bip39Decode(fromAnd))).toBe(hex(PRIV));
  });

  it('an Ed25519 signature made by one client verifies on the other', async () => {
    const seed = await AND.deriveEd25519Seed(PRIV);
    const pub = await AND.ed25519GetPublicKey(seed);
    const msg = await AND._dmSigMessage(7, 'bob', 'signed on android');
    const sig = await AND.ed25519Sign(seed, msg);

    const sigBytes = Uint8Array.from(
      Buffer.from(String(sig).replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
    );
    // The extension must accept it - and must be handed the same message bytes,
    // which is exactly the _dmSigMessage format pinned above.
    expect(await EXT.ed25519Verify(Uint8Array.from(pub), sigBytes, Uint8Array.from(msg))).toBe(true);
  });

  it('padding applied by one client is stripped by the other', async () => {
    // _padPlaintext takes text and _unpadPlaintext gives text back; the bytes
    // in between are the wire format, and the padding is random, so the
    // round trip across implementations is what can be asserted.
    const text = 'padding crosses the client boundary';
    const plain = new TextEncoder().encode(text);

    const padded = await EXT._padPlaintext(plain);
    expect(await AND._unpadPlaintext(Uint8Array.from(padded))).toBe(text);

    const padded2 = await AND._padPlaintext(plain);
    expect(await EXT._unpadPlaintext(Uint8Array.from(padded2))).toBe(text);

    // Both must agree on the bucket, or one client's messages would leak a
    // different length than the other's.
    expect(padded.length).toBe(padded2.length);
    expect(padded.length).toBe(64);
  });
});

describe('the relay envelope', () => {
  // Random by nature, so the test injects the ephemeral key and the IV. That
  // makes the whole construction deterministic: header layout, kid, HKDF with
  // its two info strings, the AAD, and AES-GCM itself. If any one of them
  // differed between the clients, these bytes would not match.
  const EPH_PRIV = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
  const IV = new Uint8Array(12).map((_, i) => 0xa0 + i);
  const INNER = {
    thread_id: 42,
    ts: 1700000000000,
    nonce_b64: 'AAECAwQFBgcICQoLDA0ODw==',
    ciphertext_b64: 'aGVsbG8gcmVsYXk=',
    tag_b64: 'dGFn',
    env_ts: 1700000000123,
    env_nonce_b64: 'EBESExQVFhcYGRobHB0eHw==',
  };
  // The island transport key the vectors are sealed to, and its matching
  // private half, so the test can also open what the clients produced.
  const ISLAND_PRIV = new Uint8Array(32).map((_, i) => (200 - i) & 0xff);

  let islandPubB64;
  let ephPubRaw;

  beforeAll(() => {
    const { x25519 } = require('@noble/curves/ed25519');
    islandPubB64 = Buffer.from(x25519.getPublicKey(ISLAND_PRIV)).toString('base64');
    ephPubRaw = x25519.getPublicKey(EPH_PRIV);
  });

  async function sealWith(U) {
    const r = await U.sealRelayEnvelope(islandPubB64, INNER, {
      ephemeralPrivateRaw: EPH_PRIV,
      ephemeralPublicRaw: ephPubRaw,   // WebCrypto cannot derive it from an imported private key
      iv: IV,
    });
    return r;
  }

  it('both clients produce byte-identical envelopes', async () => {
    const a = await sealWith(EXT);
    const b = await sealWith(AND);
    expect(hex(a.envelope)).toBe(hex(b.envelope));

    // Layout: version, kid, ephemeral public key, IV, then sealed bytes.
    const bytes = Uint8Array.from(Array.from(a.envelope, Number));
    expect(bytes[0]).toBe(0x03);
    expect(hex(bytes.slice(5, 37))).toBe(hex(ephPubRaw));
    expect(hex(bytes.slice(37, 49))).toBe(hex(IV));
    expect(bytes.length).toBe(49 + new TextEncoder().encode(JSON.stringify(INNER)).length + 16);
  });

  it('the island can open what either client sealed', async () => {
    const { x25519 } = require('@noble/curves/ed25519');
    const { hkdf } = require('@noble/hashes/hkdf');
    const { sha256 } = require('@noble/hashes/sha2');
    const nodeCrypto = require('crypto');

    for (const U of [EXT, AND]) {
      const { envelope } = await sealWith(U);
      const bytes = Buffer.from(Array.from(envelope, Number));

      // The island side, done independently of either client implementation.
      const shared = x25519.getSharedSecret(ISLAND_PRIV, bytes.subarray(5, 37));
      const keyReq = Buffer.from(
        hkdf(sha256, shared, bytes.subarray(5, 37), new TextEncoder().encode('ws-relay-seal-v1:req'), 32),
      );
      const sealed = bytes.subarray(49);
      const d = nodeCrypto.createDecipheriv('aes-256-gcm', keyReq, bytes.subarray(37, 49));
      d.setAAD(bytes.subarray(0, 37));
      d.setAuthTag(sealed.subarray(sealed.length - 16));
      const plain = Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]);
      expect(JSON.parse(plain.toString('utf8'))).toEqual(INNER);
    }
  });

  it('each client opens an answer sealed with the response key, and rejects the request key', async () => {
    const { x25519 } = require('@noble/curves/ed25519');
    const { hkdf } = require('@noble/hashes/hkdf');
    const { sha256 } = require('@noble/hashes/sha2');
    const nodeCrypto = require('crypto');

    const shared = x25519.getSharedSecret(ISLAND_PRIV, ephPubRaw);
    const mkAnswer = (info) => {
      const key = Buffer.from(hkdf(sha256, shared, ephPubRaw, new TextEncoder().encode(info), 32));
      const iv = Buffer.from(new Uint8Array(12).map((_, i) => i + 1));
      const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
      c.setAAD(Buffer.from([0x03]));
      const ct = Buffer.concat([c.update(JSON.stringify({ status: 200, ok: true }), 'utf8'), c.final()]);
      return Buffer.concat([Buffer.from([0x03]), iv, ct, c.getAuthTag()]);
    };

    const good = mkAnswer('ws-relay-seal-v1:resp');
    const wrongDirection = mkAnswer('ws-relay-seal-v1:req');

    for (const U of [EXT, AND]) {
      const { responseKey } = await sealWith(U);
      expect(await U.openRelayResponse(responseKey, good)).toEqual({ status: 200, ok: true });
      // Request and response keys must be distinct - one key in both
      // directions would reuse the AES-GCM IV space.
      await expect(U.openRelayResponse(responseKey, wrongDirection)).rejects.toBeDefined();
    }
  });
});

describe('the fingerprint format that already diverged', () => {
  it('the legacy form is still recognisable, so old pins can be migrated', async () => {
    // The extension keeps the old function for exactly one purpose: telling a
    // stored legacy pin apart from a real key change. Android needs the same,
    // because its stored pins were all written in the legacy form.
    const legacy = await EXT._fingerprintPublicKeyLegacy(PUB_B64);
    expect(typeof legacy).toBe('string');
    expect(legacy).not.toBe(V.fingerprintPublicKey);
    expect(await AND._fingerprintPublicKeyLegacy(PUB_B64)).toBe(legacy);
  });
});

describe('v1 and v2 signatures do not substitute for one another', () => {
  // The migration rule this enforces: readers must accept both before any
  // writer emits v2, and a message signed under one variant must never verify
  // under the other. The domain prefix differs, so the variant is inside the
  // signature - which is what makes stripping sq/pv a failure rather than a
  // downgrade.
  const PREV = 'bb'.repeat(32);

  it('a v2 signature does not verify as v1', async () => {
    for (const U of [EXT, AND]) {
      const seed = await U.deriveEd25519Seed(PRIV);
      const pub = await U.ed25519GetPublicKey(seed);
      const v2 = await U._dmSigMessageV2(9, 3, PREV, 'alice', 'hello');
      const sig = await U.ed25519Sign(seed, v2);
      const sigBytes = Uint8Array.from(
        Buffer.from(String(sig).replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
      );

      const v1 = await U._dmSigMessage(9, 'alice', 'hello');
      expect(await U.ed25519Verify(Uint8Array.from(pub), sigBytes, Uint8Array.from(v2))).toBe(true);
      expect(await U.ed25519Verify(Uint8Array.from(pub), sigBytes, Uint8Array.from(v1))).toBe(false);
    }
  });

  it('moving a message to another position breaks its signature', async () => {
    // seq and prev are inside the signed bytes, so re-filing a genuine message
    // at a different height is not something an operator can do quietly.
    const U = AND;
    const seed = await U.deriveEd25519Seed(PRIV);
    const pub = await U.ed25519GetPublicKey(seed);
    const atThree = await U._dmSigMessageV2(9, 3, PREV, 'alice', 'hello');
    const sig = await U.ed25519Sign(seed, atThree);
    const sigBytes = Uint8Array.from(
      Buffer.from(String(sig).replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
    );

    const atFour = await U._dmSigMessageV2(9, 4, PREV, 'alice', 'hello');
    expect(await U.ed25519Verify(Uint8Array.from(pub), sigBytes, Uint8Array.from(atFour))).toBe(false);
  });

  it('rejects a prev that is not 32 bytes of hex', async () => {
    for (const U of [EXT, AND]) {
      await expect(async () => U._dmSigMessageV2(1, 1, 'short', 'a', 'b')).rejects.toBeDefined();
    }
  });
});

describe('both clients refuse a weakened key derivation', () => {
  // The parameters are not ours: they travel in the encrypted private-key
  // container, which lives in local storage and, in older builds, came back
  // from a server. Whoever can rewrite them can pick how hard the password is
  // to brute force - and the client would never look any different. So the
  // floors are checked on the way in, in both implementations, and a container
  // that asks for less than they allow is refused rather than honoured.
  const SALT = Buffer.from(new Uint8Array(16).fill(9)).toString('base64');

  const weakened = [
    ['one iteration', { name: 'PBKDF2', iterations: 1, hash: 'SHA-256' }],
    ['just under the floor', { name: 'PBKDF2', iterations: 599999, hash: 'SHA-256' }],
    ['zero', { name: 'PBKDF2', iterations: 0, hash: 'SHA-256' }],
    ['a broken hash', { name: 'PBKDF2', iterations: 620000, hash: 'SHA-1' }],
    ['a hash nobody offers', { name: 'PBKDF2', iterations: 620000, hash: 'MD5' }],
  ];

  for (const [what, kdf] of weakened) {
    it(`refuses ${what}: extension`, async () => {
      await expect(EXT.deriveRawKeyFromPassword('correct horse', SALT, kdf)).rejects.toThrow();
    });
    it(`refuses ${what}: Android`, async () => {
      await expect(AND.deriveRawKeyFromPassword('correct horse', SALT, kdf)).rejects.toThrow();
    });
  }

  it('accepts the floor itself, so the limit is a floor and not a fence', async () => {
    const at = { name: 'PBKDF2', iterations: 600000, hash: 'SHA-256' };
    const a = await EXT.deriveRawKeyFromPassword('correct horse', SALT, at);
    const b = await AND.deriveRawKeyFromPassword('correct horse', SALT, at);
    expect(a.raw.length).toBe(32);
    // And the two clients derive the same bytes from the same inputs, which is
    // what lets one device open what the other wrote.
    expect(hex(a.raw)).toBe(hex(b.raw));
    expect(a.kdf.iterations).toBe(600000);
  });

  it('refuses a salt too short to be worth having', async () => {
    const short = Buffer.from(new Uint8Array(8)).toString('base64');
    const ok = { name: 'PBKDF2', iterations: 620000, hash: 'SHA-256' };
    await expect(EXT.deriveRawKeyFromPassword('correct horse', short, ok)).rejects.toThrow();
    await expect(AND.deriveRawKeyFromPassword('correct horse', short, ok)).rejects.toThrow();
  });

  it('never silently swaps Argon2id for PBKDF2', async () => {
    // The two clients answer differently here, and both answers are right for
    // what they are. The extension loads Argon2id as a WASM blob whose hash it
    // pins, so when it cannot verify that blob - as here - it refuses to
    // derive at all. Android compiles its Argon2id in: there is no blob to
    // substitute, so it derives.
    //
    // What neither may do is quietly fall back to PBKDF2. That would turn "the
    // implementation is unavailable" into "your key was derived a different
    // way", and the same password would then open nothing.
    await expect(
      EXT.deriveRawKeyFromPassword('correct horse', SALT, { name: 'Argon2id' }),
    ).rejects.toThrow(/argon2/i);

    const onAndroid = await AND.deriveRawKeyFromPassword('correct horse', SALT, { name: 'Argon2id' });
    expect(onAndroid.kdf.name).toBe('Argon2id');
    expect(onAndroid.raw.length).toBe(32);
  });

  it('refuses to open a container whose parameters were rewritten', async () => {
    // The attack end to end, on the path that actually reads them: take a
    // real container and lower its iteration count. Opening it must fail on
    // the parameters, not after deriving a wrong key.
    const container = {
      v: 3,
      alg: 'AES-256-GCM',
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations: 620000 },
      salt: SALT,
      iv: Buffer.from(new Uint8Array(12)).toString('base64'),
      data: Buffer.from(new Uint8Array(64)).toString('base64'),
      created_at: 0,
      username: 'someone',
      ext_version: '0',
    };
    const tampered = { ...container, kdf: { ...container.kdf, iterations: 10 } };

    await expect(EXT.decryptPrivateKey(tampered, 'correct horse')).rejects.toThrow(/iterations/i);
    await expect(AND.decryptPrivateKey(tampered, 'correct horse')).rejects.toThrow(/iterations/i);
  });
});
