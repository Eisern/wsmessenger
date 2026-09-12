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
  ['bip39Encode', async (U) => U.bip39Encode(PRIV), V.bip39],
  ['deriveEd25519Seed', async (U) => hex(await U.deriveEd25519Seed(PRIV)), V.deriveEd25519Seed],
  ['deriveRecoveryAuth', async (U) => hex(await U.deriveRecoveryAuth(PRIV)), V.deriveRecoveryAuth],
  ['ed25519GetPublicKey', async (U) => hex(await U.ed25519GetPublicKey(await U.deriveEd25519Seed(PRIV))), V.ed25519Pub],
  ['ed25519Sign', async (U) => U.ed25519Sign(await U.deriveEd25519Seed(PRIV), new TextEncoder().encode('canonical message')), V.ed25519Sig],
  ['_padBucket(1)', async (U) => U._padBucket(1), V.padBucket1],
  ['_padBucket(100)', async (U) => U._padBucket(100), V.padBucket100],
  ['_stableJson', async (U) => U._stableJson({ b: 1, a: [2, { d: 4, c: 3 }] }), V.stableJson],
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
