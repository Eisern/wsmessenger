// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Recovering an account with a signature (account-recovery.js, both copies,
 * and CryptoUtils.deriveRecoverySigningSeed / recoveryProof in both clients).
 *
 * The vectors were computed separately, in Python with `cryptography`, from
 * the same fixed key: HKDF-SHA256(ikm=01..20, salt=0*32, "ws-recovery-sign-v1"),
 * its Ed25519 public key, and the signature over the challenge the server
 * builds (_recovery_challenge in server/main.py). If either client drifts from
 * them, every recovery key it registered stops matching the phrase.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
import AND from '../../crypto/CryptoUtils';

const AR = require('../account-recovery');
const EXT_DIR = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension');

function loadExtension(file, global) {
  const sandbox = { crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, console, URL };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_DIR, file), 'utf8'), sandbox, { filename: file });
  return global(sandbox);
}

const EXT = loadExtension('crypto-utils.js', (s) => s.__wsCrypto.utils);
const AR_EXT = loadExtension('account-recovery.js', (s) => s.WSAccountRecovery);

const PRIV = new Uint8Array(32).map((_, i) => i + 1);
const V = {
  seed: '8c8f9754b111bcc5be14f81021d7e581013cda51118cfc6a538a9663367e926b',
  pub: '81ea55b1e49a17e135b39858194609b37af1393f61d086b2194e12fb461bc37e',
  auth: 'f2ef659c12c605cac34f84155f00a8b4d1f67018d228520e5552156b4fe8fbab',
  // "ws-recover-v1" 0 "alice" 0 "n0nce" 0 sha256("Newpass!67890")
  challenge: '77732d7265636f7665722d763100616c696365006e306e636500aef95be1eeca2b6f112a842b845db5f165c73518e23f62f214780e28c9dd0886',
  sig: '2JbxgCuufDhxJYHm3VBaMuMRh96dRks0ZXLCF3__leErGtOR1vKd_m8qTs1gNHlMbrreQf7b0HcN5Sdq9NpPCg',
};
const hex = (u8) => Buffer.from(u8).toString('hex');
const unb64 = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const sha256 = async (b) => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', b));

describe('the recovery key is the same in both clients, and the same as the server expects', () => {
  it.each([['extension', EXT], ['Android', AND]])('%s', async (_n, U) => {
    const seed = await U.deriveRecoverySigningSeed(PRIV);
    expect(hex(seed)).toBe(V.seed);
    const proof = await U.recoveryProof(PRIV);
    expect(hex(unb64(proof.pubB64))).toBe(V.pub);
    expect(hex(unb64(proof.authB64))).toBe(V.auth);
    expect(await U.ed25519Sign(seed, Buffer.from(V.challenge, 'hex'))).toBe(V.sig);
  });

  it.each([['extension copy', AR_EXT], ['Android copy', AR]])('%s builds the challenge the server checks', async (_n, M) => {
    expect(hex(await M.challengeBytes(sha256, ' Alice ', 'n0nce', 'Newpass!67890'))).toBe(V.challenge);
  });

  it('the recovery key is not the identity signing key', async () => {
    // The island publishes and serves the identity key; a recovery key it
    // could stand in for would be no key at all.
    expect(hex(await AND.deriveRecoverySigningSeed(PRIV))).not.toBe(hex(await AND.deriveEd25519Seed(PRIV)));
  });
});

function island(replies) {
  const sent = [];
  let nonces = 0;
  return {
    sent,
    d: {
      start: async () => `nonce${++nonces}`,
      send: async (body) => { sent.push(body); return replies.shift() || { ok: false, status: 500 }; },
      sign: async () => 'SIG',
      sha256,
      legacyAuthB64: async () => 'OLD_SECRET',
    },
  };
}

describe('recover', () => {
  test('signs first, and sends nothing else when that is accepted', async () => {
    const { d, sent } = island([{ ok: true, status: 200 }]);
    expect(await AR.recover(d, { username: 'alice', newPassword: 'Newpass!67890' })).toEqual({ ok: true, method: 'key' });
    expect(sent).toEqual([{ username: 'alice', nonce: 'nonce1', signature_b64: 'SIG', new_password: 'Newpass!67890' }]);
  });

  test('falls back to the old secret on a refusal, with a fresh nonce', async () => {
    const { d, sent } = island([{ ok: false, status: 401 }, { ok: true, status: 200 }]);
    expect(await AR.recover(d, { username: 'alice', newPassword: 'x'.repeat(8) })).toEqual({ ok: true, method: 'legacy' });
    expect(sent[1]).toEqual({ username: 'alice', nonce: 'nonce2', recovery_auth_b64: 'OLD_SECRET', new_password: 'x'.repeat(8) });
    expect(sent[1].signature_b64).toBeUndefined();
  });

  test('a limit or a failure is not a refusal: the old secret is not sent for it', async () => {
    for (const status of [429, 0, 500, 400]) {
      const { d, sent } = island([{ ok: false, status }]);
      expect((await AR.recover(d, { username: 'a', newPassword: 'x'.repeat(8) })).ok).toBe(false);
      expect(sent).toHaveLength(1);
    }
  });

  test('without a way to make the old secret, a refusal is the answer', async () => {
    const { d, sent } = island([{ ok: false, status: 401, detail: 'no' }]);
    delete d.legacyAuthB64;
    expect(await AR.recover(d, { username: 'a', newPassword: 'x'.repeat(8) })).toEqual({ ok: false, status: 401, detail: 'no' });
    expect(sent).toHaveLength(1);
  });
});

describe('migrate', () => {
  function server(state) {
    const posted = [];
    let proofs = 0;
    return {
      posted,
      proofs: () => proofs,
      d: {
        state: async () => state,
        proof: async () => { proofs += 1; return { authB64: 'OLD', pubB64: 'PUB' }; },
        post: async (b) => { posted.push(b); return { ok: true, status: 200 }; },
      },
    };
  }

  test('an account from before sends its old secret once, with the new key', async () => {
    const s = server('hash');
    expect(await AR.migrate(s.d)).toBe('moved');
    expect(s.posted).toEqual([{ recovery_auth_b64: 'OLD', recovery_pub: 'PUB' }]);
  });

  test.each(['key', 'none', 'unknown'])('an account that is "%s" sends nothing, and makes no proof', async (st) => {
    const s = server(st);
    expect(await AR.migrate(s.d)).toBe(st);
    expect(s.posted).toHaveLength(0);
    expect(s.proofs()).toBe(0);
  });
});
