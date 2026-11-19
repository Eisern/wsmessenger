// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Getting back in with the twenty-four words, against a real island.
 *
 * This path is used once, by somebody who has already lost something, and it
 * has two ways to be wrong that are opposites. Too strict and the words do not
 * work, which means the account is gone for good - the private key is on the
 * device and the island answers 410 to anyone who asks for it, so there is no
 * other copy. Too loose and the words are not needed, which means somebody
 * else can take the account.
 *
 * Nothing tested it end to end. The pieces were pinned - bip39 both ways, the
 * derivation of the recovery token - but not the conversation with the island
 * that turns them into a password reset.
 *
 * Requires island A; see integration/README.md.
 */

const { makePanel, http } = require('./helpers/panelHarness');

const ISLAND = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const OLD_PASS = 'Testpass!12345';
const NEW_PASS = 'Brandnew!67890';

const b64 = (b) => Buffer.from(b).toString('base64');

let CU;
let stamp;

jest.setTimeout(120000);

/** Everything a client needs to register an account that can be recovered. */
async function makeRecoverableAccount(username) {
  const kp = await CU.generateIdentityKeyPair();
  const pkcs8 = await CU.exportPrivateKey(kp.privateKey);
  const publicKeyB64 = await CU.exportPublicKey(kp.publicKey);

  // The 32 raw private bytes are what the words encode, and what every
  // recovery secret is derived from.
  const rawPriv = Uint8Array.from(
    Buffer.from(String(pkcs8).replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  ).slice(-32);
  const words = await CU.bip39Encode(rawPriv);
  const recoveryAuth = await CU.deriveRecoveryAuth(rawPriv);
  const recoveryKeyHash = await CU.sha256Hex(recoveryAuth);

  const reg = await http(ISLAND, '/auth/register', {
    method: 'POST',
    body: {
      username,
      password: OLD_PASS,
      public_key: publicKeyB64,
      recovery_key_hash: recoveryKeyHash,
    },
  });
  if (!reg.ok && reg.status !== 409) throw new Error(`register ${username}: ${reg.status}`);

  return { username, words, rawPriv, recoveryAuth, publicKeyB64 };
}

/** What the client does with the words somebody typed back in. */
async function recoveryAuthFromWords(words) {
  const raw = await CU.bip39Decode(words);
  return CU.deriveRecoveryAuth(raw);
}

beforeAll(async () => {
  const h = await fetch(`${ISLAND}/health`).then((r) => r.json()).catch(() => null);
  if (!h || h.status !== 'ok') throw new Error(`island not reachable at ${ISLAND}`);
  CU = makePanel({ apiBase: ISLAND, islandId: 'island-local', username: 'x', token: '' }).CU;
  stamp = Date.now().toString().slice(-7);
});

describe('the twenty-four words', () => {
  it('decode back to the key they were made from', async () => {
    // If this drifts, every phrase ever written down stops working, and there
    // is no second copy of the key to fall back on.
    const acc = await makeRecoverableAccount(`rec_a_${stamp}`);
    expect(acc.words.split(/\s+/)).toHaveLength(24);

    const back = await CU.bip39Decode(acc.words);
    expect(Buffer.from(back).toString('hex')).toBe(Buffer.from(acc.rawPriv).toString('hex'));
  });

  it('refuse a phrase with a word changed', async () => {
    const acc = await makeRecoverableAccount(`rec_b_${stamp}`);
    const words = acc.words.split(/\s+/);
    words[7] = words[7] === 'abandon' ? 'ability' : 'abandon';
    // The checksum is the point: a typo has to be refused here, not turned
    // into a different key that silently fails against the island. Caught
    // rather than asserted with .rejects, because this one throws on the spot
    // and the two clients need not agree about that.
    let refused = false;
    try { await CU.bip39Decode(words.join(' ')); } catch { refused = true; }
    expect(refused).toBe(true);
  });
});

describe('getting back in', () => {
  let acc;

  beforeAll(async () => {
    acc = await makeRecoverableAccount(`rec_c_${stamp}`);
  });

  it('gives a nonce to anyone who asks, including for accounts that do not exist', async () => {
    // Answering differently would turn this endpoint into a way to ask the
    // island which usernames are real.
    const real = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: acc.username },
    });
    const fake = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: `no_such_user_${stamp}` },
    });
    expect(real.ok).toBe(true);
    expect(fake.ok).toBe(true);
    expect(String(real.data.nonce)).toHaveLength(String(fake.data.nonce).length);
    expect(real.data.nonce).not.toBe(fake.data.nonce);
  });

  it('refuses the wrong phrase', async () => {
    const other = await makeRecoverableAccount(`rec_d_${stamp}`);
    const start = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: acc.username },
    });
    // A missing nonce here would make every later assertion meaningless: the
    // island would be refusing a malformed request, not a wrong phrase.
    expect(start.data.nonce).toBeTruthy();
    const res = await http(ISLAND, '/auth/recover', {
      method: 'POST',
      body: {
        username: acc.username,
        nonce: start.data.nonce,
        recovery_auth_b64: b64(await recoveryAuthFromWords(other.words)),
        new_password: NEW_PASS,
      },
    });
    expect(res.ok).toBe(false);
    expect(res.status).toBe(401);

    // And the account is untouched: the old password still works.
    const login = await http(ISLAND, '/auth/login', {
      method: 'POST', body: { username: acc.username, password: OLD_PASS },
    });
    expect(login.ok).toBe(true);
  });

  it('accepts the right phrase and sets the new password', async () => {
    const start = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: acc.username },
    });
    const res = await http(ISLAND, '/auth/recover', {
      method: 'POST',
      body: {
        username: acc.username,
        nonce: start.data.nonce,
        recovery_auth_b64: b64(await recoveryAuthFromWords(acc.words)),
        new_password: NEW_PASS,
      },
    });
    expect(res.ok).toBe(true);

    const withNew = await http(ISLAND, '/auth/login', {
      method: 'POST', body: { username: acc.username, password: NEW_PASS },
    });
    expect(withNew.ok).toBe(true);

    const withOld = await http(ISLAND, '/auth/login', {
      method: 'POST', body: { username: acc.username, password: OLD_PASS },
    });
    expect(withOld.ok).toBe(false);
  });

  it('will not take the same nonce twice', async () => {
    // Single use, or a captured recovery could be repeated to take the account
    // back after the owner has settled on a new password.
    const start = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: acc.username },
    });
    const body = {
      username: acc.username,
      nonce: start.data.nonce,
      recovery_auth_b64: b64(await recoveryAuthFromWords(acc.words)),
      new_password: NEW_PASS,
    };

    expect((await http(ISLAND, '/auth/recover', { method: 'POST', body })).ok).toBe(true);
    const replay = await http(ISLAND, '/auth/recover', { method: 'POST', body });
    expect(replay.ok).toBe(false);
    // One answer for every refusal, a spent nonce included.
    expect(replay.status).toBe(401);
  });

  it('leaves the phrase working after a recovery', async () => {
    // The recovery secret comes from the key, not from the password, so
    // changing the password must not spend it. Somebody who recovers twice in
    // a month is exactly the person who will need it again.
    const start = await http(ISLAND, '/auth/recover-start', {
      method: 'POST', body: { username: acc.username },
    });
    const res = await http(ISLAND, '/auth/recover', {
      method: 'POST',
      body: {
        username: acc.username,
        nonce: start.data.nonce,
        recovery_auth_b64: b64(await recoveryAuthFromWords(acc.words)),
        new_password: OLD_PASS,
      },
    });
    expect(res.ok).toBe(true);
    expect((await http(ISLAND, '/auth/login', {
      method: 'POST', body: { username: acc.username, password: OLD_PASS },
    })).ok).toBe(true);
  });
});

/**
 * The recovery key, end to end: the extension's own CryptoUtils and
 * account-recovery.js against the island, so the bytes a client signs are the
 * bytes the server checks - not two descriptions of them.
 */
describe('recovering with a signature', () => {
  let panel;
  let AR;

  beforeAll(() => {
    panel = makePanel({ apiBase: ISLAND, islandId: 'island-local', username: 'x', token: '' });
    AR = panel.sandbox.WSAccountRecovery;
  });

  /** The extension's recovery, as login.js runs it. */
  async function recoverWith(raw, username, newPassword) {
    const seed = await CU.deriveRecoverySigningSeed(raw);
    const sent = [];
    const res = await AR.recover({
      start: async (name) => (await http(ISLAND, '/auth/recover-start', { method: 'POST', body: { username: name } })).data.nonce,
      send: async (body) => {
        sent.push(Object.keys(body).sort().join(','));
        const r = await http(ISLAND, '/auth/recover', { method: 'POST', body });
        return { ok: r.ok, status: r.status, detail: r.data?.detail };
      },
      sign: (msg) => CU.ed25519Sign(seed, msg),
      sha256: async (b) => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', b)),
      legacyAuthB64: async () => b64(await CU.deriveRecoveryAuth(raw)),
    }, { username, newPassword });
    return { res, sent };
  }

  async function register(username, raw, { withKey }) {
    const kp = await CU.generateIdentityKeyPair();
    const auth = await CU.deriveRecoveryAuth(raw);
    const body = {
      username, password: OLD_PASS, public_key: await CU.exportPublicKey(kp.publicKey),
      recovery_key_hash: await CU.sha256Hex(auth),
    };
    if (withKey) body.recovery_pub = (await CU.recoveryProof(raw)).pubB64;
    const r = await http(ISLAND, '/auth/register', { method: 'POST', body });
    expect(r.status).toBe(201);
  }

  const rawKey = () => globalThis.crypto.getRandomValues(new Uint8Array(32));
  const login = (username, password) => http(ISLAND, '/auth/login', { method: 'POST', body: { username, password } });

  it('an account registered today recovers by signing, and sends no secret', async () => {
    const name = `rec_k_${stamp}`;
    const raw = rawKey();
    await register(name, raw, { withKey: true });
    const { res, sent } = await recoverWith(raw, name, NEW_PASS);
    expect(res).toEqual({ ok: true, method: 'key' });
    expect(sent).toEqual(['new_password,nonce,signature_b64,username']);
    expect((await login(name, NEW_PASS)).ok).toBe(true);
  });

  it('the wrong phrase is refused both ways, and the password stays', async () => {
    const name = `rec_w_${stamp}`;
    await register(name, rawKey(), { withKey: true });
    const { res } = await recoverWith(rawKey(), name, NEW_PASS);
    expect(res.ok).toBe(false);
    expect((await login(name, OLD_PASS)).ok).toBe(true);
  });

  it('an account from before recovers with its secret, then moves to a key on unlock', async () => {
    // The panel's own migrateRecoveryKeyIfNeeded, with the proof the real
    // key manager kept from the unlock.
    const name = `rec_m_${stamp}`;
    const p = makePanel({ apiBase: ISLAND, islandId: 'island-local', username: name, token: '' });
    const { unlockRealManager, PASS } = require('./helpers/panelHarness');
    const id = await unlockRealManager(p.sandbox, { username: name, password: PASS });
    const raw = new Uint8Array(Buffer.from(id.pkcs8B64, 'base64')).slice(-32);
    const reg = await http(ISLAND, '/auth/register', {
      method: 'POST',
      body: { username: name, password: OLD_PASS, public_key: id.publicKeyB64,
        recovery_key_hash: await CU.sha256Hex(await CU.deriveRecoveryAuth(raw)) },
    });
    expect(reg.status).toBe(201);

    // Not moved yet: the old secret still works.
    expect((await recoverWith(raw, name, NEW_PASS)).res).toEqual({ ok: true, method: 'legacy' });

    const token = (await login(name, NEW_PASS)).data.access_token;
    p.setToken(token);
    expect(await p.sandbox.migrateRecoveryKeyIfNeeded()).toBe('moved');
    const st = await http(ISLAND, '/auth/recovery-key', { token });
    expect(st.data.state).toBe('key');
    // The proof was used once and is gone.
    expect(p.manager.takeRecoveryProof()).toBe(null);

    // From now on only a signature opens it - the old secret, sent on its own, does not.
    const nonce = (await http(ISLAND, '/auth/recover-start', { method: 'POST', body: { username: name } })).data.nonce;
    const old = await http(ISLAND, '/auth/recover', {
      method: 'POST',
      body: { username: name, nonce, recovery_auth_b64: b64(await CU.deriveRecoveryAuth(raw)), new_password: OLD_PASS },
    });
    expect(old.status).toBe(401);
    expect((await recoverWith(raw, name, OLD_PASS)).res).toEqual({ ok: true, method: 'key' });
  });
});
