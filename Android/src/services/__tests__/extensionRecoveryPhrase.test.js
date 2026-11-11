// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * A recovery phrase that was never confirmed (chrome_extension/panel-crypto.js,
 * _surfacePendingMnemonicIfNeeded, called from initializeCrypto).
 *
 * Registration shows the 24 words and keeps a flag until the user confirms
 * them; if the window closes first, the phrase - the only way back into the
 * account without the password - has to be shown again. login.js does that
 * at the next login with the password. A session that survived needs no
 * login: the user unlocks in the panel, and the panel's half of this lived
 * only in a function nothing called, so the phrase was never shown again.
 *
 * Runs the real initializeCrypto with the real CryptoUtils and CryptoManager;
 * only the overlay itself is replaced by a recorder.
 */

const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const USER = 'phrase_user';
const FLAG = 'e2ee_pending_mnemonic_v1';

async function settle(cond, ms = 2000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (cond()) return true;
    await new Promise((r) => setTimeout(r, 10));
  }
  return cond();
}

async function lockedPanel({ flagFor = USER } = {}) {
  const P = makePanel({ apiBase: 'http://127.0.0.1:1', islandId: 'test', username: USER, token: '' });
  const id = await unlockRealManager(P.sandbox, { username: USER, password: PASS });
  P.manager.clear();

  const s = P.sandbox;
  const seen = { shown: [], acks: [] };
  s.resolveActiveUsername = async () => USER;
  s.loadLocalIdentity = async () => ({ encrypted_private_key: id.encrypted, public_key: id.publicKeyB64 });
  s.assertEpkKdfMatchesPin = () => {};
  s.pinEpkKdfNameIfNeeded = async () => {};
  s.ensureEd25519KeyRegistered = async () => {};
  s.sendMasterKeyToBackground = async () => {};
  s.promptPassword = async () => seen.password;
  s._showMnemonicOverlay = (mnemonic, onAck) => { seen.shown.push(mnemonic); seen.acks.push(onAck); };
  if (flagFor) await s.chrome.storage.local.set({ [FLAG]: { username: flagFor, ts: Date.now() } });

  const expected = P.CU.bip39Encode(
    P.CU.extractRawKeyFromPkcs8(new Uint8Array(P.CU.base64ToArrayBuffer(id.pkcs8B64))),
  );
  const flag = async () => (await s.chrome.storage.local.get([FLAG]))[FLAG];
  const unlock = (opts) => vm.runInContext(`initializeCrypto(${JSON.stringify(opts)})`, s);
  return { P, id, s, seen, expected, flag, unlock };
}

describe('a recovery phrase that was never confirmed', () => {
  it('is shown again when the panel is unlocked with the password', async () => {
    const T = await lockedPanel();
    T.seen.password = PASS;

    expect(await T.unlock({ interactive: true, reason: 'test' })).toBe(true);
    expect(await settle(() => T.seen.shown.length > 0)).toBe(true);

    // The same 24 words registration showed: the phrase of this identity.
    expect(T.seen.shown).toEqual([T.expected]);
    expect(T.expected.split(' ')).toHaveLength(24);
    // The unlock did not wait for the user to read it.
    expect(await T.flag()).toBeTruthy();

    await T.seen.acks[0]();
    expect(await T.flag()).toBeUndefined();
  });

  it('and after an unlock from the key the worker handed over', async () => {
    const T = await lockedPanel();
    T.s.__kek = T.id.aesKey;
    expect(await vm.runInContext('initializeCrypto({ interactive: false, kekKey: __kek })', T.s)).toBe(true);
    expect(await settle(() => T.seen.shown.length > 0)).toBe(true);
    expect(T.seen.shown).toEqual([T.expected]);
  });

  it('is shown once, however many unlocks come before it is confirmed', async () => {
    const T = await lockedPanel();
    T.seen.password = PASS;
    await T.unlock({ interactive: true, reason: 'one' });
    await settle(() => T.seen.shown.length > 0);
    T.P.manager.clear();
    await T.unlock({ interactive: true, reason: 'two' });
    await new Promise((r) => setTimeout(r, 200));
    expect(T.seen.shown).toHaveLength(1);

    // Once confirmed and set again (a later registration), it is shown again.
    await T.seen.acks[0]();
    await T.s.chrome.storage.local.set({ [FLAG]: { username: USER, ts: Date.now() } });
    T.P.manager.clear();
    await T.unlock({ interactive: true, reason: 'three' });
    expect(await settle(() => T.seen.shown.length === 2)).toBe(true);
  });
});

describe('and nothing else', () => {
  it('shows nothing when nothing is pending', async () => {
    const T = await lockedPanel({ flagFor: null });
    T.seen.password = PASS;
    expect(await T.unlock({ interactive: true, reason: 'test' })).toBe(true);
    await new Promise((r) => setTimeout(r, 200));
    expect(T.seen.shown).toEqual([]);
  });

  it("drops another account's flag instead of showing anything", async () => {
    const T = await lockedPanel({ flagFor: 'someone_else' });
    T.seen.password = PASS;
    expect(await T.unlock({ interactive: true, reason: 'test' })).toBe(true);
    await new Promise((r) => setTimeout(r, 200));
    expect(T.seen.shown).toEqual([]);
    expect(await T.flag()).toBeUndefined();
  });

  it('shows nothing for a wrong password, and keeps the flag for the right one', async () => {
    const T = await lockedPanel();
    T.seen.password = 'not-the-password-1';
    expect(await T.unlock({ interactive: true, reason: 'test' })).toBe(false);
    await new Promise((r) => setTimeout(r, 200));
    expect(T.seen.shown).toEqual([]);
    expect(await T.flag()).toBeTruthy();
  });
});
