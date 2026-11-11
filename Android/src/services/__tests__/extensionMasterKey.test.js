// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The worker's copy of the password-derived key, while the panel is in use
 * (chrome_extension/background.js, panel.js, panel-crypto.js).
 *
 * The worker encrypts room passwords and room-key archives with it, and
 * forgets it after ten idle minutes. Two things were missing around that:
 *
 *  - Only encrypting or decrypting counted as use, and a session goes far
 *    longer than ten minutes without either. The key vanished under an
 *    unlocked panel, and every room password and key archive after that was
 *    quietly not saved ("Room password was not saved: storage encryption is
 *    unavailable" in the console, nowhere else).
 *  - Unlocking the panel with the password opened the identity key and gave
 *    the worker nothing. Only a full login handed the key over, so once it
 *    had gone it stayed gone until the user logged out and in again.
 *
 * Both run here on the real files: the whole worker, the panel's half of the
 * handoff, and initializeCrypto with the real CryptoUtils and CryptoManager.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { startWorker } = require('./integration/helpers/workerHarness');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const EXT = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension');
const source = (f) => fs.readFileSync(path.join(EXT, f), 'utf8').split('\r\n').join('\n');

/** From `head` up to and including the first line that is exactly `close`. */
function block(src, head, close) {
  const start = src.indexOf(head);
  if (start < 0) throw new Error(`${head} not found`);
  const end = src.indexOf('\n' + close + '\n', start);
  if (end < 0) throw new Error(`end of ${head} not found`);
  return src.slice(start, end + close.length + 2);
}

const USER = 'master_key_user';
const MIN = 60 * 1000;
const b64 = (u8) => Buffer.from(u8).toString('base64');

/**
 * The panel's half of the handoff, taken from panel.js, talking to the real
 * worker over a port that carries messages both ways.
 */
function panelAgainst(w) {
  const listeners = new Set();
  const toWorker = w.port.postMessage;
  w.port.postMessage = (m) => {
    toWorker(m);
    for (const fn of [...listeners]) fn(m);
  };

  const sandbox = {
    crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, setTimeout, clearTimeout,
    port: {
      postMessage: (m) => { w.send(m).catch(() => {}); },
      onMessage: { addListener: (fn) => listeners.add(fn), removeListener: (fn) => listeners.delete(fn) },
    },
  };
  vm.createContext(sandbox);
  const src = source('panel.js');
  vm.runInContext(
    block(src, 'function sendMasterKeyToBackground(', '}')
      + block(src, 'function _unlockHandoffToBackground(', '}'),
    sandbox, { filename: 'panel.js' },
  );
  return sandbox;
}

async function storageWorks(w, tag) {
  w.clear();
  await w.send({ type: 'storage_encrypt', reqId: `enc_${tag}`, plaintext: 'пароль комнаты' });
  return (await w.waitFor('storage_crypto_res')).ok;
}

let takes = 0;
async function takeAs(w, username) {
  w.clear();
  // A request id seen before is refused as a replay, which is not what is
  // being asked here.
  takes += 1;
  await w.send({ type: 'unlock_master_take', reqId: `take_${takes}`, username });
  return (await w.waitFor('unlock_master_take_res')).master_b64;
}

jest.setTimeout(60000);

describe('the worker keeps the key while a panel is unlocked', () => {
  it('as long as the panel keeps saying so', async () => {
    const w = startWorker();
    const panel = panelAgainst(w);
    await vm.runInContext(`sendMasterKeyToBackground(${JSON.stringify(b64(new Uint8Array(32).fill(7)))}, "${USER}")`, panel);
    expect(await storageWorks(w, 'start')).toBe(true);

    // Twenty-four minutes, no room password saved, the panel open throughout.
    for (let i = 0; i < 3; i++) {
      w.advance(8 * MIN);
      await w.send({ type: 'master_touch' });
    }
    expect(await storageWorks(w, 'after')).toBe(true);
  });

  it('and not past its ten minutes once the panel stops', async () => {
    const w = startWorker();
    const panel = panelAgainst(w);
    await vm.runInContext(`sendMasterKeyToBackground(${JSON.stringify(b64(new Uint8Array(32).fill(7)))}, "${USER}")`, panel);
    w.advance(11 * MIN);
    expect(await storageWorks(w, 'cold')).toBe(false);
  });

  it('a touch does not bring back a key that has already gone', async () => {
    // The key is only checked for age, not dropped when it runs out, so a
    // touch that simply reset the clock would revive it.
    const w = startWorker();
    const panel = panelAgainst(w);
    await vm.runInContext(`sendMasterKeyToBackground(${JSON.stringify(b64(new Uint8Array(32).fill(7)))}, "${USER}")`, panel);
    w.advance(11 * MIN);
    await w.send({ type: 'master_touch' });
    expect(await storageWorks(w, 'revived')).toBe(false);
  });
});

describe("the panel's handoff of the key itself", () => {
  it('installs it as the storage key, bound to the user who unlocked', async () => {
    const w = startWorker();
    const panel = panelAgainst(w);
    const key = b64(globalThis.crypto.getRandomValues(new Uint8Array(32)));

    await vm.runInContext(`sendMasterKeyToBackground(${JSON.stringify(key)}, "${USER}")`, panel);
    const res = await w.waitFor('unlock_handoff_commit_res');
    expect(res.ok).toBe(true);
    expect(res.applied_master).toBe(true);
    expect(await storageWorks(w, 'installed')).toBe(true);

    // The worker keeps a one-shot copy for a panel that opens right after a
    // login; it must not go to another account's panel.
    expect(await takeAs(w, 'someone_else')).toBe('');
  });

  it('and the right user can take it back once', async () => {
    const w = startWorker();
    const panel = panelAgainst(w);
    const key = b64(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    await vm.runInContext(`sendMasterKeyToBackground(${JSON.stringify(key)}, "${USER.toUpperCase()}")`, panel);
    await w.waitFor('unlock_handoff_commit_res');
    expect(await takeAs(w, USER)).toBe(key);
    expect(await takeAs(w, USER)).toBe('');
  });
});

/**
 * initializeCrypto from the real panel-crypto.js, with a real identity
 * container (PBKDF2 - the Argon2 WASM self-test is not what is under test).
 */
async function unlockingPanel() {
  const P = makePanel({ apiBase: 'http://127.0.0.1:1', islandId: 'test', username: USER, token: '' });
  const id = await unlockRealManager(P.sandbox, { username: USER, password: PASS });
  // Start locked, the way a panel is after its idle timeout.
  P.manager.clear();

  const seen = { prompts: 0, handed: [], managerOpenAtHandoff: [] };
  const s = P.sandbox;
  s.resolveActiveUsername = async () => USER;
  s.loadLocalIdentity = async () => ({ encrypted_private_key: id.encrypted, public_key: id.publicKeyB64 });
  s.assertEpkKdfMatchesPin = () => {};
  s.pinEpkKdfNameIfNeeded = async () => {};
  s.ensureEd25519KeyRegistered = async () => {};
  s.promptPassword = async () => { seen.prompts += 1; return seen.password; };
  s.sendMasterKeyToBackground = async (key, username) => {
    seen.managerOpenAtHandoff.push(!!P.manager.userPrivateKey);
    seen.handed.push({ key, username });
    if (seen.handoffFails) throw new Error('No port');
  };
  return { P, id, seen, run: (opts) => vm.runInContext(`initializeCrypto(${JSON.stringify(opts)})`, s) };
}

/** What login.js hands the worker for the same password and container. */
async function loginKeyFor(P, password, epk) {
  const src = source('login.js');
  const fn = block(src, '  async function deriveUnlockKekBase64(', '  }');
  const sandbox = { CryptoUtils: P.CU, String };
  vm.createContext(sandbox);
  vm.runInContext(fn, sandbox, { filename: 'login.js' });
  return sandbox.deriveUnlockKekBase64(password, epk);
}

describe('unlocking the panel with the password', () => {
  it('gives the worker the same key a login gives it, once the private key opened', async () => {
    const { P, id, seen, run } = await unlockingPanel();
    seen.password = PASS;

    expect(await run({ interactive: true, reason: 'test' })).toBe(true);

    expect(seen.handed).toHaveLength(1);
    expect(seen.handed[0].username).toBe(USER);
    // Not just "a key": the one login.js derives. A different one would make
    // everything the worker encrypted before this unlock unreadable after it.
    expect(seen.handed[0].key).toBe(await loginKeyFor(P, PASS, id.encrypted));
    expect(seen.managerOpenAtHandoff).toEqual([true]);
  });

  it('gives it nothing for a wrong password', async () => {
    const { seen, run } = await unlockingPanel();
    seen.password = 'not-the-password-1';
    expect(await run({ interactive: true, reason: 'test' })).toBe(false);
    expect(seen.handed).toEqual([]);
  });

  it('gives it nothing when the panel unlocked from the key the worker already has', async () => {
    const { P, id, seen } = await unlockingPanel();
    P.sandbox.__kek = id.aesKey;
    const ok = await vm.runInContext('initializeCrypto({ interactive: false, kekKey: __kek })', P.sandbox);
    expect(ok).toBe(true);
    expect(seen.prompts).toBe(0);
    expect(seen.handed).toEqual([]);
  });

  it('still unlocks if the worker cannot be reached', async () => {
    const { seen, run } = await unlockingPanel();
    seen.password = PASS;
    seen.handoffFails = true;
    expect(await run({ interactive: true, reason: 'test' })).toBe(true);
    expect(seen.handed).toHaveLength(1);
  });
});

describe('an unlocked panel telling the worker it is in use', () => {
  function withFakeTimers(P) {
    const timers = { intervals: [], cleared: [] };
    P.sandbox.setInterval = (fn, ms) => { timers.intervals.push({ fn, ms }); return timers.intervals.length; };
    P.sandbox.clearInterval = (id) => { timers.cleared.push(id); };
    P.sandbox.setTimeout = () => 0;
    P.sandbox.clearTimeout = () => {};
    return timers;
  }

  it('starts with the unlock, once, and says so every minute', async () => {
    const { P, seen, run } = await unlockingPanel();
    const timers = withFakeTimers(P);
    seen.password = PASS;
    expect(await run({ interactive: true, reason: 'test' })).toBe(true);

    // What ensureCryptoReady does after initializeCrypto succeeds, and what
    // every click and key press in the panel does after that.
    vm.runInContext('cryptoUnlocked = true; cryptoInitialized = true; bumpCryptoIdleTimer(); bumpCryptoIdleTimer();', P.sandbox);
    expect(timers.intervals.map((t) => t.ms)).toEqual([MIN]);

    P.posted.length = 0;
    timers.intervals[0].fn();
    expect(P.posted).toEqual([{ type: 'master_touch' }]);
  });

  it('stops when the panel locks', async () => {
    const { P, seen, run } = await unlockingPanel();
    const timers = withFakeTimers(P);
    seen.password = PASS;
    await run({ interactive: true, reason: 'test' });
    vm.runInContext('cryptoUnlocked = true; cryptoInitialized = true; bumpCryptoIdleTimer();', P.sandbox);

    vm.runInContext('lockCryptoSession()', P.sandbox);
    expect(timers.cleared).toEqual([1]);

    // A tick already queued when the lock came says nothing.
    P.posted.length = 0;
    timers.intervals[0].fn();
    expect(P.posted.filter((m) => m.type === 'master_touch')).toEqual([]);
  });
});
