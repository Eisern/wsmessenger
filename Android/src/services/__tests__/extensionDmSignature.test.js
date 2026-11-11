// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Who wrote a direct message, in the extension (chrome_extension/panel-crypto.js
 * decryptDm, panel.js __warnAboutDmSignature).
 *
 * The server attaches no author to a direct message; the name inside the
 * envelope is what the chat shows. So whoever holds the thread key could put
 * any name there - a third party's, or ours - and before this it earned at
 * most a quiet note, or nothing: an envelope naming us without a signature, a
 * message with no envelope at all, a signature that could not even be read.
 *
 * decryptDm runs from the real panel-crypto.js with the real CryptoUtils and
 * CryptoManager; the island is a fetch stub. The warnings run from panel.js.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');

const EXT = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension');
const source = (f) => fs.readFileSync(path.join(EXT, f), 'utf8').split('\r\n').join('\n');
function block(src, head, close) {
  const start = src.indexOf(head);
  if (start < 0) throw new Error(`${head} not found`);
  const end = src.indexOf('\n' + close + '\n', start);
  return src.slice(start, end + close.length + 2);
}

const THREAD = 77;

async function setUp({ serveBobKey = true } = {}) {
  const P = makePanel({ apiBase: 'http://island.test', islandId: 'island.test', username: 'alice', token: 'tok' });
  await unlockRealManager(P.sandbox, { username: 'alice', password: PASS });
  const CU = P.CU;
  const s = P.sandbox;
  const seed = () => s.crypto.getRandomValues(new Uint8Array(32));
  const bob = seed();
  const bobPub = CU.arrayBufferToBase64(await CU.ed25519GetPublicKey(bob));
  s.fetch = async (url) => {
    const body = serveBobKey && String(url).includes('/keys/bob') ? { username: 'bob', ed25519_public_key: bobPub } : {};
    return { ok: true, status: 200, json: async () => body };
  };
  s.ensureDmKeyReady = async () => {};
  s._foreignForThread = async () => null;

  const rid = vm.runInContext(`dmRid(${THREAD})`, s);
  await P.manager.loadRoomKey(rid, await CU.exportRoomKey(await CU.generateRoomKey(true)));

  const seal = async (inner) => {
    const ct = await P.manager.encryptMessage(rid, typeof inner === 'string' ? inner : JSON.stringify(inner));
    return typeof ct === 'string' ? ct : JSON.stringify(ct);
  };
  const signed = async (from, body, key) => ({
    ss: 1, from, body, sig: await CU.ed25519Sign(key, CU._dmSigMessage(THREAD, from, body)),
  });
  s.__a = null;
  const open = async (inner, ts = Date.now()) => {
    s.__a = [await seal(inner), ts];
    return vm.runInContext(`decryptDm(${THREAD}, __a[0], 'bob', __a[1])`, s);
  };
  return { P, CU, s, bob, seed, signed, open };
}

describe('what a direct message proves', () => {
  test('signed by the peer whose name is on it', async () => {
    const T = await setUp();
    const out = await T.open(await T.signed('bob', 'hello', T.bob));
    expect(out).toMatchObject({ text: 'hello', sealedFrom: 'bob', sealed: true, sigValid: true });
    expect(out.unsigned).toBeUndefined();
  });

  test('a name that is neither of us is forged, signed or not', async () => {
    const T = await setUp();
    expect(await T.open(await T.signed('carol', 'from a third party', T.seed())))
      .toMatchObject({ sealedFrom: 'carol', sigValid: false, notParticipant: true });
    expect(await T.open({ ss: 1, from: 'support', body: 'reset your password here' }))
      .toMatchObject({ sealedFrom: 'support', sigValid: false, notParticipant: true });
  });

  test('an envelope no client writes is forged: no name, a body that is not text, an unreadable signature', async () => {
    const T = await setUp();
    expect((await T.open({ ss: 1, body: 'no name' })).sigValid).toBe(false);
    const objBody = await T.open({ ss: 1, from: 'bob', body: { not: 'text' } });
    expect(objBody.sigValid).toBe(false);
    expect(typeof objBody.text).toBe('string');
    for (const sig of ['not base64 at all!!', T.CU.arrayBufferToBase64(new Uint8Array(10))]) {
      expect((await T.open({ ss: 1, from: 'bob', body: 'x', sig })).sigValid).toBe(false);
    }
  });

  test('signed, but no key known for the signer: unverified, and not called unsigned', async () => {
    const T = await setUp({ serveBobKey: false });
    const out = await T.open(await T.signed('bob', 'hi', T.bob));
    expect(out.sigValid).toBeNull();
    expect(out.unsigned).toBeUndefined();
  });

  test('no signature: unsigned - and forged once the peer is known to sign', async () => {
    const T = await setUp();
    expect(await T.open({ ss: 1, from: 'bob', body: 'early' }, 1000))
      .toMatchObject({ sealedFrom: 'bob', sigValid: null, unsigned: true });
    await T.open(await T.signed('bob', 'signed now', T.bob), 2000);
    expect((await T.open({ ss: 1, from: 'bob', body: 'later, unsigned' }, 3000)).sigValid).toBe(false);
  });

  test('our own name without a signature is reported, not shown as ours', async () => {
    const T = await setUp();
    expect(await T.open({ ss: 1, from: 'alice', body: 'words put in my mouth' }))
      .toMatchObject({ sealedFrom: 'alice', sigValid: null, unsigned: true });
  });

  test('no envelope at all is unsigned under nobody - and forged on the same terms', async () => {
    const T = await setUp();
    expect(await T.open('plain words', 1000))
      .toEqual({ text: 'plain words', sealedFrom: null, sealed: true, sigValid: null, chain: null, unsigned: true });
    await T.open(await T.signed('bob', 'signed', T.bob), 2000);
    expect((await T.open('plain, later', 3000)).sigValid).toBe(false);
  });
});

describe('what the conversation shows', () => {
  function policy() {
    const shown = { fail: [], note: [] };
    const sandbox = {
      console: { warn() {} },
      addSigFailWarning: (who) => shown.fail.push(who),
      addSigUnverifiedWarning: (who, reason) => shown.note.push(`${who}:${reason}`),
      chat: { innerHTML: 'x' },
      lastMsgAuthor: 'x',
      updatePinnedBar: () => {},
      window: {},
    };
    vm.createContext(sandbox);
    const panel = source('panel.js');
    expect(panel).toContain('const _sigUnverifiedShown = new Set();');
    vm.runInContext(
      'const _sigUnverifiedShown = new Set();\n' + block(panel, 'function __warnAboutDmSignature(', '}')
      + block(source('panel-ui.js'), 'function clearChat(opts = {}) {', '}'),
      sandbox, { filename: 'panel.js+panel-ui.js' },
    );
    sandbox.__d = null;
    const warn = (dec, fallback) => {
      sandbox.__d = [dec, fallback];
      vm.runInContext('__warnAboutDmSignature(__d[0], __d[1])', sandbox);
    };
    return { shown, warn, clear: () => vm.runInContext('clearChat()', sandbox) };
  }

  test('a conversation drawn again notes it again - the old note went with the DOM', () => {
    // A history is drawn on open and again once the key is in; the second
    // pass used to find every sender already "noted" and show nothing.
    const S = policy();
    const unsigned = { sealed: true, sealedFrom: 'dmalice', sigValid: null, unsigned: true };
    S.warn(unsigned, 'bob');
    S.clear();
    S.warn(unsigned, 'bob');
    expect(S.shown.note).toEqual(['dmalice:unsigned', 'dmalice:unsigned']);
  });

  test('a forgery is shown every time, under the name it claimed', () => {
    const S = policy();
    S.warn({ sealed: true, sealedFrom: 'support', sigValid: false, notParticipant: true }, 'bob');
    S.warn({ sealed: true, sealedFrom: 'support', sigValid: false }, 'bob');
    expect(S.shown.fail).toEqual(['support', 'support']);
  });

  test('unsigned is noted once per sender - our own name included', () => {
    const S = policy();
    S.warn({ sealed: true, sealedFrom: 'bob', sigValid: null, unsigned: true }, 'bob');
    S.warn({ sealed: true, sealedFrom: 'Bob', sigValid: null, unsigned: true }, 'bob');
    S.warn({ sealed: true, sealedFrom: 'alice', sigValid: null, unsigned: true }, 'bob');
    expect(S.shown.note).toEqual(['bob:unsigned', 'alice:unsigned']);
  });

  test('no key to check it is noted as that', () => {
    const S = policy();
    S.warn({ sealed: true, sealedFrom: 'bob', sigValid: null }, 'bob');
    expect(S.shown.note).toEqual(['bob:nokey']);
  });

  test('no envelope is noted under the name it is shown with', () => {
    const S = policy();
    S.warn({ sealed: true, sealedFrom: null, sigValid: null, unsigned: true }, 'bob');
    expect(S.shown.note).toEqual(['bob:unsigned']);
  });

  test('a signature that holds says nothing', () => {
    const S = policy();
    S.warn({ sealed: true, sealedFrom: 'bob', sigValid: true }, 'bob');
    expect(S.shown).toEqual({ fail: [], note: [] });
  });
});
