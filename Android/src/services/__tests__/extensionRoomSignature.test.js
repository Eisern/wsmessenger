// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Who wrote a room message, in the extension (chrome_extension/panel-crypto.js
 * openRoomEnvelope + fetchPeerEd25519PubKey, panel.js __warnAboutRoomSignature,
 * panel-ui.js clearChat).
 *
 * The signature is what keeps a member and the server from putting words under
 * somebody else's name. Two holes let them anyway: the island could switch the
 * check off for a pinned peer simply by not answering /keys/<name> - the result
 * was "could not be checked", which a room showed as nothing - and a message
 * sent without a signature was shown with no mark at all.
 *
 * openRoomEnvelope runs from the real panel-crypto.js with the real CryptoUtils;
 * the island is a fetch stub. The warning policy runs from panel.js itself.
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

const ROOM = 42;

async function setUp() {
  const P = makePanel({ apiBase: 'http://island.test', islandId: 'island.test', username: 'alice', token: 'tok' });
  await unlockRealManager(P.sandbox, { username: 'alice', password: PASS });
  const CU = P.CU;
  const seed = () => P.sandbox.crypto.getRandomValues(new Uint8Array(32));
  const bob = seed();
  const bobPub = CU.arrayBufferToBase64(await CU.ed25519GetPublicKey(bob));

  const island = { down: false, asked: [] };
  P.sandbox.fetch = async (url) => {
    const u = String(url);
    island.asked.push(u);
    // island.down: how it fails to answer - '503', 'throw' (the network), or
    // 'empty' (a 200 with nothing readable). None says anything about anybody.
    if (island.down && u.includes('/keys/')) {
      if (island.down === 'throw') throw new TypeError('Failed to fetch');
      const empty = island.down === 'empty';
      return { ok: empty, status: empty ? 200 : 503, json: async () => { throw new Error('not json'); } };
    }
    const body = u.includes('/keys/bob') ? { username: 'bob', ed25519_public_key: bobPub } : {};
    return { ok: true, status: 200, json: async () => body };
  };

  const envelope = async (from, body, signWith, extra = {}) => JSON.stringify({
    rs: 1, from, body,
    ...(signWith ? { sig: await CU.ed25519Sign(signWith, CU._roomSigMessage(ROOM, from, body)) } : {}),
    ...extra,
  });
  P.sandbox.__args = null;
  const open = (plain, claimed) => {
    P.sandbox.__args = [plain, claimed];
    return vm.runInContext(`openRoomEnvelope(${ROOM}, __args[0], __args[1])`, P.sandbox);
  };
  // A fresh panel session: nothing cached, the pins stay where they are.
  const forget = () => vm.runInContext('_ed25519PubKeyCache.clear()', P.sandbox);
  return { P, CU, bob, seed, island, envelope, open, forget };
}

describe('what a room message signature proves', () => {
  test('signed by the peer named on it', async () => {
    const T = await setUp();
    expect(await T.open(await T.envelope('bob', 'hello room', T.bob), 'bob'))
      .toEqual({ text: 'hello room', from: 'bob', sigValid: true, mismatch: false });
  });

  test('our own message, checked against our own key', async () => {
    const T = await setUp();
    const out = await T.open(await T.envelope('alice', 'mine', T.P.manager.ed25519Seed), 'alice');
    expect(out.sigValid).toBe(true);
  });

  test('somebody else signing under the name fails', async () => {
    const T = await setUp();
    expect((await T.open(await T.envelope('bob', 'not bob', T.seed()), 'bob')).sigValid).toBe(false);
  });

  test('the server naming somebody else than the envelope is caught', async () => {
    const T = await setUp();
    const out = await T.open(await T.envelope('bob', 'said by bob', T.bob), 'carol');
    expect(out).toMatchObject({ from: 'bob', sigValid: true, mismatch: true });
  });

  test('an envelope no client writes - no signature, or one that cannot be read - is forged', async () => {
    const T = await setUp();
    expect((await T.open(await T.envelope('bob', 'x', null), 'bob')).sigValid).toBe(false);
    for (const sig of ['not base64 at all!!', T.CU.arrayBufferToBase64(new Uint8Array(10))]) {
      expect((await T.open(JSON.stringify({ rs: 1, from: 'bob', body: 'x', sig }), 'bob')).sigValid).toBe(false);
    }
  });

  test('a signer with no key known anywhere is unverified, not forged', async () => {
    const T = await setUp();
    expect(await T.open(await T.envelope('dave', 'hi', T.seed()), 'dave'))
      .toEqual({ text: 'hi', from: 'dave', sigValid: null, mismatch: false });
  });

  test('no envelope at all comes back marked unsigned, the text intact', async () => {
    const T = await setUp();
    expect(await T.open('just text', 'bob'))
      .toEqual({ text: 'just text', from: null, sigValid: null, mismatch: false, unsigned: true });
    const reply = JSON.stringify({ v: 2, t: 'hi', reply: { author: 'bob', text: 'yo' } });
    expect(await T.open(reply, 'bob')).toMatchObject({ text: reply, unsigned: true });
  });
});

describe('an island that stops answering for a pinned peer', () => {
  test.each(['503', 'throw', 'empty'])('cannot switch the check off (%s): the pinned key still decides', async (how) => {
    const T = await setUp();
    expect((await T.open(await T.envelope('bob', 'pin me', T.bob), 'bob')).sigValid).toBe(true);

    T.forget();
    T.island.down = how;
    expect((await T.open(await T.envelope('bob', 'still bob', T.bob), 'bob')).sigValid).toBe(true);
    // The point: a forgery under bob's name is caught, not waved through as
    // "could not be checked" because the island went quiet about bob.
    expect((await T.open(await T.envelope('bob', 'send money', T.seed()), 'bob')).sigValid).toBe(false);
    // ...and it really did ask, and really did fail.
    expect(T.island.asked.filter((u) => u.includes('/keys/bob')).length).toBeGreaterThanOrEqual(2);
  });

  test('a name never pinned stays unverified - silence pins nothing', async () => {
    const T = await setUp();
    T.island.down = '503';
    expect((await T.open(await T.envelope('erin', 'hello', T.seed()), 'erin')).sigValid).toBeNull();
    T.island.down = false;
    // Nothing was pinned while it was down: erin is still unknown, not "whatever came first".
    expect((await T.open(await T.envelope('erin', 'hello', T.seed()), 'erin')).sigValid).toBeNull();
  });
});

describe('what the room shows', () => {
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
    // The set is declared at top level beside the function; the test needs both.
    expect(panel).toContain('const _roomSigNoticeShown = new Set();');
    vm.runInContext(
      'const _roomSigNoticeShown = new Set();\n'
      + block(panel, 'function __warnAboutRoomSignature(', '}')
      + block(source('panel-ui.js'), 'function clearChat(opts = {}) {', '}'),
      sandbox, { filename: 'panel.js+panel-ui.js' },
    );
    sandbox.__d = null;
    const warn = (dec, claimed) => {
      sandbox.__d = [dec, claimed];
      vm.runInContext('__warnAboutRoomSignature(__d[0], __d[1])', sandbox);
    };
    return { shown, warn, clear: () => vm.runInContext('clearChat()', sandbox) };
  }

  test('a forgery or a moved author is shown every time', () => {
    const S = policy();
    S.warn({ from: 'bob', sigValid: false, mismatch: false }, 'bob');
    S.warn({ from: 'bob', sigValid: false, mismatch: false }, 'bob');
    S.warn({ from: 'bob', sigValid: true, mismatch: true }, 'carol');
    expect(S.shown.fail).toEqual(['bob', 'bob', 'bob']);
    expect(S.shown.note).toEqual([]);
  });

  test('no signature is noted, once per sender', () => {
    const S = policy();
    const unsigned = { text: 'x', from: null, sigValid: null, mismatch: false, unsigned: true };
    S.warn(unsigned, 'bob');
    S.warn(unsigned, 'Bob');
    S.warn(unsigned, 'carol');
    expect(S.shown.note).toEqual(['bob:unsigned', 'carol:unsigned']);
  });

  test('no key to check it is noted as that, not as unsigned', () => {
    const S = policy();
    S.warn({ text: 'x', from: 'dave', sigValid: null, mismatch: false }, 'dave');
    expect(S.shown.note).toEqual(['dave:nokey']);
  });

  test('a signature that holds, a placeholder, or a verdict-less feed item say nothing', () => {
    const S = policy();
    S.warn({ from: 'bob', sigValid: true, mismatch: false }, 'bob');
    S.warn('[Encrypted message - key not available]', 'bob');
    S.warn({ from: null, sigValid: null, mismatch: false, unsigned: false }, 'bob');
    expect(S.shown).toEqual({ fail: [], note: [] });
  });

  test('a redrawn chat notes it again - the old note went with the DOM', () => {
    const S = policy();
    const unsigned = { from: null, sigValid: null, mismatch: false, unsigned: true };
    S.warn(unsigned, 'bob');
    S.clear();
    S.warn(unsigned, 'bob');
    expect(S.shown.note).toEqual(['bob:unsigned', 'bob:unsigned']);
  });
});
