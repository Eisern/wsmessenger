// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// The endpoint selector is hand-duplicated between the two clients. Every
// byte-format helper in this repository written that way has already diverged
// silently at least once (fingerprintPublicKey), so the duplication is checked
// mechanically rather than by discipline.

const fs = require('fs');
const path = require('path');

const ANDROID_PATH = path.join(__dirname, '..', 'endpoints.js');
const EXTENSION_PATH = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'endpoints.js');

// core.autocrlf is on for this repository, so the two working-tree copies can
// legitimately differ in line endings. Content is what must match.
function normalized(file) {
  return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');
}

const IL_ANDROID = path.join(__dirname, '..', 'island-list.js');
const IL_EXTENSION = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'island-list.js');

describe('island-list.js parity between the two clients', () => {
  it('both copies exist and are identical', () => {
    expect(fs.existsSync(IL_ANDROID)).toBe(true);
    expect(fs.existsSync(IL_EXTENSION)).toBe(true);
    expect(normalized(IL_ANDROID)).toBe(normalized(IL_EXTENSION));
  });

  it('both copies canonicalize identically', () => {
    const a = require('../island-list');
    // Loaded in a sandbox rather than required: the extension copy lives
    // outside rootDir, where babel cannot resolve its own runtime helpers for
    // the async functions. A sandbox runs the file as the browser would.
    const vm = require('vm');
    const sandbox = { console, TextEncoder, JSON, Date };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(IL_EXTENSION, 'utf8'), sandbox, { filename: 'island-list.js' });
    const b = sandbox.WSIslandList;
    expect(b).toBeTruthy();
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());

    // Canonical JSON is what the signature covers; a difference here would
    // make one client reject every list the other accepts.
    const cases = [
      { b: 1, a: [2, { d: 4, c: 3 }] },
      { label: 'основной', nested: { z: null, y: true } },
      { list: [], empty: {}, n: -17 },
    ];
    for (const c of cases) expect(a.canonicalJson(c)).toBe(b.canonicalJson(c));
  });
});

const OB_ANDROID = path.join(__dirname, '..', 'outbox.js');
const OB_EXTENSION = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'outbox.js');

const TC_ANDROID = path.join(__dirname, '..', 'thread-chain.js');
const TC_EXTENSION = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'thread-chain.js');

describe('thread-chain.js parity between the two clients', () => {
  it('both copies exist and are identical', () => {
    expect(fs.existsSync(TC_ANDROID)).toBe(true);
    expect(fs.existsSync(TC_EXTENSION)).toBe(true);
    expect(normalized(TC_ANDROID)).toBe(normalized(TC_EXTENSION));
  });

  it('both copies reach the same verdicts', () => {
    const a = require('../thread-chain');
    const vm = require('vm');
    const sandbox = { console, JSON, Date };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(TC_EXTENSION, 'utf8'), sandbox, { filename: 'thread-chain.js' });
    const b = sandbox.WSThreadChain;
    expect(b).toBeTruthy();
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());

    const sha256 = () => new Uint8Array(32).fill(7);
    const ca = a.createThreadChain({ sha256 });
    const cb = b.createThreadChain({ sha256 });
    const H = (n) => String(n).repeat(64).slice(0, 64).replace(/[^0-9a-f]/g, '0');

    // One client calling a reordering a gap while the other calls it a break
    // would mean the two show a user different things about the same history.
    const cases = [
      [{ seq: 0, hash: a.GENESIS_HEX }, { seq: 1, prev: a.GENESIS_HEX, link: H(1) }],
      [{ seq: 1, hash: H(1) }, { seq: 3, prev: H(2), link: H(3) }],
      [{ seq: 1, hash: H(1) }, { seq: 2, prev: H(9), link: H(2) }],
      [{ seq: 5, hash: H(5) }, { seq: 2, prev: H(1), link: H(2) }],
      [{ seq: 1, hash: H(1) }, { seq: 'x', prev: 'nope', link: null }],
    ];
    for (const [state, msg] of cases) {
      expect(ca.accept(state, msg).verdict).toBe(cb.accept(state, msg).verdict);
    }
  });
});

describe('outbox.js parity between the two clients', () => {
  it('both copies exist and are identical', () => {
    expect(fs.existsSync(OB_ANDROID)).toBe(true);
    expect(fs.existsSync(OB_EXTENSION)).toBe(true);
    expect(normalized(OB_ANDROID)).toBe(normalized(OB_EXTENSION));
  });

  it('both copies classify send outcomes identically', () => {
    const a = require('../outbox');
    const vm = require('vm');
    const sandbox = { console, JSON, Date };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(OB_EXTENSION, 'utf8'), sandbox, { filename: 'outbox.js' });
    const b = sandbox.WSOutbox;
    expect(b).toBeTruthy();
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());

    // Getting 409 wrong in one client only would either lose messages or
    // deliver them twice, depending on which way it drifted.
    const cases = [{ ok: true }, { status: 409 }, { status: 0 }, { status: 403 },
                   { status: 400 }, { status: 503 }, { name: 'TypeError' }];
    for (const c of cases) expect(a.classifySendOutcome(c)).toBe(b.classifySendOutcome(c));
  });
});

const FD_ANDROID = path.join(__dirname, '..', 'foreign-dm.js');
const FD_EXTENSION = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'foreign-dm.js');

describe('foreign-dm.js parity between the two clients', () => {
  it('both copies exist and are identical', () => {
    expect(fs.existsSync(FD_ANDROID)).toBe(true);
    expect(fs.existsSync(FD_EXTENSION)).toBe(true);
    expect(normalized(FD_ANDROID)).toBe(normalized(FD_EXTENSION));
  });

  it('both copies sign the same bytes for a claim', () => {
    const a = require('../foreign-dm');
    const vm = require('vm');
    const sandbox = { console, JSON, Date, TextEncoder, TextDecoder, atob, btoa };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(FD_EXTENSION, 'utf8'), sandbox, { filename: 'foreign-dm.js' });
    const b = sandbox.WSForeignDm;
    expect(b).toBeTruthy();
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());

    // A claim is a signature over these bytes, checked by the island that
    // issued the nonce. One byte of disagreement here and a client can never
    // collect the mailbox waiting for it on the other side.
    const nonce = new Uint8Array(32).map((_, i) => i);
    const hex = (u8) => Buffer.from(Array.from(u8, Number)).toString('hex');
    for (const [island, kid] of [
      ['island-b', 'ca2a4fe727faaecf16ecd130a86e0885'],
      ['остров-б', '00112233445566778899aabbccddeeff'],
    ]) {
      expect(hex(a.claimSigBytes(island, kid, nonce)))
        .toBe(hex(b.claimSigBytes(island, kid, nonce)));
    }

    // And the same canonical form for a contact card, which is signed once and
    // verified on a device that may be the other client entirely.
    const payload = { v: 1, kid: 'aa', display_name: 'Алиса', entry_points: [{ apiBase: 'https://x' }] };
    expect(a.stableJson(payload)).toBe(b.stableJson(payload));
    expect(hex(a.contactSigBytes(payload))).toBe(hex(b.contactSigBytes(payload)));

    // Key slots are island-scoped in both, or one client would file a
    // conversation where the other cannot find it.
    expect(a.contactKey('Island.A', 'Me', 'KID')).toBe(b.contactKey('Island.A', 'Me', 'KID'));
    expect(a.contactKey('island.a', 'me', 'kid')).toBe('__foreign:island.a:me:kid');
  });
});

describe('endpoints.js parity between the two clients', () => {
  it('both copies exist', () => {
    expect(fs.existsSync(ANDROID_PATH)).toBe(true);
    expect(fs.existsSync(EXTENSION_PATH)).toBe(true);
  });

  it('the copies are identical', () => {
    expect(normalized(ANDROID_PATH)).toBe(normalized(EXTENSION_PATH));
  });

  it('both copies expose the same surface and behave identically', () => {
    const a = require('../endpoints');
    const b = require(EXTENSION_PATH);

    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());

    const defaults = { defaultApiBase: 'https://default.example' };
    const raw = {
      schema: 2,
      endpoints: [{ apiBase: 'https://alpha.example/api?x=1' }, { apiBase: 'https://beta.example' }],
      activeIdx: 1,
    };
    expect(a.normalizeServerConfig(raw, defaults)).toEqual(b.normalizeServerConfig(raw, defaults));
    expect(a.normalizeServerConfig({ apiBase: 'https://legacy.example' }, defaults)).toEqual(
      b.normalizeServerConfig({ apiBase: 'https://legacy.example' }, defaults),
    );

    const httpCases = [{ status: 0 }, { name: 'TypeError' }, { status: 401 }, { status: 503, body: '' }, { status: 500, body: { detail: 'x' } }];
    for (const c of httpCases) expect(a.classifyHttpFailure(c)).toBe(b.classifyHttpFailure(c));

    const wsCases = [
      { code: 1006, opened: false },
      { code: 1006, opened: true, uptimeMs: 4000 },
      { code: 1008, opened: true, uptimeMs: 100 },
      { code: 1000, opened: true, uptimeMs: 90000 },
    ];
    for (const c of wsCases) expect(a.classifyWsClose(c)).toBe(b.classifyWsClose(c));
  });
});
