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
