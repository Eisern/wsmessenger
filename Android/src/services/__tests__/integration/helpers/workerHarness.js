// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's service worker, running headless.
 *
 * chrome_extension/background.js is where the password-derived key lives, and
 * where it is supposed to stop living: a ten-minute idle TTL, a one-shot
 * handoff with its own thirty-second window, and a refusal to accept the key
 * by the old direct route. None of that had a test. All of it fails silently
 * in the direction that costs the most - a key that outlives its TTL, or a
 * handoff that is not actually a handoff, looks exactly like a client that
 * works.
 *
 * The clock is the reason this is a harness rather than a mock. Everything
 * here turns on elapsed time, so the sandbox gets a Date whose `now` the test
 * can move forward; the worker reads it exactly as it reads the real one.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const EXT_DIR = path.join(__dirname, '..', '..', '..', '..', '..', '..', 'chrome_extension');

// chrome.storage answers either a promise or a callback depending on how it is
// called, and the worker uses both styles in different places.
function makeStore() {
  const mem = new Map();
  const read = (keys) => {
    if (keys == null) return Object.fromEntries(mem);
    const list = Array.isArray(keys) ? keys : [keys];
    const out = {};
    for (const k of list) if (mem.has(k)) out[k] = mem.get(k);
    return out;
  };
  return {
    get(keys, cb) {
      const out = read(keys);
      if (typeof cb === 'function') { cb(out); return undefined; }
      return Promise.resolve(out);
    },
    set(obj, cb) {
      for (const [k, v] of Object.entries(obj || {})) mem.set(k, v);
      if (typeof cb === 'function') { cb(); return undefined; }
      return Promise.resolve();
    },
    remove(keys, cb) {
      for (const k of (Array.isArray(keys) ? keys : [keys])) mem.delete(k);
      if (typeof cb === 'function') { cb(); return undefined; }
      return Promise.resolve();
    },
    _mem: mem,
  };
}

/**
 * Start the worker and connect one panel to it.
 *
 * Returns the port the worker sees from the other side: `send` is what a panel
 * posts, `sent` is everything the worker posted back, and `waitFor` reads the
 * answer to one message.
 */
function startWorker({ apiBase = 'http://127.0.0.1:8000' } = {}) {
  const posted = [];
  let offsetMs = 0;

  const sandbox = {
    crypto: globalThis.crypto,
    TextEncoder, TextDecoder, atob, btoa, console, fetch,
    URL, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval,
    WebSocket: function () { throw new Error('the worker should not dial a socket here'); },
  };

  // A clock the test can move. The worker never sees the difference; every
  // expiry it enforces is measured against this.
  const RealDate = Date;
  function FakeDate(...args) {
    return args.length ? new RealDate(...args) : new RealDate(RealDate.now() + offsetMs);
  }
  FakeDate.prototype = RealDate.prototype;
  FakeDate.now = () => RealDate.now() + offsetMs;
  FakeDate.parse = RealDate.parse;
  FakeDate.UTC = RealDate.UTC;
  sandbox.Date = FakeDate;

  // A service worker registers lifecycle handlers on itself; none of them fire
  // here, but the file expects the methods to exist.
  const swEvents = new Map();
  sandbox.addEventListener = (name, fn) => { swEvents.set(name, fn); };
  sandbox.removeEventListener = (name) => { swEvents.delete(name); };
  sandbox.skipWaiting = async () => {};
  sandbox.clients = { claim: async () => {}, matchAll: async () => [] };
  sandbox.registration = { scope: 'chrome-extension://test/' };

  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;

  let onConnect = null;
  sandbox.chrome = {
    runtime: {
      onConnect: { addListener: (fn) => { onConnect = fn; } },
      onMessage: { addListener() {} },
      onInstalled: { addListener() {} },
      onStartup: { addListener() {} },
      getManifest: () => ({ version: '0.0.0' }),
      lastError: null,
      id: 'test-extension',
    },
    storage: {
      local: makeStore(),
      session: makeStore(),
      onChanged: { addListener() {} },
    },
    action: { onClicked: { addListener() {} } },
    sidePanel: { open() {}, setPanelBehavior() {} },
    permissions: { async contains() { return true; }, async request() { return true; } },
    alarms: { create() {}, onAlarm: { addListener() {} }, clear() {} },
    contextMenus: { create() {}, onClicked: { addListener() {} }, removeAll(cb) { cb && cb(); } },
    tabs: { onUpdated: { addListener() {} }, query: async () => [] },
    notifications: { create() {}, onClicked: { addListener() {} } },
  };

  // The worker loads the entry-point selector this way; nothing else.
  sandbox.importScripts = (...files) => {
    for (const f of files) {
      vm.runInContext(fs.readFileSync(path.join(EXT_DIR, f), 'utf8'), sandbox, { filename: f });
    }
  };

  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(EXT_DIR, 'background.js'), 'utf8'), sandbox,
    { filename: 'background.js' });

  if (!onConnect) throw new Error('background.js registered no connection listener');

  // The worker refuses anything that is not demonstrably one of its own pages -
  // a port with no URL used to be accepted, and unlock_master_take would have
  // handed the master key to it.
  function makePort({ url = 'chrome-extension://test-extension/panel.html', id = 'test-extension', tab = undefined } = {}) {
    const listeners = [];
    let disconnected = false;
    return {
      name: 'ws-panel',
      postMessage: (m) => { posted.push(m); },
      onMessage: { addListener: (fn) => listeners.push(fn) },
      onDisconnect: { addListener() {} },
      disconnect() { disconnected = true; },
      sender: { id, url, tab },
      _listeners: listeners,
      get accepted() { return !disconnected && listeners.length > 0; },
    };
  }

  const port = makePort();
  onConnect(port);
  const listeners = port._listeners;

  async function send(msg) {
    for (const fn of listeners) await fn(msg, port);
  }

  async function waitFor(type, { timeoutMs = 5000 } = {}) {
    const deadline = RealDate.now() + timeoutMs;
    for (;;) {
      const hit = posted.find((m) => m && m.type === type);
      if (hit) return hit;
      if (RealDate.now() > deadline) {
        throw new Error(`worker never posted ${type}; it posted: ${posted.map((m) => m && m.type).join(', ')}`);
      }
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  return {
    sandbox,
    port,
    posted,
    connect: (opts) => { const p = makePort(opts); onConnect(p); return p; },
    send,
    waitFor,
    apiBase,
    clear: () => { posted.length = 0; },
    advance: (ms) => { offsetMs += ms; },
  };
}

module.exports = { startWorker, makeStore, EXT_DIR };
