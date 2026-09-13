// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's panel, running headless against a real island.
 *
 * chrome_extension/panel-crypto.js holds most of what the extension does with
 * keys - room keys and their archive, DM keys, sealed sender, TOFU pins,
 * safety numbers, cross-island mailboxes - and none of it was reachable from a
 * test, because it is a classic script that expects a browser and a service
 * worker around it. So it was only ever exercised by a person clicking, and
 * the parts a person clicks least were exercised least.
 *
 * This supplies the browser: storage, permissions, a DOM that answers nothing,
 * and the few globals panel.js would have defined. What it does NOT supply is
 * the server - that is a real island, because the point is to run the real
 * request paths.
 *
 * The CryptoManager stand-in is deliberate. The real one unlocks from an
 * encrypted identity blob behind an Argon2 WASM self-test, which is a
 * different thing to test; its encryptMessage is copied byte for byte here,
 * because the shape of what the client emits is the interface under test.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const EXT_DIR = path.join(__dirname, '..', '..', '..', '..', '..', '..', 'chrome_extension');
const PASS = 'Testpass!12345';

const unb64 = (s) =>
  Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

function makeStore() {
  const mem = new Map();
  return {
    async get(keys) {
      if (keys == null) return Object.fromEntries(mem);
      const list = Array.isArray(keys) ? keys : [keys];
      const out = {};
      for (const k of list) if (mem.has(k)) out[k] = mem.get(k);
      return out;
    },
    async set(obj) { for (const [k, v] of Object.entries(obj)) mem.set(k, v); },
    async remove(keys) { for (const k of (Array.isArray(keys) ? keys : [keys])) mem.delete(k); },
  };
}

/**
 * Unlock the REAL CryptoManager with a throwaway identity.
 *
 * The shipped unlock derives its key with Argon2id behind a WASM self-test that
 * fails closed - right for a client, and not something a test should be
 * dragging into a sandbox. The container format allows PBKDF2, so this builds
 * one the same way login.js does and hands it to the same entry point
 * (initializeUserKeyWithKek), which is also the path that recovers the Ed25519
 * signing seed.
 *
 * Using the real manager is the point. A stand-in with the same method names
 * proves nothing about key versioning: the first version of this harness had
 * one, and its createRoomKey did not archive the key it replaced - so a test
 * for "old messages still decrypt after a rotation" failed against the stub
 * while the shipped code was right.
 */
async function unlockRealManager(sandbox, { username, password }) {
  const CU = sandbox.__wsCrypto.utils;
  const manager = sandbox.__wsCrypto.manager;

  const kp = await CU.generateIdentityKeyPair();
  const pkcs8B64 = await CU.exportPrivateKey(kp.privateKey);
  const publicKeyB64 = await CU.exportPublicKey(kp.publicKey);

  const salt = sandbox.crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = CU.arrayBufferToBase64(salt);
  const derived = await CU.deriveRawKeyFromPassword(password, saltB64, { name: "PBKDF2" });
  const aesKey = await sandbox.crypto.subtle.importKey(
    "raw", derived.raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
  );

  const iv = sandbox.crypto.getRandomValues(new Uint8Array(12));
  const container = {
    v: 3,
    alg: "AES-256-GCM",
    kdf: derived.kdf,
    salt: saltB64,
    iv: CU.arrayBufferToBase64(iv),
    created_at: Date.now(),
    username: String(username).toLowerCase(),
    ext_version: "0",
  };
  const aad = new TextEncoder().encode(CU.buildPrivateKeyContainerAAD(container));
  const ct = await sandbox.crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad }, aesKey, new TextEncoder().encode(pkcs8B64),
  );
  const encrypted = { ...container, data: CU.arrayBufferToBase64(ct) };

  const ok = await manager.initializeUserKeyWithKek(encrypted, aesKey, publicKeyB64, container.username);
  if (!ok) throw new Error("could not unlock the manager with a test identity");
  if (!manager.ed25519Seed) throw new Error("unlocked without a signing seed");

  return { manager, publicKeyB64, pkcs8B64, encrypted, aesKey };
}


function makePanel({ apiBase, islandId, username, token }) {
  const posted = [];
  const sandbox = {
    crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa, console, URL, fetch,
    setTimeout, clearTimeout, setInterval, clearInterval, Event, CustomEvent,
  };
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  sandbox.window = { addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; } };
  sandbox.document = {
    getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
    createElement: () => ({ style: {}, classList: { add() {}, remove() {} }, appendChild() {} }),
    addEventListener() {},
  };
  sandbox.chrome = {
    storage: { local: makeStore(), session: makeStore(), onChanged: { addListener() {} } },
    permissions: { async contains() { return true; }, async request() { return true; } },
    runtime: { getManifest: () => ({ version: '0.0.0' }) },
  };
  vm.createContext(sandbox);

  for (const f of ['crypto-utils.js', 'crypto-manager.js', 'endpoints.js', 'thread-chain.js',
    'island-list.js', 'outbox.js', 'foreign-dm.js']) {
    vm.runInContext(fs.readFileSync(path.join(EXT_DIR, f), 'utf8'), sandbox, { filename: f });
  }
  const CU = sandbox.__wsCrypto.utils;
  const manager = sandbox.__wsCrypto.manager;

  // Before the load: panel-crypto runs a few statements at top level, and one
  // of them posts to the worker.
  sandbox.API_BASE = apiBase;
  sandbox.ISLAND_ID = islandId;
  sandbox.__apiBaseReady = Promise.resolve(apiBase);
  sandbox.__activeForeignKid = null;
  const auth = { token: token };
  sandbox.getMeUsername = () => username;
  sandbox.requestToken = async () => auth.token;
  sandbox.safePost = (msg) => { posted.push(msg); };
  sandbox.encryptForStorage = async () => null;
  sandbox.decryptFromStorage = async () => null;
  sandbox.__ui = { alert: async () => {}, confirm: async () => true, prompt: async () => '' };

  vm.runInContext(fs.readFileSync(path.join(EXT_DIR, 'panel-crypto.js'), 'utf8'), sandbox,
    { filename: 'panel-crypto.js' });

  // After the load: panel-crypto declares some of these itself, and a function
  // declaration wins over anything assigned before the file ran.
  sandbox.ensureCryptoReady = async () => true;
  sandbox.isCryptoUsable = () => true;

  return { sandbox, CU, manager, posted, setToken: (t) => { auth.token = t; } };
}

async function http(base, p, { method = 'GET', body, token } = {}) {
  const r = await fetch(base + p, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  return { ok: r.ok, status: r.status, data };
}

async function setUp(base, islandId, username) {
  // The identity comes first: the account is registered with the key the
  // manager was unlocked with, the way a real registration does it, rather
  // than with a second keypair that would never match.
  const panel = makePanel({ apiBase: base, islandId, username, token: '' });
  panel.identity = await unlockRealManager(panel.sandbox, { username, password: PASS });

  await http(base, '/auth/register', {
    method: 'POST',
    body: { username, password: PASS, public_key: panel.identity.publicKeyB64 },
  });
  const login = await http(base, '/auth/login', { method: 'POST', body: { username, password: PASS } });
  if (!login.ok) throw new Error(`login ${username} on ${base}: ${login.status}`);
  panel.setToken(login.data.access_token);

  // The panel publishes this on every unlock; a harness that skips it leaves
  // the island unable to answer questions the real one can.
  // Without this the island cannot answer "what is this person's signing key",
  // and every DM signature verifies as "unknown" rather than "good" - which is
  // a quiet downgrade, so a failure here is raised rather than ignored.
  const published = await http(base, '/crypto/ed25519-key', {
    method: 'POST',
    token: login.data.access_token,
    body: {
      public_key: Buffer.from(await panel.CU.ed25519GetPublicKey(panel.manager.ed25519Seed))
        .toString('base64'),
    },
  });
  if (!published.ok) {
    throw new Error(
      `could not publish a signing key for ${username}: ${published.status}` +
      (published.status === 429 ? ' (raise RL_ED25519_KEY_* in the island .env)' : ''),
    );
  }
  panel.token = login.data.access_token;
  panel.username = username;
  return panel;
}

function udDecode(stored) {
  const t = String(stored || '').trim();
  if (t.startsWith('{')) return t;
  return Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

async function lastMessage(base, threadId, token) {
  const hist = await http(base, `/dm/${threadId}/history`, { token });
  const rows = hist.data.messages || hist.data;
  return udDecode(rows[rows.length - 1].text);
}


module.exports = { makePanel, unlockRealManager, makeStore, setUp, http, udDecode, lastMessage, unb64, PASS, EXT_DIR };
