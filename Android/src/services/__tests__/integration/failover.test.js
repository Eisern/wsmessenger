// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Entry-point failover, against a real backend.
 *
 * The real NetworkService runs here — only the React Native surface is stubbed
 * (AsyncStorage, Keychain, AppState). fetch and WebSocket are genuine, the
 * server is genuine, and two controllable proxies stand in for two entry points
 * of one island. Failures are injected at the proxy, so nothing in the client
 * or the server is aware a test is running.
 *
 * Requires a backend on 127.0.0.1:8000 — see integration/README.md.
 * Run with: npm run test:failover
 */

const { createEntryPoint } = require('./helpers/entryPoint');

const UPSTREAM = 'http://127.0.0.1:8000';
const PORT_A = 18101;
const PORT_B = 18102;

const SUFFIX = 'fo1';                       // stable, so reruns reuse accounts
const USER_A = `failover_a_${SUFFIX}`;
const USER_B = `failover_b_${SUFFIX}`;
const PASS = 'Testpass!12345';

let epA;
let epB;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(predicate, { timeout = 12000, step = 100, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    let ok = false;
    try { ok = await predicate(); } catch { ok = false; }
    if (ok) return true;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(step);
  }
}

function randomKeyB64() {
  return require('crypto').randomBytes(32).toString('base64');
}

/** A NetworkService with fresh module state, logged in, aimed at [A, B]. */
async function freshClient({ username = USER_A, endpoints } = {}) {
  jest.resetModules();
  const NetworkService = require('../../NetworkService').default || require('../../NetworkService');
  const list = endpoints || [
    { apiBase: epA.apiBase, wsBase: epA.wsBase },
    { apiBase: epB.apiBase, wsBase: epB.wsBase },
  ];
  await NetworkService.saveIsland({ schema: 2, endpoints: list, activeIdx: 0 });
  const r = await NetworkService.login(username, PASS);
  if (!r?.ok) throw new Error('login failed: ' + JSON.stringify(r));
  clients.push(NetworkService);
  return NetworkService;
}

beforeAll(async () => {
  epA = createEntryPoint({ port: PORT_A });
  epB = createEntryPoint({ port: PORT_B });
  await epA.listen();
  await epB.listen();

  const health = await fetch(`${UPSTREAM}/health`).then((r) => r.json()).catch(() => null);
  if (!health || health.status !== 'ok') {
    throw new Error(`backend not reachable at ${UPSTREAM} — start it first (see integration/README.md)`);
  }

  // Accounts are reused across runs; a duplicate registration is expected.
  for (const u of [USER_A, USER_B]) {
    await fetch(`${UPSTREAM}/auth/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: u, password: PASS, public_key: randomKeyB64() }),
    }).catch(() => {});

    // Privacy defaults refuse DMs from non-friends, so /dm/open would 403.
    const login = await fetch(`${UPSTREAM}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ username: u, password: PASS }),
    }).then((r) => r.json()).catch(() => null);
    const token = login?.access_token || login?.token;
    if (token) {
      await fetch(`${UPSTREAM}/profile/me`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
        body: JSON.stringify({
          about: '',
          privacy: { allow_group_invites_from_non_friends: true, allow_dm_from_non_friends: true },
        }),
      }).catch(() => {});
    }
  }
}, 60000);

afterAll(async () => {
  if (epA) await epA.close();
  if (epB) await epB.close();
});

beforeEach(() => {
  epA.setMode('ok');
  epB.setMode('ok');
});

// Every client is a live singleton holding up to three sockets and timers;
// leaving one running would keep the next test's server busy and jest alive.
const clients = [];
afterEach(() => {
  while (clients.length) {
    const NS = clients.pop();
    try { NS.disconnectRoom(); } catch { /* already down */ }
    try { NS.disconnectDm(); } catch { /* already down */ }
    try { NS.disconnectNotify(); } catch { /* already down */ }
    try { NS._clearSession?.(); } catch { /* best effort */ }
  }
});

describe('server assumptions', () => {
  it('accepts a request that arrived under a host name it does not know', async () => {
    // The whole design rests on this: entry points are new names in front of
    // the same backend, and the server must not care which one was used.
    const r = await fetch(`${epA.apiBase}/health`, { headers: { Host: 'bridge.volunteer.example' } });
    expect(r.status).toBe(200);
    expect((await r.json()).status).toBe('ok');
  });

  it('serves both entry points from the same backend', async () => {
    const [a, b] = await Promise.all([
      fetch(`${epA.apiBase}/health`).then((r) => r.json()),
      fetch(`${epB.apiBase}/health`).then((r) => r.json()),
    ]);
    expect(a).toEqual(b);
  });
});

describe('entry-point failover', () => {
  jest.setTimeout(90000);

  it('connects all three sockets through the first entry point', async () => {
    const NS = await freshClient();
    const room = await NS.createRoom({ name: `r-${Date.now()}`, is_public: false, encrypted_room_key: randomKeyB64() });
    const thread = await NS.openDmThread(USER_B);

    NS.connectNotify();
    await NS.connectRoom(room.id);
    await NS.connectDm(thread.thread_id, USER_B);

    await waitFor(() => NS.isConnectedToRoom(room.id), { what: 'room WS' });
    await waitFor(() => NS.isDmReady(thread.thread_id), { what: 'DM WS' });

    expect(NS.getServerConfig().apiBase).toBe(epA.apiBase);
    NS.disconnectRoom(); NS.disconnectDm(); NS.disconnectNotify();
  });

  it('rotates to the second entry point when the first stops answering, and keeps the session', async () => {
    const NS = await freshClient();
    const room = await NS.createRoom({ name: `r-${Date.now()}`, is_public: false, encrypted_room_key: randomKeyB64() });
    const thread = await NS.openDmThread(USER_B);

    NS.connectNotify();
    await NS.connectRoom(room.id);
    await NS.connectDm(thread.thread_id, USER_B);
    await waitFor(() => NS.isConnectedToRoom(room.id), { what: 'room WS on A' });

    // Seed the delivery-secret cache: it must survive a rotation, because the
    // secret belongs to the backend, not to the door we came through.
    await NS.getDeliverySecret(thread.thread_id, USER_B).catch(() => {});
    const secretsBefore = NS._deliverySecretCache.size;
    const tokenBefore = NS._token;
    expect(secretsBefore).toBeGreaterThan(0);

    epA.setMode('refuse');
    epA.cut();

    await waitFor(() => NS.getServerConfig().apiBase === epB.apiBase, { what: 'rotation to B', timeout: 30000 });

    expect(NS._token).toBe(tokenBefore);                    // not logged out
    expect(NS._deliverySecretCache.size).toBe(secretsBefore); // cache untouched
    expect(NS.getServerConfig().wsBase).toBe(epB.wsBase);

    await waitFor(() => NS.isConnectedToRoom(room.id), { what: 'room WS re-joined on B', timeout: 30000 });
    await waitFor(() => NS.isDmReady(thread.thread_id), { what: 'DM WS re-dialed on B', timeout: 30000 });

    NS.disconnectRoom(); NS.disconnectDm(); NS.disconnectNotify();
  });

  it('treats one 503 as a strike and rotates on the second', async () => {
    const NS = await freshClient();
    const gen0 = NS._epGen();

    epA.setMode('503');
    await NS.getRooms().catch(() => {});
    expect(NS.getServerConfig().apiBase).toBe(epA.apiBase);   // first 503: strike only
    expect(NS._epGen()).toBe(gen0);

    await NS.getRooms().catch(() => {});
    await waitFor(() => NS.getServerConfig().apiBase === epB.apiBase, { what: 'rotation after second 503' });
  });

  it('rotates when the WebSocket never reaches onopen', async () => {
    const NS = await freshClient();
    const room = await NS.createRoom({ name: `r-${Date.now()}`, is_public: false, encrypted_room_key: randomKeyB64() });

    epA.setMode('drop-ws');                 // HTTP fine, upgrades destroyed
    await NS.connectRoom(room.id);

    await waitFor(() => NS.getServerConfig().apiBase === epB.apiBase, { what: 'rotation on handshake failure', timeout: 30000 });
    await waitFor(() => NS.isConnectedToRoom(room.id), { what: 'room WS on B', timeout: 30000 });
    NS.disconnectRoom();
  });

  it('does not rotate when the server rejects on policy (wrong room password)', async () => {
    const NS = await freshClient();
    const room = await NS.createRoom({
      name: `r-${Date.now()}`, is_public: false, password: 'the-right-one', encrypted_room_key: randomKeyB64(),
    });

    const gen0 = NS._epGen();
    await NS.connectRoom(room.id, 'the-wrong-one');
    await sleep(4000);

    // The server spoke; the entry point is fine. Rotating here would burn
    // through every door of the island over a user typo.
    expect(NS.getServerConfig().apiBase).toBe(epA.apiBase);
    expect(NS._epGen()).toBe(gen0);
    NS.disconnectRoom();
  });

  it('survives both entry points being down without logging the user out', async () => {
    const NS = await freshClient();
    const tokenBefore = NS._token;

    epA.setMode('refuse');
    epB.setMode('refuse');
    for (let i = 0; i < 4; i++) await NS.getRooms().catch(() => {});

    expect(NS._token).toBe(tokenBefore);
    expect(NS._deliverySecretCache).toBeDefined();

    epA.setMode('ok');
    epB.setMode('ok');
    await waitFor(async () => {
      try { await NS.getRooms(); return true; } catch { return false; }
    }, { what: 'recovery once an entry point returns', timeout: 30000 });
  });

  it('blacklists an entry point that rejects the session and rotates back', async () => {
    const NS = await freshClient();
    expect(NS.getServerConfig().apiBase).toBe(epA.apiBase);

    // B answers /health but 401s everything authenticated — a mistyped address
    // leading to a different instance. Losing the session here would be the
    // worst possible outcome of a failover.
    epB.setMode('foreign');
    epA.setMode('refuse');
    await NS.getRooms().catch(() => {});
    await waitFor(() => NS.getServerConfig().apiBase === epB.apiBase, { what: 'rotation to the foreign entry point', timeout: 30000 });

    epA.setMode('ok');
    await NS.getRooms().catch(() => {});

    await waitFor(() => NS.getServerConfig().apiBase === epA.apiBase, { what: 'rotation back off the foreign entry point', timeout: 30000 });
    expect(NS._token).toBeTruthy();
    expect(NS._epSelector().isUnusable(epB.apiBase)).toBe('foreignIsland');
  });

  it('upgrades a legacy {apiBase, wsBase} config in place and connects', async () => {
    jest.resetModules();
    const AsyncStorage = require('./helpers/rnStubs').AsyncStorage;
    await AsyncStorage.setItem(
      'com.wsmessenger.server_config',
      JSON.stringify({ apiBase: epA.apiBase, wsBase: epA.wsBase }),
    );

    const NS = require('../../NetworkService').default || require('../../NetworkService');
    await NS.loadServerConfig();

    const cfg = NS.getServerConfig();
    expect(cfg.endpoints).toHaveLength(1);
    expect(cfg.apiBase).toBe(epA.apiBase);

    const stored = JSON.parse(await AsyncStorage.getItem('com.wsmessenger.server_config'));
    expect(stored.schema).toBe(2);               // upgrade persisted, once
    expect(stored.endpoints[0].apiBase).toBe(epA.apiBase);

    const r = await NS.login(USER_A, PASS);
    expect(r.ok).toBe(true);
  });
});
