// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Two genuinely independent islands, in two containers.
 *
 * Not two names in front of one backend, and not a proxy pretending to be
 * hostile: two processes, two databases, two JWT secrets, two island signing
 * keys, two relay transport keys. That distinction is the point — the
 * highest-risk behaviour in this codebase was previously exercised against a
 * proxy that returned 401 on command, which proves the client handles a 401,
 * not that it handles a different server.
 *
 * Cross-island direct messaging is designed but NOT implemented, so nothing
 * here sends a message from a user on one island to a user on the other.
 *
 * Requires both islands and the relay; see integration/README.md.
 */

const crypto = require('crypto');
const { ed25519 } = require('@noble/curves/ed25519');

const IL = require('../../island-list');
import AND_UTILS from '../../../crypto/CryptoUtils';
const { createEntryPoint } = require('./helpers/entryPoint');

const ISLAND_A = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';
const ISLAND_B = process.env.TWO_ISLANDS_B || 'http://127.0.0.1:8001';
const RELAY = process.env.RELAY_TEST_RELAY || 'http://127.0.0.1:18800';

const PORT_A = 18201;
const PORT_B = 18202;

const USER = 'twoisl_a_1';
const PASS = 'Testpass!12345';

const b64 = (b) => Buffer.from(b).toString('base64');
const utf8Encode = (s) => new TextEncoder().encode(s);
const b64decode = (s) =>
  Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

const verifier = IL.createIslandListVerifier({
  ed25519Verify: (pub, sig, msg) => ed25519.verify(sig, msg, pub),
  b64decode,
  utf8Encode,
});

let epA;
let epB;
let docA;
let docB;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(predicate, { timeout = 30000, what = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    let ok = false;
    try { ok = await predicate(); } catch { ok = false; }
    if (ok) return true;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(100);
  }
}

async function post(base, path, body, token) {
  const r = await fetch(base + path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  });
  return { status: r.status, data: await r.json().catch(() => null) };
}

beforeAll(async () => {
  for (const [name, url] of [['A', ISLAND_A], ['B', ISLAND_B]]) {
    const h = await fetch(`${url}/health`).then((r) => r.json()).catch(() => null);
    if (!h || h.status !== 'ok') throw new Error(`island ${name} not reachable at ${url}`);
  }

  docA = await fetch(`${ISLAND_A}/.well-known/wsapp-island`).then((r) => r.json());
  docB = await fetch(`${ISLAND_B}/.well-known/wsapp-island`).then((r) => r.json());

  // The account exists on A only. B is a different island with an empty database.
  await post(ISLAND_A, '/auth/register', {
    username: USER, password: PASS, public_key: b64(crypto.randomBytes(32)),
  });

  epA = createEntryPoint({ port: PORT_A, upstreamPort: 8000 });
  epB = createEntryPoint({ port: PORT_B, upstreamPort: 8001 });
  await epA.listen();
  await epB.listen();
}, 60000);

afterAll(async () => {
  if (epA) await epA.close();
  if (epB) await epB.close();
});

beforeEach(() => {
  epA.setMode('ok');
  epB.setMode('ok');
});

describe('two islands really are independent', () => {
  it('each publishes its own identity and its own keys', () => {
    expect(docA.payload.island_id).not.toBe(docB.payload.island_id);
    expect(docA.signing_key_b64).not.toBe(docB.signing_key_b64);
    expect(docA.payload.transport_keys[0].public_key_b64)
      .not.toBe(docB.payload.transport_keys[0].public_key_b64);
  });

  it('an account on one does not exist on the other', async () => {
    const onA = await post(ISLAND_A, '/auth/login', { username: USER, password: PASS });
    expect(onA.status).toBe(200);
    const onB = await post(ISLAND_B, '/auth/login', { username: USER, password: PASS });
    expect(onB.status).not.toBe(200);
  });

  it('a token minted by one is worthless at the other', async () => {
    // Different JWT secrets, so this is a real rejection rather than a
    // membership check that happens to fail.
    const { data } = await post(ISLAND_A, '/auth/login', { username: USER, password: PASS });
    // A GET that exists and requires auth: routing answers before auth does,
    // so a method-not-allowed would prove nothing about the token.
    const r = await fetch(`${ISLAND_B}/dm/list`, {
      headers: { authorization: `Bearer ${data.access_token}` },
    });
    expect(r.status).toBe(401);
  });
});

describe('the signed list distinguishes them', () => {
  it('each document verifies under its own key', async () => {
    expect((await verifier.verify(docA, null)).ok).toBe(true);
    expect((await verifier.verify(docB, null)).ok).toBe(true);
  });

  it('refuses the other document once one island is pinned', async () => {
    const pinnedToA = {
      signingKeyB64: docA.signing_key_b64,
      islandId: docA.payload.island_id,
      version: docA.payload.version,
    };
    const r = await verifier.verify(docB, pinnedToA);
    expect(r.ok).toBe(false);
    // The island id is checked before the signature, so that is what is
    // reported. Either answer is a refusal; this pins which one.
    expect(r.reason).toBe('different island');
  });

  it('refuses a document carrying the wrong signature', async () => {
    // The subtler attack: keep the expected island id, sign with another key.
    const forged = JSON.parse(JSON.stringify(docB));
    forged.payload.island_id = docA.payload.island_id;
    const pinnedToA = {
      signingKeyB64: docA.signing_key_b64,
      islandId: docA.payload.island_id,
      version: 1,
    };
    const r = await verifier.verify(forged, pinnedToA);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad signature');
  });
});

describe('the relay keeps the two apart', () => {
  jest.setTimeout(60000);

  it('carries for both, each under its own transport key', async () => {
    for (const [islandId, doc] of [['island-test', docA], ['island-b', docB]]) {
      const inner = { probe: true, env_ts: Date.now(), env_nonce_b64: b64(crypto.randomBytes(16)) };
      const { envelope, responseKey } = await AND_UTILS.sealRelayEnvelope(
        doc.payload.transport_keys[0].public_key_b64, inner,
      );
      const r = await fetch(`${RELAY}/forward`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          next: islandId,
          blob: Buffer.from(Array.from(envelope, Number)).toString('base64'),
        }),
      });
      // The island opened it - the answer comes back sealed, so it got that
      // far - and then refused the contents, because there is no such thread.
      expect(r.status).toBe(200);
      const answer = await AND_UTILS.openRelayResponse(responseKey, Buffer.from(await r.arrayBuffer()));
      expect(answer.status).toBeGreaterThanOrEqual(400);
    }
  });

  it('refuses an envelope sealed to the other transport key', async () => {
    // Addressed to B, sealed for A: B holds no key that opens it, and says so
    // in the clear, because it could not derive a response key either.
    const inner = { probe: true, env_ts: Date.now(), env_nonce_b64: b64(crypto.randomBytes(16)) };
    const { envelope } = await AND_UTILS.sealRelayEnvelope(
      docA.payload.transport_keys[0].public_key_b64, inner,
    );
    const r = await fetch(`${RELAY}/forward`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        next: 'island-b',
        blob: Buffer.from(Array.from(envelope, Number)).toString('base64'),
      }),
    });
    expect(r.status).toBe(400);
  });
});

describe('a foreign island in the entry-point list', () => {
  jest.setTimeout(120000);

  it('is blacklisted and rolled back from, without destroying the session', async () => {
    // The scenario: a typo, or a copied config, puts a DIFFERENT island into
    // what the client believes is one island's list of entry points. This was
    // previously exercised against a proxy returning 401 on command; here
    // island B really is another server with another JWT secret, and the
    // rejection is genuine.
    jest.resetModules();
    const NS = require('../../NetworkService').default || require('../../NetworkService');

    await NS.saveIsland({
      schema: 2,
      endpoints: [
        { apiBase: epA.apiBase, wsBase: epA.wsBase },
        { apiBase: epB.apiBase, wsBase: epB.wsBase },
      ],
      activeIdx: 0,
    });

    const login = await NS.login(USER, PASS);
    expect(login.ok).toBe(true);
    const tokenBefore = NS._token;
    expect(NS.getServerConfig().apiBase).toBe(epA.apiBase);

    // A goes away; the client has nowhere to go but the foreign island.
    epA.setMode('refuse');
    epA.cut();
    await NS.getRooms().catch(() => {});
    await waitFor(() => NS.getServerConfig().apiBase === epB.apiBase,
      { what: 'rotation onto the foreign island' });

    // A comes back. The client must notice B is not its island and return.
    epA.setMode('ok');
    await NS.getRooms().catch(() => {});
    await waitFor(() => NS.getServerConfig().apiBase === epA.apiBase,
      { what: 'rotation back off the foreign island' });

    expect(NS._token).toBe(tokenBefore);                                    // never logged out
    expect(NS._epSelector().isUnusable(epB.apiBase)).toBe('foreignIsland'); // and remembered

    const rooms = await NS.getRooms();
    expect(rooms).toBeDefined();                                            // still working

    try { NS.disconnectRoom(); NS.disconnectDm(); NS.disconnectNotify(); } catch { /* already down */ }
  });
});
