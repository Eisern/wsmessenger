// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * guest-rooms.js: signing in to another island as a guest, and the invitation
 * that tells somebody they may.
 *
 * The island below checks the session signature the way server/main.py
 * `foreign_guest_session` does - its own byte layout, its own Ed25519 verify -
 * so a client that drifted from the server fails here rather than against a
 * real island, where every refusal is the same 403.
 */

const crypto = require('crypto');
const GR = require('../guest-rooms');

const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

function edPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(ED25519_SPKI.length);
  return {
    raw,
    sign: async (bytes) => new Uint8Array(crypto.sign(null, Buffer.from(bytes), privateKey)),
  };
}

function kidOf(seedish) {
  return crypto.createHash('sha256').update(seedish).digest('hex').slice(0, 32);
}

/** An island as far as a guest can see it. */
function makeIsland(id, { host = id } = {}) {
  const nonces = new Set();
  const guests = new Map();   // kid -> { raw, username }
  const tokens = new Map();   // token -> username
  const calls = [];
  let n = 0;

  async function fetchJson(url, opts = {}) {
    const u = new URL(url);
    if (u.host !== host) throw new TypeError('Failed to fetch');
    const method = opts.method || 'GET';
    calls.push(`${method} ${u.pathname}`);

    if (u.pathname === '/foreign/challenge') {
      const nonce = crypto.randomBytes(32).toString('base64');
      nonces.add(nonce);
      return { ok: true, status: 200, body: { island_id: id, nonce_b64: nonce } };
    }
    if (u.pathname === '/foreign/guest/session') {
      const b = JSON.parse(opts.body);
      const refuse = { ok: false, status: 403, body: { detail: 'forbidden' } };
      if (!nonces.delete(b.nonce_b64)) return refuse;     // spent either way
      const g = guests.get(b.kid);
      if (!g) return refuse;
      // server/main.py: GUEST_SESSION_DOMAIN + island.encode("utf-8") + kid.encode("ascii") + nonce
      const msg = Buffer.concat([
        Buffer.from('ws-guest-session-v1'), Buffer.from(id, 'utf8'),
        Buffer.from(b.kid, 'ascii'), Buffer.from(b.nonce_b64, 'base64'),
      ]);
      const pub = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, g.raw]), format: 'der', type: 'spki' });
      if (!crypto.verify(null, msg, pub, Buffer.from(b.sig_b64, 'base64'))) return refuse;
      const token = `t${++n}`;
      tokens.set(token, g.username);
      return {
        ok: true, status: 200,
        body: { access_token: token, username: g.username, expires_in: 900, guest: true, island_id: id },
      };
    }

    const token = String((opts.headers || {}).Authorization || '').replace(/^Bearer /, '');
    if (!tokens.has(token)) return { ok: false, status: 401, body: { detail: 'Invalid token' } };
    return { ok: true, status: 200, body: { path: u.pathname, as: tokens.get(token), body: opts.body || null } };
  }

  return {
    id, host, calls, tokens, fetchJson,
    admit(kid, raw, username) { guests.set(kid, { raw, username }); },
    revokeAll() { tokens.clear(); },
  };
}

function deps(island, me, extra = {}) {
  let signed = 0;
  return {
    fetchJson: island.fetchJson,
    sign: async (bytes) => { signed++; return me.sign(bytes); },
    now: () => Date.now(),
    myKid: async () => me.kid,
    signedCount: () => signed,
    ...extra,
  };
}

function guest(name) {
  const pair = edPair();
  return { ...pair, kid: kidOf(name), name };
}

describe('signing in as a guest', () => {
  test('is a signature the island checks over its own layout', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@island-g~' + alice.kid.slice(0, 6));

    const s = await GR.openSession(deps(R, alice), 'https://island-r/', alice.kid, { expectIslandId: 'Island-R' });
    expect(s.ok).toBe(true);
    expect(s.username).toBe('alice@island-g~' + alice.kid.slice(0, 6));
    expect(s.apiBase).toBe('https://island-r');
    expect(R.tokens.get(s.token)).toBe(s.username);
  });

  test('works for an island id that is not ASCII', async () => {
    const R = makeIsland('остров-р', { host: 'island-r' });
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const s = await GR.openSession(deps(R, alice), 'https://island-r', alice.kid);
    expect(s.ok).toBe(true);
  });

  test('signs nothing for an island other than the one it was sent to', async () => {
    const elsewhere = makeIsland('island-x', { host: 'island-r' });
    const alice = guest('alice');
    elsewhere.admit(alice.kid, alice.raw, 'alice@x');
    const d = deps(elsewhere, alice);

    const s = await GR.openSession(d, 'https://island-r', alice.kid, { expectIslandId: 'island-r' });
    expect(s).toMatchObject({ ok: false, reason: 'wrong island' });
    expect(d.signedCount()).toBe(0);
    expect(elsewhere.calls).toEqual(['GET /foreign/challenge']);
  });

  test('a key the island has no guest for is refused', async () => {
    const R = makeIsland('island-r');
    const stranger = guest('stranger');
    const s = await GR.openSession(deps(R, stranger), 'https://island-r', stranger.kid);
    expect(s).toMatchObject({ ok: false, status: 403 });
  });

  test('somebody else\'s kid with my key is refused', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    const mallory = guest('mallory');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const s = await GR.openSession(deps(R, mallory), 'https://island-r', alice.kid);
    expect(s).toMatchObject({ ok: false, status: 403 });
  });
});

describe('sessions with several islands', () => {
  const island = (R, bases) => ({ islandId: R.id, entryPoints: bases.map((b) => ({ apiBase: b })) });

  test('one sign-in serves requests that arrive together', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const S = GR.createSessions(deps(R, alice));
    const where = island(R, ['https://island-r']);

    const out = await Promise.all([
      S.request(where, '/rooms/1/history'),
      S.request(where, '/rooms/1/members'),
      S.request(where, '/crypto/room-key/1'),
    ]);
    expect(out.every((r) => r.ok)).toBe(true);
    expect(R.calls.filter((c) => c === 'GET /foreign/challenge')).toHaveLength(1);
  });

  test('a 401 signs in again once, and does not loop', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const d = deps(R, alice);
    const S = GR.createSessions(d);
    const where = island(R, ['https://island-r']);

    expect((await S.request(where, '/rooms/list')).ok).toBe(true);
    R.revokeAll();
    expect((await S.request(where, '/rooms/list')).ok).toBe(true);
    expect(d.signedCount()).toBe(2);

    // An island that refuses every token it issues: one retry, then the 401.
    const stubborn = { ...d, fetchJson: async (url, opts) => {
      const r = await R.fetchJson(url, opts);
      if (new URL(url).pathname.startsWith('/rooms/')) return { ok: false, status: 401, body: {} };
      return r;
    } };
    const S2 = GR.createSessions(stubborn);
    const r = await S2.request(where, '/rooms/list');
    expect(r).toMatchObject({ ok: false, status: 401 });
  });

  test('requests refused together sign in again once, not once each', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const d = deps(R, alice);
    const S = GR.createSessions(d);
    const where = island(R, ['https://island-r']);

    await S.get(where);
    R.revokeAll();
    const out = await Promise.all([1, 2, 3, 4].map((i) => S.request(where, `/rooms/${i}/history`)));
    expect(out.every((r) => r.ok)).toBe(true);
    expect(d.signedCount()).toBe(2);
  });

  test('a refusal of a token that was already replaced does not sign in again', async () => {
    // A slow request sent with the old token comes back 401 after a quicker
    // one has already signed in again. It must use the new session, not make
    // a third.
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    let release;
    const gate = new Promise((r) => { release = r; });
    const d = deps(R, alice, {
      fetchJson: async (url, opts) => {
        const slow = new URL(url).pathname === '/slow';
        const r = await R.fetchJson(url, opts);   // the island decides now...
        if (slow) await gate;   // ...the answer arrives later
        return r;
      },
    });
    const S = GR.createSessions(d);
    const where = island(R, ['https://island-r']);

    await S.get(where);
    R.revokeAll();
    const slow = S.request(where, '/slow');
    await new Promise((r) => setImmediate(r));
    expect((await S.request(where, '/fast')).ok).toBe(true);
    expect(d.signedCount()).toBe(2);

    release();
    expect((await slow).ok).toBe(true);
    expect(d.signedCount()).toBe(2);
  });

  test('a kid written in capitals signs what the island checks - its lower-case form', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const s = await GR.openSession(deps(R, alice), 'https://island-r', alice.kid.toUpperCase());
    expect(s.ok).toBe(true);
  });

  test('a panel that cannot sign says so, and does not knock on the other doors', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const asked = [];
    const S = GR.createSessions({
      ...deps(R, alice),
      fetchJson: async (url, opts) => { asked.push(new URL(url).host); return R.fetchJson(url, opts); },
      sign: async () => { throw new Error('Locked: no signing key'); },
    });
    const s = await S.get({ islandId: 'island-r', entryPoints: [{ apiBase: 'https://island-r' }, { apiBase: 'https://island-r:8443' }] });
    expect(s).toMatchObject({ ok: false, reason: 'cannot sign', status: 0 });
    expect(asked).toEqual(['island-r']);

    const S2 = GR.createSessions({ ...deps(R, alice), myKid: async () => { throw new Error('Locked'); } });
    expect(await S2.get({ islandId: 'island-r', entryPoints: [{ apiBase: 'https://island-r' }] }))
      .toMatchObject({ ok: false, reason: 'locked' });
    // And a request through it answers instead of throwing.
    expect(await S2.request({ islandId: 'island-r', entryPoints: [{ apiBase: 'https://island-r' }] }, '/rooms/list'))
      .toMatchObject({ ok: false, status: 0, reason: 'locked' });
  });

  test('an entry point that does not answer is passed over; one that refuses is final', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    const S = GR.createSessions(deps(R, alice));

    const r = await S.request(island(R, ['https://dead-door', 'https://island-r']), '/rooms/list');
    expect(r.ok).toBe(true);
    expect(r.session.apiBase).toBe('https://island-r');

    // A refusal from the island is its answer; another door into it would
    // only be asked to sign again.
    const stranger = guest('stranger');
    const asked = [];
    const S2 = GR.createSessions({
      ...deps(R, stranger),
      fetchJson: async (url, opts) => { asked.push(new URL(url).host); return R.fetchJson(url, opts); },
    });
    const refused = await S2.get({ islandId: 'island-r', entryPoints: [{ apiBase: 'https://island-r' }, { apiBase: 'https://island-r:8443' }] });
    expect(refused).toMatchObject({ ok: false, status: 403 });
    expect(new Set(asked)).toEqual(new Set(['island-r']));
  });

  test('a session is signed again shortly before it runs out', async () => {
    const R = makeIsland('island-r');
    const alice = guest('alice');
    R.admit(alice.kid, alice.raw, 'alice@x');
    let now = 1_000_000;
    const d = deps(R, alice, { now: () => now });
    const S = GR.createSessions(d);
    const where = island(R, ['https://island-r']);

    await S.get(where);
    now += 10 * 60 * 1000;
    await S.get(where);
    expect(d.signedCount()).toBe(1);
    now += 4.5 * 60 * 1000;   // 15 min token, within a minute of the end
    await S.get(where);
    expect(d.signedCount()).toBe(2);

    S.forget('ISLAND-R');
    expect(S.peek('island-r')).toBeNull();
  });
});

describe('the invitation', () => {
  const inv = { islandId: 'island-r', roomId: 42, roomName: 'Книжный клуб', guestName: 'alice@island-g~ca2a4f' };

  test('round-trips, and is only ever read as one when it is one', () => {
    const text = GR.buildInvite(inv);
    expect(text.startsWith(GR.INVITE_PREFIX)).toBe(true);
    expect(GR.parseInvite(text)).toEqual(inv);

    const enc = (o) => GR.INVITE_PREFIX + Buffer.from(JSON.stringify(o)).toString('base64url');
    for (const bad of [
      'hello',
      GR.INVITE_PREFIX,
      GR.INVITE_PREFIX + '!!!',
      enc({ v: 2, island: 'r', room_id: 1 }),
      enc({ v: 1, island: 'r', room_id: 0 }),
      enc({ v: 1, island: 'r', room_id: 1.5 }),
      enc({ v: 1, island: '', room_id: 1 }),
      enc([1, 2, 3]),
      null,
    ]) {
      expect(GR.parseInvite(bad)).toBeNull();
    }
  });

  test('cannot be built without an island and a room', () => {
    expect(() => GR.buildInvite({ ...inv, islandId: '' })).toThrow();
    expect(() => GR.buildInvite({ ...inv, roomId: 0 })).toThrow();
  });
});

describe('where a guest room is kept', () => {
  test('a key slot no local room or DM can share', () => {
    expect(GR.slot('Island-R', 42)).toBe('gr:island-r:42');
    expect(GR.slot('', 42)).toBe('');
    expect(GR.slot('island-r', 'x')).toBe('');
    expect(GR.listKey('Home.Island', 'Alice')).toBe('__guest_rooms:home.island:alice');
  });

  test('the same room is the same island and id, whatever the case', () => {
    expect(GR.sameRoom({ islandId: 'Island-R', roomId: 42 }, { islandId: 'island-r', roomId: '42' })).toBe(true);
    expect(GR.sameRoom({ islandId: 'island-r', roomId: 42 }, { islandId: 'island-s', roomId: 42 })).toBe(false);
  });

  test('the socket address comes from the entry point', () => {
    expect(GR.socketUrl({ apiBase: 'https://r.example', wsBase: 'wss://ws.r.example/' }, 42))
      .toBe('wss://ws.r.example/ws?room_id=42');
    expect(GR.socketUrl({ apiBase: 'https://r.example/' }, 7)).toBe('wss://r.example/ws?room_id=7');
  });
});
