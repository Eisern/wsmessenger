// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * key-sweep.js: when a client hands out missing room keys, how often, and
 * what each kind of failure costs. Shared byte for byte by both clients, so
 * this is the one place its rules are pinned. Time and timers are the test's.
 */

const KS = require('../key-sweep');

function harness(over = {}) {
  let t = 1_000_000;
  const timers = [];
  const calls = { fetch: [], refresh: [], share: [] };
  const island = {
    pages: [],          // queue of pages; when empty, { gaps: [] }
    shareResult: {},    // "rid:name" -> 'ok' | 'had' | Error
    ready: true,
  };
  const done = [];
  const sweep = KS.createKeySweep({
    isReady: async () => island.ready,
    fetchGaps: async (q) => {
      calls.fetch.push(q);
      const next = island.pages.length ? island.pages.shift() : { gaps: [] };
      if (next instanceof Error) throw next;
      return next;
    },
    refreshRoomKey: async (rid) => { calls.refresh.push(rid); },
    share: async (rid, name) => {
      calls.share.push(`${rid}:${name}`);
      const r = island.shareResult[`${rid}:${name}`];
      if (r instanceof Error) throw r;
      return { written: r !== 'had' };
    },
    isTransient: (e) => e.code === 'TRUST_UNVERIFIABLE' || e.status === 0 || e.status >= 500,
    onDone: (summary, blocked) => done.push({ summary, blocked }),
    timers: {
      setTimeout: (fn, ms) => { const h = { fn, at: t + ms, live: true }; timers.push(h); return h; },
      clearTimeout: (h) => { if (h) h.live = false; },
    },
    now: () => t,
    ...over,
  });
  return {
    sweep, calls, island, done,
    advance(ms) { t += ms; },
    // Fire every live timer that is due, as the clock stands.
    async fireDue() {
      for (const h of timers.splice(0)) {
        if (h.live && h.at <= t) { h.live = false; h.fn(); } else if (h.live) timers.push(h);
      }
      for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
    },
    get timers() { return timers.filter((h) => h.live); },
  };
}

const gaps = (...pairs) => ({ gaps: pairs.map(([room_id, username]) => ({ room_id, username })), truncated: false });
const err = (message, extra = {}) => Object.assign(new Error(message), extra);
const L = KS.LIMITS;

describe('a run', () => {
  test('hands the key to every gap, refreshing each room\'s key once first', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'ann'], [7, 'bob'], [8, 'cat'])];
    H.island.shareResult['7:bob'] = 'had';
    const res = await H.sweep.run({ reason: 'test' });
    expect(res).toEqual({ ran: true, shared: 2, alreadyHad: 1, skipped: 0, failed: 0, incomplete: false });
    expect(H.calls.refresh).toEqual([7, 8]);
    expect(H.calls.share).toEqual(['7:ann', '7:bob', '8:cat']);
    expect(H.done).toHaveLength(1);
  });

  test('does not start while locked, and asks nothing', async () => {
    const H = harness();
    H.island.ready = false;
    expect(await H.sweep.run()).toMatchObject({ ran: false });
    expect(H.calls.fetch).toHaveLength(0);
    expect(H.done).toHaveLength(0);
  });

  test('two callers arriving together: one runs, the other is queued, not dropped', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    let n = 0;
    const H2 = harness({ isReady: async () => { n += 1; await gate; return true; } });
    const a = H2.sweep.run({ roomId: 7 });
    const b = H2.sweep.run({ roomId: 8 });   // before a has even checked readiness
    release();
    expect((await b).ran).toBe(false);
    expect((await a).ran).toBe(true);
    expect(n).toBe(1);
    expect(H2.timers).toHaveLength(1);   // b's room comes back as a rerun
    expect(H2.calls.fetch).toHaveLength(1);
  });

  test('a provider of nothing here is an answer, not a failure', async () => {
    const H = harness();
    H.island.pages = [{ gaps: [], truncated: false, notProvider: true }];
    await H.sweep.run({ roomId: 7 });
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + L.MIN_INTERVAL_MS);
  });

  test('runs no sooner than the interval allows, however often asked', async () => {
    const H = harness();
    await H.sweep.run();
    expect((await H.sweep.run()).ran).toBe(false);
    H.advance(L.MIN_INTERVAL_MS);
    expect((await H.sweep.run()).ran).toBe(true);
  });
});

describe('failures', () => {
  test('a member whose key changed is held back until verified - not retried, not counted as a failure', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'bob'], [7, 'ann'])];
    H.island.shareResult['7:bob'] = err('changed', { code: 'TRUST_CHANGED' });
    const res = await H.sweep.run();
    expect(res).toMatchObject({ shared: 1, skipped: 1, failed: 0 });
    expect(H.sweep.trustBlocked()).toEqual([{ username: 'bob', reason: 'TRUST_CHANGED', rooms: [7] }]);
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + L.MIN_INTERVAL_MS);   // not an infrastructure failure

    H.advance(L.MIN_INTERVAL_MS);
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ skipped: 1 });
    expect(H.calls.share.filter((s) => s === '7:bob')).toHaveLength(1);

    H.sweep.clearTrustBlock('BOB');
    delete H.island.shareResult['7:bob'];
    H.advance(L.MIN_INTERVAL_MS);
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ shared: 1 });
  });

  test('a trust block runs out on its own, and the member is tried again', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'bob'])];
    H.island.shareResult['7:bob'] = err('unverified', { code: 'TRUST_UNVERIFIED' });
    await H.sweep.run();
    H.advance(L.TRUST_BLOCK_MS - 1);
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ skipped: 1 });
    expect(H.calls.share).toEqual(['7:bob']);

    H.advance(L.TRUST_BLOCK_MS);
    expect(H.sweep.trustBlocked()).toEqual([]);
    delete H.island.shareResult['7:bob'];
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ shared: 1 });
    expect(H.calls.share).toEqual(['7:bob', '7:bob']);
  });

  test('one member that cannot be served cools down alone; the sweep does not back off for it', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'bob'])];
    H.island.shareResult['7:bob'] = err('not a member', { status: 404 });
    expect(await H.sweep.run()).toMatchObject({ failed: 1 });
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + L.MIN_INTERVAL_MS);

    H.advance(L.MIN_INTERVAL_MS);
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ skipped: 1, failed: 0 });

    H.advance(L.PAIR_COOLDOWN_MS);
    H.island.pages = [gaps([7, 'bob'])];
    expect(await H.sweep.run()).toMatchObject({ failed: 1 });
  });

  test('infrastructure trouble backs the whole sweep off, and ends a pass after a few in a row', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'a'], [7, 'b'], [7, 'c'], [7, 'd'], [7, 'e'])];
    for (const n of 'abcde') H.island.shareResult[`7:${n}`] = err('down', { status: 503 });
    const res = await H.sweep.run();
    expect(res.failed).toBe(L.MAX_TRANSIENT);
    expect(H.calls.share).toHaveLength(L.MAX_TRANSIENT);
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + L.ERROR_BACKOFF_MS);
  });

  test('"could not check the pin right now" is infrastructure, not a verdict on the member', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'bob'])];
    H.island.shareResult['7:bob'] = err('storage', { code: 'TRUST_UNVERIFIABLE' });
    await H.sweep.run();
    expect(H.sweep.trustBlocked()).toEqual([]);
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + L.ERROR_BACKOFF_MS);
  });

  test('a run that could not get the list says so - zeros are not "nobody is missing a key"', async () => {
    const H = harness();
    H.island.pages = [err('down', { status: 503 })];
    expect(await H.sweep.run()).toEqual({ ran: true, shared: 0, alreadyHad: 0, skipped: 0, failed: 0, incomplete: true });

    const H2 = harness();
    H2.island.pages = [gaps([7, 'a'], [7, 'b'], [7, 'c'])];
    for (const n of 'abc') H2.island.shareResult[`7:${n}`] = err('down', { status: 503 });
    expect(await H2.sweep.run()).toMatchObject({ failed: 3, incomplete: true });

    const H3 = harness();
    H3.island.pages = Array.from({ length: 10 }, (_, i) => ({ ...gaps([7, `m${i}`]), truncated: true }));
    expect(await H3.sweep.run()).toMatchObject({ shared: L.MAX_PASSES, incomplete: true });

    const H4 = harness();
    H4.island.pages = [gaps([7, 'a'])];
    H4.island.shareResult['7:a'] = err('not a member', { status: 404 });
    expect(await H4.sweep.run()).toMatchObject({ failed: 1, incomplete: false });
  });

  test('a rate limit is obeyed for as long as the island asks', async () => {
    const H = harness();
    H.island.pages = [err('slow down', { status: 429, retryAfterS: 900 })];
    await H.sweep.run();
    expect(H.sweep.nextAllowedAt).toBe(1_000_000 + 900_000);
    const H2 = harness();
    H2.island.pages = [err('slow down', { status: 429 })];
    await H2.sweep.run();
    expect(H2.sweep.nextAllowedAt).toBe(1_000_000 + Math.max(L.ERROR_BACKOFF_MS, L.RETRY_AFTER_DEFAULT_S * 1000));
  });
});

describe('pages', () => {
  test('the next page is fetched while each one makes progress', async () => {
    const H = harness();
    H.island.pages = [{ ...gaps([7, 'a']), truncated: true }, { ...gaps([7, 'b']), truncated: true }, gaps([7, 'c'])];
    expect(await H.sweep.run()).toMatchObject({ shared: 3 });
    expect(H.calls.fetch).toHaveLength(3);
  });

  test('and not when a page closed nothing - the next would be the same page', async () => {
    const H = harness();
    H.island.pages = [{ ...gaps([7, 'a']), truncated: true }, gaps([7, 'b'])];
    H.island.shareResult['7:a'] = err('nope', { status: 404 });
    await H.sweep.run();
    expect(H.calls.fetch).toHaveLength(1);
  });

  test('at most MAX_PASSES pages in one run', async () => {
    const H = harness();
    H.island.pages = Array.from({ length: 10 }, (_, i) => ({ ...gaps([7, `m${i}`]), truncated: true }));
    await H.sweep.run();
    expect(H.calls.fetch).toHaveLength(L.MAX_PASSES);
  });
});

describe('scheduling', () => {
  test('a burst of triggers is one run; one room alone is asked about alone', async () => {
    const H = harness();
    H.sweep.schedule('a', { roomId: 7 });
    H.sweep.schedule('b', { roomId: 7, delayMs: 5000 });
    await H.fireDue();
    expect(H.calls.fetch).toEqual([{ roomId: 7, limit: L.PAGE }]);
  });

  test('two rooms, or a request for all, become one unfiltered question', async () => {
    const H = harness();
    H.sweep.schedule('a', { roomId: 7 });
    H.sweep.schedule('b', { roomId: 8 });
    await H.fireDue();
    H.advance(L.MIN_INTERVAL_MS);
    H.sweep.schedule('c', { roomId: 9 });
    H.sweep.schedule('d');
    await H.fireDue();
    expect(H.calls.fetch.map((q) => q.roomId)).toEqual([0, 0]);
  });

  test('a trigger during a run comes back after it, on the run\'s clock', async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const H = harness({ refreshRoomKey: async () => { await gate; } });
    H.island.pages = [gaps([7, 'a'])];
    const first = H.sweep.run();
    await new Promise((r) => setImmediate(r));
    await H.sweep.run({ roomId: 8 });   // while the first is busy
    release();
    await first;
    expect(H.timers).toHaveLength(1);
    H.advance(L.MIN_INTERVAL_MS);
    await H.fireDue();
    expect(H.calls.fetch.at(-1)).toEqual({ roomId: 8, limit: L.PAGE });
  });

  test('reset forgets everything, including a pending timer', async () => {
    const H = harness();
    H.island.pages = [gaps([7, 'bob'])];
    H.island.shareResult['7:bob'] = err('changed', { code: 'TRUST_CHANGED' });
    await H.sweep.run();
    H.sweep.schedule('x');
    H.sweep.reset();
    expect(H.sweep.trustBlocked()).toEqual([]);
    expect(H.sweep.nextAllowedAt).toBe(0);
    expect(H.timers).toHaveLength(0);
  });
});
