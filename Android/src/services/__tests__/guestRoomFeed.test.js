// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * guest-room-feed.js on its own: what a guest room shows, in what order, and
 * what it says when it cannot show anything. extensionGuestRoomView.test.js
 * runs the same module under the extension's view; this one reaches the
 * corners a view test does not - timers, a key load that throws, notices -
 * with the clock in the test's hands.
 */

const Feed = require('../guest-room-feed');

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

const flush = async (n = 20) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

/** Timers that fire only when the test says so. */
function manualTimers() {
  let n = 0;
  const timeouts = new Map();
  const intervals = new Map();
  return {
    setTimeout: (fn) => { const id = ++n; timeouts.set(id, fn); return id; },
    clearTimeout: (id) => { timeouts.delete(id); },
    setInterval: (fn) => { const id = ++n; intervals.set(id, fn); return id; },
    clearInterval: (id) => { intervals.delete(id); },
    fireTimeouts() { const fns = [...timeouts.values()]; timeouts.clear(); fns.forEach((f) => f()); },
    async tickIntervals() { for (const f of [...intervals.values()]) await f(); },
    get intervals() { return intervals.size; },
    get timeouts() { return timeouts.size; },
  };
}

function make(overrides = {}) {
  const shown = [];
  const notices = [];
  const sockets = [];
  const island = { history: [], keyRes: { ok: true }, historyError: null };
  const timers = manualTimers();
  const feed = Feed.createFeed({
    openSocket: (h) => {
      const s = { h, closed: false, close() { this.closed = true; }, send(t) { this.sent = t; }, online: false };
      sockets.push(s);
      return s;
    },
    loadKey: async () => island.keyRes,
    fetchHistory: async () => {
      if (island.historyError) throw island.historyError;
      return { messages: island.history.map((text) => ({ username: 'carol', text, ts: 1 })) };
    },
    decrypt: async (ct, user) => (ct === 'locked' ? null : { text: ct, from: user, sigValid: true, mismatch: false }),
    isMe: (u) => u === 'me',
    onReset: (items) => { shown.length = 0; shown.push(...items.map((i) => i.text)); },
    onAppend: (it) => { shown.push(it.text); },
    onNotice: (n) => { notices.push(n); },
    timers,
    ...overrides,
  });
  return { feed, shown, notices, sockets, island, timers, up: () => sockets[0].h.onStatus({ online: true }) };
}

describe('the feed', () => {
  test('waits for the socket, but not forever, and then reads again when it does come', async () => {
    const F = make();
    F.island.history = ['h1'];
    const started = F.feed.start();
    await flush();
    expect(F.shown).toEqual([]);

    // The socket does not come; after the wait the history is shown anyway...
    F.timers.fireTimeouts();
    await started;
    expect(F.shown).toEqual(['h1']);

    // ...and read again once it does, for whatever was written in between.
    F.island.history.push('meanwhile');
    F.up();
    await F.feed.idle();
    expect(F.shown).toEqual(['h1', 'meanwhile']);
  });

  test('a key load that throws still shows the history, and says the key is missing', async () => {
    const F = make({ loadKey: async () => { throw new Error('boom'); } });
    F.island.history = ['h1'];
    const started = F.feed.start();
    F.up();
    await started;
    expect(F.shown).toEqual(['h1']);
    expect(F.notices.map((n) => n.kind)).toEqual(['key-error']);
  });

  test('a missing key is looked for again, and the history redrawn when it arrives', async () => {
    const F = make();
    F.island.keyRes = { ok: false, notFound: true };
    F.island.history = ['locked-out'];
    const started = F.feed.start();
    F.up();
    await started;
    expect(F.notices.map((n) => n.kind)).toEqual(['key-notFound']);
    expect(F.timers.intervals).toBe(1);

    await F.timers.tickIntervals();   // still nothing
    expect(F.timers.intervals).toBe(1);

    F.island.keyRes = { ok: true };
    F.island.history = ['readable'];
    await F.timers.tickIntervals();
    await F.feed.idle();
    expect(F.timers.intervals).toBe(0);
    expect(F.shown).toEqual(['readable']);
  });

  test('a key that failed for a passing reason is looked for again', async () => {
    const F = make();
    F.island.keyRes = { ok: false, error: true, status: 500 };
    const started = F.feed.start();
    F.up();
    await started;
    expect(F.timers.intervals).toBe(1);
  });

  test('the same thing is not said twice in a row, but is said again after a redraw', async () => {
    const F = make();
    F.island.historyError = Object.assign(new Error('nope'), { status: 403 });
    const started = F.feed.start();
    F.sockets[0].h.onStatus({ online: false, error: 'refused' });   // the socket says it first
    await started;
    expect(F.notices.map((n) => n.kind)).toEqual(['refused']);

    F.island.historyError = null;
    F.island.history = ['h1'];
    await F.feed.refresh();
    F.sockets[0].h.onStatus({ online: true, error: 'slow down' });
    F.sockets[0].h.onStatus({ online: true, error: 'slow down' });
    await F.feed.idle();
    expect(F.notices.map((n) => n.text)).toEqual([
      'Their server no longer lets you into this room.',
      'Their server: slow down',
    ]);

    // A redraw clears what was shown, so the same thing is said again after it.
    await F.feed.refresh();
    F.sockets[0].h.onStatus({ online: true, error: 'slow down' });
    await F.feed.idle();
    expect(F.notices.map((n) => n.text).at(-1)).toBe('Their server: slow down');
    expect(F.notices).toHaveLength(3);
  });

  test('a refused key is not retried - nothing will change by asking again', async () => {
    const F = make();
    F.island.keyRes = { ok: false, refused: true };
    const started = F.feed.start();
    F.up();
    await started;
    expect(F.notices.map((n) => n.kind)).toEqual(['key-refused']);
    expect(F.timers.intervals).toBe(0);
  });

  test('says what the island refused, and what it said', async () => {
    const F = make();
    const started = F.feed.start();
    F.up();
    await started;
    F.sockets[0].h.onStatus({ online: true, error: 'Room is read-only: only owner/admin can post' });
    F.sockets[0].h.onStatus({ online: false, error: 'refused' });
    await F.feed.idle();
    expect(F.notices.map((n) => n.text)).toEqual([
      'Their server: Room is read-only: only owner/admin can post',
      'Their server no longer lets you into this room.',
    ]);

    const G = make();
    G.island.historyError = Object.assign(new Error('nope'), { status: 403 });
    const s2 = G.feed.start();
    G.up();
    await s2;
    expect(G.notices[0].kind).toBe('refused');
  });

  test('after stop(), nothing more is shown - not even an answer already on its way', async () => {
    const gate = deferred();
    const F = make({ fetchHistory: async () => { await gate.promise; return { messages: [{ username: 'c', text: 'late' }] }; } });
    const started = F.feed.start();
    F.up();
    await flush();
    F.feed.stop();
    expect(F.sockets[0].closed).toBe(true);
    gate.resolve();
    await started;
    F.sockets[0].h.onMessage({ text: 'later' });
    await F.feed.idle();
    expect(F.shown).toEqual([]);
    expect(F.notices).toEqual([]);
    expect(() => F.feed.send('x')).toThrow(/closed/);
  });

  test('a message both in the history and on the socket is shown once', async () => {
    const F = make();
    F.island.history = ['h1', 'm2'];
    const started = F.feed.start();
    F.up();
    await started;
    F.sockets[0].h.onMessage({ text: 'm2' });   // its live copy, late
    F.sockets[0].h.onMessage({ text: 'm3' });
    await F.feed.idle();
    expect(F.shown).toEqual(['h1', 'm2', 'm3']);
  });

  test('live messages keep their order when the first takes longer to decrypt', async () => {
    const slow = deferred();
    const F = make({
      decrypt: async (ct, user) => {
        if (ct === 'l1') await slow.promise;
        return { text: ct, from: user, sigValid: true, mismatch: false };
      },
    });
    const started = F.feed.start();
    F.up();
    await started;
    F.sockets[0].h.onMessage({ text: 'l1' });
    F.sockets[0].h.onMessage({ text: 'l2' });
    await flush();
    expect(F.shown).toEqual([]);
    slow.resolve();
    await F.feed.idle();
    expect(F.shown).toEqual(['l1', 'l2']);
  });

  test('a message that cannot be read now is skipped, not shown as something else', async () => {
    const F = make();
    F.island.history = ['h1', 'locked', 'h2'];
    const started = F.feed.start();
    F.up();
    await started;
    expect(F.shown).toEqual(['h1', 'h2']);
  });

  test('items say whose they are and what the signature showed', async () => {
    const items = [];
    const F = make({ onAppend: (it) => items.push(it) });
    const started = F.feed.start();
    F.up();
    await started;
    F.sockets[0].h.onMessage({ text: 'mine', from: 'me', ts: 5 });
    await F.feed.idle();
    expect(items[0]).toEqual({
      key: 'mine', user: 'me', text: 'mine', ts: 5, mine: true, from: 'me', sigValid: true, mismatch: false,
    });
  });
});
