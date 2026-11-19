// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * room-key-guard.js on its own: which keys a room has moved on from, and when
 * an island's answer may become the current key. Both clients run this file
 * byte for byte (endpoints-parity.test.js).
 */

const RKG = require('../room-key-guard');

function store() {
  const data = new Map();
  return {
    data,
    reads: 0,
    async read(name) { this.reads += 1; return data.has(name) ? JSON.parse(data.get(name)) : null; },
    async write(name, value) { data.set(name, JSON.stringify(value)); },
  };
}

function guard(st, scope = 'island-a:alice') {
  const sc = { value: scope };
  const g = RKG.createRoomKeyGuard({
    read: (n) => st.read(n), write: (n, v) => st.write(n, v), scope: () => sc.value,
  });
  return { g, sc };
}

describe('which keys a room has moved on from', () => {
  test('a key replaced by a newer one is retired; the current one and unknown ones are not', async () => {
    const st = store();
    const { g } = guard(st);
    const t0 = await g.prepare(7);
    expect(g.verdict(t0, 'k1')).toBe('ok');
    g.noteCurrent(7, 'k1');
    g.noteCurrent(7, 'k2');
    const t = await g.prepare(7);
    expect(g.verdict(t, 'k1')).toBe('retired');
    expect(g.verdict(t, 'k2')).toBe('ok');
    expect(g.verdict(t, 'k9')).toBe('ok');
    expect(await g.lastCurrent(7)).toBe('k2');
  });

  test('what it learned survives a restart, per island and account', async () => {
    const st = store();
    const a = guard(st).g;
    await a.prepare(7);
    a.noteCurrent(7, 'k1');
    a.noteCurrent(7, 'k2');
    await a.flushed();

    const again = guard(st).g;
    const t = await again.prepare(7);
    expect(again.verdict(t, 'k1')).toBe('retired');
    expect(await again.lastCurrent(7)).toBe('k2');

    // Another island's room 7, or another account here: another history.
    const other = guard(st, 'island-b:alice').g;
    expect(other.verdict(await other.prepare(7), 'k1')).toBe('ok');
    const bob = guard(st, 'island-a:bob').g;
    expect(bob.verdict(await bob.prepare(7), 'k1')).toBe('ok');
  });

  test('an answer asked for before another key became current is stale, never applied', async () => {
    // A slow answer from before a rotation must not land after it, go back,
    // and retire the key the rotation made.
    const { g } = guard(store());
    await g.prepare(7);
    g.noteCurrent(7, 'k1');
    const before = await g.prepare(7);
    g.noteCurrent(7, 'k2');
    expect(g.verdict(before, 'k1')).toBe('stale');
    expect(g.verdict(before, 'k2')).toBe('stale');
    const after = await g.prepare(7);
    expect(g.verdict(after, 'k2')).toBe('ok');
  });

  test('the same key reported again changes nothing - no retirement, no stale answers', async () => {
    const { g } = guard(store());
    await g.prepare(7);
    g.noteCurrent(7, 'k1');
    const t = await g.prepare(7);
    g.noteCurrent(7, 'k1');
    expect(g.verdict(t, 'k1')).toBe('ok');
  });

  test('a key noted before the room was ever read is not lost', async () => {
    // A room made on this device reports its first key before anything asked
    // the island about it.
    const st = store();
    const { g } = guard(st);
    g.noteCurrent(7, 'k1');
    g.noteCurrent(7, 'k2');
    const t = await g.prepare(7);
    expect(g.verdict(t, 'k1')).toBe('retired');
    expect(await g.lastCurrent(7)).toBe('k2');
  });

  test('a stored history that was there is not overwritten by a key noted before it was read', async () => {
    const st = store();
    const first = guard(st).g;
    await first.prepare(7);
    first.noteCurrent(7, 'k1');
    first.noteCurrent(7, 'k2');
    await first.flushed();

    const second = guard(st).g;
    second.noteCurrent(7, 'k3');          // before any read of room 7
    const t = await second.prepare(7);
    expect(second.verdict(t, 'k1')).toBe('retired');
    expect(second.verdict(t, 'k2')).toBe('retired');
    expect(await second.lastCurrent(7)).toBe('k3');
  });

  test('ids are compared as the key manager writes them, whatever their case', async () => {
    const { g } = guard(store());
    await g.prepare(7);
    g.noteCurrent(7, 'ABCD');
    g.noteCurrent(7, 'ef01');
    expect(g.verdict(await g.prepare(7), 'abcd')).toBe('retired');
  });

  test('a long history keeps its newest retired keys', async () => {
    const { g } = guard(store());
    await g.prepare(7);
    const n = RKG.LIMITS.MAX_RETIRED + 5;
    for (let i = 0; i <= n; i++) g.noteCurrent(7, 'k' + i);
    const t = await g.prepare(7);
    expect(g.verdict(t, 'k' + (n - 1))).toBe('retired');
    expect(g.verdict(t, 'k' + (n - RKG.LIMITS.MAX_RETIRED))).toBe('retired');
    expect(g.verdict(t, 'k0')).toBe('ok');
  });
});

describe('what it does not track', () => {
  test('DM threads, unknown scopes and nonsense slots are left alone', async () => {
    const st = store();
    const { g, sc } = guard(st);
    for (const slot of ['dm:island-a:3', 0, -1, NaN, null]) {
      g.noteCurrent(slot, 'k1');
      g.noteCurrent(slot, 'k2');
      expect(g.verdict(await g.prepare(slot), 'k1')).toBe('ok');
    }
    sc.value = '';
    g.noteCurrent(9, 'k1');
    g.noteCurrent(9, 'k2');
    expect(g.verdict(await g.prepare(9), 'k1')).toBe('ok');
    await g.flushed();
    expect(st.data.size).toBe(0);
  });

  test('rooms on other islands are tracked under their own slot', async () => {
    const { g } = guard(store());
    expect(RKG.tracks('gr:island-b:4')).toBe(true);
    await g.prepare('gr:island-b:4');
    g.noteCurrent('gr:island-b:4', 'k1');
    g.noteCurrent('gr:island-b:4', 'k2');
    expect(g.verdict(await g.prepare('gr:island-b:4'), 'k1')).toBe('retired');
    expect(g.verdict(await g.prepare(4), 'k1')).toBe('ok');
  });

  test('storage that fails costs the protection, never the room', async () => {
    const g = RKG.createRoomKeyGuard({
      read: async () => { throw new Error('disk'); },
      write: async () => { throw new Error('disk'); },
      scope: () => 'island-a:alice',
    });
    const t = await g.prepare(7);
    expect(g.verdict(t, 'k1')).toBe('ok');
    g.noteCurrent(7, 'k1');
    g.noteCurrent(7, 'k2');
    await g.flushed();
    expect(g.verdict(await g.prepare(7), 'k1')).toBe('retired');
  });
});
