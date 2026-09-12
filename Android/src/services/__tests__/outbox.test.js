// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

const OB = require('../outbox');

function memoryStorage(initial) {
  let saved = initial ? JSON.parse(JSON.stringify(initial)) : [];
  return {
    load: async () => JSON.parse(JSON.stringify(saved)),
    save: async (items) => { saved = JSON.parse(JSON.stringify(items)); },
    peek: () => saved,
  };
}

let t;
const now = () => t;

function makeOutbox(storage = memoryStorage()) {
  return { outbox: OB.createOutbox({ storage, now }), storage };
}

const MSG = { threadId: 7, ciphertextB64: 'Y2lwaGVy', nonceB64: 'bm9uY2U=' };

beforeEach(() => { t = 1_700_000_000_000; });

describe('classifySendOutcome', () => {
  const cases = [
    ['delivered', { ok: true }, 'sent'],
    // The island already holds this (thread_id, nonce): our earlier attempt
    // arrived and we lost the answer, not the message.
    ['409 replay means it already arrived', { status: 409 }, 'sent'],
    ['network failure', { status: 0 }, 'retry'],
    ['fetch TypeError', { name: 'TypeError' }, 'retry'],
    ['timeout', { name: 'AbortError' }, 'retry'],
    ['rate limited', { status: 429 }, 'retry'],
    ['server error', { status: 503 }, 'retry'],
    ['stale delivery secret', { status: 403 }, 'secret'],
    ['unauthorized', { status: 401 }, 'secret'],
    ['malformed, never acceptable', { status: 400 }, 'drop'],
  ];
  it.each(cases)('%s', (_label, outcome, expected) => {
    expect(OB.classifySendOutcome(outcome)).toBe(expected);
  });
});

describe('queueing', () => {
  it('persists across a restart, holding ciphertext only', async () => {
    const { outbox, storage } = makeOutbox();
    await outbox.enqueue(MSG);

    const raw = JSON.stringify(storage.peek());
    expect(raw).toContain('Y2lwaGVy');
    expect(raw).not.toContain('plaintext');

    // A fresh instance over the same storage is what a restart looks like.
    const reopened = OB.createOutbox({ storage, now });
    expect(await reopened.size()).toBe(1);
    expect((await reopened.list())[0].threadId).toBe(7);
  });

  it('does not queue the same message twice', async () => {
    const { outbox } = makeOutbox();
    const a = await outbox.enqueue(MSG);
    const b = await outbox.enqueue(MSG);
    expect(b.id).toBe(a.id);
    expect(await outbox.size()).toBe(1);
  });

  it('refuses an item without the fields a retry needs', async () => {
    const { outbox } = makeOutbox();
    await expect(outbox.enqueue({ threadId: 1 })).rejects.toThrow();
  });

  it('bounds the queue rather than growing without limit', async () => {
    const { outbox } = makeOutbox();
    for (let i = 0; i < OB.MAX_ITEMS + 25; i++) {
      await outbox.enqueue({ ...MSG, nonceB64: `n${i}` });
    }
    expect(await outbox.size()).toBe(OB.MAX_ITEMS);
    // The oldest go first: a queue this long is not draining anyway.
    expect((await outbox.list())[0].nonceB64).toBe('n25');
  });
});

describe('draining', () => {
  it('removes what was delivered and keeps what failed', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue({ ...MSG, nonceB64: 'a' });
    await outbox.enqueue({ ...MSG, nonceB64: 'b' });

    const r = await outbox.drain(async (item) =>
      (item.nonceB64 === 'a' ? { ok: true } : { status: 0 }));

    expect(r.sent).toBe(1);
    expect(r.retried).toBe(1);
    expect(await outbox.size()).toBe(1);
    expect((await outbox.list())[0].nonceB64).toBe('b');
  });

  it('hands the retry the SAME nonce, so the island can still de-duplicate', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);

    const seen = [];
    await outbox.drain(async (item) => { seen.push(item.nonceB64); return { status: 0 }; });
    t += 60_000;
    await outbox.drain(async (item) => { seen.push(item.nonceB64); return { ok: true }; });

    expect(seen).toEqual(['bm9uY2U=', 'bm9uY2U=']);
  });

  it('treats a 409 on a retry as success, because the message did arrive', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);
    await outbox.drain(async () => ({ status: 0 }));
    t += 60_000;

    const r = await outbox.drain(async () => ({ status: 409 }));
    expect(r.sent).toBe(1);
    expect(await outbox.size()).toBe(0);
  });

  it('backs off instead of hammering', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);

    await outbox.drain(async () => ({ status: 0 }));
    const first = (await outbox.list())[0];
    expect(first.attempts).toBe(1);
    expect(first.nextAttemptAt).toBe(t + OB.BACKOFF_MS[0]);

    // Not due yet: a drain right now must not touch it.
    let calls = 0;
    await outbox.drain(async () => { calls++; return { ok: true }; });
    expect(calls).toBe(0);

    t += OB.BACKOFF_MS[0];
    await outbox.drain(async () => { calls++; return { ok: true }; });
    expect(calls).toBe(1);
  });

  it('gives the delivery secret exactly one refresh before giving up', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);

    await outbox.drain(async () => ({ status: 403 }));
    expect(await outbox.size()).toBe(1);          // first 403: worth a refresh

    t += 60_000;
    const r = await outbox.drain(async () => ({ status: 403 }));
    expect(r.dropped).toBe(1);                    // second: we are not a member
    expect(await outbox.size()).toBe(0);
  });

  it('drops a message the island will never accept', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);
    const r = await outbox.drain(async () => ({ status: 400 }));
    expect(r.dropped).toBe(1);
    expect(await outbox.size()).toBe(0);
  });

  it('gives up once a retry would no longer be idempotent', async () => {
    // Past the island's nonce retention the de-duplication row is gone, so a
    // retry could be accepted a second time. Better to lose the message than
    // to deliver it twice.
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);
    t += OB.MAX_AGE_MS + 1000;

    let calls = 0;
    const r = await outbox.drain(async () => { calls++; return { ok: true }; });
    expect(calls).toBe(0);
    expect(r.dropped).toBe(1);
  });

  it('gives up after too many attempts', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);
    for (let i = 0; i < OB.MAX_ATTEMPTS + 2; i++) {
      t += 20 * 60 * 1000;
      await outbox.drain(async () => ({ status: 0 }));
    }
    expect(await outbox.size()).toBe(0);
  });

  it('is single-flight, so a reconnect storm sends nothing twice', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);

    let inFlight = 0;
    let maxInFlight = 0;
    let calls = 0;
    const slowSend = async () => {
      inFlight++; calls++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return { ok: true };
    };

    const results = await Promise.all([
      outbox.drain(slowSend), outbox.drain(slowSend), outbox.drain(slowSend),
    ]);

    expect(calls).toBe(1);
    expect(maxInFlight).toBe(1);
    expect(results.filter((r) => r.skipped)).toHaveLength(2);
  });

  it('survives a send that throws instead of returning a status', async () => {
    const { outbox } = makeOutbox();
    await outbox.enqueue(MSG);
    const r = await outbox.drain(async () => { throw Object.assign(new Error('boom'), { status: 0 }); });
    expect(r.retried).toBe(1);
    expect(await outbox.size()).toBe(1);
  });

  it('starts empty rather than throwing when stored data is unreadable', async () => {
    const broken = { load: async () => { throw new Error('corrupt'); }, save: async () => {} };
    const outbox = OB.createOutbox({ storage: broken, now });
    expect(await outbox.size()).toBe(0);
    await outbox.enqueue(MSG);
    expect(await outbox.size()).toBe(1);
  });
});
