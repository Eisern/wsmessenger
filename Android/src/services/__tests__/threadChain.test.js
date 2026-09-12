// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

const nodeCrypto = require('crypto');
const TC = require('../thread-chain');

// Real SHA-256, not a stub: a chain verified against a fake hash proves nothing.
const chain = TC.createThreadChain({
  sha256: (bytes) => new Uint8Array(nodeCrypto.createHash('sha256').update(Buffer.from(bytes)).digest()),
});

const enc = (s) => new TextEncoder().encode(s);

/** Build a well-formed run of one sender's messages. */
async function buildRun(bodies, from = TC.GENESIS_HEX) {
  const out = [];
  let prev = from;
  let seq = 0;
  for (const body of bodies) {
    seq += 1;
    const signed = enc(`${seq}|${prev}|${body}`);
    const link = await chain.linkFor(signed);
    out.push({ seq, prev, link, body });
    prev = link;
  }
  return out;
}

describe('a clean chain', () => {
  it('accepts messages in order and moves the head forward', async () => {
    const run = await buildRun(['one', 'two', 'three']);
    const r = chain.verifyRun(chain.genesis(), run);
    expect(r.ok).toBe(true);
    expect(r.state.seq).toBe(3);
    expect(r.state.hash).toBe(run[2].link);
  });

  it('starts from genesis for a sender never seen before', () => {
    expect(chain.genesis()).toEqual({ seq: 0, hash: TC.GENESIS_HEX });
  });
});

describe('what tampering looks like', () => {
  it('notices a deleted message as a gap, with how many are missing', async () => {
    const run = await buildRun(['one', 'two', 'three', 'four']);
    const withHole = [run[0], run[2], run[3]];       // message 2 removed from storage

    const r = chain.verifyRun(chain.genesis(), withHole);
    expect(r.ok).toBe(false);
    expect(r.problems[0].verdict).toBe(TC.VERDICT_GAP);
    expect(r.problems[0].seq).toBe(3);
    expect(r.problems[0].missing).toBe(1);
  });

  it('notices a reordering as a break, not merely a gap', async () => {
    // Swapping two adjacent messages leaves the sequence numbers intact but
    // makes `prev` disagree with the message we actually hold at seq-1.
    const run = await buildRun(['one', 'two', 'three']);
    const swapped = [run[0], run[2], run[1]];

    const r = chain.verifyRun(chain.genesis(), swapped);
    expect(r.ok).toBe(false);
    expect(r.problems.some((p) => p.verdict === TC.VERDICT_BREAK
      || p.verdict === TC.VERDICT_DUPLICATE)).toBe(true);
  });

  it('notices a substituted message even when its own signature is valid', async () => {
    // The strongest case: an operator replaces message 2 with a genuine,
    // properly signed message the sender wrote elsewhere. Its own bytes check
    // out; its link does not match what message 3 committed to.
    const run = await buildRun(['one', 'two', 'three']);
    const [elsewhere] = await buildRun(['a message from another thread'], run[0].link);
    const doctored = [run[0], { ...elsewhere, seq: 2 }, run[2]];

    const r = chain.verifyRun(chain.genesis(), doctored);
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => p.verdict)).toContain(TC.VERDICT_BREAK);
  });

  it('notices an old message replayed into a later position', async () => {
    const run = await buildRun(['one', 'two', 'three']);
    const r1 = chain.verifyRun(chain.genesis(), run);
    const r2 = chain.accept(r1.state, run[0]);        // message 1 served again
    expect(r2.verdict).toBe(TC.VERDICT_DUPLICATE);
    expect(r2.state.seq).toBe(3);                     // and the head does not rewind
  });
});

describe('what is not tampering', () => {
  it('reports a sender who has not adopted the chain, without calling it broken', () => {
    const r = chain.accept(chain.genesis(), { seq: undefined, prev: undefined, link: undefined });
    expect(r.verdict).toBe(TC.VERDICT_UNCHAINED);
    expect(r.state.seq).toBe(0);
  });

  it('treats a jump as a gap rather than an accusation', async () => {
    // Pages of history arrive newest-first and live messages overtake fetches.
    // A gap must stay survivable, or the client cries wolf on every slow load.
    const run = await buildRun(['one', 'two', 'three']);
    const r = chain.accept(chain.genesis(), run[2]);
    expect(r.verdict).toBe(TC.VERDICT_GAP);
    expect(r.missing).toBe(2);
  });

  it('keeps checking the rest of a run after a gap', async () => {
    const run = await buildRun(['one', 'two', 'three', 'four', 'five']);
    const r = chain.verifyRun(chain.genesis(), [run[0], run[2], run[3], run[4]]);
    // One gap at message 3, and nothing wrong afterwards.
    expect(r.problems).toHaveLength(1);
    expect(r.problems[0].verdict).toBe(TC.VERDICT_GAP);
    expect(r.state.seq).toBe(5);
  });
});

describe('comparing two stored copies', () => {
  it('agrees when both copies hold the same half of the conversation', async () => {
    const run = await buildRun(['one', 'two', 'three']);
    const onIslandA = chain.verifyRun(chain.genesis(), run).state;
    const onIslandB = chain.verifyRun(chain.genesis(), run).state;
    expect(chain.digestsAgree(onIslandA, onIslandB)).toBe(true);
  });

  it('disagrees when one copy is missing a message', async () => {
    // This is what the second database buys: the same conversation exists
    // twice, under two operators, so one of them dropping a row shows up as a
    // single value that no longer matches.
    const run = await buildRun(['one', 'two', 'three']);
    const intact = chain.verifyRun(chain.genesis(), run).state;
    const truncated = chain.verifyRun(chain.genesis(), run.slice(0, 2)).state;

    expect(chain.digestsAgree(intact, truncated)).toBe(false);
    expect(chain.digest(intact)).toMatch(/^3:[0-9a-f]{64}$/);
    expect(chain.digest(truncated)).toMatch(/^2:[0-9a-f]{64}$/);
  });

  it('disagrees when one copy has a substituted message at the same height', async () => {
    const run = await buildRun(['one', 'two', 'three']);
    const other = await buildRun(['one', 'TWO', 'three']);
    const a = chain.verifyRun(chain.genesis(), run).state;
    const b = chain.verifyRun(chain.genesis(), other).state;
    // Same length, different content: the heights match and the hashes do not.
    expect(a.seq).toBe(b.seq);
    expect(chain.digestsAgree(a, b)).toBe(false);
  });
});

describe('what the user is actually looking at', () => {
  // History is fetched in pages. Starting a screenful from genesis would say
  // "500 messages missing" every time somebody opens a long conversation, and
  // a warning that fires on every normal load is a warning nobody reads.
  it('does not call a partial page a gap', async () => {
    const run = await buildRun(['1', '2', '3', '4', '5', '6']);
    const lastPage = run.slice(3);            // the user scrolled in partway

    expect(chain.verifyRun(chain.genesis(), lastPage).ok).toBe(false);   // naive
    expect(chain.verifyVisibleRun(lastPage).ok).toBe(true);              // honest
  });

  it('still reports a hole between two messages on screen', async () => {
    const run = await buildRun(['1', '2', '3', '4', '5']);
    const withHole = [run[1], run[3], run[4]];   // 3 is gone from the middle

    const r = chain.verifyVisibleRun(withHole);
    expect(r.ok).toBe(false);
    expect(r.problems[0].verdict).toBe(TC.VERDICT_GAP);
    expect(r.problems[0].missing).toBe(1);
  });

  it('still reports a break between two messages on screen', async () => {
    const run = await buildRun(['1', '2', '3']);
    const [elsewhere] = await buildRun(['from another thread'], run[0].link);
    const doctored = [run[0], { ...elsewhere, seq: 2 }, run[2]];

    const r = chain.verifyVisibleRun(doctored);
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => p.verdict)).toContain(TC.VERDICT_BREAK);
  });

  it('sorts before checking, so delivery order does not matter', async () => {
    const run = await buildRun(['1', '2', '3']);
    expect(chain.verifyVisibleRun([run[2], run[0], run[1]]).ok).toBe(true);
  });

  it('says nothing about an empty screen', () => {
    expect(chain.verifyVisibleRun([]).ok).toBe(true);
    expect(chain.verifyVisibleRun(null).ok).toBe(true);
  });
});

describe('turning a screenful into things to show', () => {
  async function entriesFor(sender, bodies, startFrom = TC.GENESIS_HEX) {
    const run = await buildRun(bodies, startFrom);
    return run.map((m, i) => ({ id: `${sender}-${i + 1}`, sender, seq: m.seq, prev: m.prev, link: m.link }));
  }

  it('says nothing about an intact conversation', async () => {
    const mine = await entriesFor('alice', ['a', 'b', 'c']);
    const theirs = await entriesFor('bob', ['x', 'y']);
    expect(chain.problemsByRun([...mine, ...theirs])).toEqual([]);
  });

  it('does not mistake two people writing at once for a gap', async () => {
    // The chains are per sender, so interleaving is normal conversation and
    // must never be reported. Getting this wrong would make the warning fire
    // constantly and therefore mean nothing.
    const mine = await entriesFor('alice', ['a', 'b', 'c']);
    const theirs = await entriesFor('bob', ['x', 'y', 'z']);
    const interleaved = [mine[0], theirs[0], mine[1], theirs[1], theirs[2], mine[2]];
    expect(chain.problemsByRun(interleaved)).toEqual([]);
  });

  it('points at the message the hole is in front of', async () => {
    const mine = await entriesFor('alice', ['a', 'b', 'c', 'd']);
    const withHole = [mine[0], mine[2], mine[3]];   // "b" removed

    const problems = chain.problemsByRun(withHole);
    expect(problems).toHaveLength(1);
    expect(problems[0].verdict).toBe(TC.VERDICT_GAP);
    expect(problems[0].missing).toBe(1);
    expect(problems[0].id).toBe('alice-3');          // the marker goes before "c"
    expect(problems[0].sender).toBe('alice');
  });

  it('reports only the sender whose run was touched', async () => {
    const mine = await entriesFor('alice', ['a', 'b', 'c']);
    const theirs = await entriesFor('bob', ['x', 'y', 'z']);
    const problems = chain.problemsByRun([mine[0], mine[2], ...theirs]);
    expect(problems.map((p) => p.sender)).toEqual(['alice']);
  });

  it('ignores messages that carry no chain, so a part-rolled-out thread looks fine', async () => {
    const mine = await entriesFor('alice', ['a', 'b']);
    const legacy = [{ id: 'old-1', sender: 'alice' }, { id: 'old-2', sender: 'alice', seq: 'x' }];
    expect(chain.problemsByRun([...legacy, ...mine])).toEqual([]);
  });
});
