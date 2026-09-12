// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Per-sender hash chains, so that deleting or reordering stored messages stops
// being invisible.
//
// AES-GCM already makes silent modification impossible: altered bytes fail the
// tag. What it does not cover is the message's PLACE in the conversation.
// Nothing in the envelope binds a message to its position, and the timestamp a
// client displays comes from the server row, so whoever holds the database can
// drop a message or move a genuine one next to a different question, and both
// remain perfectly valid.
//
// The construction: every sender chains their OWN messages in a thread.
// Message n carries `seq` and `prev` = hash of message n-1's signed content,
// and both are inside the signature. Interleaving the two senders into one
// chain would need them to agree on an order, which is consensus; chaining
// each sender separately needs no coordination at all, and between the two
// chains every message in the conversation is covered.
//
// What the recipient can then tell apart:
//   * a GAP - seq jumped. May be innocent: messages arrive out of order and
//     history is fetched in pages. Worth holding, not worth accusing anyone.
//   * a BREAK - we hold message seq-1 and its hash is not what seq claims.
//     That is not a race. The stored history is inconsistent with what the
//     sender signed.
//
// The chain head (seq + hash) doubles as a digest of one party's half of the
// conversation, which is what makes two independently stored copies comparable
// in a single value.
//
// This file is duplicated byte-for-byte in two places:
//   chrome_extension/thread-chain.js
//   Android/src/services/thread-chain.js
// Keep them identical; the parity test enforces it. The hash is injected,
// because the two clients compute SHA-256 on different stacks.

// `root` is passed in rather than read from `self`/`globalThis` inside: the two
// clients lint under different environments, and a bare reference to either
// name is an error in one of them.
(function (root) {
  "use strict";

  // 32 zero bytes: the `prev` of the first message a sender puts in a thread.
  const GENESIS_HEX = "0000000000000000000000000000000000000000000000000000000000000000";

  const VERDICT_OK = "ok";
  const VERDICT_GAP = "gap";
  const VERDICT_BREAK = "break";
  const VERDICT_DUPLICATE = "duplicate";
  const VERDICT_UNCHAINED = "unchained";

  function isHex32(s) {
    return typeof s === "string" && /^[0-9a-f]{64}$/.test(s);
  }

  function toHex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return out;
  }

  /**
   * createThreadChain({ sha256 })
   *   sha256(Uint8Array) -> Promise<Uint8Array> | Uint8Array
   */
  function createThreadChain(deps) {
    const d = deps || {};
    const sha256 = d.sha256;
    if (!sha256) throw new Error("createThreadChain: sha256 is required");

    /**
     * The link a message contributes to its sender's chain.
     *
     * Hashing the SIGNED bytes, not the plaintext: that is what the sender
     * committed to, and it keeps the chain meaningful even for a message whose
     * body we cannot decrypt.
     */
    async function linkFor(signedBytes) {
      const h = await sha256(signedBytes);
      return toHex(h instanceof Uint8Array ? h : new Uint8Array(h));
    }

    /**
     * Where a sender's chain stands for one thread.
     * { seq, hash } - the last accepted message and its link.
     */
    function genesis() {
      return { seq: 0, hash: GENESIS_HEX };
    }

    /**
     * Decide what an incoming message means for a chain.
     *
     * @param {object} state   { seq, hash } or null for a fresh chain
     * @param {object} msg     { seq, prev, link } - link is linkFor(signedBytes)
     * @returns {{verdict, state, missing?}}
     */
    function accept(state, msg) {
      const cur = state && isHex32(state.hash) ? state : genesis();

      const seq = Number(msg && msg.seq);
      const prev = msg && msg.prev;
      const link = msg && msg.link;

      // A sender who has not adopted the chained format yet. Not an error, and
      // deliberately not silently treated as valid chaining either.
      if (!isFinite(seq) || seq < 1 || !isHex32(prev) || !isHex32(link)) {
        return { verdict: VERDICT_UNCHAINED, state: cur };
      }

      if (seq <= cur.seq) {
        // Already seen, or an older message replayed into a later position.
        return { verdict: VERDICT_DUPLICATE, state: cur };
      }

      if (seq === cur.seq + 1) {
        if (prev !== cur.hash) {
          // We hold seq-1 and it does not hash to what this message commits
          // to. Nothing innocent produces that.
          return { verdict: VERDICT_BREAK, state: cur };
        }
        return { verdict: VERDICT_OK, state: { seq: seq, hash: link } };
      }

      // seq jumped. Could be delivery order or a page we have not fetched -
      // or messages that are gone. The caller decides how loud to be.
      return { verdict: VERDICT_GAP, state: cur, missing: seq - cur.seq - 1 };
    }

    /**
     * Replay a whole run of a sender's messages, in the order given.
     * Returns the resulting state and everything noticed along the way.
     */
    function verifyRun(state, messages) {
      let cur = state || genesis();
      const problems = [];
      const list = Array.isArray(messages) ? messages : [];
      for (let i = 0; i < list.length; i++) {
        const r = accept(cur, list[i]);
        if (r.verdict !== VERDICT_OK) {
          problems.push({ index: i, seq: Number(list[i] && list[i].seq), verdict: r.verdict, missing: r.missing });
        }
        cur = r.state;
        if (r.verdict === VERDICT_OK) continue;
        // A gap is survivable: adopt the newer position so the rest of the run
        // can still be checked against itself.
        if (r.verdict === VERDICT_GAP && isHex32(list[i] && list[i].link)) {
          cur = { seq: Number(list[i].seq), hash: list[i].link };
        }
      }
      return { state: cur, problems: problems, ok: problems.length === 0 };
    }

    /**
     * Check a run of messages the user can actually see.
     *
     * verifyRun starts from a known head, which is right when the client has
     * been following a thread. It is wrong for a screenful: history is fetched
     * in pages, so the earliest visible message is nearly always preceded by
     * messages that simply have not been loaded, and starting from genesis
     * would report "500 missing" every time somebody opens a conversation.
     *
     * Here the first message's own claim about its predecessor is taken as the
     * starting point. That makes the first message valid by construction — it
     * is not evidence of anything — and every gap or break reported afterwards
     * is strictly BETWEEN two messages the user is looking at.
     */
    function verifyVisibleRun(messages) {
      const list = Array.isArray(messages) ? messages.slice() : [];
      if (!list.length) return { state: genesis(), problems: [], ok: true };

      list.sort(function (a, b) { return Number(a.seq) - Number(b.seq); });
      const first = list[0];
      if (!isHex32(first && first.prev) || !isFinite(Number(first && first.seq))) {
        return verifyRun(genesis(), list);
      }
      const start = { seq: Number(first.seq) - 1, hash: first.prev };
      return verifyRun(start, list);
    }

    /**
     * Everything wrong with a screenful of messages, ready to render.
     *
     * @param {Array} entries [{ id, sender, seq, prev, link }] in any order
     * @returns {Array} [{ id, sender, verdict, missing }] - `id` is the
     *          message the problem was noticed AT, so a marker goes before it.
     *
     * Grouped by sender, because the chains are per sender: two people writing
     * at once is not a gap in either of their runs. A message with no chain
     * fields is skipped rather than counted, so a thread part-way through the
     * rollout does not look damaged.
     */
    function problemsByRun(entries) {
      const bySender = {};
      const list = Array.isArray(entries) ? entries : [];
      for (let i = 0; i < list.length; i++) {
        const e = list[i];
        if (!e || !isFinite(Number(e.seq)) || !isHex32(e.prev)) continue;
        const who = String(e.sender == null ? "" : e.sender).toLowerCase();
        (bySender[who] = bySender[who] || []).push(e);
      }

      const out = [];
      const senders = Object.keys(bySender);
      for (let i = 0; i < senders.length; i++) {
        const run = bySender[senders[i]];
        const r = verifyVisibleRun(run);
        const sorted = run.slice().sort(function (a, b) { return Number(a.seq) - Number(b.seq); });
        for (let j = 0; j < r.problems.length; j++) {
          const p = r.problems[j];
          const at = sorted[p.index];
          out.push({
            id: at && at.id,
            sender: senders[i],
            seq: p.seq,
            verdict: p.verdict,
            missing: p.missing,
          });
        }
      }
      return out;
    }

    /**
     * One value summarising a sender's half of a thread, for comparing two
     * independently stored copies of the same conversation.
     */
    function digest(state) {
      const cur = state && isHex32(state.hash) ? state : genesis();
      return cur.seq + ":" + cur.hash;
    }

    /** Do two copies of the same half agree? */
    function digestsAgree(a, b) {
      return digest(a) === digest(b);
    }

    return {
      genesis: genesis,
      linkFor: linkFor,
      accept: accept,
      verifyRun: verifyRun,
      verifyVisibleRun: verifyVisibleRun,
      problemsByRun: problemsByRun,
      digest: digest,
      digestsAgree: digestsAgree,
    };
  }

  const API = {
    GENESIS_HEX: GENESIS_HEX,
    VERDICT_OK: VERDICT_OK,
    VERDICT_GAP: VERDICT_GAP,
    VERDICT_BREAK: VERDICT_BREAK,
    VERDICT_DUPLICATE: VERDICT_DUPLICATE,
    VERDICT_UNCHAINED: VERDICT_UNCHAINED,
    createThreadChain: createThreadChain,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSThreadChain = API;
})(this);
