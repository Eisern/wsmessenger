// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// A durable queue for messages that could not be sent.
//
// Until now a failed send showed an alert and put the text back in the input
// box. Close the app and the message was gone. That is a small annoyance when
// the only way to fail is your own server being down - you notice immediately,
// because nothing else works either. It stops being small as soon as a message
// can be addressed to somewhere other than your own island: your side is fine,
// you are online, and the delivery still fails.
//
// Two rules carry the design:
//
//   * The queue holds CIPHERTEXT, never plaintext. A message is encrypted
//     before it is enqueued, so a stolen queue is worth no more than a stolen
//     server row.
//
//   * The nonce is fixed when the item is enqueued; the timestamp and the HMAC
//     tag are recomputed on every attempt. The transport tag covers `ts` and
//     the island only accepts a +/-5 minute window, so a stored tag goes stale
//     within minutes - but the nonce is what makes a retry safe, because the
//     island de-duplicates on (thread_id, nonce) for seven days. Keeping the
//     nonce and refreshing the timestamp gives idempotency and freshness at
//     once, and it is why a 409 "replay" answer means the message already
//     arrived - a success, not an error.
//
// This file is duplicated byte-for-byte in two places:
//   chrome_extension/outbox.js
//   Android/src/services/outbox.js
// Keep them identical; the parity test enforces it. Storage, transport and the
// clock are injected, because the two clients provide them differently.

// `root` is passed in rather than read from `self`/`globalThis` inside: the two
// clients lint under different environments, and a bare reference to either
// name is an error in one of them.
(function (root) {
  "use strict";

  const MAX_ITEMS = 200;
  const MAX_ATTEMPTS = 12;
  // Beyond the island's nonce retention a retry is no longer idempotent: the
  // de-duplication row is gone, so a message that did arrive could be accepted
  // a second time. Give up well before that.
  const MAX_AGE_MS = 5 * 24 * 60 * 60 * 1000;
  const BACKOFF_MS = [2000, 5000, 15000, 60000, 300000, 900000];

  function backoffFor(attempts) {
    const i = Math.min(Math.max(attempts - 1, 0), BACKOFF_MS.length - 1);
    return BACKOFF_MS[i];
  }

  /**
   * What to do with one send outcome.
   *
   *   'sent'   - it is on the server; remove from the queue
   *   'retry'  - transport or transient; keep and back off
   *   'secret' - the delivery secret is stale; refresh it once, then retry
   *   'drop'   - permanently unacceptable; remove and tell the user
   */
  function classifySendOutcome(outcome) {
    if (!outcome) return "retry";
    if (outcome.ok) return "sent";

    const name = String(outcome.name || "");
    if (name === "TypeError" || name === "AbortError" || name === "TimeoutError") return "retry";

    const status = Number(outcome.status);
    if (!isFinite(status) || status === 0) return "retry";

    // The island already has this exact (thread_id, nonce). Our earlier attempt
    // did arrive and we lost the answer, not the message.
    if (status === 409) return "sent";

    // The delivery secret expired or was rotated. Worth exactly one refresh -
    // beyond that we are not a member of that thread any more.
    if (status === 401 || status === 403) return "secret";

    if (status === 429 || status >= 500) return "retry";

    // 400 and friends: the island will never accept this message.
    return "drop";
  }

  /**
   * createOutbox({ storage, now, log })
   *
   *   storage.load()        -> Promise<item[]>
   *   storage.save(items)   -> Promise<void>
   *   now()                 -> ms
   */
  function createOutbox(opts) {
    const o = opts || {};
    const storage = o.storage;
    const now = o.now || function () { return Date.now(); };
    const log = o.log || function () {};
    if (!storage || !storage.load || !storage.save) {
      throw new Error("createOutbox: storage.load and storage.save are required");
    }

    let items = null;      // lazily loaded
    let draining = false;
    let seq = 0;

    async function ensureLoaded() {
      if (items) return items;
      let loaded = [];
      try {
        loaded = await storage.load();
      } catch (e) {
        log("outbox load failed; starting empty", { error: e && e.message });
        loaded = [];
      }
      items = Array.isArray(loaded) ? loaded.filter(isStoredItem) : [];
      return items;
    }

    // What a caller must supply to enqueue anything.
    function isEnqueueable(m) {
      return !!m && typeof m === "object" && m.threadId != null &&
        typeof m.ciphertextB64 === "string" && m.ciphertextB64 &&
        typeof m.nonceB64 === "string" && m.nonceB64;
    }

    // What a row read back from storage must look like to be retried. Stricter
    // than the above: it also carries the id assigned at enqueue time.
    function isStoredItem(it) {
      return isEnqueueable(it) && !!it.id;
    }

    async function persist() {
      try {
        await storage.save(items);
      } catch (e) {
        log("outbox save failed", { error: e && e.message });
      }
    }

    /**
     * @param {object} msg {threadId, ciphertextB64, nonceB64, meta?}
     *   `meta` is for the UI only (a local id to mark as pending) and must not
     *   contain plaintext.
     */
    async function enqueue(msg) {
      await ensureLoaded();
      if (!isEnqueueable(msg)) throw new Error("outbox.enqueue: threadId, ciphertextB64 and nonceB64 are required");

      // Same nonce already queued: this is a double-enqueue of one message,
      // not a second message.
      for (let i = 0; i < items.length; i++) {
        if (items[i].nonceB64 === msg.nonceB64 && String(items[i].threadId) === String(msg.threadId)) {
          return items[i];
        }
      }

      const item = {
        id: msg.id || ("ob_" + now() + "_" + (++seq)),
        threadId: msg.threadId,
        ciphertextB64: msg.ciphertextB64,
        nonceB64: msg.nonceB64,
        meta: msg.meta || null,
        createdAt: now(),
        attempts: 0,
        nextAttemptAt: now(),
        lastError: null,
      };
      items.push(item);

      // Oldest first: a queue that has grown past this is not going to drain,
      // and unbounded growth on a phone is worse than losing the oldest item.
      if (items.length > MAX_ITEMS) items = items.slice(items.length - MAX_ITEMS);

      await persist();
      log("queued for retry", { threadId: item.threadId, queued: items.length });
      return item;
    }

    function due() {
      const t = now();
      return (items || []).filter(function (it) { return (it.nextAttemptAt || 0) <= t; });
    }

    /**
     * drain(send) - one pass over everything due.
     *
     *   send(item) -> {ok:true} | {status, name}
     * `send` recomputes ts and the HMAC tag from item.nonceB64; it must not
     * invent a new nonce, or a retry stops being idempotent.
     *
     * Single-flight: a second drain while one is running is a no-op, so a
     * reconnect storm does not send everything several times over.
     */
    async function drain(send) {
      // The flag is set BEFORE the first await on purpose. Setting it after
      // one would let every concurrent caller past the guard, which is exactly
      // the reconnect storm this is meant to absorb.
      if (draining) return { skipped: true };
      draining = true;
      const result = { sent: 0, retried: 0, dropped: 0 };
      try {
        await ensureLoaded();
        for (const item of due().slice()) {
          if (now() - item.createdAt > MAX_AGE_MS) {
            remove(item.id);
            result.dropped++;
            log("gave up: too old to retry idempotently", { threadId: item.threadId });
            continue;
          }

          let outcome;
          try {
            outcome = await send(item);
          } catch (e) {
            outcome = { status: Number(e && e.status), name: e && e.name };
          }

          let verdict = classifySendOutcome(outcome);
          if (verdict === "secret") {
            // One refresh, then it is a permanent failure for this thread.
            verdict = item.secretRefreshed ? "drop" : "retry";
            item.secretRefreshed = true;
          }

          if (verdict === "sent") {
            remove(item.id);
            result.sent++;
          } else if (verdict === "drop") {
            remove(item.id);
            result.dropped++;
            log("dropped permanently", { threadId: item.threadId, status: outcome && outcome.status });
          } else {
            item.attempts++;
            item.lastError = outcome && (outcome.status || outcome.name) || "unknown";
            if (item.attempts >= MAX_ATTEMPTS) {
              remove(item.id);
              result.dropped++;
              log("gave up after too many attempts", { threadId: item.threadId });
            } else {
              item.nextAttemptAt = now() + backoffFor(item.attempts);
              result.retried++;
            }
          }
        }
        await persist();
      } finally {
        draining = false;
      }
      return result;
    }

    function remove(id) {
      items = (items || []).filter(function (it) { return it.id !== id; });
    }

    return {
      enqueue: enqueue,
      drain: drain,
      async list() { await ensureLoaded(); return items.slice(); },
      async size() { await ensureLoaded(); return items.length; },
      async pendingFor(threadId) {
        await ensureLoaded();
        return items.filter(function (it) { return String(it.threadId) === String(threadId); });
      },
      async remove(id) { await ensureLoaded(); remove(id); await persist(); },
      async clear() { items = []; await persist(); },
      _state() { return { items: items, draining: draining }; },
    };
  }

  const API = {
    MAX_ITEMS: MAX_ITEMS,
    MAX_ATTEMPTS: MAX_ATTEMPTS,
    MAX_AGE_MS: MAX_AGE_MS,
    BACKOFF_MS: BACKOFF_MS,
    backoffFor: backoffFor,
    classifySendOutcome: classifySendOutcome,
    createOutbox: createOutbox,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSOutbox = API;
})(this);
