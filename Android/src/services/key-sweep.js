// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Room-key backfill: hand the room key to every accepted member who has none.
//
// A member who accepts an invitation while no owner or admin is watching that
// room used to stay keyless for good: delivery was a push nothing retried. The
// server now derives "accepted member with no key row" (GET
// /crypto/rooms/key-gaps) and gives the list to anyone entitled to serve it;
// every provider drains it whenever it is alive and unlocked.
//
// This is the part both clients must do identically - when to ask, how often,
// what a failure means, when to give up on a pair - so it lives here once,
// with the network, the crypto and the clock injected (as guest-room-feed.js).
// Each client supplies only how to fetch the list and how to share one key.
//
// It never prompts on its own: an automatic run with a locked client defers to
// the unlock trigger. Only an explicit `interactive` run may ask to unlock.

(function (root) {
  "use strict";

  const LIMITS = {
    MIN_INTERVAL_MS: 60 * 1000,        // between two runs, however often asked
    ERROR_BACKOFF_MS: 5 * 60 * 1000,   // after infrastructure trouble
    PAIR_COOLDOWN_MS: 10 * 60 * 1000,  // one room + member that failed
    TRUST_BLOCK_MS: 30 * 60 * 1000,    // a member whose key needs verifying
    MAX_PASSES: 5,                     // pages per run
    PAGE: 100,
    MAX_TRANSIENT: 3,                  // transient failures in a row end a pass
    PAIR_COOLDOWN_CAP: 500,
    RETRY_AFTER_DEFAULT_S: 120,
  };

  // A share refused for these needs a person to verify a safety number; asking
  // again changes nothing until they do.
  const TRUST_BLOCK = { TRUST_CHANGED: true, TRUST_UNVERIFIED: true };

  /**
   * @param {object} d
   * @param {function} d.isReady        async ({interactive}) => boolean - unlocked and signed in
   * @param {function} d.fetchGaps      async ({roomId, limit}) => {gaps:[{room_id, username}], truncated, notProvider?}
   *                                    throws on failure; a 429 carries {status: 429, retryAfterS}
   * @param {function} d.refreshRoomKey async (roomId) => void - the CURRENT key, from the island
   * @param {function} d.share          async (roomId, username) => {written} - fill the gap only
   *                                    (if_absent); trust refusals carry .code TRUST_*
   * @param {function} d.isTransient    (error) => boolean - infrastructure, worth the global backoff
   * @param {function} [d.onDone]       (summary, trustBlocked) => void, after every run that ran
   * @param {object}   [d.timers]       { setTimeout, clearTimeout }
   * @param {function} [d.now]
   * @param {function} [d.log]
   * @param {object}   [d.limits]       overrides for LIMITS (tests)
   */
  function createKeySweep(d) {
    const C = Object.assign({}, LIMITS, d.limits || {});
    // Looked up when called, not when created: the clock in force is the one
    // that counts (a test's, or the platform's).
    const T = d.timers || {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: (h) => clearTimeout(h),
    };
    const now = d.now || (() => Date.now());
    const log = d.log || (() => {});

    let running = false;
    let rerun = new Set();          // roomIds (0 = all) asked for while running
    let nextAllowed = 0;
    let timer = null;
    let pending = new Set();
    let wantAll = false;
    const pairCooldown = new Map(); // "rid:name" -> ts
    const blocked = new Map();      // name -> {ts, reason, rooms:Set}

    function pairKey(rid, name) {
      return String(rid) + ":" + String(name).toLowerCase();
    }

    function notePair(rid, name) {
      if (pairCooldown.size >= C.PAIR_COOLDOWN_CAP) {
        // Insertion order: the first key is the oldest.
        const oldest = pairCooldown.keys().next();
        if (!oldest.done) pairCooldown.delete(oldest.value);
      }
      pairCooldown.set(pairKey(rid, name), now());
    }

    function pairCooling(rid, name) {
      const ts = pairCooldown.get(pairKey(rid, name));
      return !!ts && now() - ts < C.PAIR_COOLDOWN_MS;
    }

    function isBlocked(name) {
      const key = String(name).toLowerCase();
      const e = blocked.get(key);
      if (!e) return false;
      if (now() - e.ts >= C.TRUST_BLOCK_MS) {
        blocked.delete(key);
        return false;
      }
      return true;
    }

    function block(name, reason, rid) {
      const key = String(name).toLowerCase();
      const e = blocked.get(key) || { ts: 0, reason: reason, rooms: new Set() };
      e.ts = now();
      e.reason = reason;
      e.rooms.add(rid);
      blocked.set(key, e);
    }

    /** Members a key cannot go to until somebody verifies their safety number. */
    function trustBlocked() {
      const out = [];
      for (const [name, e] of blocked.entries()) {
        if (now() - e.ts >= C.TRUST_BLOCK_MS) continue;
        out.push({ username: name, reason: e.reason, rooms: Array.from(e.rooms) });
      }
      return out;
    }

    /** Once they have been verified. */
    function clearTrustBlock(name) {
      blocked.delete(String(name || "").toLowerCase());
    }

    async function passes(roomId, reason, summary) {
      let anyFailure = false;
      let pass = 0;
      let more = true;

      while (more && pass < C.MAX_PASSES) {
        pass += 1;
        more = false;

        let page;
        try {
          page = await d.fetchGaps({ roomId: roomId, limit: C.PAGE });
        } catch (e) {
          anyFailure = true;
          summary.incomplete = true;
          if (e && e.status === 429) {
            const s = Number(e.retryAfterS) > 0 ? Number(e.retryAfterS) : C.RETRY_AFTER_DEFAULT_S;
            nextAllowed = Math.max(nextAllowed, now() + s * 1000);
          }
          log("gap fetch failed (" + reason + "):", e && e.message ? e.message : e);
          break;
        }
        // Not a provider here, or nothing missing: an answer, not a failure.
        if (!page || page.notProvider || !Array.isArray(page.gaps) || !page.gaps.length) break;

        const byRoom = new Map();
        for (const g of page.gaps) {
          const rid = Number(g && g.room_id);
          const name = String((g && g.username) || "").trim();
          if (!rid || !name) continue;
          if (!byRoom.has(rid)) byRoom.set(rid, []);
          byRoom.get(rid).push(name);
        }

        let transientRun = 0;
        let progressed = false;

        for (const [rid, names] of byRoom.entries()) {
          // The current key from the island first: a key held since before a
          // rotation would otherwise be handed out as current.
          try {
            await d.refreshRoomKey(rid);
          } catch (e) {
            log("room " + rid + ": key refresh failed:", e && e.message ? e.message : e);
          }

          for (const name of names) {
            if (isBlocked(name) || pairCooling(rid, name)) {
              summary.skipped += 1;
              continue;
            }
            try {
              const res = await d.share(rid, name);
              // written:false - another provider closed the gap first. The gap
              // is closed, which is all that was wanted.
              if (res && res.written === false) summary.alreadyHad += 1;
              else summary.shared += 1;
              progressed = true;
              transientRun = 0;
            } catch (e) {
              const code = (e && e.code) || "";
              if (TRUST_BLOCK[code]) {
                block(name, code, rid);
                summary.skipped += 1;
                log(name + " needs verification before the key goes to them");
                continue;
              }
              summary.failed += 1;
              notePair(rid, name);
              if (d.isTransient(e)) {
                // Only infrastructure trouble earns the global backoff. One
                // member with, say, an unusable public key is cooled down per
                // pair and must not throttle every other room.
                anyFailure = true;
                transientRun += 1;
                log("room " + rid + "/" + name + " transient failure:", e && e.message ? e.message : e);
                if (transientRun >= C.MAX_TRANSIENT) break;
              } else {
                log("room " + rid + "/" + name + " skipped:", e && e.message ? e.message : e);
              }
            }
          }
          if (transientRun >= C.MAX_TRANSIENT) break;
        }

        if (transientRun >= C.MAX_TRANSIENT) summary.incomplete = true;
        // Another page is only worth fetching if this one shrank the set.
        more = !!page.truncated && progressed && transientRun < C.MAX_TRANSIENT;
      }
      // Stopped at the page limit with more to do.
      if (more) summary.incomplete = true;
      return anyFailure;
    }

    /**
     * One run: every gap this account may close, or those of one room.
     * Resolves {ran, shared, alreadyHad, skipped, failed, incomplete}; ran=false
     * means it declined to start - already running, locked, or inside the
     * backoff. incomplete=true means it did not get through: the list could not
     * be fetched, the pass ended on failures in a row, or the page limit left
     * more - so all zeros do NOT mean "nobody is missing a key".
     */
    async function run(opts) {
      const o = opts || {};
      const roomId = Number(o.roomId) || 0;
      const reason = String(o.reason || "");
      const summary = { ran: false, shared: 0, alreadyHad: 0, skipped: 0, failed: 0, incomplete: false };

      // Claimed before the first await: two callers arriving together must
      // not both get past this line.
      if (running) {
        rerun.add(roomId);
        return summary;
      }
      running = true;
      let anyFailure = false;
      let deferred = false;
      try {
        let ready = false;
        try {
          ready = !!(await d.isReady({ interactive: !!o.interactive }));
        } catch (e) {
          log("readiness check failed:", e && e.message ? e.message : e);
        }
        if (ready && now() >= nextAllowed) {
          summary.ran = true;
          anyFailure = await passes(roomId, reason, summary);
        } else if (ready) {
          // Inside the interval: not now, but not never. Dropped here, the
          // trigger leaves a member without the key until something else
          // happens to ask - the first person a new room's owner invites
          // accepts within a minute of the sweep that creating it started.
          deferred = true;
        }
      } finally {
        running = false;
        if (summary.ran) {
          nextAllowed = Math.max(nextAllowed, now() + (anyFailure ? C.ERROR_BACKOFF_MS : C.MIN_INTERVAL_MS));
        }
        // Locked is not deferred: unlocking is a trigger of its own.
        if (deferred) schedule(reason || "deferred", { roomId: roomId, delayMs: Math.max(0, nextAllowed - now()) });
        // Triggers that arrived meanwhile are not dropped; the clock above
        // still decides when they actually run.
        if (rerun.size) {
          const again = Array.from(rerun);
          rerun = new Set();
          for (const r of again) schedule("rerun", { roomId: r, delayMs: C.MIN_INTERVAL_MS });
        }
      }

      if (summary.ran) {
        if (summary.shared || summary.alreadyHad || summary.skipped || summary.failed) {
          log((reason || "sweep") + " done:", summary);
        }
        try {
          if (d.onDone) d.onDone(summary, trustBlocked());
        } catch (e) {
          log("onDone failed:", e && e.message ? e.message : e);
        }
      }
      return summary;
    }

    /**
     * The entry point for every automatic trigger: one timer, so a burst of
     * triggers is one run, and the run's own clock still applies.
     */
    function schedule(reason, opts) {
      const o = opts || {};
      const rid = Number(o.roomId) || 0;
      if (rid) pending.add(rid);
      else wantAll = true;
      if (timer) return;

      timer = T.setTimeout(() => {
        timer = null;
        const rooms = Array.from(pending);
        const all = wantAll;
        pending = new Set();
        wantAll = false;
        // A request for everything supersedes the per-room ones queued behind
        // it, and two rooms are cheaper as one unfiltered query than as two.
        const only = (!all && rooms.length === 1) ? rooms[0] : 0;
        run({ roomId: only, reason: String(reason || "") }).catch((e) => {
          log("sweep threw:", e && e.message ? e.message : e);
        });
      }, Math.max(0, Number(o.delayMs) || 0));
    }

    /** Forget everything - signing out, or the key being put away. */
    function reset() {
      if (timer) T.clearTimeout(timer);
      timer = null;
      pending = new Set();
      wantAll = false;
      rerun = new Set();
      nextAllowed = 0;
      pairCooldown.clear();
      blocked.clear();
    }

    return {
      run: run,
      schedule: schedule,
      reset: reset,
      trustBlocked: trustBlocked,
      clearTrustBlock: clearTrustBlock,
      get running() { return running; },
      get nextAllowedAt() { return nextAllowed; },
    };
  }

  const API = { LIMITS: LIMITS, createKeySweep: createKeySweep };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSKeySweep = API;
})(this);
