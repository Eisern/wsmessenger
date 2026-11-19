// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// A room's key only moves forward on this device.
//
// The island hands out a room's current key as a wrap the owner signed, and a
// signature proves who made the wrap and for which room, member and key id -
// not that the key is still the room's. An island that kept an old wrap could
// hand it back after the key was changed, and a client that took whatever it
// was given as current would go back to writing under a key that somebody
// removed from the room still holds.
//
// So each device remembers, per room, which key was current here last and
// which keys were current here once and then replaced. A replaced ("retired")
// key is never taken from the island as current again; the room stays on the
// last key it had. A key this device never had as current is new to it and is
// taken: a rotation always makes a fresh key, so the only way back is a
// retired one.
//
// It learns from the key manager, not from its callers: every key that
// becomes current, by any path, is reported (`noteCurrent`), so a path that
// forgets to say so cannot leave the way back open. The check and the switch
// happen in one synchronous step inside the key manager (`verdict`), and an
// island answer requested before some other key became current here is stale
// and never applied - otherwise a slow answer from before a rotation would
// land after it, go back, and retire the new key.
//
// Not covered: a device with no history of the room (new, or recovered) has
// nothing to compare with and takes what the island says.
//
// Platform-free like key-sweep.js: storage and the scope (island + account)
// are injected.

(function (root) {
  "use strict";

  const LIMITS = {
    MAX_RETIRED: 64,   // per room; the oldest go first
  };

  const PREFIX = "__rkguard_v1:";

  /** Rooms (numbers) and rooms on other islands ("gr:..."); not DM threads. */
  function tracks(slot) {
    if (typeof slot === "number") return Number.isFinite(slot) && slot > 0;
    return typeof slot === "string" && slot.indexOf("gr:") === 0;
  }

  function cleanKid(kid) {
    return typeof kid === "string" ? kid.trim().toLowerCase() : "";
  }

  /**
   * @param {object} d
   * @param {function} d.read   async (name) => object|null|undefined
   * @param {function} d.write  async (name, object) => void
   * @param {function} d.scope  () => string - "<island>:<account>", "" when unknown
   * @param {function} [d.log]
   */
  function createRoomKeyGuard(d) {
    const log = typeof d.log === "function" ? d.log : function () {};
    const state = new Map();     // name -> {cur, retired: string[], gen}
    const loading = new Map();   // name -> promise of the first read
    const early = new Map();     // name -> kids noted before the first read finished
    let writes = Promise.resolve();

    function nameOf(slot) {
      const scope = String(d.scope() || "");
      if (!scope || !tracks(slot)) return "";
      return PREFIX + scope + ":" + String(slot);
    }

    function apply(name, st, kid) {
      if (st.cur === kid) return false;
      const retired = st.retired.filter(function (x) { return x !== kid; });
      if (st.cur && retired.indexOf(st.cur) === -1) retired.push(st.cur);
      while (retired.length > LIMITS.MAX_RETIRED) retired.shift();
      st.cur = kid;
      st.retired = retired;
      st.gen += 1;
      const snapshot = { v: 1, cur: st.cur, retired: st.retired.slice() };
      writes = writes.then(function () { return d.write(name, snapshot); }).catch(function (e) {
        log("write failed:", e && e.message ? e.message : e);
      });
      return true;
    }

    function load(name) {
      if (state.has(name)) return Promise.resolve(state.get(name));
      if (loading.has(name)) return loading.get(name);
      const p = Promise.resolve()
        .then(function () { return d.read(name); })
        .catch(function (e) {
          log("read failed:", e && e.message ? e.message : e);
          return null;
        })
        .then(function (stored) {
          const st = {
            cur: cleanKid(stored && stored.cur),
            retired: Array.isArray(stored && stored.retired)
              ? stored.retired.map(cleanKid).filter(Boolean) : [],
            gen: 0,
          };
          state.set(name, st);
          loading.delete(name);
          for (const kid of early.get(name) || []) apply(name, st, kid);
          early.delete(name);
          return st;
        });
      loading.set(name, p);
      return p;
    }

    /**
     * Read the room's state before asking the island, and take a token: the
     * answer is applied only if no other key became current in between.
     * Resolves a token for `verdict`.
     */
    async function prepare(slot) {
      const name = nameOf(slot);
      if (!name) return { name: "", gen: 0 };
      const st = await load(name);
      return { name: name, gen: st.gen };
    }

    /**
     * Synchronous: may the island's `kid` become this room's current key now?
     * "ok", "stale" (another key became current since `token` was taken) or
     * "retired" (this device moved on from it). Untracked rooms are "ok".
     */
    function verdict(token, kid) {
      if (!token || !token.name) return "ok";
      const st = state.get(token.name);
      if (!st) return "ok";
      const k = cleanKid(kid);
      if (st.gen !== token.gen) return "stale";
      if (k && k !== st.cur && st.retired.indexOf(k) !== -1) return "retired";
      return "ok";
    }

    /**
     * `kid` is now the room's current key on this device; the key it replaces
     * is retired. Synchronous once the room's state has been read (prepare);
     * before that it is applied as soon as the read finishes.
     */
    function noteCurrent(slot, kid) {
      const name = nameOf(slot);
      const k = cleanKid(kid);
      if (!name || !k) return;
      const st = state.get(name);
      if (st) {
        apply(name, st, k);
        return;
      }
      if (!early.has(name)) early.set(name, []);
      early.get(name).push(k);
      load(name);
    }

    /** The key id that was current here last, "" when none is known. */
    async function lastCurrent(slot) {
      const name = nameOf(slot);
      if (!name) return "";
      return (await load(name)).cur;
    }

    /** Everything noted so far is on its way to storage. */
    function flushed() {
      return writes;
    }

    /** Forget what was read (lock, logout, another island); storage stays. */
    function clear() {
      state.clear();
      loading.clear();
      early.clear();
    }

    return {
      tracks: tracks,
      prepare: prepare,
      verdict: verdict,
      noteCurrent: noteCurrent,
      lastCurrent: lastCurrent,
      flushed: flushed,
      clear: clear,
    };
  }

  const API = { LIMITS: LIMITS, PREFIX: PREFIX, tracks: tracks, createRoomKeyGuard: createRoomKeyGuard };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSRoomKeyGuard = API;
})(this);
