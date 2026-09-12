// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Entry-point selection for one island.
//
// An "island" is one backend with one database. It may be reachable through
// several entry points (its own domains today, volunteer TCP-passthrough
// bridges later). Rotating between entry points of the SAME island must never
// clear session state: the token, the delivery secrets and the room keys are
// all still valid, because it is the same server. Changing island is the
// opposite — everything goes. See docs/internal/federation-assessment.md §4.4.
//
// This file is duplicated byte-for-byte in two places:
//   chrome_extension/endpoints.js
//   Android/src/services/endpoints.js
// Keep them identical; endpoints-parity.test.js enforces it. That is why the
// module takes no platform imports at all — no chrome.*, no fetch, no RN, no
// ambient timers. The probe and the clock are injected by the caller.

// `root` is passed in rather than read from `self`/`globalThis` inside: the two
// clients lint under different environments, and a bare reference to either
// name is an error in one of them.
(function (root) {
  "use strict";

  let MAX_ENDPOINTS = 8;
  let STRIKE_THRESHOLD = 2;          // consecutive strikes before rotating
  let ROTATE_COOLDOWN_MS = 10000;    // floor between two rotations
  let SHORT_LIVED_MS = 5000;         // socket lifetime below which a close is suspicious
  let COME_HOME_INTERVAL_MS = 30 * 60 * 1000;
  let EXHAUST_BACKOFF_MS = [5000, 10000, 20000, 60000];

  // Codes that prove the server spoke to us: it is alive, the entry point is
  // fine, and the problem is the request. 1008 covers a wrong room password.
  let WS_POLICY_CODES = [1008, 1009, 1013];
  let WS_NORMAL_CODES = [1000, 1001];

  // ---------------------------------------------------------------- helpers

  function stripSlash(s) {
    return String(s == null ? "" : s).trim().replace(/\/+$/, "");
  }

  function parseUrl(s) {
    try {
      return new URL(String(s));
    } catch {
      return null;
    }
  }

  // Origin only — path, query and fragment are dropped. Same rule the login
  // pages already apply before saving a server address.
  function normalizeApiBase(s) {
    let u = parseUrl(stripSlash(s));
    if (!u) return "";
    if (u.protocol !== "https:" && u.protocol !== "http:") return "";
    return u.origin;
  }

  function deriveWsBase(apiBase) {
    let api = stripSlash(apiBase);
    if (!api) return "";
    return api.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
  }

  function normalizeWsBase(s, apiBase) {
    let u = parseUrl(stripSlash(s));
    if (u && (u.protocol === "wss:" || u.protocol === "ws:")) return u.origin;
    return deriveWsBase(apiBase);
  }

  function hostOf(apiBase) {
    let u = parseUrl(apiBase);
    return u ? u.host : String(apiBase || "");
  }

  function indexOfCode(list, code) {
    for (let i = 0; i < list.length; i++) if (list[i] === code) return i;
    return -1;
  }

  // ------------------------------------------------------------ config shape

  // Schema 2:
  //   { schema, islandId, endpoints:[{apiBase, wsBase, label}], activeIdx,
  //     apiBase, wsBase }
  //
  // The top-level apiBase/wsBase are a DENORMALIZED MIRROR of
  // endpoints[activeIdx]. They exist so that every pre-existing reader — which
  // knows only `cfg.apiBase` — keeps working and transparently reads the
  // currently active entry point. Never let them drift from activeIdx: always
  // build the config through this function.
  function normalizeServerConfig(raw, defaults) {
    let defApi = normalizeApiBase(defaults && defaults.defaultApiBase);
    let defWs = normalizeWsBase(defaults && defaults.defaultWsBase, defApi);

    let list = [];
    let activeIdx = 0;

    if (raw && typeof raw === "object") {
      if (Number(raw.schema) === 2 && Array.isArray(raw.endpoints)) {
        list = raw.endpoints;
        activeIdx = Number(raw.activeIdx);
      } else if (raw.apiBase) {
        // Legacy {apiBase, wsBase} — upgrade in place to a single-entry island.
        list = [{ apiBase: raw.apiBase, wsBase: raw.wsBase, label: "primary" }];
        activeIdx = 0;
      }
    }

    let clean = [];
    let seen = {};
    for (let i = 0; i < list.length && clean.length < MAX_ENDPOINTS; i++) {
      let e = list[i];
      if (!e || typeof e !== "object") continue;
      let api = normalizeApiBase(e.apiBase);
      if (!api) continue;
      if (seen[api]) continue;
      seen[api] = true;
      clean.push({
        apiBase: api,
        wsBase: normalizeWsBase(e.wsBase, api),
        label: String(e.label == null ? "" : e.label).slice(0, 40)
      });
    }

    if (!clean.length) {
      if (!defApi) {
        // No usable input and no default: an empty island. Callers must cope
        // (the UI asks for a server); returning a half-built object would be
        // worse than an explicit empty list.
        return { schema: 2, islandId: "", endpoints: [], activeIdx: 0, apiBase: "", wsBase: "" };
      }
      clean = [{ apiBase: defApi, wsBase: defWs, label: "default" }];
      activeIdx = 0;
    }

    if (!isFinite(activeIdx) || activeIdx < 0 || activeIdx >= clean.length) activeIdx = 0;
    activeIdx = Math.floor(activeIdx);

    return {
      schema: 2,
      islandId: hostOf(clean[0].apiBase),
      endpoints: clean,
      activeIdx: activeIdx,
      apiBase: clean[activeIdx].apiBase,
      wsBase: clean[activeIdx].wsBase
    };
  }

  function endpointKeys(cfg) {
    let out = [];
    let list = (cfg && cfg.endpoints) || [];
    for (let i = 0; i < list.length; i++) if (list[i] && list[i].apiBase) out.push(list[i].apiBase);
    return out;
  }

  // Deciding whether to tear the session down is done by comparing the SETS of
  // entry points, not by comparing a user-visible island name. A name can be
  // retyped differently for the same island; an overlapping set cannot lie —
  // if any entry point is shared, it is the same backend and the same database.
  function classifyConfigChange(oldCfg, newCfg) {
    let a = endpointKeys(oldCfg);
    let b = endpointKeys(newCfg);
    if (!a.length || !b.length) return "island";

    let inA = {};
    for (let i = 0; i < a.length; i++) inA[a[i]] = true;

    let shared = 0;
    for (let j = 0; j < b.length; j++) if (inA[b[j]]) shared++;

    if (!shared) return "island";
    if (shared === a.length && shared === b.length) {
      let sameOrder = a.length === b.length;
      for (let k = 0; sameOrder && k < a.length; k++) if (a[k] !== b[k]) sameOrder = false;
      let sameIdx = Number(oldCfg.activeIdx || 0) === Number(newCfg.activeIdx || 0);
      if (sameOrder && sameIdx) return "none";
    }
    return "endpoints";
  }

  // ---------------------------------------------------------- classification

  // 'rotate' — the transport failed; this entry point is suspect.
  // 'strike' — suspicious, but one occurrence also looks like a server restart.
  // 'ignore' — the server answered, so it is alive and reachable.
  function classifyHttpFailure(err) {
    if (!err) return "ignore";

    let name = String(err.name || "");
    // fetch() rejects with TypeError on DNS/TLS/connection failure. Android's
    // _fetch normalizes the same condition to status 0.
    if (name === "TypeError" || name === "AbortError" || name === "TimeoutError") return "rotate";

    let status = Number(err.status);
    if (!isFinite(status) || status === 0) return "rotate";
    if (status < 500) return "ignore";              // 401/403/429 included: the server spoke
    if (status === 502 || status === 503 || status === 504) {
      // An edge that is up while the backend behind it is not. Real, but a
      // single one is indistinguishable from a restart, so only a strike.
      return hasAppErrorBody(err) ? "ignore" : "strike";
    }
    return "ignore";
  }

  function hasAppErrorBody(err) {
    let b = err && err.body;
    if (!b) return false;
    if (typeof b === "object") return !!(b.detail || b.reason || b.error);
    if (typeof b === "string") {
      let t = b.trim();
      if (!t) return false;
      try {
        let parsed = JSON.parse(t);
        return !!(parsed && (parsed.detail || parsed.reason || parsed.error));
      } catch {
        return false;
      }
    }
    return false;
  }

  // `opened` must be false unless the socket actually reached onopen. Do not
  // substitute "time since we dialed" for it: a socket that opened and lived
  // four seconds looks identical by clock alone, and that conflation is the
  // bug both clients already shipped once.
  function classifyWsClose(info) {
    let code = Number((info && info.code) || 0);
    let opened = !!(info && info.opened);
    let uptimeMs = Number((info && info.uptimeMs) || 0);

    // 1006 is generated locally by the WebSocket implementation; a server can
    // never send it. It means "the connection died without a close frame".
    if (indexOfCode(WS_POLICY_CODES, code) >= 0) return "ignore";
    if (indexOfCode(WS_NORMAL_CODES, code) >= 0) return "ignore";
    if (!opened) return "rotate";
    if (uptimeMs < SHORT_LIVED_MS) return "strike";
    return "ignore";
  }

  // ------------------------------------------------------------- the selector

  // probe(endpoint) -> Promise<boolean>   (caller owns the timeout)
  // now()           -> ms
  // log(msg, data)  -> optional
  function createSelector(opts) {
    let o = opts || {};
    let cfg = o.cfg || normalizeServerConfig(null, {});
    let probe = o.probe || function () { return Promise.resolve(false); };
    let now = o.now || function () { return Date.now(); };
    let log = o.log || function () {};

    let idx = cfg.activeIdx || 0;
    let gen = 0;
    let strikes = 0;
    let rotating = null;
    let lastRotateTs = 0;
    let lastComeHomeTs = 0;
    let exhaustCount = 0;
    let unusable = {};   // apiBase -> reason ('foreignIsland' | 'permissionMissing')

    function current() {
      return cfg.endpoints[idx] || null;
    }

    function isUsable(i) {
      let e = cfg.endpoints[i];
      return !!e && !unusable[e.apiBase];
    }

    // Preference order, current entry point last: it just failed.
    function candidates() {
      let out = [];
      for (let i = 0; i < cfg.endpoints.length; i++) if (i !== idx && isUsable(i)) out.push(i);
      return out;
    }

    function switchTo(i, reason) {
      idx = i;
      gen++;
      strikes = 0;
      exhaustCount = 0;
      lastRotateTs = now();
      // Start the come-home clock here: having just moved away from a failing
      // entry point, we must not bounce straight back to it.
      lastComeHomeTs = now();
      // Rebuild the config so the mirrored apiBase/wsBase follow activeIdx —
      // that mirror is what every existing reader in both clients consumes.
      cfg = {
        schema: 2,
        islandId: cfg.islandId,
        endpoints: cfg.endpoints,
        activeIdx: i,
        apiBase: cfg.endpoints[i].apiBase,
        wsBase: cfg.endpoints[i].wsBase
      };
      log("endpoint rotated", { idx: i, apiBase: cfg.apiBase, reason: reason });
      return { rotated: true, idx: i, gen: gen, endpoint: current(), config: cfg };
    }

    function runPass(reason) {
      let list = candidates();
      let pos = 0;

      function step() {
        if (pos >= list.length) {
          exhaustCount++;
          let backoff = EXHAUST_BACKOFF_MS[Math.min(exhaustCount - 1, EXHAUST_BACKOFF_MS.length - 1)];
          log("no entry point reachable", { attempts: list.length, retryAfterMs: backoff });
          // Deliberately keep idx where it is and keep every cache: "nothing is
          // reachable right now" is a network state, not a reason to log out.
          return Promise.resolve({ rotated: false, exhausted: true, retryAfterMs: backoff, gen: gen });
        }
        let i = list[pos++];
        return Promise.resolve()
          .then(function () { return probe(cfg.endpoints[i]); })
          .then(function (ok) { return ok ? switchTo(i, reason) : step(); })
          .catch(function () { return step(); });
      }

      return step();
    }

    return {
      activeEndpoint: current,
      activeIndex: function () { return idx; },
      config: function () { return cfg; },
      epGen: function () { return gen; },

      // An authenticated response arrived, or a socket reached onopen: this
      // entry point works. Clears the strike counter.
      noteAlive: function (observedGen) {
        if (observedGen != null && observedGen !== gen) return false;
        strikes = 0;
        exhaustCount = 0;
        return true;
      },

      // kind: 'rotate' | 'strike' | 'ignore' (the caller classifies first).
      reportFailure: function (kind, observedGen) {
        if (kind === "ignore" || !kind) return Promise.resolve({ rotated: false, ignored: true });

        // Stale report: it describes an entry point we already left. Three
        // sockets dying together must produce ONE rotation, not three.
        if (observedGen != null && observedGen !== gen) {
          return Promise.resolve({ rotated: false, stale: true });
        }
        if (rotating) return rotating;

        if (kind === "strike") {
          strikes++;
          if (strikes < STRIKE_THRESHOLD) {
            return Promise.resolve({ rotated: false, strikes: strikes });
          }
        }

        let since = now() - lastRotateTs;
        if (lastRotateTs && since < ROTATE_COOLDOWN_MS) {
          return Promise.resolve({ rotated: false, cooldown: true, retryAfterMs: ROTATE_COOLDOWN_MS - since });
        }
        if (!candidates().length) {
          return Promise.resolve({ rotated: false, exhausted: true, retryAfterMs: EXHAUST_BACKOFF_MS[0] });
        }

        rotating = runPass(kind).then(
          function (r) { rotating = null; return r; },
          function (e) { rotating = null; throw e; }
        );
        return rotating;
      },

      // Running on a fallback: check whether a more preferred entry point came
      // back. Rate-limited so a long session does not keep poking a censored
      // domain (and lighting it up in the censor's logs).
      maybeComeHome: function () {
        if (idx === 0) return Promise.resolve({ rotated: false });
        if (now() - lastComeHomeTs < COME_HOME_INTERVAL_MS) return Promise.resolve({ rotated: false, throttled: true });
        lastComeHomeTs = now();
        if (rotating) return rotating;

        let list = [];
        for (let i = 0; i < idx; i++) if (isUsable(i)) list.push(i);
        let pos = 0;

        function step() {
          if (pos >= list.length) return Promise.resolve({ rotated: false });
          let cand = list[pos++];
          return Promise.resolve()
            .then(function () { return probe(cfg.endpoints[cand]); })
            .then(function (ok) { return ok ? switchTo(cand, "come-home") : step(); })
            .catch(function () { return step(); });
        }

        rotating = step().then(
          function (r) { rotating = null; return r; },
          function (e) { rotating = null; throw e; }
        );
        return rotating;
      },

      // Exclude an entry point for the rest of the session: it answered /health
      // but is not this island (a typo leading to someone else's instance), or
      // the browser has no host permission for it.
      markUnusable: function (apiBase, reason) {
        let key = normalizeApiBase(apiBase);
        if (!key) return false;
        unusable[key] = reason || "unusable";
        log("entry point marked unusable", { apiBase: key, reason: reason });
        return true;
      },
      isUnusable: function (apiBase) {
        let key = normalizeApiBase(apiBase);
        return key ? unusable[key] || null : null;
      },
      clearUnusable: function () { unusable = {}; },

      setConfig: function (nextCfg) {
        let change = classifyConfigChange(cfg, nextCfg);
        cfg = nextCfg;
        idx = cfg.activeIdx || 0;
        strikes = 0;
        exhaustCount = 0;
        if (change === "island") unusable = {};
        gen++;
        return change;
      },

      // For logging and tests.
      state: function () {
        return {
          idx: idx, gen: gen, strikes: strikes, exhaustCount: exhaustCount,
          rotating: !!rotating, unusable: unusable
        };
      }
    };
  }

  let API = {
    MAX_ENDPOINTS: MAX_ENDPOINTS,
    STRIKE_THRESHOLD: STRIKE_THRESHOLD,
    ROTATE_COOLDOWN_MS: ROTATE_COOLDOWN_MS,
    SHORT_LIVED_MS: SHORT_LIVED_MS,
    COME_HOME_INTERVAL_MS: COME_HOME_INTERVAL_MS,
    EXHAUST_BACKOFF_MS: EXHAUST_BACKOFF_MS,
    deriveWsBase: deriveWsBase,
    normalizeApiBase: normalizeApiBase,
    normalizeServerConfig: normalizeServerConfig,
    classifyConfigChange: classifyConfigChange,
    classifyHttpFailure: classifyHttpFailure,
    classifyWsClose: classifyWsClose,
    createSelector: createSelector
  };

  // Three load environments: <script src> in panel.html/login.html,
  // importScripts() in the service worker, require() in jest / Metro.
  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSEndpoints = API;
})(this);
