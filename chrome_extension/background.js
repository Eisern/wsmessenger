// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// background.js (MV3 service worker)

let _unlockKekKey = null; // CryptoKey AES-GCM
let _unlockKekTs = 0;

let _masterKey = null;
let _masterKeyTs = 0;

let _masterB64 = "";
let _masterB64User = "";
let _masterB64Timer = null; // SEC: auto-clear timer
const _unlockHandoffSessions = new Map(); // reqId -> { port, createdAt, nonceB64, privateKey, username }
const UNLOCK_HANDOFF_TTL_MS = 30_000;
// A2: Per-username unlock rate limiting (exponential backoff on failed attempts)
const _unlockAttemptsByUser = new Map(); // normalized username -> { failures, blockedUntil, lastAttemptTs }
const UNLOCK_BACKOFF_BASE_MS = 1_000;
const UNLOCK_BACKOFF_MAX_MS = 30_000;
const _portSensitiveState = new WeakMap(); // port -> { hits: number[], reqIds: Map<string, number> }
const SENSITIVE_PORT_WINDOW_MS = 60_000;
const SENSITIVE_PORT_MAX_HITS = 120;
const SENSITIVE_REQID_TTL_MS = 3 * 60 * 1000;
const SENSITIVE_PORT_TYPES = new Set([
  "unlock_handoff_begin",
  "unlock_handoff_commit",
  "unlock_master_take",
  "unlock_master_clear",
  "unlock_kek_clear",
  "storage_encrypt",
  "storage_decrypt",
  "dm_delete",
  "file_upload",
  "room_logo_upload",
]);

function hasMasterKey(maxAgeMs = 10 * 60 * 1000) {
  return !!_masterKey && (Date.now() - _masterKeyTs) < maxAgeMs;
}

async function setMasterKeyFromB64(master_b64) {
  const b64 = String(master_b64 || "").trim();
  if (!b64) throw new Error("No master_b64");
  const raw = b64decode(b64);
  _masterKey = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  _masterKeyTs = Date.now();
}

function clearIdentityCache() {
  try { delete globalThis.__e2eeIdentityCache; } catch {}
}

function clearMasterB64Cache() {
  _masterB64 = "";
  _masterB64User = "";
  if (_masterB64Timer) {
    clearTimeout(_masterB64Timer);
    _masterB64Timer = null;
  }
}

function clearMasterKey() {
  _masterKey = null;
  _masterKeyTs = 0;
  clearMasterB64Cache();
  clearIdentityCache();
}

async function maybePublishAfterUnlock() {
  try {
    await ensureAuthLoaded();

    // Ensure token is fresh before publishing key
    if (wsState.token) {
      const p = decodeJwtPayload(wsState.token);
      const expSec = p?.exp ? Number(p.exp) : 0;
      if (expSec > 0 && (expSec * 1000 - Date.now()) < 30_000) {
        // Token expires in <30s â€” force refresh first
        await doRefresh();
      }
    }

    if (pendingE2eePublish && wsState.token && hasMasterKey()) {
      await e2eePublishMyKey(API_BASE, wsState.token);
      pendingE2eePublish = false;
    }
  } catch (e) {
    swarn("E2EE publish after unlock failed:", e?.message || e, e);
  }
}

let authExpiryTimer = null;
let __authExpiredNotified = false;

const __ERR_MAX = 5000;
const __ERR_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

function decodeJwtPayload(token) {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = atob(padded);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

async function readBody(r) {
  const ct = (r.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("application/json")) {
    try { return await r.json(); } catch { return null; }
  }
  try { return await r.text(); } catch { return null; }
}



// ===== Ban helpers =====
function banInfoFromBody(body) {
  // Expected backend shapes:
  //  - { reason: "banned", detail: "User is banned: ..." }
  //  - { detail: "User is banned: ..." }
  //  - "User is banned: ..."
  if (!body) return { banned: false, message: "" };

  if (typeof body === "string") {
    const s = body.trim();
    if (!s) return { banned: false, message: "" };
    const sl = s.toLowerCase();
    if (sl.includes("banned")) return { banned: true, message: s };
    return { banned: false, message: "" };
  }

  if (typeof body === "object") {
    const reason = String(body.reason || "").toLowerCase();
    const detail = (body.detail != null) ? String(body.detail) : "";
    const msg = detail || String(body.message || "");
    const ml = String(msg || "").toLowerCase();
    if (reason === "banned" || ml.includes("banned")) {
      return { banned: true, message: msg || "User is banned" };
    }
  }

  return { banned: false, message: "" };
}

async function handleBannedLogout(message) {
  const msg = String(message || "User is banned");

  try { await clearAuth(); } catch {}
  try { disconnectWs(true); } catch {}
  try { closeDmWs({ manual: true }); } catch {}
  try { closeNotifyWs({ manual: true }); } catch {}

  broadcastToPanels({ type: "banned", message: msg });
  broadcastToPanels({ type: "auth_state", loggedIn: false });
}
function bytesLikeToArrayBuffer(x) {
  if (!x) return null;

  if (x instanceof ArrayBuffer) return x;

  if (ArrayBuffer.isView(x) && x.buffer instanceof ArrayBuffer) {
    return x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength);
  }

  if (typeof x === "object" && typeof x.byteLength === "number" && typeof x.slice === "function") {
    try { return x.slice(0); } catch {}
  }

  if (Array.isArray(x)) {
    try { return new Uint8Array(x).buffer; } catch {}
  }

  if (typeof x === "object" && Array.isArray(x.data)) {
    try { return new Uint8Array(x.data).buffer; } catch {}
  }

  if (typeof x === "object" && typeof x.length === "number") {
    const n = x.length >>> 0;
    if (n > 0) {
      try {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = (x[i] ?? 0) & 255;
        return out.buffer;
      } catch {}
    }
  }

  return null;
}

/**
 * Wipe sensitive fields from a message object as soon as they're extracted.
 * JS strings are immutable so we can't zero the actual bytes, but we remove
 * the reference from the object ASAP so it becomes eligible for GC immediately.
 */
function _wipeMsgFields(obj, ...keys) {
  if (!obj || typeof obj !== "object") return;
  for (const k of keys) {
    if (k in obj) {
      try { obj[k] = ""; } catch {}
      try { delete obj[k]; } catch {}
    }
  }
}

function _getSensitivePortState(port) {
  let st = _portSensitiveState.get(port);
  if (!st) {
    st = { hits: [], reqIds: new Map() };
    _portSensitiveState.set(port, st);
  }
  return st;
}

function _cleanupSensitivePortState(st, now = Date.now()) {
  st.hits = st.hits.filter((t) => (now - t) <= SENSITIVE_PORT_WINDOW_MS);
  for (const [k, ts] of st.reqIds.entries()) {
    if ((now - ts) > SENSITIVE_REQID_TTL_MS) st.reqIds.delete(k);
  }
}

function _validateSensitiveMessage(msg) {
  const type = String(msg?.type || "");
  if (!SENSITIVE_PORT_TYPES.has(type)) return;

  if (type === "dm_delete") {
    const tid = Number(msg?.thread_id);
    const scope = String(msg?.scope || "").trim().toLowerCase();
    if (!Number.isInteger(tid) || tid <= 0) throw new Error("Invalid dm_delete thread_id");
    if (scope !== "self" && scope !== "both") throw new Error("Invalid dm_delete scope");
  }
  if (type === "storage_encrypt") {
    if (typeof msg?.plaintext !== "string") throw new Error("storage_encrypt plaintext must be string");
    // 64 KiB limit — covers room passwords (short) and room key archives
    // (up to ~500 archived keys per room) while still bounding abuse.
    if (String(msg.plaintext).length > 65536) throw new Error("storage_encrypt plaintext too large");
  }
  if (type === "storage_decrypt") {
    const iv = String(msg?.iv || "");
    const ct = String(msg?.ct || "");
    if (!iv || !ct) throw new Error("storage_decrypt payload is missing");
    // iv is fixed 12 bytes (base64 ≈ 16 chars) — keep tight.
    // ct grows with plaintext; accommodate the new 64 KiB plaintext limit.
    if (iv.length > 128 || ct.length > 131072) throw new Error("storage_decrypt payload too large");
  }
}

function _preflightSensitivePortMessage(port, msg) {
  const type = String(msg?.type || "");
  if (!SENSITIVE_PORT_TYPES.has(type)) return;

  // Validate shape FIRST. Recording rate-limit hits or reqIds before
  // validation lets a malformed-payload spammer eat the rate-limit budget
  // (soft DoS) and also blocks legitimate retries of the same reqId after
  // a transient validation failure with a bogus "Replay detected" response.
  _validateSensitiveMessage(msg);

  const now = Date.now();

  // Stale-timestamp check is also a shape-level concern; do it before any
  // state mutation so a bad ts doesn't burn budget either.
  const ts = Number(msg?.ts || 0);
  if (ts > 0 && Math.abs(now - ts) > 90_000) {
    throw new Error(`Stale sensitive message timestamp (${type})`);
  }

  const st = _getSensitivePortState(port);
  _cleanupSensitivePortState(st, now);
  st.hits.push(now);
  if (st.hits.length > SENSITIVE_PORT_MAX_HITS) {
    throw new Error(`Rate limit exceeded for sensitive port messages (${type})`);
  }

  const reqId = String(msg?.reqId || "").trim();
  if (reqId) {
    const k = `${type}:${reqId}`;
    if (st.reqIds.has(k)) throw new Error(`Replay detected for sensitive message (${type})`);
    st.reqIds.set(k, now);
  }
}

// A2: Per-username unlock rate limiting helpers
function _checkUnlockRateLimit(username) {
  const u = String(username || "").trim().toLowerCase();
  if (!u) return;
  const st = _unlockAttemptsByUser.get(u);
  if (!st) return;
  const now = Date.now();
  if (st.blockedUntil > now) {
    const secsLeft = Math.ceil((st.blockedUntil - now) / 1000);
    throw new Error(`Too many failed unlock attempts. Try again in ${secsLeft}s.`);
  }
}

function _recordUnlockAttempt(username, success) {
  const u = String(username || "").trim().toLowerCase();
  if (!u) return;
  if (success) {
    _unlockAttemptsByUser.delete(u);
    return;
  }
  let st = _unlockAttemptsByUser.get(u);
  if (!st) { st = { failures: 0, blockedUntil: 0, lastAttemptTs: 0 }; _unlockAttemptsByUser.set(u, st); }
  const now = Date.now();
  st.failures += 1;
  st.lastAttemptTs = now;
  const delay = Math.min(UNLOCK_BACKOFF_BASE_MS * Math.pow(2, st.failures - 1), UNLOCK_BACKOFF_MAX_MS);
  st.blockedUntil = now + delay;
  console.warn(`[unlock-rl] ${u} failed ${st.failures}x → blocked ${delay}ms`);
}

const __SENSITIVE_KEYS = new Set([
  "token", "jwt", "authorization", "Authorization",
  "password", "pass", "secret",
  "kek", "kekB64", "__tmp_unlock_kek",
  "privateKey", "privKey", "encryptedPrivateKey",
  "masterB64", "master_b64",
]);

function redactDeep(value, depth = 0) {
  if (depth > 5) return "[...]";

  if (Array.isArray(value)) return value.map(v => redactDeep(v, depth + 1));

  if (value && typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (__SENSITIVE_KEYS.has(k)) out[k] = "[REDACTED]";
      else out[k] = redactDeep(v, depth + 1);
    }
    return out;
  }

  if (typeof value === "string") {

    if (value.split(".").length === 3 && value.length > 40) return "[REDACTED_JWT]";
  }
  return value;
}

function slog(...args) {
  try { console.log(...args.map(a => redactDeep(a))); } catch { console.log(...args); }
}
function swarn(...args) {
  try { console.warn(...args.map(a => redactDeep(a))); } catch { console.warn(...args); }
}
function serr(...args) {
  try { console.error(...args.map(a => redactDeep(a))); } catch { console.error(...args); }
}

function redactSecrets(s) {
  let out = String(s || "");

  out = out.replace(/\beyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\b/g, "[REDACTED_JWT]");

  out = out.replace(/(authorization\s*:\s*bearer\s+)[^\s'"]+/ig, "$1[REDACTED]");
  out = out.replace(/(bearer\s+)[^\s'"]+/ig, "$1[REDACTED]");

  out = out.replace(/([?&]token=)[^&\s'"]+/ig, "$1[REDACTED]");
  out = out.replace(/("token"\s*:\s*")[^"]+(")/ig, '$1[REDACTED]$2');

  out = out.replace(/("access_token"\s*:\s*")[^"]+(")/ig, '$1[REDACTED]$2');
  out = out.replace(/("refresh_token"\s*:\s*")[^"]+(")/ig, '$1[REDACTED]$2');

  return out;
}

function normalizeErrMsg(raw) {
  const s = redactSecrets(raw);
  return s.length > __ERR_MAX ? (s.slice(0, __ERR_MAX) + "...[truncated]") : s;
}

let __lastErrSig = "";
let __lastErrTs = 0;

function saveSwLastError(kind, raw) {
  const msg = normalizeErrMsg(raw);
  const now = Date.now();
  const sig = kind + ":" + msg.slice(0, 200);

  if (sig === __lastErrSig && (now - __lastErrTs) < 10_000) return;
  __lastErrSig = sig;
  __lastErrTs = now;

  try {
    chrome.storage.local.set({ sw_last_error: { ts: now, kind, msg } });
  } catch {}
}

self.addEventListener("unhandledrejection", (e) => {
  const raw = String(e?.reason?.stack || e?.reason || "unknown unhandledrejection");
  serr("UNHANDLED REJECTION in SW:", normalizeErrMsg(raw));
  saveSwLastError("unhandledrejection", raw);
});


self.addEventListener("error", (e) => {
  const raw = String(e?.error?.stack || e?.error || e?.message || "unknown error");
  serr("UNCAUGHT ERROR in SW:", normalizeErrMsg(raw));
  saveSwLastError("error", raw);
});

const dmThreadPeers = new Map(); // threadId(string) -> peerUsername

// ===============
// KEEPALIVE PATCH
// ===============
let keepaliveInterval = null;

function startKeepalive() {
  if (keepaliveInterval) return;
  
  keepaliveInterval = setInterval(() => {

    chrome.storage.local.get(["_keepalive"], () => {});

    broadcastToPanels({ type: "pong", ts: Date.now() });
  }, 20000);
}

function stopKeepalive() {
  if (keepaliveInterval) {
    clearInterval(keepaliveInterval);
    keepaliveInterval = null;
  }
}

startKeepalive();

chrome.runtime.onSuspend?.addListener(() => {
  swarn("Service Worker suspending - saving state");

  stopKeepalive();

  try {
    chrome.storage.local.set({
      ws_state_before_suspend: {
        wantConnected: !!wsState.roomName,
        roomName: wsState.roomName || "",
        hadRoomPass: !!wsState.roomPass,
        ts: Date.now()
      }
    });
  } catch {}

  try {
    if (ws) ws.close(1000, "SW suspending");
  } catch {}
});

setTimeout(() => {
  chrome.storage.local.get(["ws_state_before_suspend"], (data) => {
    const prevState = data?.ws_state_before_suspend;

    try {
      if (prevState && prevState.wantConnected && prevState.roomName) {
        const elapsed = Date.now() - (prevState.ts || 0);

        if (elapsed < 300000) {
          slog("Restoring WS after SW wake-up");
          setTimeout(() => {
            connectWs({ roomName: prevState.roomName, roomPass: "" });
          }, 1000);
        }
      }
    } finally {
      chrome.storage.local.remove(["ws_state_before_suspend"]);
    }
  });
}, 1000);

slog("Keepalive started");

let wsPingInterval = null;

function startWsPing() {
  if (wsPingInterval) clearTimeout(wsPingInterval);

  function _schedulePing() {
    const delay = 20000 + Math.random() * 15000; // 20–35 s
    wsPingInterval = setTimeout(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: "ping" }));
        } catch (e) {
          swarn("WS ping failed:", e);
        }
      }
      _schedulePing();
    }, delay);
  }

  _schedulePing();
}

function stopWsPing() {
  if (wsPingInterval) {
    clearTimeout(wsPingInterval);
    wsPingInterval = null;
  }
}

let API_BASE = "https://imagine-1-ws.xyz";
let WS_BASE  = "wss://imagine-1-ws.xyz";
const CTX_MENU_ID = "ws-messenger-create-room-from-selection";

async function _loadServerConfig() {
  try {
    const r = await chrome.storage.local.get("server_config");
    const cfg = r.server_config;
    if (cfg?.apiBase) {
      API_BASE = cfg.apiBase.replace(/\/$/, "");
      WS_BASE  = cfg.wsBase ? cfg.wsBase.replace(/\/$/, "")
                            : API_BASE.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
    }
  } catch { /* use defaults */ }
}
// Store the promise so message handlers can await it before making network calls
const _serverConfigReady = _loadServerConfig();

chrome.action.onClicked.addListener(tab => {
  chrome.sidePanel.open({ tabId: tab.id });
});

let wsGen = 0;
let wsConnecting = false;
let ws = null;
let wsState = {
  connected: false,
  roomName: "",
  roomId: 0,
  username: "",
  roomPass: "",
  token: "",
  refreshToken: ""
};

let pendingE2eePublish = false;
let _refreshTimer = null;
let _refreshing = false;  // mutex for doRefresh

// =======================
// DM (direct messages) state
// =======================
let dmWsGen = 0;
let dmWsConnecting = false;
let dmWs = null;

let dmState = {
  connected: false,
  threadId: null,
  peer: ""
};

// UD (sealed sender) delivery secrets cache: threadId -> { secret: string, expiresAt: number (ms) }
const dmDeliverySecrets = new Map();

// =======================
// Notify WS (/ws-notify)
// =======================
let _notifyWs = null;
let _notifyWsGen = 0;
let _notifyPingInterval = null;
let _notifyReconnectTimer = null;
let _notifyReconnectDelay = 2_000;
const NOTIFY_RECONNECT_MAX_MS = 64_000;

function closeNotifyWs({ manual = false } = {}) {
  if (_notifyReconnectTimer) { clearTimeout(_notifyReconnectTimer); _notifyReconnectTimer = null; }
  if (_notifyPingInterval) { clearInterval(_notifyPingInterval); _notifyPingInterval = null; }
  try { if (_notifyWs) _notifyWs.close(); } catch {}
  _notifyWs = null;
  if (manual) _notifyReconnectDelay = 2_000; // reset backoff on intentional close
}

function _scheduleNotifyReconnect() {
  if (_notifyReconnectTimer) return;
  _notifyReconnectTimer = setTimeout(() => {
    _notifyReconnectTimer = null;
    connectNotifyWs().catch(() => {});
  }, _notifyReconnectDelay);
  _notifyReconnectDelay = Math.min(_notifyReconnectDelay * 2, NOTIFY_RECONNECT_MAX_MS);
}

async function connectNotifyWs() {
  if (!wsState.token) return;

  // Close any existing connection first
  if (_notifyPingInterval) { clearInterval(_notifyPingInterval); _notifyPingInterval = null; }
  try { if (_notifyWs) _notifyWs.close(); } catch {}
  _notifyWs = null;

  const gen = ++_notifyWsGen;
  const ws = new WebSocket(`${WS_BASE}/ws-notify`);
  _notifyWs = ws;

  ws.onopen = () => {
    if (ws !== _notifyWs) { ws.close(); return; }
    _notifyReconnectDelay = 2_000; // reset backoff on success
    try { ws.send(JSON.stringify({ type: "auth", token: wsState.token })); } catch {}
    _notifyPingInterval = setInterval(() => {
      if (ws !== _notifyWs) { clearInterval(_notifyPingInterval); _notifyPingInterval = null; return; }
      try { ws.send(JSON.stringify({ type: "ping" })); } catch {}
    }, 25_000);
  };

  ws.onmessage = (e) => {
    if (ws !== _notifyWs) return;
    try {
      const data = JSON.parse(e.data);
      if (data?.type === "notify_room_msg" || data?.type === "notify_dm_msg") {
        broadcastToPanels(data);
      }
    } catch {}
  };

  ws.onclose = (ev) => {
    if (ws !== _notifyWs) return;
    if (_notifyPingInterval) { clearInterval(_notifyPingInterval); _notifyPingInterval = null; }
    _notifyWs = null;
    // Auto-reconnect as long as we're still logged in
    if (wsState.token) _scheduleNotifyReconnect();
  };

  ws.onerror = () => {
    // onclose will fire next and handle reconnect
  };
}

function closeDmWs({ manual = false } = {}) {
  try { if (dmWs) dmWs.close(); } catch {}
  dmWs = null;
  dmState.connected = false;
  if (!manual) {
    broadcastToPanels({ type: "dm_status", online: false });
  }
}

async function connectDmWs({ threadId }) {
  if (dmWsConnecting) return;
  dmWsConnecting = true;
  const gen = ++dmWsGen;

  try {
    await ensureAuthLoaded();
    if (!wsState.token) {
      broadcastToPanels({ type: "error", message: "Not logged in" });
      return;
    }

    if (dmWs) {
      try { dmWs.close(); } catch {}
    }
    dmWs = null;
    dmState.connected = false;
    dmState.threadId = Number(threadId);

    const url = `${WS_BASE}/ws-dm?thread_id=${encodeURIComponent(threadId)}`;

    dmWs = new WebSocket(url);

    dmWs.onopen = () => {
      if (gen !== dmWsGen) return;

      try {
        dmWs.send(JSON.stringify({ type: "auth", token: wsState.token }));
      } catch {}
      dmState.connected = true;
      broadcastToPanels({ type: "dm_status", online: true, thread_id: dmState.threadId });
    };

    dmWs.onmessage = (e) => {
      if (gen !== dmWsGen) return;

      try {
        const data = JSON.parse(e.data);

        // --- banned / auth_state forced logout ---
        try {
          if (data?.type === "banned") {
            const why = (data?.ban_reason || "").trim();
            const msg = (data?.message || "").trim() || ("User is banned" + (why ? (": " + why) : ""));
            handleBannedLogout(msg).catch(() => {});
            return;
          }
          if (data?.type === "auth_state" && data?.loggedIn === false && String(data?.reason || "") === "banned") {
            const why = (data?.ban_reason || "").trim();
            const msg = (data?.message || "").trim() || ("User is banned" + (why ? (": " + why) : ""));
            handleBannedLogout(msg).catch(() => {});
            return;
          }
        } catch {}

        if (data?.type === "dm_message") {
          broadcastToPanels({
            type: "dm_message",
            thread_id: data.thread_id ?? dmState.threadId,
            username: data.username,
            text: data.text,
            ts: data.ts ?? null
          });
          return;
        }

        if (data?.type === "dm_presence") {
          broadcastToPanels({
            type: "dm_presence",
            thread_id: data.thread_id ?? dmState.threadId,
          });
          return;
        }

        // fallback
        broadcastToPanels({ type: "dm_raw", data });
      } catch {
        broadcastToPanels({ type: "dm_raw_text", text: String(e.data) });
      }
    };

    dmWs.onclose = (ev) => {
      if (gen !== dmWsGen) return;
      dmState.connected = false;

      const code = ev?.code ?? 0;
      const reason = String(ev?.reason ?? "");
      if (code === 1008 && reason.toLowerCase().includes("banned")) {
        handleBannedLogout(reason || "User is banned").catch(() => {});
        return;
      }

      broadcastToPanels({
        type: "dm_status",
        online: false,
        code,
        reason
      });
    };

    dmWs.onerror = () => {
      if (gen !== dmWsGen) return;
      broadcastToPanels({ type: "error", message: "DM WebSocket error" });
    };

  } finally {
    dmWsConnecting = false;
  }
}

async function ensureDmDeliverySecret(threadId) {
  const tid = String(Number(threadId));
  if (!tid || tid === "NaN") throw new Error("Bad threadId");

  const cached = dmDeliverySecrets.get(tid);
  if (cached && cached.expiresAt > Date.now() + 60_000) return cached.secret;

  await ensureAuthLoaded();
  if (!wsState.token) throw new Error("Not logged in");

  const url = API_BASE + `/dm/${encodeURIComponent(tid)}/delivery-secret`;
  const r = await fetch(url, {
    method: "GET",
    headers: { "Authorization": "Bearer " + wsState.token }
  });

  const raw = await r.text();
  let data;
  try { data = JSON.parse(raw); } catch { data = {}; }

  if (!r.ok) {
    const detail = data?.detail ? JSON.stringify(data.detail) : (raw || `HTTP ${r.status}`);
    throw new Error("delivery-secret fetch failed: " + detail);
  }

  const secB64 = String(data?.delivery_secret_b64 || "").trim();
  if (!secB64) throw new Error("delivery-secret missing in response");

  const expiresAt = data?.expires_at ? new Date(data.expires_at).getTime() : (Date.now() + 23 * 60 * 60 * 1000);
  dmDeliverySecrets.set(tid, { secret: secB64, expiresAt });
  return secB64;
}


let reconnectTimer = null;
let reconnectAttempt = 0;
let manualDisconnect = false;

function clearReconnectTimer() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function scheduleReconnect(reason = "") {
  if (manualDisconnect) return;

  clearReconnectTimer();
  reconnectAttempt++;

  const base = Math.min(30000, 1000 * (2 ** (reconnectAttempt - 1)));
  const jitter = Math.floor(Math.random() * 500); // 0..500ms
  const delay = base + jitter;

  broadcastToPanels({
    type: "status",
    online: false,
    reconnecting: true,
    attempt: reconnectAttempt,
    in_ms: delay,
    reason
  });

  reconnectTimer = setTimeout(() => {
    if (!wsState.token || !wsState.roomName) return;

    connectWs({ roomName: wsState.roomName, roomPass: wsState.roomPass || "" });
  }, delay);
}

const AUTH_KEY = "auth";

function getSessionStorageOrNull() {
  return (chrome.storage && chrome.storage.session) ? chrome.storage.session : null;
}

(async () => {
  try {
    const sess = getSessionStorageOrNull();

    if (sess) {
      const s = await sess.get([AUTH_KEY]);
      const cur = s?.[AUTH_KEY] || {};

      const username = cur?.username ? String(cur.username) : "";
      const token = cur?.token ? String(cur.token) : "";
      const refreshToken = cur?.refreshToken ? String(cur.refreshToken) : "";

      if (username || token) {
        wsState.username = username;
        wsState.token = token;
        wsState.refreshToken = refreshToken;

        await sess.set({ [AUTH_KEY]: { ...cur, username, token, refreshToken } });

        // Schedule proactive refresh on SW restart
        if (token) scheduleTokenRefresh(token);
      } else {
        await sess.remove([AUTH_KEY]);
        wsState.username = "";
        wsState.token = "";
        wsState.refreshToken = "";
      }
    } else {
      wsState.username = "";
      wsState.token = "";
      wsState.refreshToken = "";
    }

    try { await chrome.storage.local.remove([AUTH_KEY]); } catch {}
  } catch (e) {
    swarn("auth storage init failed:", e);
    wsState.username = "";
    wsState.token = "";
    wsState.refreshToken = "";
  }
})();

async function setAuth(username, token, refreshToken) {
  const prevUser = String(wsState.username || "").trim().toLowerCase();
  const nextUser = String(username || "").trim().toLowerCase();
  if (prevUser && nextUser && prevUser !== nextUser) {
    clearMasterKey();
    _unlockKekKey = null;
    _unlockKekTs = 0;
  }

  wsState.username = username || "";
  wsState.token = token || "";
  if (refreshToken !== undefined) wsState.refreshToken = refreshToken || "";
  __authExpiredNotified = false;

  if (authExpiryTimer) { clearTimeout(authExpiryTimer); authExpiryTimer = null; }
  if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }

  if (wsState.token) {
    scheduleTokenRefresh(wsState.token);
    // B1: connect notify WS whenever we get a fresh token
    connectNotifyWs().catch(() => {});
  } else {
    closeNotifyWs({ manual: true });
  }

  try {
    const sess = getSessionStorageOrNull();
    if (sess) {
      const cur = (await sess.get(AUTH_KEY))?.[AUTH_KEY] || {};
      await sess.set({ [AUTH_KEY]: {
        ...cur,
        username: wsState.username,
        token: wsState.token,
        refreshToken: wsState.refreshToken,
      }});
    }
  } catch (e) {
    swarn("setAuth: session write failed:", e);
  }
}

// ==================== JWT Refresh ====================
function scheduleTokenRefresh(accessToken) {
  if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }

  const p = decodeJwtPayload(accessToken);
  const expSec = p?.exp ? Number(p.exp) : 0;
  if (expSec <= 0) return;

  const expMs = expSec * 1000;
  // Refresh 60s before expiry, but at least 5s from now
  const refreshAt = Math.max(expMs - Date.now() - 60_000, 5_000);

  _refreshTimer = setTimeout(() => doRefresh(), refreshAt);
}

async function doRefresh() {
  if (_refreshing) return;
  _refreshing = true;

  try {
    if (!wsState.refreshToken) {
      await handleSessionExpired();
      return;
    }

    const resp = await fetch(API_BASE + "/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: wsState.refreshToken }),
    });

    if (!resp.ok) {
      if (resp.status === 401) {
        await handleSessionExpired();
      } else {
        // Transient error, retry in 10s
        _refreshTimer = setTimeout(() => doRefresh(), 10_000);
      }
      return;
    }

    const data = await resp.json();
    if (!data.access_token || !data.refresh_token) {
      await handleSessionExpired();
      return;
    }

    // Update tokens everywhere
    await setAuth(wsState.username, data.access_token, data.refresh_token);

    // Broadcast fresh token to all open panels
    try { broadcastToPanels({ type: "token", token: data.access_token }); } catch {}

  } catch (e) {
    swarn("Token refresh failed:", e);
    // Retry in 10s on network error
    _refreshTimer = setTimeout(() => doRefresh(), 10_000);
  } finally {
    _refreshing = false;
  }
}

// One-shot refresh used for the "401 -> refresh -> retry once" flow in fetchJson.
// Returns true if tokens were refreshed (or became available due to another in-flight refresh).
async function refreshNowOnce() {
	console.warn("[refreshNowOnce] called");
  // Ensure we have latest auth state
  await ensureAuthLoaded();

  // If refresh already running, wait a bit for it to finish, then re-check token.
  if (_refreshing) {
    const t0 = Date.now();
    while (_refreshing && (Date.now() - t0) < 8000) {
      await new Promise(r => setTimeout(r, 100));
    }
    await ensureAuthLoaded();
    return !!wsState.token;
  }

  if (!wsState.refreshToken) return false;

  _refreshing = true;
  try {
    const resp = await fetch(API_BASE + "/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: wsState.refreshToken }),
    });

    if (!resp.ok) {
      // Refresh token invalid / reuse detected / etc.
      if (resp.status === 401) {
        await handleSessionExpired();
      }
      return false;
    }

    const data = await resp.json().catch(() => ({}));
    if (!data?.access_token || !data?.refresh_token) {
      await handleSessionExpired();
      return false;
    }

    await setAuth(wsState.username, data.access_token, data.refresh_token);
    try { broadcastToPanels({ type: "token", token: data.access_token }); } catch {}
    return true;
  } catch (e) {
    swarn("refreshNowOnce failed:", e);
    return false;
  } finally {
    _refreshing = false;
  }
}

async function handleSessionExpired() {
  if (__authExpiredNotified) return;
  __authExpiredNotified = true;

  try { closeWs?.({ manual: true, reason: "exp" }); } catch {}
  try { closeDmWs?.({ manual: true, reason: "exp" }); } catch {}
  try { closeNotifyWs({ manual: true }); } catch {}
  try { await clearAuth(); } catch {}
  try {
    broadcastToPanels({ type: "auth_state", loggedIn: false, username: "" });
    broadcastToPanels({ type: "error", message: "Session expired. Please login again." });
  } catch {}
}

async function clearAuth() {
  if (authExpiryTimer) { clearTimeout(authExpiryTimer); authExpiryTimer = null; }
  if (_refreshTimer) { clearTimeout(_refreshTimer); _refreshTimer = null; }
  _refreshing = false;
  // Logout/session-expiry hygiene: delivery secrets must not survive account switch.
  try { dmDeliverySecrets.clear(); } catch {}

  wsState.username = "";
  wsState.token = "";
  wsState.refreshToken = "";

  try {
    const sess = getSessionStorageOrNull();
    if (sess) await sess.remove([AUTH_KEY]);
  } catch {}

  try { await chrome.storage.local.remove([AUTH_KEY]); } catch {}
}

async function ensureAuthLoaded() {
  if (wsState.token) return wsState.token;

  try {
    const sess = getSessionStorageOrNull();
    if (!sess) return "";
    const v = await sess.get([AUTH_KEY]);
    const a = v?.[AUTH_KEY] || {};
    if (a.username) wsState.username = String(a.username || "");
    if (a.token) wsState.token = String(a.token || "");
    if (a.refreshToken) wsState.refreshToken = String(a.refreshToken || "");

    // Reschedule proactive refresh if we restored a token
    if (wsState.token && !_refreshTimer) {
      scheduleTokenRefresh(wsState.token);
    }
  } catch {}

  return wsState.token || "";
}

const ports = new Set();

function safePortPost(port, msg) {
  try {

    if (!ports.has(port)) return false;
    port.postMessage(msg);
    return true;
  } catch (e) {
    try { ports.delete(port); } catch {}
    return false;
  }
}

function broadcastToPanels(msg) {
  for (const p of ports) {
    try { p.postMessage(msg); } catch {}
  }
}

function closeWs({ manual = false } = {}) {
  manualDisconnect = !!manual;
  clearReconnectTimer();

  if (ws) {
    try { ws.close(); } catch {}
  }
  ws = null;
  wsState.connected = false;
  wsState.roomId = 0;

  broadcastToPanels({
    type: "status",
    online: false,
    reconnecting: !manualDisconnect
  });
}

async function loginAndGetToken(username, userPass) {
  const r = await fetch(API_BASE + "/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: userPass })
  });

  if (!r.ok) {
    const body = await readBody(r);
    const bi = banInfoFromBody(body);
    if (r.status === 403 && bi.banned) throw new Error("BANNED:" + bi.message);
    const txt = (typeof body === "string") ? body : (() => { try { return JSON.stringify(body); } catch { return String(body); } })();
    throw new Error(`${r.status}: ${txt}`);
  }

  const data = await r.json();

  if (data.requires_2fa && data.temp_token) {
    return { requires_2fa: true, temp_token: data.temp_token };
  }

  if (!data?.access_token) throw new Error("No access_token in response");
  if (!data?.refresh_token) throw new Error("No refresh_token in response");
  return {
    requires_2fa: false,
    access_token: data.access_token,
    refresh_token: data.refresh_token,
  };
}

/**
 * Verify TOTP code with temp_token, get real access_token
 */
async function verifyTotpAndGetToken(tempToken, totpCode) {
  const r = await fetch(API_BASE + "/auth/totp/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ temp_token: tempToken, code: totpCode })
  });

  if (!r.ok) {
    const txt = await r.text();
    let detail = txt;
    try { detail = JSON.parse(txt).detail || txt; } catch {}
    throw new Error(detail);
  }

  const data = await r.json();
  if (!data?.access_token) throw new Error("No access_token in response");
  return { access_token: data.access_token, refresh_token: data.refresh_token || "" };
}

async function connectWs({ roomName, roomPass, force = false, source = "manual" }) {
  manualDisconnect = false;
  clearReconnectTimer();
  reconnectAttempt = 0;
broadcastToPanels({
  type: "status",
  online: false,
  reconnecting: false,
  connecting: true
});

  if (wsConnecting) {
    if (!force) {
      swarn("connectWs skipped: already connecting");
      return;
    }

    swarn("connectWs: force override current connecting attempt");
    try { ws?.close(); } catch {}
    ws = null;
    wsState.connected = false;
    wsState.roomId = 0;
    wsConnecting = false;
  }
  wsConnecting = true;

  const gen = ++wsGen;

  try {
    if (ws) {
      try { ws.close(); } catch {}
    }
    ws = null;
    wsState.connected = false;

	await ensureAuthLoaded();
    if (!wsState.token) {
      broadcastToPanels({ type: "status", online: false, reconnecting: false, connecting: false });
      broadcastToPanels({ type: "error", message: "Not logged in" });
      return;
    }

    wsState.roomName = roomName;
    wsState.roomPass = roomPass || "";

    const roomKey = (roomName || "").trim();
    const isNumericId = /^\d+$/.test(roomKey);

    const roomParam = isNumericId
      ? `room_id=${encodeURIComponent(roomKey)}`
      : `alias=${encodeURIComponent(roomKey)}`;

    const url =
      `${WS_BASE}/ws?` +
  roomParam;

wsState._lastDial = {
  roomName,
  hadRoomPass: !!roomPass,
  usedAlias: !/^\d+$/.test((roomName || "").trim()),
  source: String(source || "manual"),
  ts: Date.now()
};

    ws = new WebSocket(url);

  ws.onopen = () => {
    if (gen !== wsGen) return;

    ws.send(JSON.stringify({
      type: "auth",
      token: wsState.token,
      room_pass: wsState.roomPass || ""   // or roomPass || ""
    }));

    wsState.connected = true;
    reconnectAttempt = 0;
    clearReconnectTimer();
    startWsPing();
    broadcastToPanels({ type: "status", online: true, reconnecting: false, connecting: false });
  };

    ws.onmessage = (e) => {
      if (gen !== wsGen) return;
      try {
        const data = JSON.parse(e.data);

        // --- banned / auth_state forced logout ---
        try {
          if (data?.type === "banned") {
            const why = (data?.ban_reason || "").trim();
            const msg = (data?.message || "").trim() || ("User is banned" + (why ? (": " + why) : ""));
            handleBannedLogout(msg).catch(() => {});
            return;
          }
          if (data?.type === "auth_state" && data?.loggedIn === false && String(data?.reason || "") === "banned") {
            const why = (data?.ban_reason || "").trim();
            const msg = (data?.message || "").trim() || ("User is banned" + (why ? (": " + why) : ""));
            handleBannedLogout(msg).catch(() => {});
            return;
          }
        } catch {}

        const isPresence =
          data?.type === "presence" ||
          data?.event === "presence" ||
          data?.kind === "presence";

        if (isPresence) {
          const rid = Number(data?.room_id);
          if (Number.isInteger(rid) && rid > 0) wsState.roomId = rid;
          const list =
            data.online ??
            data.users ??
            data.members ??
            data.payload?.online ??
            data.payload?.users ??
            data.payload?.members ??
            data.data?.online ??
            data.data?.users ??
            data.data?.members ??
            [];

          broadcastToPanels({
            type: "presence",
            online: Array.isArray(list) ? list : [],
            room_id: data.room_id ?? null,
            room_name: data.room_name ?? null,
            ts: data.ts ?? null
          });
          return;
        }

        if (data?.from && data?.text) {
          const rid = Number(data?.room_id);
          if (Number.isInteger(rid) && rid > 0) wsState.roomId = rid;
          broadcastToPanels({
            type: "message",
            from: data.from,
            text: data.text,
            room_id: data.room_id ?? null,
            room_name: data.room_name ?? null,
            ts: data.ts ?? null
          });
          return;
        }

        broadcastToPanels({ type: "raw", data });
      } catch {
        broadcastToPanels({ type: "raw_text", text: String(e.data) });
      }
    };

ws.onclose = (ev) => {
  if (gen !== wsGen) return;

  const closeCode = ev?.code ?? 0;
  const closeReason = ev?.reason ?? "";
  const wasClean = !!ev?.wasClean;

  swarn("WS close", {
    url,
    code: closeCode,
    reason: closeReason,
    wasClean,
    readyState: ws?.readyState,
  });

  stopWsPing();
  wsState.connected = false;

  const isPolicyOrAuthClose = (closeCode === 1008 || closeCode === 1013 || closeCode === 1009);

  const md = !!manualDisconnect;
  const last = wsState._lastDial;
  const looksLikeHandshakeFail =
    closeCode === 1006 &&
    last &&
    (Date.now() - (last.ts || 0)) < 5000;

  if (!md && looksLikeHandshakeFail) {

    if (last && !last.hadRoomPass) {
      broadcastToPanels({ type: "auth_needed", roomName: last.roomName });
      broadcastToPanels({ type: "status", online: false, reconnecting: false, connecting: false });
      broadcastToPanels({ type: "ws_closed", code: closeCode, reason: closeReason, wasClean });
      return;
    }

    broadcastToPanels({ type: "error", message: "WS closed before open. Check token/room access/origin/proxy." });
    broadcastToPanels({ type: "status", online: false, reconnecting: false, connecting: false });
    broadcastToPanels({ type: "ws_closed", code: closeCode, reason: closeReason, wasClean });
    return;
  }

  const shouldReconnect = !md && !isPolicyOrAuthClose;

  broadcastToPanels({
    type: "status",
    online: false,
    reconnecting: shouldReconnect,
    connecting: false
  });

  broadcastToPanels({
    type: "ws_closed",
    code: closeCode,
    reason: closeReason,
    wasClean
  });

  if (shouldReconnect) {
    scheduleReconnect(`close ${closeCode} ${closeReason}`.trim());
    return;
  }

  if (isPolicyOrAuthClose) {
    const r = String(closeReason || "").toLowerCase();
    let msg = `Connection closed (${closeCode}). ${closeReason}`.trim();

    const autoDialDenied =
      last &&
      String(last.source || "") === "auto" &&
      (Date.now() - Number(last.ts || 0)) < 15000 &&
      closeCode === 1008 &&
      (r.includes("forbidden") || r.includes("no access") || r.includes("room not found") || r.includes("bad room password"));

    // Suppress noisy startup popup when auto-connect targets stale/inaccessible room.
    if (autoDialDenied) {
      try { chrome.storage.local.remove("conn"); } catch {}
      swarn("Auto-connect denied; suppressed UI error and cleared saved conn", {
        roomName: last?.roomName || "",
        code: closeCode,
        reason: closeReason || "",
      });
      return;
    }

    if (closeCode === 1013) {
      if (r.includes("too many bad passwords")) msg = "Too many wrong passwords. Please wait a bit and try again.";
      else if (r.includes("rate limited")) msg = "Rate limited. Please wait and try again.";
      else msg = "Server asked to retry later (rate limited).";
    } else if (closeCode === 1009) {
      msg = "Message too big.";
    } else {
      // 1008
      if (r.includes("banned")) {
        const bm = closeReason || "User is banned";
        handleBannedLogout(bm).catch(() => {});
        return;
      }
      if (r.includes("no access")) msg = "No access: you are not a member of this room (invite required).";
      else if (r.includes("bad room password")) msg = "Wrong room password.";
      else if (r.includes("room not found")) msg = "Room not found.";
      else msg = `Access denied (1008). ${closeReason}`.trim();
    }

    broadcastToPanels({ type: "error", message: msg });
  }
};

    ws.onerror = (e) => {
      if (gen !== wsGen) return;
      swarn("WS error", e);
      broadcastToPanels({ type: "error", message: "WebSocket error" });
    };

  } catch (e) {
    serr("connectWs failed:", e);
    broadcastToPanels({ type: "status", online: false, reconnecting: false, connecting: false });
    broadcastToPanels({ type: "error", message: "Connect failed: " + (e?.message || e) });
  } finally {
    wsConnecting = false;
  }
}

// --- Port API from panel.js ---
chrome.runtime.onConnect.addListener((port) => {
  const sender = port.sender || {};
  const url = String(sender.url || "");
  const extPrefix = `chrome-extension://${chrome.runtime.id}/`;

  if (sender?.id && sender.id !== chrome.runtime.id) {
    swarn("Rejecting port from foreign extension:", sender.id);
    try { port.disconnect(); } catch {}
    return;
  }

  // Content scripts always carry sender.tab; extension pages (panel, login) never do.
  if (sender.tab) {
    swarn("Rejecting port from content script, tab:", sender.tab.id);
    try { port.disconnect(); } catch {}
    return;
  }

  // Require an explicit, known extension-page URL.
  // Removed the previous "!url" fallback which would have accepted connections
  // from any sender that had no URL (native messaging, unknown contexts, etc.)
  // and could have allowed unlock_master_take to leak the master key.
  const ok =
    url.startsWith(`${extPrefix}panel.html`) ||
    url.startsWith(`${extPrefix}login.html`);

  if (!ok) {
    swarn("Rejecting port (not panel/login):", url || "(empty)");
    try { port.disconnect(); } catch {}
    return;
  }

  ports.add(port);

  chrome.storage.local.get(["sw_last_error"], (d) => {
    if (d?.sw_last_error) {
      safePortPost(port, { type: "sw_last_error", ...d.sw_last_error });
    }
  });

  safePortPost(port, { type: "status", online: !!wsState.connected });

  chrome.storage.session.get(
    ["pendingRoomFromSelection", "pendingRoomFromSelectionMode"],
    (data) => {
      const p = data?.pendingRoomFromSelection;

      if (p) {
        try {
          port.postMessage({ type: "context_room_pending", payload: p });
          chrome.storage.session.remove(["pendingRoomFromSelection", "pendingRoomFromSelectionMode"]);
        } catch (e) {
          swarn("Failed to post pending context to newly connected panel", e);
        }
      }
    }
  );

port.onMessage.addListener((msg) => {
  (async () => {
    async function fetchJson(url, opts = {}) {
      // helper: set/replace Authorization header
      const withAuth = (baseOpts, token) => {
        const o = { ...(baseOpts || {}) };
        const h0 = (o.headers instanceof Headers) ? Object.fromEntries(o.headers.entries())
                  : (o.headers && typeof o.headers === "object") ? { ...o.headers }
                  : {};
        if (token) h0["Authorization"] = "Bearer " + token;
        o.headers = h0;
        return o;
      };

      // 1) first try
      let r = await fetch(url, opts);
      let body = await readBody(r);

      // 2) if unauthorized once -> refresh -> retry once
      if (r.status === 401 && !opts.__retried401) {
        try {
          const ok = await refreshNowOnce(); // updates wsState + session on success
          if (ok && wsState.token) {
            const opts2 = { ...(opts || {}), __retried401: true };
            r = await fetch(url, withAuth(opts2, wsState.token));
            body = await readBody(r);
          }
        } catch {}
      }

      if (!r.ok) {
        const detail =
          body && typeof body === "object" && body.detail
            ? body.detail
            : typeof body === "string"
              ? body
              : "";
        throw new Error(detail || `${r.status} ${r.statusText}`.trim());
      }

      return body;
    }

    try {
      if (!msg || !msg.type) return;
	  
	  const post = (m) => safePortPost(port, m);
      try {
        _preflightSensitivePortMessage(port, msg);
      } catch (secErr) {
        post({ type: "error", message: secErr?.message || String(secErr) });
        return;
      }

      // Ensure server config is loaded before any network operation
      await _serverConfigReady;

      // --- ping ---
      if (msg.type === "ping") {
        try {
          post({ type: "pong", ts: Date.now() });
        } catch {}
        return;
      }

      // --- server config reload ---
      if (msg.type === "server_config_updated") {
        await _loadServerConfig();
        // Drop any open WS connections — they point at the old server
        try { closeWs({ manual: true }); } catch {}
        try { closeDmWs({ manual: true }); } catch {}
        try { closeNotifyWs({ manual: true }); } catch {}
        try { dmDeliverySecrets.clear(); } catch {}
        return;
      }

if (msg.type === "unlock_handoff_begin") {
  try {
    const reqId = String(msg.reqId || "").trim();
    const username = String(msg.username || "").trim().toLowerCase();
    _checkUnlockRateLimit(username); // A2: reject early if user is rate-limited
    const out = await beginUnlockHandoff(port, reqId, username);
    post({
      type: "unlock_handoff_begin_res",
      reqId,
      ok: true,
      server_pub_b64: out.serverPubB64,
      nonce_b64: out.nonceB64,
    });
  } catch (e) {
    post({ type: "unlock_handoff_begin_res", reqId: String(msg?.reqId || ""), ok: false, error: e?.message || String(e) });
  }
  return;
}

if (msg.type === "unlock_handoff_commit") {
  const reqId = String(msg.reqId || "").trim();
  // Peek username before commitUnlockHandoff deletes the session (one-shot replay guard)
  const _commitUsername = _unlockHandoffSessions.get(reqId)?.username || "";
  try {
    const applied = await commitUnlockHandoff(port, msg);
    if (_commitUsername) _recordUnlockAttempt(_commitUsername, true); // A2: reset on success
    await maybePublishAfterUnlock();
    if (applied.appliedKek) {
      post({ type: "unlock_kek_set_ok", ok: true, via: "secure_handoff" });
    }
    post({
      type: "unlock_handoff_commit_res",
      reqId,
      ok: true,
      applied_master: !!applied.appliedMaster,
      applied_kek: !!applied.appliedKek,
    });
  } catch (e) {
    if (_commitUsername) _recordUnlockAttempt(_commitUsername, false); // A2: exponential backoff on failure
    post({ type: "unlock_handoff_commit_res", reqId, ok: false, error: e?.message || String(e) });
    post({ type: "unlock_kek_set_ok", ok: false, error: e?.message || String(e), via: "secure_handoff" });
  }
  return;
}

// Legacy plaintext unlock transport is disabled.
if (msg.type === "unlock_master_set") {
  post({ type: "unlock_master_set_ok", ok: false, error: "Legacy unlock transport disabled; use secure handoff" });
  return;
}

if (msg.type === "unlock_master_take") {
  const reqUser = normalizeUnlockUsername(msg?.username || "");
  const cachedUser = normalizeUnlockUsername(_masterB64User || "");
  let out = "";

  if (_masterB64) {
    const sameUser = !!reqUser && !!cachedUser && reqUser === cachedUser;
    const noBinding = !reqUser || !cachedUser;
    if (sameUser || noBinding) {
      out = _masterB64;
      clearMasterB64Cache(); // one-shot wipe (only on successful take)
    } else {
      swarn("unlock_master_take rejected: username mismatch", { reqUser, cachedUser });
      clearMasterB64Cache(); // wipe stale cache on mismatch — don't leave it for TTL expiry
    }
  }

  post({ type: "unlock_master_take_res", reqId: msg.reqId, master_b64: out });
  return;
}

if (msg.type === "unlock_master_clear") {
  try {
    clearMasterKey();
  } catch {}
  return;
}

// --- SEC: storage encryption for room passwords (Fix #3) ---
if (msg.type === "storage_encrypt") {
  (async () => {
    try {
      if (!_masterKey) throw new Error("master_locked");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(String(msg.plaintext || ""));
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        _masterKey,
        encoded
      );
      post({
        type: "storage_crypto_res", reqId: msg.reqId, ok: true,
        result: { iv: b64encode(iv), ct: b64encode(new Uint8Array(ciphertext)) }
      });
    } catch (e) {
      post({ type: "storage_crypto_res", reqId: msg.reqId, ok: false, error: e?.message || String(e) });
    }
  })();
  return;
}

if (msg.type === "storage_decrypt") {
  (async () => {
    try {
      if (!_masterKey) throw new Error("master_locked");
      const iv = new Uint8Array(b64decode(msg.iv));
      const ct = b64decode(msg.ct);
      const plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        _masterKey,
        ct
      );
      post({
        type: "storage_crypto_res", reqId: msg.reqId, ok: true,
        result: new TextDecoder().decode(plainBuf)
      });
    } catch (e) {
      post({ type: "storage_crypto_res", reqId: msg.reqId, ok: false, error: e?.message || String(e) });
    }
  })();
  return;
}

    // --- unlock kek (from panel) ---
if (msg.type === "unlock_kek_set") {
  post({ type: "unlock_kek_set_ok", ok: false, error: "Legacy unlock transport disabled; use secure handoff" });
  return;
}

if (msg.type === "unlock_kek_clear") {
  try {
    _unlockKekKey = null;
    _unlockKekTs = 0;
    clearIdentityCache();
  } catch {}
  return;
}

      // --- auth_get ---
      if (msg.type === "auth_get") {
        const token = await ensureAuthLoaded();

      post({
        type: "auth_state",
        loggedIn: !!token,
        username: wsState.username || "",
      });

      if (token) post({ type: "token", token });

      return;
}

// --- auth_login ---
if (msg.type === "auth_login") {
  try {
    await ensureAuthLoaded();
    clearMasterB64Cache();
    _unlockKekKey = null;
    _unlockKekTs = 0;

    const username = (msg.username || "").trim();
    let password = msg.password || "";
    _wipeMsgFields(msg, "password");
    if (!username || !password) throw new Error("Missing username/password");

    const result = await loginAndGetToken(username, password);
    password = "";  // discard ASAP

    //2FA required, ask client for TOTP code
    if (result.requires_2fa) {
      post({
        type: "auth_2fa_required",
        temp_token: result.temp_token,
        username,
      });
      return;
    }

    const token = result.access_token;
    const refreshToken = result.refresh_token || "";
    await setAuth(username, token, refreshToken);

try {
  await e2eePublishMyKey(API_BASE, token);
  pendingE2eePublish = false;
} catch (e) {
  const emsg =
    (e && (e.message || e.detail)) ? String(e.message || e.detail)
    : (typeof e === "string" ? e : (e?.toString ? e.toString() : String(e)));

  const locked =
    /identity locked/i.test(emsg) ||
    /need unlock/i.test(emsg) ||
    /locked/i.test(emsg);

  if (locked) {
    pendingE2eePublish = true;
 
    swarn("E2EE identity locked; publish deferred until unlock");
  } else {
    swarn("E2EE publish key failed:", e);
  }
}

    post({ type: "auth_ok", username });
  } catch (e) {
    const em = String(e?.message || e);
    if (em.startsWith("BANNED:")) {
      const msg = em.slice("BANNED:".length).trim() || "User is banned";
      try { await handleBannedLogout(msg); } catch {}
      post({ type: "banned", message: msg });
      return;
    }
    post({ type: "auth_error", message: "Login failed: " + em });
  }
  return;
}

// --- auth_2fa_verify (TOTP code submission) ---
if (msg.type === "auth_2fa_verify") {
  try {
    await ensureAuthLoaded();
    clearMasterB64Cache();
    _unlockKekKey = null;
    _unlockKekTs = 0;

    const tempToken = msg.temp_token || "";
    const totpCode = (msg.code || "").trim();
    const username = (msg.username || "").trim();
    if (!tempToken || !totpCode) throw new Error("Missing temp_token or TOTP code");

    const result = await verifyTotpAndGetToken(tempToken, totpCode);
    const token = result.access_token;
    const refreshToken = result.refresh_token || "";
    await setAuth(username, token, refreshToken);

    try {
      await e2eePublishMyKey(API_BASE, token);
      pendingE2eePublish = false;
    } catch (e) {
      const emsg =
        (e && (e.message || e.detail)) ? String(e.message || e.detail)
        : (typeof e === "string" ? e : (e?.toString ? e.toString() : String(e)));

      const locked =
        /identity locked/i.test(emsg) ||
        /need unlock/i.test(emsg) ||
        /locked/i.test(emsg);

      if (locked) {
        pendingE2eePublish = true;
        swarn("E2EE identity locked; publish deferred until unlock");
      } else {
        swarn("E2EE publish key failed:", e);
      }
    }

    post({ type: "auth_ok", username });
  } catch (e) {
    const em = String(e?.message || e);
    if (em.startsWith("BANNED:")) {
      const msg = em.slice("BANNED:".length).trim() || "User is banned";
      try { await handleBannedLogout(msg); } catch {}
      post({ type: "banned", message: msg });
      return;
    }
    post({ type: "auth_2fa_error", message: em });
  }
  return;
}

// --- auth_logout ---
if (msg.type === "auth_logout") {
  try {
    await ensureAuthLoaded();

    // Save token for server-side revoke, then clear state SYNCHRONOUSLY
    // so that any concurrent auth_get from login.html sees loggedIn=false immediately.
    const savedToken = wsState.token || "";

    wsState.token = "";
    wsState.refreshToken = "";
    wsState.username = "";
    wsState.roomName = "";
    wsState.roomPass = "";
    wsState.connected = false;

    try { closeWs({ manual: true }); } catch {}
    try { closeDmWs({ manual: true }); } catch {}
    try { closeNotifyWs({ manual: true }); } catch {}

    try { await clearAuth(); } catch {}

    try {
      post({ type: "auth_state", loggedIn: false, username: "" });
      broadcastToPanels({ type: "auth_state", loggedIn: false, username: "" });
    } catch {}

    // Server-side: revoke all refresh tokens (best-effort, AFTER clearing local state)
    if (savedToken) {
      try {
        await fetch(API_BASE + "/auth/logout", {
          method: "POST",
          headers: { Authorization: "Bearer " + savedToken },
        });
      } catch {}
    }

    try { await chrome.storage.local.remove(["conn"]); } catch {}

    try { pendingE2eePublish = false; } catch {}
    try {
      clearMasterKey();
      _unlockKekKey = null;
      _unlockKekTs = 0;
    } catch {}

  } catch (e) {
    // Ensure state is clean even on error
    wsState.token = "";
    wsState.refreshToken = "";
    wsState.username = "";
    try {
      clearMasterKey();
      _unlockKekKey = null;
      _unlockKekTs = 0;
    } catch {}
    try { await clearAuth(); } catch {}
    try {
      post({ type: "error", message: "Logout failed: " + (e?.message || String(e)) });
    } catch {}
  }
  return;
}

// --- change_password ---
// Crypto (decrypt + re-encrypt EPK) is done in the panel which has CryptoUtils.
// Background receives the pre-computed newEpk, calls the server, then saves.
if (msg.type === "change_password") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");
    if (!wsState.username) throw new Error("Username missing");

    const { oldPassword, newPassword, newEpk } = msg;
    _wipeMsgFields(msg, "oldPassword", "newPassword", "newEpk");
    if (!oldPassword || typeof oldPassword !== "string") throw new Error("Old password required");
    if (!newPassword || typeof newPassword !== "string") throw new Error("New password required");
    if (!newEpk || typeof newEpk !== "object" || newEpk.v !== 3) throw new Error("Invalid re-encrypted key");

    const username = normUser(wsState.username);
    const storageKey = localIdentityStorageKey(username);

    // Server-side password change (rate limited, verifies old password)
    const r = await fetch(API_BASE + "/auth/change-password", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + wsState.token,
      },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    if (!r.ok) {
      const body = await readBody(r).catch(() => ({}));
      throw new Error(body?.detail || ("Server error " + r.status));
    }

    // Persist new EPK. Refresh the device's KDF pin to match the new EPK —
    // a legitimate user-initiated password change is the only place the
    // pinned algorithm is allowed to advance.
    const stored = await chrome.storage.local.get([storageKey]);
    const prev = stored?.[storageKey] || {};
    const newKdfNameRaw = String(newEpk?.kdf?.name || "").trim();
    const newKdfName =
      /^argon2id$/i.test(newKdfNameRaw) ? "Argon2id" :
      /^pbkdf2$/i.test(newKdfNameRaw)   ? "PBKDF2"   :
      newKdfNameRaw || prev?.kdf_name_pinned || "";
    const newIdentity = {
      ...prev,
      encrypted_private_key: newEpk,
      kdf_name_pinned: newKdfName,
      updated_at: Date.now(),
    };
    await chrome.storage.local.set({ [storageKey]: newIdentity });

    post({ type: "change_password_res", ok: true });
  } catch (e) {
    post({ type: "change_password_res", ok: false, message: e?.message || String(e) });
  }
  return;
}

// === TOTP 2FA management (from panel settings) ===

// --- totp_status: check if 2FA is enabled ---
if (msg.type === "totp_status") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/auth/totp/status", {
      method: "GET",
      headers: { Authorization: "Bearer " + wsState.token },
    });
    if (!r.ok) throw new Error(`${r.status}`);
    const data = await r.json();
    post({ type: "totp_status", enabled: !!data.enabled });
  } catch (e) {
    post({ type: "totp_status_error", message: String(e?.message || e) });
  }
  return;
}

// --- totp_setup: initiate TOTP setup, get secret + otpauth URI ---
if (msg.type === "totp_setup") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/auth/totp/setup", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + wsState.token,
        "Content-Type": "application/json",
      },
    });
    if (!r.ok) {
      const txt = await r.text();
      let detail = txt;
      try { detail = JSON.parse(txt).detail || txt; } catch {}
      throw new Error(detail);
    }
    const data = await r.json();
    // server returns: { secret, otpauth_uri, qr_svg? }
    post({
      type: "totp_setup_data",
      secret: data.secret,
      otpauth_uri: data.otpauth_uri,
      qr_svg: data.qr_svg || "",
    });
  } catch (e) {
    post({ type: "totp_setup_error", message: String(e?.message || e) });
  }
  return;
}

// --- totp_verify_setup: confirm setup with first code ---
if (msg.type === "totp_verify_setup") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const code = (msg.code || "").trim();
    if (!code) throw new Error("Missing TOTP code");

    const r = await fetch(API_BASE + "/auth/totp/verify-setup", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + wsState.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code }),
    });
    if (!r.ok) {
      const txt = await r.text();
      let detail = txt;
      try { detail = JSON.parse(txt).detail || txt; } catch {}
      throw new Error(detail);
    }
    const data = await r.json();
    post({
      type: "totp_setup_complete",
      backup_codes: data.backup_codes || [],
    });
  } catch (e) {
    post({ type: "totp_setup_error", message: String(e?.message || e) });
  }
  return;
}

// --- totp_disable: turn off 2FA ---
if (msg.type === "totp_disable") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const code = (msg.code || "").trim();
    let password = msg.password || "";
    _wipeMsgFields(msg, "password", "code");
    if (!code && !password) throw new Error("Provide TOTP code or password");

    const r = await fetch(API_BASE + "/auth/totp/disable", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + wsState.token,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ code, password }),
    });
    password = "";  // discard
    if (!r.ok) {
      const txt = await r.text();
      let detail = txt;
      try { detail = JSON.parse(txt).detail || txt; } catch {}
      throw new Error(detail);
    }
    post({ type: "totp_disabled" });
  } catch (e) {
    post({ type: "totp_disable_error", message: String(e?.message || e) });
  }
  return;
}

// WS: auto-connect right after login (for notifications)
if (msg.type === "ws_connect_auto") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await chrome.storage.local.get("conn");
    const key = String(r?.conn?.room || r?.conn?.roomName || r?.conn?.key || "").trim();

    if (!key) {
      post({ type: "status", online: false, reconnecting: false });
      return;
    }

    await connectWs({ roomName: key, roomPass: "", force: false, source: "auto" });

  } catch (e) {
    post({ type: "status", online: false, reconnecting: false });
  }
  return;
}

if (msg.type === "rooms_mine") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) {
      post({ type: "rooms_mine", rooms: [] });
      return;
    }

    const rooms = await fetchJson(API_BASE + "/rooms/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "rooms_mine", rooms: Array.isArray(rooms) ? rooms : [] });
  } catch (e) {
    post({ type: "rooms_mine", rooms: [] });
    post({ type: "error", message: "Failed to fetch the room list:" + e.message });
  }
  return;
}

if (msg.type === "rooms_public_list") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) {
      post({ type: "rooms_public_list", ok: true, rooms: [] });
      return;
    }

    const rooms = await fetchJson(API_BASE + "/rooms/public/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "rooms_public_list", ok: true, rooms: Array.isArray(rooms) ? rooms : [] });
  } catch (e) {
    post({ type: "rooms_public_list", ok: false, rooms: [], message: e.message });
  }
  return;
}

if (msg.type === "rooms_join_request") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!roomId) throw new Error("Missing roomId");

    let password = (msg.password || "").trim();
    _wipeMsgFields(msg, "password");

    const body = await fetchJson(API_BASE + `/rooms/${encodeURIComponent(roomId)}/join-request`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ password })
    });
    password = "";  // discard

    post({ type: "rooms_join_request", ok: true, roomId, body });
  } catch (e) {
    post({ type: "rooms_join_request", ok: false, message: e.message });
  }
  return;
}

if (msg.type === "rooms_join_requests_list") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!roomId) throw new Error("Missing roomId");

    const items = await fetchJson(API_BASE + `/rooms/${encodeURIComponent(roomId)}/join-requests`, {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "rooms_join_requests_list", ok: true, roomId, items: Array.isArray(items) ? items : [] });
  } catch (e) {
    post({ type: "rooms_join_requests_list", ok: false, message: e.message, items: [] });
  }
  return;
}

if (msg.type === "rooms_join_requests_all") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const rooms = await fetchJson(API_BASE + "/rooms/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const my = Array.isArray(rooms) ? rooms : [];
    const ownedPublic = my.filter(r => !!r && !!r.is_owner && !!r.is_public);

    const out = [];
    for (const r of ownedPublic) {
      const rid = Number(r.id);
      if (!rid) continue;

      const items = await fetchJson(API_BASE + `/rooms/${encodeURIComponent(rid)}/join-requests`, {
        method: "GET",
        headers: { "Authorization": "Bearer " + wsState.token }
      });

      const arr = Array.isArray(items) ? items : [];
      for (const it of arr) {
        const username = String(it?.username || "").trim();
        if (!username) continue;
        out.push({
          room_id: rid,
          room_name: String(r.name || r.alias || rid),
          room_alias: String(r.alias || ""),
          username
        });
      }
    }

    post({ type: "rooms_join_requests_all", ok: true, items: out });
  } catch (e) {
    post({ type: "rooms_join_requests_all", ok: false, message: e.message, items: [] });
  }
  return;
}

if (msg.type === "rooms_join_approve") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const username = (msg.username || "").trim();
    if (!roomId) throw new Error("Missing roomId");
    if (!username) throw new Error("Missing username");

    const body = await fetchJson(API_BASE + `/rooms/${encodeURIComponent(roomId)}/join-requests/${encodeURIComponent(username)}/approve`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "rooms_join_approve", ok: true, roomId, username, body });
  } catch (e) {
    post({ type: "rooms_join_approve", ok: false, message: e.message });
  }
  return;
}

if (msg.type === "rooms_join_reject") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const username = (msg.username || "").trim();
    if (!roomId) throw new Error("Missing roomId");
    if (!username) throw new Error("Missing username");

    const body = await fetchJson(API_BASE + `/rooms/${encodeURIComponent(roomId)}/join-requests/${encodeURIComponent(username)}/reject`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "rooms_join_reject", ok: true, roomId, username, body });
  } catch (e) {
    post({ type: "rooms_join_reject", ok: false, message: e.message });
  }
  return;
}
        // --- rooms_delete ---
        if (msg.type === "rooms_delete") {
          try {
			  await ensureAuthLoaded();
            if (!wsState.token) throw new Error("Not logged in");

            const roomId = Number(msg.roomId);
            if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

            const r = await fetch(API_BASE + "/rooms/" + encodeURIComponent(roomId), {
              method: "DELETE",
              headers: { "Authorization": "Bearer " + wsState.token }
            });

            if (!r.ok) {
              const txt = await r.text();
              throw new Error(`${r.status}: ${txt}`);
            }

            post({ type: "rooms_delete", ok: true, roomId });
          } catch (e) {
            post({ type: "rooms_delete", ok: false, message: "Delete room failed: " + e.message });
          }
          return;
        }

// --- friends_request ---
if (msg.type === "friends_request") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const username = (msg.username || "").trim();
    if (!username) throw new Error("Missing username");

    const r = await fetch(API_BASE + "/friends/request", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({
      type: "friends_request",
      ok: true,
      username,
      status: body?.status,
      message: body?.message
    });
  } catch (e) {
    post({ type: "friends_request", ok: false, message: "Friends request failed: " + e.message });
  }
  return;
}

// --- friends_list (accepted) ---
if (msg.type === "friends_list") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/friends/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_list", ok: true, friends: Array.isArray(body) ? body : [] });
  } catch (e) {
    post({ type: "friends_list", ok: false, message: "Friends list failed: " + e.message, friends: [] });
  }
  return;
}

// --- friends_requests_incoming ---
if (msg.type === "friends_requests_incoming") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/friends/requests/incoming", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_requests_incoming", ok: true, items: Array.isArray(body) ? body : [] });
  } catch (e) {
    post({ type: "friends_requests_incoming", ok: false, message: "Incoming requests failed: " + e.message, items: [] });
  }
  return;
}

if (msg.type === "friends_requests_outgoing") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/friends/requests/outgoing", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_requests_outgoing", ok: true, items: Array.isArray(body) ? body : [] });
  } catch (e) {
    post({ type: "friends_requests_outgoing", ok: false, message: "Outgoing requests failed: " + e.message, items: [] });
  }
  return;
}

// --- friends_accept ---
if (msg.type === "friends_accept") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const username = (msg.username || "").trim();
    if (!username) throw new Error("Missing username");

    const r = await fetch(API_BASE + "/friends/requests/accept", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_accept", ok: true, username });
  } catch (e) {
    post({ type: "friends_accept", ok: false, message: "Accept failed: " + e.message });
  }
  return;
}

if (msg.type === "friends_decline") {
  try {
	  await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const username = (msg.username || "").trim();
    if (!username) throw new Error("Missing username");

    const r = await fetch(API_BASE + "/friends/requests/decline", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_decline", ok: true, username });
  } catch (e) {
    post({ type: "friends_decline", ok: false, message: "Decline failed: " + e.message });
  }
  return;
}

if (msg.type === "friends_remove") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const username = (msg.username || "").trim();
    if (!username) throw new Error("Missing username");

    const r = await fetch(API_BASE + "/friends/remove", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "friends_remove", ok: true, username });
  } catch (e) {
    post({ type: "friends_remove", ok: false, message: "Remove friend failed: " + e.message });
  }
  return;
}

// =======================
// DM: open dialog with user
// =======================
if (msg.type === "dm_open") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const username = (msg.username || "").trim();
    if (!username) throw new Error("Missing username");

    const data = await fetchJson(API_BASE + "/dm/open", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    post({
      type: "dm_open_ok",
      ok: true,
      thread_id: data.thread_id,
      peer_username: data.peer_username || username
    });
  } catch (e) {
    post({ type: "dm_open_ok", ok: false, message: "DM open failed: " + e.message });
  }
  return;
}

// =======================
// DM: list dialogs
// =======================
if (msg.type === "dm_list") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const data = await fetchJson(API_BASE + "/dm/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    post({ type: "dm_list_res", ok: true, items: Array.isArray(data) ? data : [] });
  } catch (e) {
    post({ type: "dm_list_res", ok: false, message: "DM list failed: " + e.message, items: [] });
  }
  return;
}

// =======================
// DM: delete thread (self / both)
// =======================
if (msg.type === "dm_delete") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const threadId = Number(msg.thread_id);
    const scope = String(msg.scope || "self").trim().toLowerCase();
    if (!Number.isInteger(threadId) || threadId <= 0) throw new Error("Invalid thread_id");
    if (scope !== "self" && scope !== "both") throw new Error("Invalid scope");

    const data = await fetchJson(API_BASE + `/dm/${encodeURIComponent(threadId)}/delete`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ scope }),
    });

    post({
      type: "dm_delete_res",
      ok: true,
      reqId: String(msg.reqId || ""),
      thread_id: threadId,
      scope: data?.scope || scope,
      pending_confirmation: !!data?.pending_confirmation,
      confirm_ttl_sec: Number(data?.confirm_ttl_sec || 0),
    });
  } catch (e) {
    post({
      type: "dm_delete_res",
      ok: false,
      reqId: String(msg.reqId || ""),
      thread_id: Number(msg.thread_id || 0),
      scope: String(msg.scope || "self"),
      message: "DM delete failed: " + e.message,
    });
  }
  return;
}

// =======================
// DM: history
// =======================
if (msg.type === "dm_history") {
  try {
    await ensureAuthLoaded();
    if (!wsState.token) throw new Error("Not logged in");

    const threadId = Number(msg.thread_id);
    const requestedLimit = Math.max(1, Math.min(Number(msg.limit || 50), 2000));
    const beforeId = Number(msg.before_id || 0);
    let nextBefore = Number.isInteger(beforeId) && beforeId > 0 ? beforeId : null;
    if (!Number.isInteger(threadId) || threadId <= 0) throw new Error("Invalid thread_id");

    const PAGE_LIMIT = 200;
    const maxPages = Math.max(1, Math.ceil(requestedLimit / PAGE_LIMIT) + 1);
    let merged = [];
    let hasMore = false;

    for (let page = 0; page < maxPages && merged.length < requestedLimit; page++) {
      const chunkLimit = Math.max(1, Math.min(requestedLimit - merged.length, PAGE_LIMIT));
      const qs =
        `limit=${encodeURIComponent(chunkLimit)}` +
        (nextBefore ? `&before_id=${encodeURIComponent(nextBefore)}` : "");

      const data = await fetchJson(
        API_BASE + `/dm/${encodeURIComponent(threadId)}/history?${qs}`,
        {
          method: "GET",
          headers: { "Authorization": "Bearer " + wsState.token }
        }
      );
      const chunk = Array.isArray(data) ? data : (Array.isArray(data?.messages) ? data.messages : []);
      if (!chunk.length) {
        hasMore = false;
        break;
      }

      if (page === 0) merged = chunk;
      else merged = chunk.concat(merged);

      hasMore = !!(data && typeof data === "object" && data.has_more);
      if (!hasMore) break;

      const oldestId = (data && typeof data === "object") ? Number(data.oldest_id || 0) : 0;
      if (!Number.isInteger(oldestId) || oldestId <= 0) break;
      nextBefore = oldestId;
    }

    const overfetch = Math.max(0, merged.length - requestedLimit);
    const messages = overfetch > 0 ? merged.slice(merged.length - requestedLimit) : merged;
    const oldestId = messages.length ? (messages[0]?.id ?? null) : null;

    post({
      type: "dm_history_res",
      ok: true,
      thread_id: threadId,
      messages,
      has_more: hasMore || overfetch > 0,
      oldest_id: oldestId,
      append_older: !!msg.append_older,
    });
  } catch (e) {
    post({
      type: "dm_history_res",
      ok: false,
      thread_id: msg.thread_id,
      message: "DM history failed: " + e.message,
      messages: [],
      has_more: false,
      oldest_id: null,
      append_older: !!msg.append_older,
    });
  }
  return;
}

// =======================
// DM: connect WS
// =======================
if (msg.type === "dm_connect") {
  try {
    const threadId = Number(msg.thread_id);
    if (!Number.isInteger(threadId) || threadId <= 0) throw new Error("Invalid thread_id");

    const peer = String(msg.peer_username || "").trim();
    if (peer) {
      dmThreadPeers.set(String(threadId), peer);
      dmState.peer = peer;
    }

    await connectDmWs({ threadId });
    // Refresh delivery secret on (re)connect in case it was rotated server-side.
    dmDeliverySecrets.delete(String(threadId));
	try { await ensureDmDeliverySecret(threadId); } catch (e) {
    console.warn("UD delivery secret prefetch failed:", e?.message || e);
  }
    post({ type: "dm_connect_res", ok: true, thread_id: threadId });
  } catch (e) {
    post({ type: "dm_connect_res", ok: false, message: "DM connect failed: " + e.message });
  }
  return;
}

if (msg.type === "dm_disconnect") {
  closeDmWs({ manual: true });
  post({ type: "dm_status", online: false });
  return;
}

// =======================
// DM: send message
// =======================
if (msg.type === "dm_send") {
  await ensureAuthLoaded();

  const threadId = Number(msg.thread_id);
  const textMsg = typeof msg.text === "string" ? msg.text : "";
  if (!Number.isInteger(threadId) || threadId <= 0) return;
  if (!textMsg.trim()) return;

  try {
    // 1) ciphertext_b64 = base64url(utf8(JSON_ENCRYPTED_STRING))
    const ptBytes = utf8enc(textMsg);
    const ciphertext_b64 = b64urlEncode(ptBytes);

    const url = API_BASE + "/ud/dm/send";
    const sep = utf8enc("|");
    const tidB = utf8enc(String(threadId));
    const h = await sha256U8(ptBytes);

    const udSendWithSecret = async (secB64) => {
      // Generate fresh ts + nonce on every attempt to avoid replay/expiry rejects.
      const ts = Date.now();
      const nonce = crypto.getRandomValues(new Uint8Array(16));
      const nonce_b64 = b64urlEncode(nonce);
      const tsB = utf8enc(String(ts));
      const secret = b64urlToU8(secB64);
      const msgU8 = concatU8(tidB, sep, tsB, sep, nonce, sep, h);
      const tagU8 = await hmacSha256(secret, msgU8);
      const tag_b64 = b64urlEncode(tagU8);
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          thread_id: threadId,
          ts,
          nonce_b64,
          ciphertext_b64,
          tag_b64,
        }),
      });
      const raw = await r.text();
      let data = {};
      try { data = JSON.parse(raw); } catch {}
      const detail = data?.detail ? JSON.stringify(data.detail) : (raw || `HTTP ${r.status}`);
      return { ok: r.ok, status: r.status, detail };
    };

    // 3) delivery secret (auth-only fetch, cached)
    let secB64 = await ensureDmDeliverySecret(threadId);
    let sendRes = await udSendWithSecret(secB64);

    // Secret may be stale (rotation) or expired (TTL); retry once with fresh secret.
    // Server returns uniform 403 for all auth failures (expired, missing, bad HMAC).
    const needsRefresh = !sendRes.ok && (
      sendRes.status === 401 || sendRes.status === 403
    );
    if (needsRefresh) {
      dmDeliverySecrets.delete(String(threadId));
      secB64 = await ensureDmDeliverySecret(threadId);
      sendRes = await udSendWithSecret(secB64);
    }

    if (!sendRes.ok) {
      post({ type: "dm_send_res", ok: false, thread_id: threadId, message: sendRes.detail });
      return;
    }

    post({ type: "dm_send_res", ok: true, thread_id: threadId });
  } catch (e) {
    post({
      type: "dm_send_res",
      ok: false,
      thread_id: Number(msg.thread_id || 0),
      message: String(e?.message || e),
    });
  }
  return;
}

        // --- connect ---
        if (msg.type === "connect") {
			await ensureAuthLoaded();
          const { roomName, roomPass, force } = msg;

          if (!roomName) {
            post({ type: "error", message: "Room ID/alias is required" });
            return;
          }

          await connectWs({
            roomName: roomName.trim(),
            roomPass: roomPass || "",
			force: !!force
          });
          return;
        }

if (msg.type === "history_get") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const requestedLimit = Math.max(1, Math.min(Number(msg.limit || 50), 2000));
    const beforeId = Number(msg.before_id || 0);
    let nextBefore = Number.isInteger(beforeId) && beforeId > 0 ? beforeId : null;
    if (!Number.isInteger(roomId) || roomId <= 0) {
      throw new Error("Missing/invalid roomId");
    }

    const PAGE_LIMIT = 200;
    const maxPages = Math.max(1, Math.ceil(requestedLimit / PAGE_LIMIT) + 1);
    let merged = [];
    let hasMore = false;

    for (let page = 0; page < maxPages && merged.length < requestedLimit; page++) {
      const chunkLimit = Math.max(1, Math.min(requestedLimit - merged.length, PAGE_LIMIT));
      const url =
        API_BASE +
        `/rooms/${encodeURIComponent(roomId)}/history` +
        `?limit=${encodeURIComponent(chunkLimit)}` +
        (nextBefore ? `&before_id=${encodeURIComponent(nextBefore)}` : "");

      const data = await fetchJson(url, {
        method: "GET",
        headers: {
          "Authorization": "Bearer " + wsState.token
        }
      });
      const chunk = (typeof data === "object" && Array.isArray(data?.messages)) ? data.messages : [];
      if (!chunk.length) {
        hasMore = false;
        break;
      }

      if (page === 0) merged = chunk;
      else merged = chunk.concat(merged);

      hasMore = !!(typeof data === "object" && data?.has_more);
      if (!hasMore) break;

      const oldestId = (typeof data === "object") ? Number(data?.oldest_id || 0) : 0;
      if (!Number.isInteger(oldestId) || oldestId <= 0) break;
      nextBefore = oldestId;
    }

    const overfetch = Math.max(0, merged.length - requestedLimit);
    const messages = overfetch > 0 ? merged.slice(merged.length - requestedLimit) : merged;
    const oldestId = messages.length ? (messages[0]?.id ?? null) : null;

    post({
      type: "history_res",
      ok: true,
      roomId,
      messages,
      has_more: hasMore || overfetch > 0,
      oldest_id: oldestId,
      append_older: !!msg.append_older,
    });

  } catch (e) {
    const msgText =
      (e instanceof Error) ? e.message :
      (typeof e === "string") ? e :
      JSON.stringify(e);

    post({
      type: "history_res",
      ok: false,
      roomId: msg.roomId,
      message: "History failed: " + msgText
    });
  }
  return;
}

// --- rooms_invite ---
if (msg.type === "rooms_invite") {
	await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const username = (msg.username || "").trim();
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");
    if (!username || username.length > 255) throw new Error("Missing/invalid username");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/invite`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail =
        (body && typeof body === "object" && body.detail) ? body.detail :
        (typeof body === "string" ? body : "");
      throw new Error(detail || `${r.status} ${r.statusText}`.trim());
    }

    post({ type: "rooms_invite", ok: true, roomId, username });
  } catch (e) {
    post({ type: "rooms_invite", ok: false, message: "Invite failed: " + e.message });
  }
  return;
}

// --- rooms_invites_incoming (pending invites for current user) ---
if (msg.type === "rooms_invites_incoming") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const r = await fetch(API_BASE + "/rooms/invites", {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "rooms_invites_incoming", ok: true, items: Array.isArray(body) ? body : [] });
  } catch (e) {
    post({ type: "rooms_invites_incoming", ok: false, message: "Invites fetch failed: " + e.message, items: [] });
  }
  return;
}

// --- rooms_invite_accept ---
if (msg.type === "rooms_invite_accept") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/invites/accept`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "rooms_invite_accept", ok: true, roomId });
  } catch (e) {
    post({ type: "rooms_invite_accept", ok: false, message: "Invite accept failed: " + e.message });
  }
  return;
}

// --- rooms_invite_decline ---
if (msg.type === "rooms_invite_decline") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/invites/decline`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `${r.status}`);
    }

    post({ type: "rooms_invite_decline", ok: true, roomId });
  } catch (e) {
    post({ type: "rooms_invite_decline", ok: false, message: "Invite decline failed: " + e.message });
  }
  return;
}

// --- rooms_leave ---
if (msg.type === "rooms_leave") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/leave`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail =
        (body && typeof body === "object" && body.detail) ? body.detail :
        (typeof body === "string" ? body : "");
      throw new Error(detail || `${r.status} ${r.statusText}`.trim());
    }

    closeWs({ manual: true });

    post({ type: "rooms_leave", ok: true, roomId });

    try {
      const rooms = await fetchJson(API_BASE + "/rooms/list", {
        method: "GET",
        headers: { "Authorization": "Bearer " + wsState.token }
      });
      broadcastToPanels({ type: "rooms_mine", rooms: Array.isArray(rooms) ? rooms : [] });
    } catch {}
  } catch (e) {
    post({ type: "rooms_leave", ok: false, message: "Leave failed: " + e.message });
  }
  return;
}

// --- rooms_kick ---
if (msg.type === "rooms_kick") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const username = (msg.username || "").trim();
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");
    if (!username || username.length > 255) throw new Error("Missing/invalid username");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/kick`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ username })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail =
        (body && typeof body === "object" && body.detail) ? body.detail :
        (typeof body === "string" ? body : "");
      throw new Error(detail || `${r.status} ${r.statusText}`.trim());
    }

    post({ type: "rooms_kick", ok: true, roomId, username });
  } catch (e) {
    post({ type: "rooms_kick", ok: false, message: "Kick failed: " + e.message });
  }
  return;
}

// --- rooms_set_role ---
if (msg.type === "rooms_set_role") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const username = (msg.username || "").trim();
    const role = (msg.role || "").trim().toLowerCase();

    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");
    if (!username || username.length > 255) throw new Error("Missing/invalid username");
    if (!role || !["admin", "member"].includes(role)) throw new Error("Invalid role");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/members/${encodeURIComponent(username)}/role`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token
      },
      body: JSON.stringify({ role })
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail =
        (body && typeof body === "object" && body.detail) ? body.detail :
        (typeof body === "string" ? body : "");
      throw new Error(detail || `${r.status} ${r.statusText}`.trim());
    }

    post({ type: "rooms_set_role", ok: true, roomId, username, role });
  } catch (e) {
    post({ type: "rooms_set_role", ok: false, message: "Set role failed: " + e.message });
  }
  return;
}

// --- rooms_members_get ---
if (msg.type === "rooms_members_get") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/members`, {
      method: "GET",
      headers: { "Authorization": "Bearer " + wsState.token }
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail =
        (body && typeof body === "object" && body.detail) ? body.detail :
        (typeof body === "string" ? body : "");
      throw new Error(detail || `${r.status} ${r.statusText}`.trim());
    }

post({
  type: "rooms_members_res",
  ok: true,
  roomId,
  members: Array.isArray(body) ? body : []
});
  } catch (e) {
    post({ type: "rooms_members_res", ok: false, roomId: msg.roomId, message: "Members failed: " + e.message });
  }
  return;
}

// --- rooms_meta_get ---
if (msg.type === "rooms_meta_get") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const r = await fetch(API_BASE + `/rooms/${roomId}/meta`, {
      method: "GET",
      headers: {
        "Authorization": "Bearer " + wsState.token,
      },
    });

    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const body = ct.includes("application/json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((body && body.detail) ? body.detail : (`HTTP ${r.status}`));

    post({ type: "rooms_meta_get", ok: true, roomId, meta: body });
  } catch (e) {
    post({ type: "rooms_meta_get", ok: false, roomId: msg.roomId, message: e?.message || String(e) });
  }
  return;
}

// --- rooms_meta_set ---
// payload: { roomId, title?, description?, logo_token?, logo_url?, ... }
if (msg.type === "rooms_meta_set") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    const payload = {};
    if (typeof msg.title === "string") payload.title = msg.title.trim();
    if (typeof msg.description === "string") payload.description = msg.description.trim();

    if (typeof msg.logo_token === "string" && msg.logo_token.trim()) payload.logo_token = msg.logo_token.trim();
    if (typeof msg.logo_url === "string" && msg.logo_url.trim()) payload.logo_url = msg.logo_url.trim();

    const r = await fetch(API_BASE + `/rooms/${roomId}/meta`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token,
      },
      body: JSON.stringify(payload),
    });

    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const body = ct.includes("application/json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((body && body.detail) ? body.detail : (`HTTP ${r.status}`));

    post({ type: "rooms_meta_set", ok: true, roomId, data: body });
  } catch (e) {
    post({ type: "rooms_meta_set", ok: false, error: e?.message || String(e) });
  }
  return;
}

// --- rooms_change_password ---
if (msg.type === "rooms_change_password") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");

    let password = String(msg.password ?? "");
    _wipeMsgFields(msg, "password");

    const r = await fetch(API_BASE + `/rooms/${roomId}/password`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token,
      },
      body: JSON.stringify({ password }),
    });
    password = "";

    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const body = ct.includes("application/json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((body && body.detail) ? body.detail : (`HTTP ${r.status}`));

    post({ type: "rooms_change_password", ok: true, roomId, has_password: body.has_password });
  } catch (e) {
    post({ type: "rooms_change_password", ok: false, roomId: Number(msg.roomId) || 0, message: e?.message || String(e) });
  }
  return;
}

// --- rooms_rename ---
if (msg.type === "rooms_rename") {
  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    if (!Number.isInteger(roomId) || roomId <= 0) throw new Error("Missing/invalid roomId");
    const name = String(msg.name || "").trim();
    if (!name) throw new Error("Missing room name");

    const r = await fetch(API_BASE + `/rooms/${roomId}/name`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + wsState.token,
      },
      body: JSON.stringify({ name }),
    });

    const ct = (r.headers.get("content-type") || "").toLowerCase();
    const body = ct.includes("application/json") ? await r.json() : await r.text();
    if (!r.ok) throw new Error((body && body.detail) ? body.detail : (`HTTP ${r.status}`));

    post({ type: "rooms_rename", ok: true, roomId, name: body?.name || name });
  } catch (e) {
    post({ type: "rooms_rename", ok: false, roomId: Number(msg.roomId) || 0, message: e?.message || String(e) });
  }
  return;
}

                // --- rooms_create ---
        if (msg.type === "rooms_create") {
			await ensureAuthLoaded();
          try {
            if (!wsState.token) throw new Error("Not logged in");
            const is_public = !!msg.is_public;
            const is_readonly = !!msg.is_readonly;
            const name = (msg.name || "").trim();
            let password = msg.password || "";
            _wipeMsgFields(msg, "password");

            if (!name) throw new Error("Missing room name");

            const r = await fetch(API_BASE + "/rooms", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + wsState.token
              },
              body: JSON.stringify({
                name,
                password: password || null,
                encrypted_room_key: msg.encrypted_room_key || null,
                is_public,
                is_readonly,
              })
            });

            if (!r.ok) {
              const txt = await r.text();
              if (r.status === 409) {
                post({ type: "rooms_create", ok: false, message: "Room name already exists (409)" });
                return;
              }
              throw new Error(`${r.status}: ${txt}`);
            }

            const room = await r.json();
            post({ type: "rooms_create", ok: true, room });
          } catch (e) {
            post({ type: "rooms_create", ok: false, message: "Create room failed: " + (e?.message || e) });
          }
          return;
        }

// --- room_logo_upload ---
// payload: {roomId, filename, mime, bytes (ArrayBuffer or ArrayBufferView)}
if (msg.type === "room_logo_upload") {
  const MAX_LOGO = 5 * 1024 * 1024;

  slog("logo bytes debug:", {
    has_bytes: msg.bytes instanceof ArrayBuffer,
    bytes_is_view: ArrayBuffer.isView(msg.bytes),
    has_bytes_u8: !!msg.bytes_u8,
    bytes_u8_is_view: ArrayBuffer.isView(msg.bytes_u8),
    bytes_len: msg.bytes_len,
  });

  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const filename = (msg.filename || "").trim();
    const mime = msg.mime || "application/octet-stream";

    if (!roomId) throw new Error("Missing roomId");
    if (!filename) throw new Error("Missing filename");

    // ---- Normalize incoming bytes into ArrayBuffer (ab) safely ----
    let ab = null;

    // Prefer msg.bytes, then msg.bytes_u8
    let b = null;
    if (msg.bytes instanceof ArrayBuffer || ArrayBuffer.isView(msg.bytes) || Array.isArray(msg.bytes)) {
      b = msg.bytes;
    } else if (msg.bytes_u8 && (ArrayBuffer.isView(msg.bytes_u8) || Array.isArray(msg.bytes_u8))) {
      b = msg.bytes_u8;
    } else if (msg.bytes_u8 && typeof msg.bytes_u8 === "object") {
      // might be "worst case" object with numeric keys
      b = msg.bytes_u8;
    } else if (msg.bytes && typeof msg.bytes === "object") {
      b = msg.bytes;
    }

    if (b instanceof ArrayBuffer) {
      // Already an ArrayBuffer
      ab = b;
    } else if (ArrayBuffer.isView(b) && b.buffer instanceof ArrayBuffer) {
      // TypedArray/DataView -> slice to avoid entire underlying buffer
      if (b.byteLength > MAX_LOGO) throw new Error("Logo too large (max 5MB)");
      ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    } else if (b && b.buffer instanceof ArrayBuffer) {
      // Some buffer-like object; slice if it exposes offsets
      if (typeof b.byteOffset === "number" && typeof b.byteLength === "number") {
        if (b.byteLength > MAX_LOGO) throw new Error("Logo too large (max 5MB)");
        ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
      } else {
        ab = b.buffer;
      }
    } else if (Array.isArray(b)) {
      // Plain array of bytes
      if (b.length > MAX_LOGO) throw new Error("Logo too large (max 5MB)");
      ab = new Uint8Array(b).buffer;
    } else if (b && Array.isArray(b.data)) {
      // Buffer-like: { type:"Buffer", data:[...] }
      if (b.data.length > MAX_LOGO) throw new Error("Logo too large (max 5MB)");
      ab = new Uint8Array(b.data).buffer;
    } else if (typeof msg.bytes_len === "number" && b && typeof b === "object") {
      // Worst case: plain object with numeric keys, but no view/length
      const n = msg.bytes_len >>> 0;

      // ✅ EARLY CAP BEFORE ALLOCATION (DoS fix)
      if (n > MAX_LOGO) throw new Error("Logo too large (max 5MB)");

      if (n > 0) {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = (b[i] ?? 0) & 255;
        ab = out.buffer;
      }
    }

    if (!ab || ab.byteLength <= 0) throw new Error("Missing bytes");

    // 5MB max (final guard)
    if (ab.byteLength > MAX_LOGO) throw new Error("Logo too large (max 5MB)");

    const blob = new Blob([ab], { type: mime });
    const form = new FormData();
    form.append("file", blob, filename);

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/logo`, {
      method: "POST",
      headers: { Authorization: "Bearer " + wsState.token },
      body: form,
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = body && typeof body === "object" && body.detail ? body.detail : String(body || "");
      throw new Error(detail || `HTTP ${r.status}`);
    }

    const token =
      body && typeof body === "object"
        ? (body.token ?? body.logo_token ?? null)
        : null;

    const url =
      body && typeof body === "object"
        ? (body.url ?? body.logo_url ?? null)
        : null;

    post({
      type: "room_logo_uploaded",
      ok: true,
      roomId,
      token,
      url,
      url_full: url ? API_BASE + url : null,
      data: body,
    });
  } catch (e) {
    post({
      type: "room_logo_uploaded",
      ok: false,
      roomId: Number(msg.roomId) || 0,
      message: "Logo upload failed: " + (e?.message || e),
    });
  }
  return;
}

// --- file_upload ---
// payload: {roomId, filename, mime, bytes (ArrayBuffer or ArrayBufferView)}
if (msg.type === "file_upload") {
  const MAX_FILE = 100 * 1024 * 1024;

  await ensureAuthLoaded();
  try {
    if (!wsState.token) throw new Error("Not logged in");

    const roomId = Number(msg.roomId);
    const filename = (msg.filename || "").trim();
    const mime = msg.mime || "application/octet-stream";

    if (!roomId) throw new Error("Missing roomId");
    if (!filename) throw new Error("Missing filename");

    let ab = null;

    // Prefer msg.bytes, then msg.bytes_u8
    let b = null;
    if (msg.bytes instanceof ArrayBuffer || ArrayBuffer.isView(msg.bytes) || Array.isArray(msg.bytes)) {
      b = msg.bytes;
    } else if (msg.bytes_u8 && (ArrayBuffer.isView(msg.bytes_u8) || Array.isArray(msg.bytes_u8))) {
      b = msg.bytes_u8;
    } else if (msg.bytes_u8 && typeof msg.bytes_u8 === "object") {
      b = msg.bytes_u8;
    } else if (msg.bytes && typeof msg.bytes === "object") {
      b = msg.bytes;
    }

    if (b instanceof ArrayBuffer) {
      ab = b;
    } else if (ArrayBuffer.isView(b) && b.buffer instanceof ArrayBuffer) {
      // slice so we don't send the entire underlying buffer
      if (b.byteLength > MAX_FILE) throw new Error("File too large (max 100MB)");
      ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    } else if (b && b.buffer instanceof ArrayBuffer) {
      // Some buffer-like object; slice if it exposes offsets
      if (typeof b.byteOffset === "number" && typeof b.byteLength === "number") {
        if (b.byteLength > MAX_FILE) throw new Error("File too large (max 100MB)");
        ab = b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
      } else {
        ab = b.buffer;
      }
    } else if (Array.isArray(b)) {
      // plain array of bytes
      if (b.length > MAX_FILE) throw new Error("File too large (max 100MB)");
      ab = new Uint8Array(b).buffer;
    } else if (b && Array.isArray(b.data)) {
      // Buffer-like: { type:"Buffer", data:[...] }
      if (b.data.length > MAX_FILE) throw new Error("File too large (max 100MB)");
      ab = new Uint8Array(b.data).buffer;
    } else if (typeof msg.bytes_len === "number" && b && typeof b === "object") {
      // Worst case: plain object with numeric keys, no view/length
      const n = msg.bytes_len >>> 0;

      // ✅ EARLY CAP BEFORE ALLOCATION (DoS fix)
      if (n > MAX_FILE) throw new Error("File too large (max 100MB)");

      if (n > 0) {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = (b[i] ?? 0) & 255;
        ab = out.buffer;
      }
    } else if (b && typeof b.length === "number") {
      // array-like: {0:...,1:...,length:N}
      const n = (b.length >>> 0);

      // ✅ EARLY CAP BEFORE ALLOCATION (DoS fix)
      if (n > MAX_FILE) throw new Error("File too large (max 100MB)");

      if (n > 0) {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) out[i] = (b[i] ?? 0) & 255;
        ab = out.buffer;
      }
    }

    if (!ab || ab.byteLength <= 0) throw new Error("Missing bytes");

    // Final guard
    if (ab.byteLength > MAX_FILE) throw new Error("File too large (max 100MB)");

    const blob = new Blob([ab], { type: mime });
    const form = new FormData();
    form.append("file", blob, filename);

    const r = await fetch(API_BASE + `/rooms/${encodeURIComponent(roomId)}/files`, {
      method: "POST",
      headers: { "Authorization": "Bearer " + wsState.token },
      body: form
    });

    const body = await readBody(r);
    if (!r.ok) {
      const detail = (body && typeof body === "object" && body.detail) ? body.detail : String(body || "");
      throw new Error(detail || `Upload failed (${r.status})`);
    }

    post({
      type: "file_uploaded",
      ok: true,
      filename: body.filename,
      size_bytes: body.size_bytes,
      url: body.url,
      url_full: API_BASE + body.url
    });
  } catch (e) {
    post({ type: "file_uploaded", ok: false, message: "File upload failed: " + (e?.message || e) });
  }
  return;
}

        // --- disconnect ---
        if (msg.type === "disconnect") {
			await ensureAuthLoaded();
          closeWs({ manual: true });
          return;
        }

        // --- send ---
        if (msg.type === "send") {
			await ensureAuthLoaded();
          if (!ws || ws.readyState !== WebSocket.OPEN) {
            post({ type: "error", message: "No connection (WS not open)" });
            return;
          }
          const reqRoomId = Number(msg.room_id);
          if (!Number.isInteger(reqRoomId) || reqRoomId <= 0) {
            post({ type: "error", message: "Missing/invalid room_id for send" });
            return;
          }
          let currentRoomId = Number(wsState.roomId || 0);
          if (!Number.isInteger(currentRoomId) || currentRoomId <= 0) {
            const rn = String(wsState.roomName || "").trim();
            if (/^\d+$/.test(rn)) currentRoomId = Number(rn);
          }
          if (!Number.isInteger(currentRoomId) || currentRoomId <= 0) {
            post({ type: "error", message: "Room connection is not ready yet" });
            return;
          }
          if (currentRoomId !== reqRoomId) {
            post({ type: "error", message: "Room mismatch: reconnect and retry send" });
            return;
          }
          const textMsg = typeof msg.text === "string" ? msg.text : "";
          if (!textMsg.trim()) return;
          ws.send(textMsg);
          return;
        }

        // --- seed_context ---
        if (msg.type === "seed_context") {
			await ensureAuthLoaded();
          try {
            post({ type: "system", kind: "context", payload: msg });
          } catch {}
          return;
        }
        swarn("Unknown msg.type:", msg.type);

} catch (e) {
  const t = (msg && msg.type) ? String(msg.type) : "unknown";

  // best-effort stringify
  let raw = "";
  try {
    raw =
      (e && e.stack) ? String(e.stack) :
      (e && e.message) ? String(e.message) :
      (typeof e === "string") ? e :
      JSON.stringify(redactDeep(e));
  } catch {
    raw = String(e);
  }

  serr("PORT HANDLER FAILED:", { type: t, err: raw });

  try {
    post({ type: "error", message: "SW handler error (" + t + "): " + normalizeErrMsg(raw) });
  } catch {}
}

    })();
  });

port.onDisconnect.addListener(() => {
  const le = chrome.runtime?.lastError;
  if (le?.message) swarn("SW port disconnected:", le.message);
  for (const [reqId, s] of _unlockHandoffSessions.entries()) {
    if (s?.port === port) _unlockHandoffSessions.delete(reqId);
  }
  ports.delete(port);
});

}); // <-- close chrome.runtime.onConnect.addListener

chrome.runtime.onSuspend?.addListener(() => {
  swarn("Service worker is suspending (going idle)");
});

function ensureContextMenus() {
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: CTX_MENU_ID,
        title: "Create chat from selection (WS Messenger)",
        contexts: ["selection"],
      });
    });
  } catch (e) {
    swarn("contextMenus init failed", e);
  }
}

chrome.runtime.onInstalled.addListener(ensureContextMenus);
chrome.runtime.onStartup.addListener(ensureContextMenus);

ensureContextMenus();

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId !== CTX_MENU_ID) return;

  if (tab?.id != null) {
    try { chrome.sidePanel.open({ tabId: tab.id }); } catch {}
  }

  setTimeout(() => handleContextSelectionAsync(info, tab), 0);
});

async function handleContextSelectionAsync(info, tab) {
  const selection = (info.selectionText || "").trim();
  if (!selection) return;
  const url = tab?.url || "";
  slog("[ctx] async start", { selectionLen: selection.length });

  const suggestedName = makeSuggestedRoomName(selection, url);
  const payload = { text: selection, url, suggestedName, ts: Date.now() };

  await chrome.storage.session.set({
    pendingRoomFromSelection: payload,
    pendingRoomFromSelectionMode: "auto",
    pendingRoomFromSelectionTs: Date.now()
  });

  broadcastToPanels({ type: "context_room_pending", payload });
  setTimeout(() => {
  chrome.storage.session.remove([
    "pendingRoomFromSelection",
    "pendingRoomFromSelectionMode",
    "pendingRoomFromSelectionTs"
  ]).catch(() => {});
}, 5 * 60 * 1000);

}

function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0);
}

function makeSuggestedRoomName(selection, url) {
  const clean = (selection || "")
    .replace(/\s+/g, " ")
    .trim();

  const base = clean.slice(0, 48);
  const hash = fnv1a32(clean + "|" + (url || "")).toString(36).slice(0, 6);

  let name = (base ? base : "Selection") + " #" + hash;

  if (name.length > 80) name = name.slice(0, 80);
  return name;
}

// ================= E2EE DM (MVP) =================
// base64 utils
function b64encode(bufOrU8) {
  const u8 = bufOrU8 instanceof Uint8Array ? bufOrU8 : new Uint8Array(bufOrU8);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function b64decode(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8.buffer;
}
const te = new TextEncoder();
const td = new TextDecoder();
function utf8enc(s) { return te.encode(String(s ?? "")); }
function utf8dec(buf) { return td.decode(buf); }

function b64urlEncode(u8) {
  const b64 = b64encode(u8);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToU8(b64url) {
  let b64 = String(b64url || "").trim().replace(/-/g, "+").replace(/_/g, "/");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  return new Uint8Array(b64decode(b64));
}

async function sha256U8(u8) {
  const d = await crypto.subtle.digest("SHA-256", u8);
  return new Uint8Array(d);
}

async function hmacSha256(secretU8, msgU8) {
  const key = await crypto.subtle.importKey(
    "raw",
    secretU8,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, msgU8);
  return new Uint8Array(sig);
}

function concatU8(...parts) {
  const total = parts.reduce((n, p) => n + (p?.length || 0), 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    if (!p || !p.length) continue;
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function normalizeUnlockUsername(v) {
  return String(v || "").trim().toLowerCase();
}

function unlockHandoffAadString(meta) {
  return JSON.stringify({
    v: Number(meta?.v || 1),
    purpose: "unlock_handoff",
    req_id: String(meta?.req_id || ""),
    username: normalizeUnlockUsername(meta?.username || ""),
    ts: Number(meta?.ts || 0),
  });
}

function cleanupUnlockHandoffSessions() {
  const now = Date.now();
  for (const [reqId, s] of _unlockHandoffSessions.entries()) {
    if (!s || (now - Number(s.createdAt || 0)) > UNLOCK_HANDOFF_TTL_MS) {
      _unlockHandoffSessions.delete(reqId);
    }
  }
}

async function beginUnlockHandoff(port, reqId, username = "") {
  const normalizedReqId = String(reqId || "").trim();
  if (!normalizedReqId || normalizedReqId.length > 160) {
    throw new Error("Invalid unlock handoff request id");
  }
  cleanupUnlockHandoffSessions();
  _unlockHandoffSessions.delete(normalizedReqId);

  const kp = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const rawPub = await crypto.subtle.exportKey("raw", kp.publicKey);
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const nonceB64 = b64encode(nonce);

  _unlockHandoffSessions.set(normalizedReqId, {
    port,
    createdAt: Date.now(),
    nonceB64,
    privateKey: kp.privateKey,
    username: normalizeUnlockUsername(username),
  });

  return { serverPubB64: b64encode(rawPub), nonceB64 };
}

async function deriveUnlockHandoffKey(session, clientPubB64, reqId) {
  const clientRaw = b64decode(String(clientPubB64 || "").trim());
  const clientPub = await crypto.subtle.importKey(
    "raw",
    clientRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: clientPub },
    session.privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const salt = await crypto.subtle.digest(
    "SHA-256",
    utf8enc(`unlock-handoff-v1|${String(reqId || "")}|${String(session.nonceB64 || "")}`)
  );
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8enc("wsapp-unlock-handoff-v1") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function commitUnlockHandoff(port, msg) {
  const reqId = String(msg?.reqId || "").trim();
  if (!reqId) throw new Error("Missing unlock handoff request id");
  cleanupUnlockHandoffSessions();
  const session = _unlockHandoffSessions.get(reqId);
  if (!session) throw new Error("Unlock handoff session not found or expired");
  if (session.port !== port) throw new Error("Unlock handoff sender mismatch");
  if ((Date.now() - Number(session.createdAt || 0)) > UNLOCK_HANDOFF_TTL_MS) {
    _unlockHandoffSessions.delete(reqId);
    throw new Error("Unlock handoff session expired");
  }

  _unlockHandoffSessions.delete(reqId); // one-shot; prevents replay

  const aadMeta = {
    v: Number(msg?.aad?.v || 1),
    req_id: reqId,
    username: normalizeUnlockUsername(msg?.aad?.username || session.username || ""),
    ts: Number(msg?.aad?.ts || 0),
  };
  const aadBytes = utf8enc(unlockHandoffAadString(aadMeta));
  const transportKey = await deriveUnlockHandoffKey(session, msg?.client_pub_b64, reqId);
  const iv = new Uint8Array(b64decode(String(msg?.iv_b64 || "")));
  const ciphertext = b64decode(String(msg?.ct_b64 || ""));
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes },
    transportKey,
    ciphertext
  );
  const payload = JSON.parse(utf8dec(plainBuf));

  if (Number(payload?.v || 0) !== 1) throw new Error("Unsupported unlock handoff payload version");
  if (String(payload?.req_id || "") !== reqId) throw new Error("Unlock handoff request id mismatch");
  const payloadUsername = normalizeUnlockUsername(payload?.username || "");
  if (payloadUsername !== normalizeUnlockUsername(aadMeta.username)) {
    throw new Error("Unlock handoff username mismatch");
  }
  const now = Date.now();
  const payloadTs = Number(payload?.ts || 0);
  const payloadExp = Number(payload?.exp || 0);
  if (!payloadTs || Math.abs(now - payloadTs) > 60_000) throw new Error("Unlock handoff timestamp rejected");
  if (!payloadExp || now > payloadExp) throw new Error("Unlock handoff payload expired");

  const masterB64 = String(payload?.master_b64 || "").trim();
  const kekB64 = String(payload?.kek_b64 || "").trim();
  if (!masterB64 && !kekB64) throw new Error("Unlock handoff payload is empty");

  let appliedMaster = false;
  let appliedKek = false;
  if (masterB64) {
    await setMasterKeyFromB64(masterB64);
    _masterB64 = masterB64;
    _masterB64User = payloadUsername;
    if (_masterB64Timer) clearTimeout(_masterB64Timer);
    _masterB64Timer = setTimeout(() => {
      _masterB64 = "";
      _masterB64User = "";
      _masterB64Timer = null;
    }, 30_000);
    appliedMaster = true;
  }
  if (kekB64) {
    await setUnlockKekFromB64(kekB64);
    appliedKek = true;
  }

  _wipeMsgFields(msg, "client_pub_b64", "iv_b64", "ct_b64");
  return { appliedMaster, appliedKek };
}

function hasUnlockKek(maxAgeMs = 10 * 60 * 1000) {
  return !!_unlockKekKey && (Date.now() - _unlockKekTs) < maxAgeMs;
}

async function setUnlockKekFromB64(kek_b64) {
  const b64 = String(kek_b64 || "").trim();
  if (!b64) throw new Error("No kek_b64");
  const raw = b64decode(b64);
  _unlockKekKey = await crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
  _unlockKekTs = Date.now();
}

async function purgeLegacyIdentityStorage() {
  const legacyKey = "e2ee_identity_v1";
  try { await chrome.storage.local.remove([legacyKey]); } catch {}
  try { await chrome.storage.session.remove([legacyKey]); } catch {}
  try { delete globalThis.__e2eeIdentityCache; } catch {}
}

const LOCAL_IDENTITY_PREFIX = "e2ee_local_identity_v2:";
const LOCAL_ACTIVE_USER_KEY = "e2ee_active_user_v2";

function normUser(v) {
  return String(v || "").trim().toLowerCase();
}

function localIdentityStorageKey(username) {
  return LOCAL_IDENTITY_PREFIX + normUser(username);
}

async function resolveActiveUsernameForPublish() {
  const fromAuth = normUser(wsState.username);
  if (fromAuth) return fromAuth;
  try {
    const got = await chrome.storage.session.get([LOCAL_ACTIVE_USER_KEY]);
    return normUser(got?.[LOCAL_ACTIVE_USER_KEY] || "");
  } catch {
    return "";
  }
}

async function loadLocalPublicKeyB64ForUser(username) {
  const key = localIdentityStorageKey(username);
  const got = await chrome.storage.local.get([key]);
  return String(got?.[key]?.public_key || "").trim();
}

async function kidFromPublicKeyB64(publicKeyB64) {
  const digest = await crypto.subtle.digest("SHA-256", b64decode(publicKeyB64));
  const u8 = new Uint8Array(digest);
  let hex = "";
  for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, "0");
  return hex.slice(0, 32);
}

async function e2eePublishMyKey(API_BASE, token) {
  await purgeLegacyIdentityStorage();
  const username = await resolveActiveUsernameForPublish();
  if (!username) throw new Error("Publish key failed: active username missing");
  const publicKey = await loadLocalPublicKeyB64ForUser(username);
  if (!publicKey) throw new Error("Publish key failed: local x25519 public_key missing");
  const kid = await kidFromPublicKeyB64(publicKey);

  const r = await fetch(API_BASE + "/keys/me", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
    },
    body: JSON.stringify({ kid, alg: "x25519", public_key: publicKey }),
  });

  const body = await readBody(r);

  if (!r.ok) {
    const detail =
      (body && typeof body === "object" && (body.detail || body.message || body.error))
        ? String(body.detail || body.message || body.error)
        : (typeof body === "string" && body.trim())
        ? body.trim()
        : `${r.status} ${r.statusText}`;

    throw new Error("Publish key failed: " + detail);
  }

  return kid;
}
