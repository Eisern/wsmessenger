// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

let port = null;
let portConnecting = false;
let pendingRoomAlias = "";
let lastLoadedRoomKey = "";
let lastMsgAuthor = "";
let roomsLoadedAfterLogin = false;
let lastHistoryRoomId = null;        
let renderedHistoryRoomId = null;    
let roomPassByAlias = {};
let portReconnectTimer = null;
let portReconnectAttempts = 0; //Counter for reconnect attempts
let roomOwnerById = {}; // room_id -> true/false
let roomRoleById = {};  // room_id -> "owner" | "admin" | "member"
let roomHasPasswordById = {}; // room_id -> true/false
let roomReadonlyById = {}; // room_id -> true/false
let lastMineRooms = [];
let lastPublicRooms = [];
let roomMembersById = {};   // roomId -> [{username, role, is_owner}, ...]
let lastOnlineByRoomId = {}; // roomId -> ["user1","user2",...]
let presenceCollapsed = true;
let presenceFilter = "";
let wsOnline = false;
let isLoggedIn = false;
let roomsFilterMode = "all";   // "all" | "private" | "public"
let roomsSearchQuery = "";
let publicRoomsSearchQuery = "";
let roomsSectionCollapsed = { private: false, public: false, requests: true };
let lastRoomsMine = [];
let lastRoomsPublic = [];
let __authNotLoggedStreak = 0;
let __authNotLoggedTimer = null;
//let lastUnlockKekB64 = "";
//let lastUnlockKekTs = 0;

let __pendingHistoryRoomId = null;
let __pendingHistorySince = 0;

let __pendingDmThreadId = null;
let __pendingDmPeer = "";
let __pendingDmSince = 0;
let __dmWsOnline = false;
let __dmWsThreadId = 0;
const HISTORY_PAGE_SIZE = 50;
const __roomHistoryHasMoreByRoom = new Map(); // roomId -> bool
const __roomHistoryLimitByRoom = new Map(); // roomId -> current window size
const __dmHistoryHasMoreByThread = new Map(); // threadId -> bool
const __dmHistoryLimitByThread = new Map(); // threadId -> current window size
let __roomOlderLoading = false;
let __dmOlderLoading = false;
let __pendingOlderScrollRestore = null;
// Sealed-sender (UD) delivers ciphertext as base64url(utf8(JSON-string)).
// decryptDm() expects the JSON string, so decode here when needed.
function __udB64urlToUtf8Maybe(s) {
  try {
    const t = String(s || "").trim();
    if (!t) return s;
    if (t.startsWith("{")) return t;

    let b64 = t.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);

    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);

    const out = new TextDecoder().decode(u8);
    if (out && out.trim().startsWith("{")) return out;
    return s;
  } catch {
    return s;
  }
}

async function retryPendingDmAfterUnlock() {
  const tid = __pendingDmThreadId;
  if (!tid) return;

  const peer = __pendingDmPeer;

  __pendingDmThreadId = null;
  __pendingDmPeer = "";
  __pendingDmSince = 0;

  await new Promise(r => setTimeout(r, 50));

  // Make sure DM key is ready; if still locked, keep pending.
  try {
    await ensureDmKeyReady?.(Number(tid), String(peer || ""));
  } catch {
    __pendingDmThreadId = Number(tid);
    __pendingDmPeer = String(peer || "");
    __pendingDmSince = Date.now();
    return;
  }

  // Re-connect DM WS in service worker, then refresh history.
  try { safePost({ type: "dm_connect", thread_id: Number(tid), peer_username: String(peer || "") }); } catch {}
  try { safePost({ type: "dm_history", thread_id: Number(tid), limit: HISTORY_PAGE_SIZE }); } catch {}
}


async function retryPendingHistoryAfterUnlock() {
  const rid = __pendingHistoryRoomId;
  if (!rid) return;

  __pendingHistoryRoomId = null;

  await new Promise(r => setTimeout(r, 50));

  try {
    const ok = await loadRoomKey(rid);
    if (!ok) {
      __pendingHistoryRoomId = rid;
      __pendingHistorySince = Date.now();
      return;
    }

    try { requestRoomHistory?.(rid); } catch {}
  } catch {}
}

function __captureOlderScrollRestore(kind, id) {
  if (!chat) return;
  __pendingOlderScrollRestore = {
    kind: String(kind || ""),
    id: Number(id || 0),
    prevHeight: Number(chat.scrollHeight || 0),
    prevTop: Number(chat.scrollTop || 0),
  };
}

function __applyOlderScrollRestore(kind, id) {
  if (!chat || !__pendingOlderScrollRestore) return;
  const p = __pendingOlderScrollRestore;
  if (p.kind !== String(kind || "") || Number(p.id || 0) !== Number(id || 0)) return;
  __pendingOlderScrollRestore = null;
  const newHeight = Number(chat.scrollHeight || 0);
  const delta = Math.max(0, newHeight - Number(p.prevHeight || 0));
  chat.scrollTop = Number(p.prevTop || 0) + delta;
}

function __updateRoomHistoryCursor(roomId, rows, hasMore, appendOlder) {
  const rid = Number(roomId || 0);
  if (!rid) return;
  __roomHistoryHasMoreByRoom.set(rid, !!hasMore);
  const currentLimit = Number(__roomHistoryLimitByRoom.get(rid) || HISTORY_PAGE_SIZE);
  if (!appendOlder) __roomHistoryLimitByRoom.set(rid, Math.max(HISTORY_PAGE_SIZE, currentLimit));
}

function __updateDmHistoryCursor(threadId, rows, hasMore, appendOlder) {
  const tid = Number(threadId || 0);
  if (!tid) return;
  __dmHistoryHasMoreByThread.set(tid, !!hasMore);
  const currentLimit = Number(__dmHistoryLimitByThread.get(tid) || HISTORY_PAGE_SIZE);
  if (!appendOlder) __dmHistoryLimitByThread.set(tid, Math.max(HISTORY_PAGE_SIZE, currentLimit));
}

function __resetRoomHistoryPaging(roomId) {
  const rid = Number(roomId || 0);
  if (!rid) return;
  __roomHistoryHasMoreByRoom.delete(rid);
  __roomHistoryLimitByRoom.delete(rid);
}

function __resetDmHistoryPaging(threadId) {
  const tid = Number(threadId || 0);
  if (!tid) return;
  __dmHistoryHasMoreByThread.delete(tid);
  __dmHistoryLimitByThread.delete(tid);
}

function __bindHistoryAutoLoadOnce() {
  if (!chat || chat.dataset.historyAutoLoadBound === "1") return;
  chat.dataset.historyAutoLoadBound = "1";
  chat.addEventListener("scroll", () => {
    try {
      if (!chat || chat.scrollTop > 40) return;
      if (__syncCryptoUiLockFromRuntime()) return;

      if (dmMode && activeDmThreadId) {
        const tid = Number(activeDmThreadId || 0);
        if (!tid || __dmOlderLoading) return;
        if (!__dmHistoryHasMoreByThread.get(tid)) return;
        const currentLimit = Number(__dmHistoryLimitByThread.get(tid) || HISTORY_PAGE_SIZE);
        const nextLimit = Math.min(2000, currentLimit + HISTORY_PAGE_SIZE);
        if (nextLimit <= currentLimit) return;
        __dmOlderLoading = true;
        __dmHistoryLimitByThread.set(tid, nextLimit);
        __captureOlderScrollRestore("dm", tid);
        safePost({
          type: "dm_history",
          thread_id: tid,
          limit: nextLimit,
          append_older: true,
        });
        return;
      }

      const rid = Number(activeRoomId || 0);
      if (!rid || __roomOlderLoading) return;
      if (!__roomHistoryHasMoreByRoom.get(rid)) return;
      const currentLimit = Number(__roomHistoryLimitByRoom.get(rid) || HISTORY_PAGE_SIZE);
      const nextLimit = Math.min(2000, currentLimit + HISTORY_PAGE_SIZE);
      if (nextLimit <= currentLimit) return;
      __roomOlderLoading = true;
      __roomHistoryLimitByRoom.set(rid, nextLimit);
      __captureOlderScrollRestore("room", rid);
      safePost({
        type: "history_get",
        roomId: rid,
        limit: nextLimit,
        append_older: true,
      });
    } catch {}
  }, { passive: true });
}

const REQUIRE_E2EE_FOR_NEW_ROOMS = true; // Safe mode: rooms just E2EE
let pendingCreatedRoomKeyBase64 = null;

// room pins cache (server-side pin content)
const __roomPinCache = new Map(); // key: rid(string) -> pin object or null

let __pendingCtxSelection = null;
let __pinnedContextRooms = new Map();       // roomId(string) -> { url, text, ts, sent, dismissed }

const PIN_STORE_KEY = "pinned_context_rooms_v1";

function loadPinnedContextRooms() {
  try {
    chrome.storage.local.get([PIN_STORE_KEY], (d) => {
      const obj = d?.[PIN_STORE_KEY] || {};
      __pinnedContextRooms = new Map(Object.entries(obj));
      updatePinnedBar();
    });
  } catch {}
}

async function putRoomPin(roomId, pin) {
  const token = await requestToken();
  if (!token) throw new Error("no token");

  const r = await fetch(API_BASE + `/rooms/${Number(roomId)}/pin`, {
    method: "PUT",
    headers: {
      "Authorization": "Bearer " + token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      url: pin?.url || null,
      text: pin?.text || null,
    }),
  });

  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j?.detail || `pin failed (${r.status})`);
  return true;
}

function savePinnedContextRooms() {
  try {
    const obj = Object.fromEntries(__pinnedContextRooms.entries());
    chrome.storage.local.set({ [PIN_STORE_KEY]: obj });
  } catch {}
}

function setPinnedContextRoom(roomId, data) {
  __pinnedContextRooms.set(String(roomId), data);
  savePinnedContextRooms();
  updatePinnedBar();
}

function getPinnedContextRoom(roomId) {
  return __pinnedContextRooms.get(String(roomId)) || null;
}

let pendingNewRoomMeta = null; // { description: string|null, logoFile: File|null }
let pendingPinFromSelection = null; // {url, text} | null


function sendUnlockKekToBackground(kekB64, ts = Date.now()) {
  const b64 = String(kekB64 || "").trim();
  if (!b64) return;

  const p = port;
  if (!p?.postMessage) throw new Error("No port");

  const reqId = `uhk:${Date.now()}:${Math.random().toString(16).slice(2)}`;

  const te = new TextEncoder();
  const b64enc = (bufOrU8) => {
    const u8 = bufOrU8 instanceof Uint8Array ? bufOrU8 : new Uint8Array(bufOrU8);
    let s = "";
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  };
  const b64decU8 = (base64) => {
    const s = atob(String(base64 || ""));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  };
  const aadString = (meta) => JSON.stringify({
    v: Number(meta?.v || 1),
    purpose: "unlock_handoff",
    req_id: String(meta?.req_id || ""),
    username: "",
    ts: Number(meta?.ts || 0),
  });

  const wait = (matcher, timeoutMs = 4000) => new Promise((resolve, reject) => {
    let done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      try { p?.onMessage?.removeListener(onMsg); } catch {}
      clearTimeout(timer);
      if (err) reject(err);
      else resolve(value);
    };
    const onMsg = (msg) => {
      try {
        if (!matcher(msg)) return;
        finish(null, msg);
      } catch (e) {
        finish(e);
      }
    };
    const timer = setTimeout(() => finish(new Error("unlock_kek handoff timeout")), timeoutMs);
    try { p.onMessage.addListener(onMsg); } catch (e) { finish(e); }
  });

  const run = async () => {
    const beginWait = wait((msg) => msg?.type === "unlock_handoff_begin_res" && msg?.reqId === reqId);
    p.postMessage({ type: "unlock_handoff_begin", reqId, username: "", ts: Date.now() });
    const beginRes = await beginWait;
    if (!beginRes?.ok) throw new Error(beginRes?.error || "unlock_handoff_begin failed");

    const serverPub = await crypto.subtle.importKey(
      "raw",
      b64decU8(beginRes.server_pub_b64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );
    const nonceU8 = b64decU8(beginRes.nonce_b64);

    const eph = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveBits"]
    );
    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: serverPub },
      eph.privateKey,
      256
    );
    const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
    const salt = await crypto.subtle.digest("SHA-256", te.encode(`unlock-handoff-v1|${reqId}|${b64enc(nonceU8)}`));
    const transportKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: te.encode("wsapp-unlock-handoff-v1") },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    const tsNow = Number(ts || Date.now());
    const aad = { v: 1, req_id: reqId, username: "", ts: tsNow };
    const aadBytes = te.encode(aadString(aad));
    const payload = {
      v: 1,
      req_id: reqId,
      username: "",
      ts: tsNow,
      exp: tsNow + 30_000,
      master_b64: "",
      kek_b64: b64,
    };
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: aadBytes },
      transportKey,
      te.encode(JSON.stringify(payload))
    );
    const clientPubRaw = await crypto.subtle.exportKey("raw", eph.publicKey);

    const commitWait = wait((msg) => msg?.type === "unlock_handoff_commit_res" && msg?.reqId === reqId);
    p.postMessage({
      type: "unlock_handoff_commit",
      reqId,
      client_pub_b64: b64enc(clientPubRaw),
      iv_b64: b64enc(iv),
      ct_b64: b64enc(ct),
      aad,
    });
    const commitRes = await commitWait;
    if (!commitRes?.ok) throw new Error(commitRes?.error || "unlock_handoff_commit failed");
  };

  return run().finally(() => { kekB64 = ""; });
}

// ===== UI modal helpers (replace alert/confirm/prompt) =====
const __ui = (() => {
  const modal = document.getElementById("uiModal");
  const titleEl = document.getElementById("uiModalTitle");
  const textEl = document.getElementById("uiModalText");
  const inputEl = document.getElementById("uiModalInput");
  const okBtn = document.getElementById("uiModalOk");
  const cancelBtn = document.getElementById("uiModalCancel");

  let resolver = null;

  function close(result) {
    if (!modal) return;
    modal.classList.add("hidden");
    modal.setAttribute("aria-hidden", "true");
    const r = resolver;
    resolver = null;
    if (r) r(result);
  }

  function open({ title, text, mode, okText, cancelText, value, placeholder, inputType }) {
    if (!modal) return Promise.resolve({ ok: false, value: "" });

    // NOTE: UI helper / rendering logic. (Comment was corrupted by encoding.)
    if (resolver) close({ ok: false, value: "" });

    titleEl.textContent = title || "Message";
    textEl.textContent = text || "";
    okBtn.textContent = okText || "OK";
    cancelBtn.textContent = cancelText || "Cancel";

    const needInput = mode === "prompt";
    inputEl.style.display = needInput ? "block" : "none";
    inputEl.type = inputType || "password";
    inputEl.value = value || "";
    inputEl.placeholder = placeholder || "";

    cancelBtn.style.display = mode === "alert" ? "none" : "";

    modal.classList.remove("hidden");
    modal.setAttribute("aria-hidden", "false");
   
    setTimeout(() => {
      if (needInput) inputEl.focus();
      else okBtn.focus();
    }, 0);

    return new Promise((resolve) => {
      resolver = resolve;
    });
  }

    modal?.addEventListener("click", (e) => {
    const t = e.target;
    if (t && t.dataset && t.dataset.uiClose !== undefined) close({ ok: false, value: inputEl.value });
  });

  okBtn?.addEventListener("click", () => close({ ok: true, value: inputEl.value }));
  cancelBtn?.addEventListener("click", () => close({ ok: false, value: inputEl.value }));

  // Enter/Escape
  document.addEventListener("keydown", (e) => {
    if (!modal || modal.classList.contains("hidden")) return;
    if (e.key === "Escape") { e.preventDefault(); close({ ok: false, value: inputEl.value }); }
    if (e.key === "Enter")  { e.preventDefault(); close({ ok: true, value: inputEl.value }); }
  });

  return {
    alert: async (text, title = "WS Messenger") => { await open({ title, text, mode: "alert", okText: "OK" }); },
    confirm: async (text, title = "WS Messenger") => {
      const r = await open({ title, text, mode: "confirm", okText: "OK", cancelText: "Cancel" });
      return !!r.ok;
    },
    prompt: async (text, { title="WS Messenger", placeholder="", value="", inputType="password", okText="OK", cancelText="Cancel" } = {}) => {
      const r = await open({ title, text, mode: "prompt", okText, cancelText, placeholder, value, inputType });
      return r.ok ? (r.value || "") : "";
    }
  };
})();

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function ensurePinnedBarEl() {
  let el = document.getElementById("pinnedBar");
  if (el) return el;

  const chatEl = document.getElementById("chat");
  if (!chatEl) return null;

  el = document.createElement("div");
  el.id = "pinnedBar";
  el.className = "pinned-bar";

  chatEl.parentNode.insertBefore(el, chatEl);
  return el;
}

function updatePinnedBar() {
  const el = ensurePinnedBarEl();
  if (!el) return;

  const rid = activeRoomId != null ? String(activeRoomId) : "";
  if (!rid) { el.style.display = "none"; el.innerHTML = ""; return; }

  const pin = __roomPinCache.get(rid) || null;
  if (!pin || (!pin.url && !pin.text)) { el.style.display = "none"; el.innerHTML = ""; return; }

  const localState = getPinnedContextRoom(rid) || {};
  const collapsed = !!localState.collapsed;

  const urlRaw = pin.url || "";
  const href = __safeHref(urlRaw);
  const urlLabel = __escapeHtml(urlRaw);

  const fullText = String(pin.text || "").trim();
  const text = __escapeHtml(fullText.replace(/\s+/g, " ").slice(0, 180));
  const hasMore = fullText.length > 180;

el.innerHTML = `
  <div class="pinned-bar__wrap">
    <div class="pinned-bar__content">
      <div id="pinTitleBtn" class="pinned-bar__title pinned-bar__title--clickable" role="button" tabindex="0">
        Created from selected text
        <span class="pinned-bar__hint">${collapsed ? "(collapsed)" : ""}</span>
      </div>

      ${collapsed ? "" : `
        ${href ? `
          <div class="pinned-bar__url">
            <a class="pinned-bar__link" href="${__escapeHtml(href)}" target="_blank" rel="noreferrer">${urlLabel}</a>
          </div>
        ` : (urlRaw ? `
          <div class="pinned-bar__url">
            <span class="pinned-bar__link">${urlLabel}</span>
          </div>
        ` : "")}

        <div class="pinned-bar__quote">"${text}${hasMore ? "Ã¢â‚¬Â¦" : ""}"</div>
      `}
    </div>

    <button id="pinToggleBtn" type="button" class="pinned-bar__dismiss"
      title="${collapsed ? "Expand" : "Collapse"}">${collapsed ? "\u25BE" : "\u25B4"}</button>
  </div>
`;
el.style.display = "block";

  const toggle = () => {

    const p = getPinnedContextRoom(rid) || {};
    p.collapsed = !p.collapsed;
    setPinnedContextRoom(rid, p);
    updatePinnedBar();
  };

  const btn = document.getElementById("pinToggleBtn");
  if (btn) btn.onclick = toggle;

  const title = document.getElementById("pinTitleBtn");
  if (title) {
    title.onclick = toggle;
    title.onkeydown = (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
    };
  }
}

const __roomMetaWaiters = new Map();      // roomId -> {resolve,reject, t}
const __roomLogoWaiters = new Map();      // roomId -> {resolve,reject, t}
const __roomPassWaiters = new Map();      // roomId -> {resolve,reject, t}
const __roomRenameWaiters = new Map();    // roomId -> {resolve,reject, t}

function __withTimeout(ms, fn) {
  const t = setTimeout(fn, ms);
  return t;
}

function waitRoomMeta(roomId, kind = "get", timeoutMs = 12000) {
  const key = String(roomId) + ":" + kind;
  return new Promise((resolve, reject) => {
    if (__roomMetaWaiters.has(key)) {
      reject(new Error("Meta request already pending"));
      return;
    }
    const t = __withTimeout(timeoutMs, () => {
      __roomMetaWaiters.delete(key);
      reject(new Error("Meta request timeout"));
    });
    __roomMetaWaiters.set(key, { resolve, reject, t });
  });
}

function waitRoomPasswordChange(roomId, timeoutMs = 12000) {
  const key = String(roomId);
  return new Promise((resolve, reject) => {
    if (__roomPassWaiters.has(key)) {
      reject(new Error("Password change already pending"));
      return;
    }
    const t = __withTimeout(timeoutMs, () => {
      __roomPassWaiters.delete(key);
      reject(new Error("Password change timeout"));
    });
    __roomPassWaiters.set(key, { resolve, reject, t });
  });
}

function waitRoomRename(roomId, timeoutMs = 12000) {
  const key = String(roomId);
  return new Promise((resolve, reject) => {
    if (__roomRenameWaiters.has(key)) {
      reject(new Error("Room rename already pending"));
      return;
    }
    const t = __withTimeout(timeoutMs, () => {
      __roomRenameWaiters.delete(key);
      reject(new Error("Room rename timeout"));
    });
    __roomRenameWaiters.set(key, { resolve, reject, t });
  });
}

function waitRoomLogo(roomId, timeoutMs = 20000) {
  const key = String(roomId);
  return new Promise((resolve, reject) => {
    if (__roomLogoWaiters.has(key)) {
      reject(new Error("Logo upload already pending"));
      return;
    }
    const t = __withTimeout(timeoutMs, () => {
      __roomLogoWaiters.delete(key);
      reject(new Error("Logo upload timeout"));
    });
    __roomLogoWaiters.set(key, { resolve, reject, t });
  });
}

async function postRoomLogoUpload(roomId, file) {
  if (!file) throw new Error("No file");
  const ab = await file.arrayBuffer();
  if (!ab || ab.byteLength <= 0) throw new Error("Empty logo bytes");

  const u8 = new Uint8Array(ab);

  safePost({
    type: "room_logo_upload",
    roomId: Number(roomId),
    filename: file.name || "logo.png",
    mime: file.type || "application/octet-stream",

    bytes_u8: Array.from(u8),
    bytes_len: u8.byteLength,
  });

  return await waitRoomLogo(Number(roomId));
}

chrome.storage.local.get(["roomPassByAlias"], d => {
  roomPassByAlias = d.roomPassByAlias || {};
});

// --- SEC: encrypt/decrypt room passwords via background master key (Fix #3) ---
function _storageCryptoRpc(type, payload) {
  return new Promise((resolve, reject) => {
    const reqId = "sec_" + Date.now() + ":" + Math.random().toString(16).slice(2);
    const timeout = setTimeout(() => {
      window.rpcOffMessage?.(handler);
      reject(new Error("storage_crypto timeout"));
    }, 5000);

    const handler = (msg) => {
      if (msg?.type === "storage_crypto_res" && msg?.reqId === reqId) {
        clearTimeout(timeout);
        window.rpcOffMessage?.(handler);
        if (msg.ok) resolve(msg.result);
        else reject(new Error(msg.error || "storage_crypto failed"));
      }
    };

    window.rpcOnMessage?.(handler);
    safePost({ type, reqId, ...payload });
  });
}

/** Encrypt plaintext for chrome.storage → returns { iv, ct } or null on failure */
async function encryptForStorage(plaintext) {
  try {
    return await _storageCryptoRpc("storage_encrypt", { plaintext });
  } catch { return null; }
}

/** Decrypt { iv, ct } from chrome.storage → returns plaintext string or "" on failure */
async function decryptFromStorage(encrypted) {
  try {
    if (!encrypted || typeof encrypted !== "object" || !encrypted.iv || !encrypted.ct) return "";
    return await _storageCryptoRpc("storage_decrypt", { iv: encrypted.iv, ct: encrypted.ct });
  } catch { return ""; }
}

/** Read a stored room password — handles both legacy plaintext and encrypted format */
async function _readStoredPass(stored) {
  if (!stored) return "";
  // Legacy plaintext string — return as-is (will be re-encrypted on next save)
  if (typeof stored === "string") return stored;
  // Encrypted object { iv, ct }
  if (typeof stored === "object" && stored.iv && stored.ct) {
    return await decryptFromStorage(stored);
  }
  return "";
}

function getAliasPass(alias) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["roomPassByAlias"], async (d) => {
      const m = d.roomPassByAlias || {};
      const raw = m[String(alias)] || "";
      resolve(await _readStoredPass(raw));
    });
  });
}

function initPort() {
  // Delegated to rpc.js. It auto-reconnects and fans out messages.
  try {
    if (typeof window.connectPort !== "function") throw new Error("rpc.js not loaded");

    // subscribe router once
    if (!window.__panelPortSubscribed) {
      window.__panelPortSubscribed = true;
      if (typeof window.rpcOnMessage === "function") window.rpcOnMessage(handlePortMessage);

      // When transport reconnects, re-sync state (auth + room/dm re-join)
      if (typeof window.rpcOnConnect === "function") {
        window.rpcOnConnect(() => {
          try {
            // refresh local port pointer (legacy)
            port = (typeof window.rpcGetPort === "function") ? window.rpcGetPort() : port;
			try { globalThis.port = port; } catch {}
          } catch {}

          // keep UI buttons consistent
          try {
            if (connectBtn) connectBtn.disabled = true;
            if (disconnectBtn) disconnectBtn.disabled = false;
          } catch {}


            // ask background whether KEK is already in memory
            try { safePost({ type: "unlock_kek_has" }); } catch {}
          // re-send KEK if still fresh
          //try {
            //if (lastUnlockKekB64 && (Date.now() - lastUnlockKekTs) < 10 * 60 * 1000) {
              //safePost({ type: "unlock_kek_set", kek_b64: lastUnlockKekB64, ts: lastUnlockKekTs });
            //}
          //} catch {}

          // re-sync auth/rooms/dm
          setTimeout(() => {
            try { safePost({ type: "auth_get" }); } catch {}

            try {
              if (activeRoomId) requestMyRooms();
            } catch {}

            try {
              if (dmMode && activeDmThreadId) {
                (async () => {
                  try { await ensureDmKeyReady(activeDmThreadId, activeDmPeer); } catch {}
                  try {
                    safePost({ type: "dm_connect", thread_id: activeDmThreadId, peer_username: activeDmPeer });
                    safePost({ type: "dm_history", thread_id: activeDmThreadId, limit: HISTORY_PAGE_SIZE });
                  } catch {}
                })();
              }
            } catch {}
          }, 400);
        });
      }

if (typeof window.rpcOnDisconnect === "function") {
  window.rpcOnDisconnect(() => {
    try {

      try { if (globalThis.port === port) globalThis.port = null; } catch {}

      port = null;
      portConnecting = false;
    } catch {}

    try {
      if (connectBtn) connectBtn.disabled = false;
      if (disconnectBtn) disconnectBtn.disabled = true;
    } catch {}
  });
}
    }

    port = window.connectPort();
	try { globalThis.port = port; } catch {}
    portConnecting = false;

    try {
      if (connectBtn) connectBtn.disabled = true;
      if (disconnectBtn) disconnectBtn.disabled = false;
    } catch {}
  } catch (e) {
    console.error("connectPort failed:", e);
    port = null;
    portConnecting = false;
    try {
      if (connectBtn) connectBtn.disabled = false;
      if (disconnectBtn) disconnectBtn.disabled = true;
    } catch {}
  }
}

// ===== Auth token plumbing (avoid logging + avoid window/localStorage exposure) =====
const DEBUG_LOGS = false;

// Redact JWT-like strings in logs (best-effort). Never log full tokens.
function redactJwt(s) {
  const str = String(s || "");
  // very small heuristic: three base64url-ish parts separated by dots
  if (/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/.test(str)) {
    return str.slice(0, 18) + "..." + str.slice(-10);
  }
  return str;
}

function sanitizeMsgForLog(msg) {
  if (!msg || typeof msg !== "object") return msg;
  if (msg.type === "token") return { type: "token", token: "<redacted>" };
  // shallow clone with token-like fields redacted
  const out = { ...msg };
  if (typeof out.token === "string") out.token = "<redacted>";
  if (typeof out.authorization === "string") out.authorization = "<redacted>";
  return out;
}

let __tokenWaiters = [];
let __tokenLast = ""; // kept in module scope, not on window

function _decodeJwtPayloadPanel(token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload));
  } catch { return null; }
}

function _isTokenFresh(token) {
  if (!token) return false;
  const p = _decodeJwtPayloadPanel(token);
  if (!p?.exp) return true; // no exp = assume OK
  return (p.exp * 1000 - Date.now()) > 30_000; // >30s remaining
}

async function requestToken() {
  // Return cached token if it's still fresh (>30s to expiry)
  if (__tokenLast && _isTokenFresh(__tokenLast)) return __tokenLast;

  // Token missing or nearly expired, ask background for a fresh one
  // (background will refresh via doRefresh() if needed)
  __tokenLast = "";

  return await new Promise((resolve) => {
    const started = Date.now();
    const HARD_TIMEOUT = 10000;

    const tick = setInterval(() => {
      if (__tokenLast && _isTokenFresh(__tokenLast)) {
        clearInterval(tick);
        resolve(__tokenLast);
        return;
      }
      if (Date.now() - started > HARD_TIMEOUT) {
        clearInterval(tick);
        resolve(__tokenLast || "");
        return;
      }
      try { safePost({ type: "auth_get" }); } catch {}
    }, 500);

    __tokenWaiters.push((tok) => {
      clearInterval(tick);
      resolve(tok || "");
    });

    try { safePost({ type: "auth_get" }); } catch {}
  });
}

function __escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function __safeHref(url) {
  const u = String(url || "").trim();
  if (!u) return "";

  if (!/^https?:\/\//i.test(u)) return "";
  return u;
}

async function fetchRoomPin(roomId) {
  const rid = String(roomId);
  try {
    const token = await requestToken();
    if (!token) { __roomPinCache.set(rid, null); return null; }

    const r = await fetch(API_BASE + `/rooms/${Number(roomId)}/pin`, {
      headers: { "Authorization": "Bearer " + token }
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j?.detail || `pin_get failed (${r.status})`);

    const pin = j?.pin || null;
    __roomPinCache.set(rid, pin);
    return pin;
  } catch (e) {
    console.warn("fetchRoomPin failed:", e?.message || e);
    __roomPinCache.set(rid, null);
    return null;
  }
}

const API_BASE = "https://imagine-1-ws.xyz";
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

function humanSize(bytes) {
  const mb = bytes / (1024 * 1024);
  return mb >= 1 ? `${mb.toFixed(1)}MB` : `${Math.round(bytes / 1024)}KB`;
}

let fileInputEl = null;

function ensureFileInput() {
  if (fileInputEl) return fileInputEl;
  fileInputEl = document.createElement("input");
  fileInputEl.type = "file";
  fileInputEl.style.display = "none";
  document.body.appendChild(fileInputEl);
  return fileInputEl;
}

function makeFileMarker(token, filename, sizeBytes) {
  const safeName = String(filename || "file").replaceAll("\n", " ").trim().slice(0, 220);
  const safeSize = Number.isFinite(sizeBytes) ? Number(sizeBytes) : null;
  const payload = {
    v: 2,
    t: String(token || "").trim(),
    n: safeName || "file",
    s: (safeSize != null && safeSize >= 0) ? safeSize : null,
    ts: Date.now(),
  };
  const json = JSON.stringify(payload);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return `FILE2::${b64}`;
}

function isReadOnlyRoomForMember(roomId = activeRoomId) {
  const rid = roomId != null ? String(roomId) : "";
  if (!rid) return false;
  const isReadonly = !!roomReadonlyById[rid];
  if (!isReadonly) return false;
  const role = String(roomRoleById[rid] || "").toLowerCase();
  const isOwner = !!roomOwnerById[rid];
  return !(isOwner || role === "owner" || role === "admin");
}

function canPostToActiveRoom() {
  return !isReadOnlyRoomForMember(activeRoomId);
}

window.__canPostToActiveRoom = canPostToActiveRoom;

async function pickAndUploadFile() {
  if (__syncCryptoUiLockFromRuntime()) {
    await __ui.alert("Crypto is locked. Unlock to send files.");
    return;
  }
  const inDm = !!dmMode;
  if (inDm && !activeDmThreadId) {
    await __ui.alert("Please open a conversation first.");
    return;
  }
  if (!inDm && !activeRoomId) {
    await __ui.alert("First, connect to the room.");
    return;
  }
  if (!inDm && isReadOnlyRoomForMember(activeRoomId)) {
    await __ui.alert("This room is read-only. Only owner/admin can send files.");
    return;
  }
  const inp = ensureFileInput();
  inp.value = "";

  inp.onchange = async () => {
    try {
      const f = inp.files && inp.files[0];
      if (!f) return;

      if (f.size > MAX_UPLOAD_BYTES) {
        await __ui.alert("File is too big. Maximum size-100MB.");
        return;
      }

      const jwt = await requestToken();
      if (!jwt) {
        await __ui.alert("No token (not logged in?)");
        return;
      }

      const form = new FormData();
      form.append("file", f, f.name);

      const uploadUrl = inDm
        ? (API_BASE + `/dm/${encodeURIComponent(activeDmThreadId)}/files`)
        : (API_BASE + `/rooms/${encodeURIComponent(activeRoomId)}/files`);
      const r = await fetch(uploadUrl, {
        method: "POST",
        headers: { "Authorization": "Bearer " + jwt },
        body: form
      });

      const body = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(body?.detail || `Upload failed (${r.status})`);

      const marker = makeFileMarker(body.token, body.filename || f.name, body.size_bytes ?? f.size);
      if (inDm) {
        const sendPeer = activeDmPeer;
        const threadId = Number(activeDmThreadId || 0);
        if (!threadId) throw new Error("DM thread is not selected");
        const enc = await encryptDm(threadId, marker, sendPeer);
        safePost({ type: "dm_send", thread_id: threadId, text: enc });
        try { __markDmSeen?.(threadId); } catch {}
      } else {
        safePost({ type: "send", room_id: Number(activeRoomId || 0), text: marker });
      }

    } catch (e) {
      await __ui.alert("File upload failed: " + (e?.message || e));
    } finally {
      
      inp.value = "";
      inp.onchange = null;
    }
  };

  inp.click();
}

const statusEl = document.getElementById("status");
const roomsSearchEl = document.getElementById("roomsSearch");
const roomsFilterAllBtn = document.getElementById("roomsFilterAll");
const roomsFilterPrivateBtn = document.getElementById("roomsFilterPrivate");
const roomsFilterPublicBtn = document.getElementById("roomsFilterPublic");

function setRoomsFilter(mode){
  roomsFilterMode = mode;
  roomsFilterAllBtn?.classList.toggle("is-active", mode === "all");
  roomsFilterPrivateBtn?.classList.toggle("is-active", mode === "private");
  roomsFilterPublicBtn?.classList.toggle("is-active", mode === "public");

  renderRooms(lastMineRooms || [], lastPublicRooms || []);
}

roomsFilterAllBtn && (roomsFilterAllBtn.onclick = () => setRoomsFilter("all"));
roomsFilterPrivateBtn && (roomsFilterPrivateBtn.onclick = () => setRoomsFilter("private"));
roomsFilterPublicBtn && (roomsFilterPublicBtn.onclick = () => setRoomsFilter("public"));

if (roomsSearchEl) {
  roomsSearchEl.addEventListener("input", () => {
    roomsSearchQuery = (roomsSearchEl.value || "").trim().toLowerCase();
    renderRooms(lastMineRooms || [], lastPublicRooms || []);
  });
}

const chat = document.getElementById("chat");
__bindHistoryAutoLoadOnce();
const msgInput = document.getElementById("message");
let __cryptoUiLocked = false;

// ---- Reply state ----
let replyTo = null; // { author, text }

function __setReplyTo(author, text) {
  replyTo = { author: String(author || ""), text: String(text || "").slice(0, 120) };
  const bar = document.getElementById("replyBar");
  if (bar) {
    bar.style.display = "";
    const a = document.getElementById("replyBarAuthor");
    const t = document.getElementById("replyBarText");
    if (a) a.textContent = replyTo.author;
    if (t) t.textContent = replyTo.text;
  }
  msgInput?.focus();
}

function __clearReplyTo() {
  replyTo = null;
  const bar = document.getElementById("replyBar");
  if (bar) bar.style.display = "none";
}

function __showMsgCtxMenu(e, author, text) {
  document.querySelectorAll(".msg-ctx-menu").forEach(el => el.remove());
  if (!text) return;
  const menu = document.createElement("div");
  menu.className = "msg-ctx-menu";
  const replyItem = document.createElement("div");
  replyItem.className = "msg-ctx-item";
  replyItem.textContent = "↩ Reply";
  replyItem.onclick = () => { __setReplyTo(author, text); menu.remove(); };
  menu.appendChild(replyItem);
  const copyItem = document.createElement("div");
  copyItem.className = "msg-ctx-item";
  copyItem.textContent = "⎘ Copy";
  copyItem.onclick = () => { navigator.clipboard?.writeText(text).catch(() => {}); menu.remove(); };
  menu.appendChild(copyItem);
  menu.style.left = Math.min(e.clientX, window.innerWidth - 140) + "px";
  menu.style.top = Math.min(e.clientY, window.innerHeight - 80) + "px";
  document.body.appendChild(menu);
  const dismiss = () => { menu.remove(); document.removeEventListener("click", dismiss, true); };
  setTimeout(() => document.addEventListener("click", dismiss, true), 0);
}

// Parse v2 reply payload: { v:2, t:"text", reply:{author,text} }
// Falls back gracefully for plain text (Chrome Extension parity with Android client)
function parseV2Payload(text) {
  if (typeof text !== "string" || !text.startsWith("{")) return { text, reply: null };
  try {
    const p = JSON.parse(text);
    if (p.v === 2 && p.t !== undefined) return { text: p.t, reply: p.reply || null };
  } catch {}
  return { text, reply: null };
}
let __cryptoLockOverlayEl = null;

function __isCryptoUiLocked() {
  return !!__cryptoUiLocked;
}
window.__isCryptoUiLocked = __isCryptoUiLocked;

function __ensureCryptoLockOverlay() {
  if (__cryptoLockOverlayEl && document.body.contains(__cryptoLockOverlayEl)) {
    return __cryptoLockOverlayEl;
  }
  const host = document.querySelector(".chat-wrap");
  if (!host) return null;

  let overlay = document.getElementById("cryptoLockOverlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "cryptoLockOverlay";
    overlay.className = "crypto-lock-overlay";
    overlay.style.display = "none";
    overlay.innerHTML = `
      <div class="crypto-lock-card">
        <div class="crypto-lock-title">Crypto locked</div>
        <div class="crypto-lock-text">Session keys were locked due to inactivity.</div>
        <button id="cryptoLockUnlockBtn" type="button" class="panel-btn">Unlock</button>
      </div>
    `;
    host.appendChild(overlay);

    const unlockBtn = overlay.querySelector("#cryptoLockUnlockBtn");
    unlockBtn?.addEventListener("click", async () => {
      try {
        const ok = await ensureCryptoReady({ interactive: true, reason: "Unlock chat" });
        if (!ok) return;
        __setCryptoUiLocked(false);
        try { await retryPendingHistoryAfterUnlock?.(); } catch {}
        try { await retryPendingDmAfterUnlock?.(); } catch {}
      } catch (e) {
        try { await __ui.alert("Crypto unlock failed: " + (e?.message || e)); } catch {}
      }
    });
  }

  __cryptoLockOverlayEl = overlay;
  return overlay;
}

function __syncComposerForCryptoLock() {
  try { window.applyComposerPolicyUI?.(); } catch {}
}

function __setCryptoUiLocked(locked) {
  const next = !!locked;
  __cryptoUiLocked = next;
  const host = document.querySelector(".chat-wrap");
  const overlay = __ensureCryptoLockOverlay();

  if (host) host.classList.toggle("crypto-ui-locked", next);
  if (overlay) overlay.style.display = next ? "flex" : "none";

  if (next) {
    if (dmMode && activeDmThreadId) {
      __pendingDmThreadId = Number(activeDmThreadId);
      __pendingDmPeer = String(activeDmPeer || "");
      __pendingDmSince = Date.now();
    } else if (activeRoomId) {
      __pendingHistoryRoomId = Number(activeRoomId);
      __pendingHistorySince = Date.now();
    }
  }

  __syncComposerForCryptoLock();
}

window.__setCryptoUiLocked = __setCryptoUiLocked;
window.onCryptoLockedNeedUnlock = () => { __setCryptoUiLocked(true); };
function __syncCryptoUiLockFromRuntime() {
  const hasPrivate = !!(typeof CM === "function" && CM()?.userPrivateKey);
  const locked = !hasPrivate;
  __setCryptoUiLocked(locked);
  return locked;
}

window.addEventListener("ws_crypto_locked", () => {
  __setCryptoUiLocked(true);
});
window.addEventListener("ws_crypto_unlocked", () => {
  __setCryptoUiLocked(false);
});
window.addEventListener("ws_crypto_lock_state", (ev) => {
  const locked = !!ev?.detail?.locked;
  __setCryptoUiLocked(locked);
});

// A3: TOFU — show informational banner on first contact with a peer (DM only)
const _tofuShownThisSession = new Set();
// Tracks peers for whom the "unverified sender" banner was already shown in the current DM thread.
// Cleared when entering a new thread so the banner reappears if needed.
const _sigUnverifiedShown = new Set();
window.addEventListener("peer_key_first_seen", (ev) => {
  const username = ev?.detail?.username;
  if (!username) return;
  const uLower = String(username).toLowerCase();
  // Only show in DM mode for the currently open thread with this peer
  if (!dmMode) return;
  const peerLower = String(activeDmPeer || "").toLowerCase();
  if (peerLower !== uLower) return;
  // Deduplicate within session
  if (_tofuShownThisSession.has(uLower)) return;
  _tofuShownThisSession.add(uLower);
  if (typeof addTofuFirstSeenBanner === "function") {
    addTofuFirstSeenBanner(username);
  }
});

const connectBtn = document.getElementById("connectBtn");
const inviteBtn = document.getElementById("inviteBtn");
const inviteBtnTop = document.getElementById("inviteBtnTop");
const friendsBtn = document.getElementById("friendsBtn");
const roomsBtn = document.getElementById("roomsBtn");
const roomsDrawer = document.getElementById("roomsDrawer");
const roomsBackdrop = document.getElementById("roomsBackdrop");
const closeRoomsBtn = document.getElementById("closeRooms");

const friendsDrawer = document.getElementById("friendsDrawer");
const friendsBackdrop = document.getElementById("friendsBackdrop");
const closeFriendsBtn = document.getElementById("closeFriends");
const friendNameInput = document.getElementById("friendName");
const sendFriendRequestBtn = document.getElementById("sendFriendRequestBtn");
const friendsIncomingEl = document.getElementById("friendsIncoming");
const friendsOutgoingEl = document.getElementById("friendsOutgoing");
const friendsAcceptedEl = document.getElementById("friendsAccepted");
const groupInvitesEl = document.getElementById("groupInvites");
const friendsBadgeEl = document.getElementById("friendsBadge");
// Friends drawer tabs (Friends / Room requests)
const friendsTabBtn = document.getElementById("friendsTabBtn");
const roomReqTabBtn = document.getElementById("roomReqTabBtn");
const roomReqBadgeEl = document.getElementById("roomReqBadge");
const friendsTabPaneEl = document.getElementById("friendsTabPane");
const roomReqTabPaneEl = document.getElementById("roomReqTabPane");
const roomReqListEl = document.getElementById("roomReqList");
const roomReqRefreshBtn = document.getElementById("roomReqRefreshBtn");
const roomsOwnedListEl = document.getElementById("roomsOwnedList");
const roomsMemberListEl = document.getElementById("roomsMemberList");
const publicRoomsSearchEl = document.getElementById("publicRoomsSearch");
const publicRoomsSearchListEl = document.getElementById("publicRoomsSearchList");
const roomsRefreshBtnEl = document.getElementById("roomsRefreshBtn");

const toggleRoomsSearchBtn = document.getElementById("toggleRoomsSearch");
const roomsSearchPanelEl = document.getElementById("roomsSearchPanel");

const roomsSearchCloseBtn = document.getElementById("roomsSearchClose");

function openRoomsSearch() {
  if (!roomsSearchPanelEl) return;
  roomsSearchPanelEl.classList.add("open");
  roomsSearchPanelEl.setAttribute("aria-hidden", "false");

  toggleRoomsSearchBtn?.classList.add("is-hidden");

  setTimeout(() => {
    try { roomsSearchEl?.focus({ preventScroll: true }); }
    catch { roomsSearchEl?.focus(); }
  }, 0);
}

function closeRoomsSearch() {
  if (!roomsSearchPanelEl) return;
  roomsSearchPanelEl.classList.remove("open");
  roomsSearchPanelEl.setAttribute("aria-hidden", "true");

  toggleRoomsSearchBtn?.classList.remove("is-hidden");

  try { toggleRoomsSearchBtn?.focus({ preventScroll: true }); }
  catch { toggleRoomsSearchBtn?.focus(); }
}

toggleRoomsSearchBtn && (toggleRoomsSearchBtn.onclick = (e) => {
  e.preventDefault();
  e.stopPropagation();
  const isOpen = roomsSearchPanelEl?.classList.contains("open");
  if (isOpen) closeRoomsSearch();
  else openRoomsSearch();
});

roomsSearchCloseBtn && (roomsSearchCloseBtn.onclick = closeRoomsSearch);

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && roomsSearchPanelEl?.classList.contains("open")) {
    closeRoomsSearch();
  }
});

// ===== Message handler + Port health =====
async function handlePortMessage(msg) {
  if (DEBUG_LOGS) console.log("MSG:", msg?.type, sanitizeMsgForLog(msg));

  if (!msg || !msg.type) return;

  // __lastAnyMsg: refreshed on every inbound message (used for tab-stale
  // detection if needed). __lastPong: refreshed ONLY on ping/pong, so the
  // watchdog has a true liveness signal that isn't masked by ordinary
  // traffic (e.g. a busy room would otherwise hide a wedged background).
  window.__lastAnyMsg = Date.now();

  if (msg.type === "ping" || msg.type === "pong") {
    window.__lastPong = Date.now();
    return;
  }

  if (msg.type === "ws_closed") {
    const code = Number(msg.code || 0);
    const reason = String(msg.reason || "");
    const r = reason.toLowerCase();
    if (code === 1008 && (r.includes("kicked") || r.includes("no access"))) {
      leaveRoomUI(reason);
      return;
    }
    return;
  }

  if (msg.type === "unlock_kek_set_ok") {
    if (msg.ok) {
      try { retryPendingHistoryAfterUnlock?.(); } catch {}
	  try { retryPendingDmAfterUnlock?.(); } catch {}
    }
    return;
  }

if (msg.type === "members_changed") {
  const rid = String(Number(msg.room_id || 0));
  if (rid && rid !== "0") {
    roomMembersById[rid] = null;
    if (membersPanelOpen) requestRoomMembers(Number(rid));
  }
  return;
}


if (msg.type === "banned") {
  const m = String(msg.message || "User is banned");
  try { await __ui.alert(m, "Banned"); } catch {}
  location.href = "login.html";
  return;
}

if (msg.type === "error") {
  const m = String(msg.message || "Error");
  const ml = m.toLowerCase();

  if (ml.includes("kicked") || ml.includes("no access")) {
    leaveRoomUI(m);
    return;
  }

  // DM socket down (often after crypto lock/unlock) reconnect DM WS
  if (ml.includes("dm: ws not open")) {
    if (dmMode && activeDmThreadId) {
      const now = Date.now();
      if (now - (__pendingDmSince || 0) < 1500) return; // debounce

      __pendingDmThreadId = Number(activeDmThreadId);
      __pendingDmPeer = String(activeDmPeer || "");
      __pendingDmSince = now;

      try {
        safePost({
          type: "dm_connect",
          thread_id: Number(activeDmThreadId),
          peer_username: String(activeDmPeer || "")
        });
      } catch {}
    }
    return;
  }
}

if (msg.type === "dm_connect_res") {
  if (msg.ok) {
    // history is HTTP-based in SW, safe to request immediately
    if (dmMode && activeDmThreadId && Number(msg.thread_id) === Number(activeDmThreadId)) {
      try { safePost({ type: "dm_history", thread_id: Number(activeDmThreadId), limit: HISTORY_PAGE_SIZE }); } catch {}
    }
  } else {
    console.warn(msg.message || "DM connect failed");
  }
  return;
}

if (msg.type === "auth_state") {
  if (!msg.loggedIn) {
    __authNotLoggedStreak++;

    isLoggedIn = false;

    // show ban notice once per page load
    try {
      if (msg.reason === "banned" && !window.__banNoticeShown) {
        window.__banNoticeShown = true;
        const why = (msg.ban_reason || "").trim();
        const text = (msg.message || "").trim() || ("You were banned" + (why ? (": " + why) : ""));
        try { __ui?.alert?.(text); } catch { alert(text); }
        // after showing message, force redirect to login quickly
        setTimeout(() => { try { location.href = "login.html"; } catch {} }, 50);
      }
    } catch {}
    try { leaveRoomUI("Logged out"); } catch {}
    try { clearChat(); } catch {}

    currentRecentUser = "";
    recentItems = [];
    recentActiveKey = "";
    renderRecent();

    if (statusEl) {
      statusEl.textContent = "WARNING: Offline";
      statusEl.className = "offline";
    }

    try { setModeRooms?.(); } catch {}
    dmMode = false;
    activeDmThreadId = null;
    activeDmPeer = "";

    wsOnline = false;
    lastHistoryRoomId = null;
    renderedHistoryRoomId = null;
    
    if (connectBtn) connectBtn.disabled = true;
    if (disconnectBtn) disconnectBtn.disabled = true;

    try {
      if (__authNotLoggedTimer) clearTimeout(__authNotLoggedTimer);
      __authNotLoggedTimer = setTimeout(() => safePost({ type: "auth_get" }), 350);
    } catch {}

    if (__authNotLoggedStreak >= 3) location.href = "login.html";
    return;
  }

  __authNotLoggedStreak = 0;
  if (__authNotLoggedTimer) { clearTimeout(__authNotLoggedTimer); __authNotLoggedTimer = null; }

  isLoggedIn = true;

  if (msg.username && nameInput) nameInput.value = msg.username;
  try {
    const activeUser = String(msg.username || "").trim().toLowerCase();
    if (activeUser) {
      await chrome.storage.session.set({ e2ee_active_user_v2: activeUser });
    }
  } catch {}
 
  currentRecentUser = msg.username || "";
  loadRecent();

  if (statusEl) {
    statusEl.textContent = "WARNING: Ready";
    statusEl.className = "idle";
  }

  if (connectBtn) connectBtn.disabled = false;
  if (disconnectBtn) disconnectBtn.disabled = true;

try {
  await ensureCryptoReady({ interactive: false, reason: "Auto-unlock after login" });
  try { retryPendingHistoryAfterUnlock?.(); } catch {}
  try { retryPendingDmAfterUnlock?.(); } catch {}
} catch (e) {
  console.warn("auto-unlock after login failed:", e);
}

  if (!roomsLoadedAfterLogin) {
    roomsLoadedAfterLogin = true;
    requestMyRooms();
  }

  safePost({ type: "dm_list" });
  safePost({ type: "ws_connect_auto" });

  if (dmMode && activeDmThreadId) {
    safePost({ type: "dm_connect", thread_id: activeDmThreadId, peer_username: activeDmPeer });
  }
  return;
}

if (msg.type === "presence") {
  if (msg.room_id != null) {
    if (typeof setActiveRoomFromServer === "function") {
    setActiveRoomFromServer(msg.room_id, msg.room_name);
  }

    const rid = Number(msg.room_id);
    try { await fetchRoomPin(rid); } catch (e) {
      console.warn("fetchRoomPin failed:", e?.message || e);
    }
  }
  updatePinnedBar(); 
  if (typeof updateLeaveBtnState === "function") updateLeaveBtnState();


  if (msg.room_id != null) {
    const rid = Number(msg.room_id);
    if (lastHistoryRoomId !== rid) {
      lastHistoryRoomId = rid;
      renderedHistoryRoomId = null;
      __resetRoomHistoryPaging(rid);
      __roomHistoryLimitByRoom.set(rid, HISTORY_PAGE_SIZE);
      let keyOk = false;
      try {
        keyOk = await loadRoomKey(rid);
      } catch (err) {
        console.error("Failed to load room key:", err);
      }

if (!keyOk) {
  __pendingHistoryRoomId = Number(msg.room_id || msg.roomId || activeRoomId || 0) || __pendingHistoryRoomId;
  __pendingHistorySince = Date.now();

  console.warn("Room key not loaded (crypto locked). Will retry after unlock.");

  try { window.onCryptoLockedNeedUnlock?.("history"); } catch {}

  return;
}
      safePost({ type: "history_get", roomId: rid, limit: HISTORY_PAGE_SIZE });
    }
  }

renderCurrentRoom({ online: true });
highlightActiveRoom();

const list = Array.isArray(msg.online) ? msg.online : [];
lastPresenceOnline = list;

if (msg.room_id != null) {
  const rid = String(Number(msg.room_id));
  lastOnlineByRoomId[rid] = list;

  if (membersPanelOpen) {
    const cached = roomMembersById[rid];
    const looksLikeFallbackStrings =
      Array.isArray(cached) && cached.length && typeof cached[0] === "string";

    if (!cached || looksLikeFallbackStrings) requestRoomMembers(Number(rid));
  }
}

if (membersPanelOpen) {
  renderPresence(list);
}
  setInviteVisible(true);

  // --- Key change notifications (Step 5) ---
  // Proactively check all online peers' public keys in the background.
  // If any key changed since last known fingerprint, show a warning banner.
  if (list.length > 0 && isCryptoUsable() && window.__keyChangeNotifications) {
    (async () => {
      try {
        const changed = await window.__keyChangeNotifications.checkRoomPeersKeyChanges(list);
        if (changed.length > 0) {
          if (typeof addKeyChangeWarnings === "function") {
            addKeyChangeWarnings(changed);
          }
        }
      } catch (e) {
        console.warn("Key change check failed:", e?.message || e);
      }
    })();
  }

  if (pendingRoomId != null && pendingRoomPass) {
    if (msg.room_id != null && Number(msg.room_id) === Number(pendingRoomId)) {
      saveRoomPass(pendingRoomId, pendingRoomPass);
      if (pendingRoomAlias) {
        // SEC: encrypt alias password before storage
        (async () => {
          const enc = await encryptForStorage(pendingRoomPass);
          if (!enc) {
            console.warn("Alias password was not saved: storage encryption is unavailable");
            return;
          }
          roomPassByAlias[pendingRoomAlias] = enc;
          chrome.storage.local.set({ roomPassByAlias });
        })();
      }
      pendingRoomId = null;
      pendingRoomPass = "";
      lastConnectRoomName = "";
    }
  }

  return;
}

if (msg.type === "auth_needed") {
  const key = (msg.roomName || (roomInput?.value || "")).trim();
  const p = (await __ui.prompt(`The room "${key}" requires a password.`, {
    placeholder: "Room password",
    inputType: "password"
  })).trim();
  if (!p) return;
  pendingRoomAlias = key;
  pendingRoomPass = p;
  if (/^\d+$/.test(key)) pendingRoomId = Number(key);
  connect(p);
  return;
}

if (msg.type === "history_res") {
  const appendOlder = !!msg.append_older;
  if (!msg.ok) {
    __roomOlderLoading = false;
    __pendingOlderScrollRestore = null;
    console.warn(msg.message || "History error");
    return;
  }
  if (activeRoomId != null && msg.roomId != null && Number(msg.roomId) !== Number(activeRoomId)) {
    if (appendOlder) {
      __roomOlderLoading = false;
      __pendingOlderScrollRestore = null;
    }
    return;
  }

  const rid = Number(msg.roomId);
  if (!appendOlder && renderedHistoryRoomId === rid) return;
  renderedHistoryRoomId = rid;

  const rows = Array.isArray(msg.messages) ? msg.messages : [];
  const hasMore = !!msg.has_more;
  __updateRoomHistoryCursor(rid, rows, hasMore, appendOlder);

  clearChat({ resetKeyAlerts: !appendOlder });
  if (__syncCryptoUiLockFromRuntime()) {
    __roomOlderLoading = false;
    __pendingOlderScrollRestore = null;
    return;
  }
  
  for (const m of rows) {
    const user = m.username || "unknown";
    const text = m.text || "";
    const meName = (nameInput.value || "anon").trim().toLowerCase();
    // Decrypt message
    const decryptedText = await decryptMessageFromRoom(rid, text);
    const msgTs = m.created_at || m.ts || null;
    const { text: _hmText, reply: _hmReply } = parseV2Payload(decryptedText || "");
    addMsg(user, _hmText, user.toLowerCase() === meName, msgTs, _hmReply);
  }
  if (appendOlder) __applyOlderScrollRestore("room", rid);
  __roomOlderLoading = false;
  return;
}

if (msg.type === "status") {
  const online = !!msg.online;
  const reconnecting = !!msg.reconnecting;

  const showIdle = !online && !reconnecting && isLoggedIn;

  wsOnline = online;
  updateLeaveBtnState();

  if (statusEl) {
    statusEl.textContent = online
      ? "\u25CF Online"
      : reconnecting
        ? "* Reconnecting..."
        : showIdle
          ? "\u25CF Ready"
          : "\u25CB Offline";

    statusEl.className = online
      ? "online"
      : reconnecting
        ? "reconnecting"
        : showIdle
          ? "idle"
          : "offline";
  }

  if (connectBtn) {
    connectBtn.disabled = online;
    connectBtn.title = online
      ? "You already in room"
      : reconnecting
        ? "Reconnecting- (You can click Join manually)"
        : "Connect to the room";
  }

  if (leaveBtn) {
    const rid = activeRoomId != null ? String(activeRoomId) : "";
    const isOwner = rid ? !!roomOwnerById[rid] : false;
    leaveBtn.disabled = !(online && !dmMode && !!rid && !isOwner);
  }

  if (disconnectBtn) {
    disconnectBtn.disabled = !online;
  }
  if (!online) renderPresence([]);
  renderCurrentRoom({ online });

  if (online) requestGroupInvites();
  return;
}

if (msg.type === "message") {
  const rid = msg.room_id != null ? String(msg.room_id) : "";
  const activeRid = activeRoomId != null ? String(activeRoomId) : "";
  const __normUser = (v) => String(v || "").trim().toLowerCase();
  const meNameRaw = (currentRecentUser || nameInput.value || "anon");
  const meName = __normUser(meNameRaw);
  const fromMe = __normUser(msg.from) === meName;

  if (!activeRid && rid) {
    if (!fromMe) __markRoomUnread(rid);
    return;
  }

  if (activeRid && rid && rid !== activeRid) {
    if (!fromMe) __markRoomUnread(rid);
    return;
  }

  if (rid) __clearRoomUnread(rid);

  // If user is in DM mode, don't render room messages into the chat element
  // (they share the same DOM node). Mark unread instead.
  if (dmMode) {
    if (rid && !fromMe) __markRoomUnread(rid);
    return;
  }

//If crypto isn't ready yet (no user private key), we can't decrypt messages now ("peek decrypt").
//Mark the room as unread (for incoming messages) and return.
   const canDecryptNow = !!CM()?.userPrivateKey; // CryptoKey

  if (!canDecryptNow) {
    if (rid && !fromMe) __markRoomUnread(rid);
    return;
  }

  const roomIdForDecrypt = msg.room_id != null ? Number(msg.room_id) : Number(activeRoomId);
  const decryptedText = await decryptMessageFromRoom(roomIdForDecrypt, msg.text);
  const msgTs = msg.ts || Date.now();
  const { text: _rmText, reply: _rmReply } = parseV2Payload(decryptedText || "");
  addMsg(msg.from, _rmText, fromMe, msgTs, _rmReply);

  // --- Key change check for message sender (Step 5) ---
  if (!fromMe && msg.from && window.__keyChangeNotifications) {
    window.__keyChangeNotifications.checkAndAlertKeyChange(msg.from).then(changedUser => {
      if (changedUser && typeof addKeyChangeWarning === "function") {
        addKeyChangeWarning(changedUser);
      }
    }).catch(() => {});
  }

  return;
}

if (msg.type === "error") {
  const m = String(msg.message || "Error");

  if (/websocket error/i.test(m)) {
    console.warn("WS transport error:", m);
    return;
  }

  // Password / access errors
  if (/pass|password|403|forbidden|denied/i.test(m)) {
    const rid = activeRoomId ?? pendingRoomId;

    if (rid != null) {
      delete roomPassById[String(rid)];
      chrome.storage.local.set({ roomPassById });
      pendingRoomId = null;
      pendingRoomPass = "";

      const title = lastConnectRoomName ? ` "${lastConnectRoomName}"` : "";
      const p = (await __ui.prompt(
        `Invalid room password${title}. Please enter the password again:`,
        {
          title: "Room password",
          placeholder: "password",
          value: "",
          inputType: "password",
          okText: "Unlock",
          cancelText: "Cancel",
        }
      )).trim();

      if (p) {
        pendingRoomId = rid;
        pendingRoomPass = p;
        connect(p);
      }
      return;
    }

    if (rid == null && pendingRoomAlias) {
      const title = lastConnectRoomName ? ` "${lastConnectRoomName}"` : "";
      const p = (await __ui.prompt(
        `Invalid room password${title}. Please enter the password again:`,
        {
          title: "Room password",
          placeholder: "password",
          value: "",
          inputType: "password",
          okText: "Unlock",
          cancelText: "Cancel",
        }
      )).trim();

      if (p) connect(p);
      return;
    }
  }

  await __ui.alert(m);
  return;
}

  if (msg.type === "rooms_mine") {
    console.log("Rooms_mine response:", {
      ok: msg.ok,
      rooms_count: msg.rooms?.length,
      first_room: msg.rooms?.[0],
      message: msg.message
    });
    
    if (msg.ok === false) {
      console.warn(msg.message || "mine rooms list failed");
      lastMineRooms = [];
    } else {
      lastMineRooms = Array.isArray(msg.rooms) ? msg.rooms : [];
      
      // Enrich rooms with cached metadata if server doesn't provide it
      for (const room of lastMineRooms) {
        const cached = __roomMetaCache.get(String(room.id));
        if (cached && (!room.logo_token && !room.logo_url)) {
          room.logo_token = cached.logo_token;
          room.logo_url = cached.logo_url;
          room.description = cached.description;
          console.log(`Enriched room ${room.id} from cache...`, { logo_token: room.logo_token, logo_url: room.logo_url });
        }
      }
    }
    lastRoomsMine = lastMineRooms;
    renderRooms(lastMineRooms, lastPublicRooms);
	window.__refreshUnreadFromServer?.();
    return;
  }

  if (msg.type === "rooms_public_list") {
    if (msg.ok === false) {
      console.warn(msg.message || "public rooms list failed");
      lastPublicRooms = [];
    } else {
      lastPublicRooms = Array.isArray(msg.rooms) ? msg.rooms : [];
    }
    lastRoomsPublic = lastPublicRooms;
    renderRooms(lastMineRooms, lastPublicRooms);
    return;
  }

  if (msg.type === "rooms_join_request") {
    (async () => {
      if (msg.ok) {
        await __ui.alert("Request sent. Waiting for admin approval.");
        safePost({ type: "rooms_public_list" });
        requestMyRooms();
      } else {
        await __ui.alert(msg.message || "Join request failed");
      }
    })();
    return;
  }

if (msg.type === "rooms_join_requests_list") {
  (async () => {
    if (!msg.ok) {
      await __ui.alert(msg.message || "Failed to retrieve requests.");
      return;
    }

    const rid = Number(msg.roomId || activeRoomId || 0);
    const items = Array.isArray(msg.items) ? msg.items : [];
    if (!rid) return;

    if (!items.length) {
      await __ui.alert("No join requests.");
      return;
    }

    for (const it of items) {
      const uname = (it.username || "").trim();
      if (!uname) continue;

      const okApprove = await __ui.confirm(
        `Approve join request from "${uname}"?`,
        "Room join request"
      );

      if (okApprove) {
        safePost({ type: "rooms_join_approve", roomId: rid, username: uname });
      } else {
        const okReject = await __ui.confirm(
          `Reject join request from "${uname}"?`,
          "Room join request"
        );
        if (okReject) safePost({ type: "rooms_join_reject", roomId: rid, username: uname });
      }
    }
  })();

  return;
}

  if (msg.type === "rooms_join_requests_all") {
    if (!msg.ok) {
      console.warn(msg.message || "Failed to retrieve requests (all)");
      renderRoomJoinRequestsAll([]);
      return;
    }
    const items = Array.isArray(msg.items) ? msg.items : [];
    window.__cachedRoomJoinRequests = items;
    renderRoomJoinRequestsAll(items);
    try { refreshRoomManageIfVisible?.(); } catch {}
    return;
  }

if (msg.type === "rooms_join_approve") {
  (async () => {
    if (msg.ok) {
      const rid = Number(msg.roomId || activeRoomId || 0);
      const uname = msg.username;

      await __ui.alert(`Approved: ${uname}`);

      try {
        if (!rid) throw new Error("No roomId");
        const isOwner = !!roomOwnerById[String(rid)];
        if (!isOwner) return;

        await shareRoomKeyToUser(rid, uname);
      } catch (e) {
        console.warn("Warning: Key share failed after approve:", e?.message || e);
        await __ui.alert("Approve OK, but key share failed: " + (e?.message || e));
      } finally {
        requestMyRooms();
        safePost({ type: "rooms_public_list" });
        if (rid) requestRoomMembers(rid);
        safePost({ type: "rooms_join_requests_list" });
      }
    } else {
      await __ui.alert(msg.message || "Approve failed");
    }
  })();

  return;
}

if (msg.type === "rooms_join_reject") {
  (async () => {
    if (msg.ok) {
      await __ui.alert(`Rejected: ${msg.username}`);
      safePost({ type: "rooms_public_list" });
      safePost({ type: "rooms_join_requests_list" });
    } else {
      await __ui.alert(msg.message || "Reject failed");
    }
  })();
  return;
}

if (msg.type === "rooms_delete") {
  (async () => {
    if (msg.ok) {
      requestMyRooms();
    } else {
      await __ui.alert(msg.message || "Delete room failed");
    }
  })();
  return;
}

if (msg.type === "rooms_invite") {
  (async () => {
    if (msg.ok) {
      // roomId might come from the action context (e.g. invite from room list)
      // so we must not rely only on activeRoomId.
      const rid = (msg.roomId != null ? Number(msg.roomId)
        : (msg.room_id != null ? Number(msg.room_id)
        : (__lastInviteRoomId != null ? Number(__lastInviteRoomId)
        : activeRoomId)));
      const uname = msg.username;

      await __ui.alert(`Invited: ${uname}`);

      try {
        if (!rid) throw new Error("No roomId");
        const isOwner = !!roomOwnerById[String(rid)];
        if (!isOwner) return;

        await shareRoomKeyToUser(rid, uname);
        console.log("Room key shared to", uname);
      } catch (e) {
        console.warn("Key share failed:", e?.message || e);
        await __ui.alert("Invite OK, but key share failed: " + (e?.message || e));
      } finally {
        requestMyRooms();
      }
    } else {
      await __ui.alert(msg.message || "Invite failed");
    }
  })();

  return;
}

if (msg.type === "rooms_kick") {
  (async () => {
    if (msg.ok) {
      const kickedUser = msg.username || "?";
      const rid = msg.roomId || activeRoomId;
      await __ui.alert(`Kicked: ${kickedUser}`);
      requestMyRooms();
      if (activeRoomId) requestRoomMembers(activeRoomId);

      // --- Room key rotation (Step 6) ---
      // After removing a member, rotate the room key so the kicked user
      // cannot decrypt future messages with the old key.
      if (rid && isCryptoUsable() && !!roomOwnerById[String(rid)]) {
        try {
          addMsg("System", `Rotating room key after removing ${kickedUser}...`, false, Date.now());
          const result = await rotateRoomKey(rid, { kickedUsername: kickedUser });
          if (result.ok) {
            addMsg("System",
              `\uD83D\uDC51 Room key rotated. New key distributed to ${result.shared} member(s).`,
              false, Date.now());
          } else {
            addMsg("System",
              `\u26A0\u00A0  Room key rotation failed: ${result.error || "unknown error"}. Old key is still in use.`,
              false, Date.now());
          }
        } catch (e) {
          console.error("Room key rotation error:", e);
          addMsg("System",
            `\u26A0\u00A0 Room key rotation error: ${e?.message || e}`,
            false, Date.now());
        }
      }
    } else {
      await __ui.alert(msg.message || "Kick failed");
    }
  })();

  return;
}

if (msg.type === "rooms_set_role") {
  (async () => {
    if (msg.ok) {
      await __ui.alert(`Role changed: ${msg.username} -> ${msg.role}`);
      if (activeRoomId) requestRoomMembers(activeRoomId);
    } else {
      await __ui.alert(msg.message || "Set role failed");
    }
  })();

  return;
}

if (msg.type === "rooms_members_res") {
  if (msg.ok) {
    const rid = Number(msg.roomId);
    roomMembersById[String(rid)] = Array.isArray(msg.members) ? msg.members : [];
    const online = lastOnlineByRoomId[String(rid)] || [];
    if (activeRoomId === rid) renderPresence(online);
    try { refreshRoomManageIfVisible?.(); } catch {}
  } else {
    console.warn(msg.message || "members failed");
  }
  return;
}

if (msg.type === "rooms_leave") {
  if (leaveBtn) leaveBtn.disabled = false;

  if (msg.ok) {
    // If user triggered leave from the Rooms list, do NOT drop the currently open room
    // unless it's exactly the same room.
    const ridNum = Number(msg.roomId || 0);
    if (ridNum && activeRoomId === ridNum) {
      leaveRoomUI("left");
    }
    requestMyRooms();
    const rid = String(Number(msg.roomId || 0));
    if (rid && rid !== "0") {
      delete roomOwnerById[rid];
      delete roomMembersById[rid];
      delete lastOnlineByRoomId[rid];
      delete roomReadonlyById[rid];
    }
  } else {
    (async () => {
      await __ui.alert(msg.message || "Leave failed");
    })();
  }

  return;
}

// --- FRIENDS: incoming requests ---
if (msg.type === "friends_requests_incoming") {
  if (!msg.ok) {
    console.warn(msg.message || "incoming failed");
    renderIncoming([]);
    return;
  }
  renderIncoming(msg.items || []);
  return;
}

// --- FRIENDS: outgoing requests ---
if (msg.type === "friends_requests_outgoing") {
  if (!msg.ok) {
    console.warn(msg.message || "outgoing failed");
    renderOutgoing([]);
    return;
  }
  renderOutgoing(msg.items || []);
  return;
}

// --- FRIENDS: accepted list ---
if (msg.type === "friends_list") {
  if (!msg.ok) {
    console.warn(msg.message || "friends_list failed");
    renderAccepted([]);
    return;
  }
  renderAccepted(msg.friends || []);
  return;
}

// --- FRIENDS: send request result ---
if (msg.type === "friends_request") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Request failed"); })();
    return;
  }
  if (friendNameInput) friendNameInput.value = "";
  requestFriendsAll();
  return;
}

// --- FRIENDS: accept/decline result ---
if (msg.type === "friends_accept") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Accept failed"); })();
    return;
  }
  requestFriendsAll();
  return;
}

if (msg.type === "friends_decline") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Decline failed"); })();
    return;
  }
  requestFriendsAll();
  return;
}

if (msg.type === "friends_remove") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Remove failed"); })();
    return;
  }
  requestFriendsAll();
  return;
}

// --- ROOMS: incoming group invites ---
if (msg.type === "rooms_invites_incoming") {
  if (!msg.ok) {
    renderGroupInvites([]);
    setFriendsInvitesBadge(0);
    return;
  }
  const items = Array.isArray(msg.items) ? msg.items : [];
  renderGroupInvites(items);
  setFriendsInvitesBadge(items.length);
  return;
}

// --- ROOMS: invite accept/decline ---
if (msg.type === "rooms_invite_accept") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Invite accept failed"); })();
    return;
  }
  requestGroupInvites();
  requestMyRooms();
  return;
}

if (msg.type === "rooms_invite_decline") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "Invite decline failed"); })();
    return;
  }
  requestGroupInvites();
  return;
}

// DM handlers
if (msg.type === "dm_open_ok") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "DM open failed"); })();
    return;
  }

  const threadId = Number(msg.thread_id);
  const peer = (msg.peer_username || "").trim();

  try {
    const r = await chrome.storage.local.get("conn");
    const prev = (r && r.conn && typeof r.conn === "object") ? r.conn : {};
    await chrome.storage.local.set({ conn: { ...prev, dm_thread_id: threadId, dm_peer: peer } });
  } catch {}

  try { __clearDmUnread(threadId); } catch {}

  setModeDm(threadId, peer);
  clearChat();
  _sigUnverifiedShown.clear(); // reset per-thread unverified banner dedup
  __resetDmHistoryPaging(threadId);
  __dmHistoryLimitByThread.set(threadId, HISTORY_PAGE_SIZE);

  try {
    await ensureDmKeyReady(threadId, peer);
  } catch (e) {
    // DM key locked: queue the thread for retry after the user unlocks,
    // and skip dm_connect/dm_history (they would proceed without a usable
    // key and silently produce undecryptable history).
    if (e?.code === "DM_KEY_LOCKED") {
      __pendingDmThreadId = threadId;
      __pendingDmPeer = peer;
      __pendingDmSince = Date.now();
    } else {
      console.warn("ensureDmKeyReady failed (dm_open_ok):", e);
    }
    return;
  }

  safePost({ type: "dm_connect", thread_id: threadId, peer_username: peer });
  safePost({ type: "dm_history", thread_id: threadId, limit: HISTORY_PAGE_SIZE });
  safePost({ type: "dm_list" });
  return;
}

if (msg.type === "dm_delete_res") {
  if (!msg.ok) {
    (async () => { await __ui.alert(msg.message || "DM delete failed"); })();
    return;
  }
  if (msg.scope === "both" && msg.pending_confirmation) {
    (async () => {
      const ttl = Number(msg.confirm_ttl_sec || 0);
      const tail = ttl > 0 ? `\nWaiting up to ${ttl}s for second participant confirmation.` : "";
      await __ui.alert("Delete-for-both request sent." + tail);
    })();
    safePost({ type: "dm_list" });
    return;
  }
  const deletedThreadId = Number(msg.thread_id || 0);
  if (deletedThreadId && Number(activeDmThreadId || 0) === deletedThreadId) {
    try { safePost({ type: "dm_disconnect" }); } catch {}
    setModeRoom();
    clearChat();
  }
  safePost({ type: "dm_list" });
  return;
}

if (msg.type === "dm_history_res") {
  const appendOlder = !!msg.append_older;
  if (!msg.ok) {
    __dmOlderLoading = false;
    __pendingOlderScrollRestore = null;
    console.warn(msg.message || "DM history failed");
    return;
  }
  if (!dmMode) {
    if (appendOlder) {
      __dmOlderLoading = false;
      __pendingOlderScrollRestore = null;
    }
    return;
  }
  if (Number(msg.thread_id) !== Number(activeDmThreadId)) {
    if (appendOlder) {
      __dmOlderLoading = false;
      __pendingOlderScrollRestore = null;
    }
    return;
  }

  const rows = Array.isArray(msg.messages) ? msg.messages : [];
  const hasMore = !!msg.has_more;
  __updateDmHistoryCursor(Number(msg.thread_id), rows, hasMore, appendOlder);
  clearChat({ resetKeyAlerts: !appendOlder });
  if (__syncCryptoUiLockFromRuntime()) {
    __dmOlderLoading = false;
    __pendingOlderScrollRestore = null;
    return;
  }
  const meName = (nameInput.value || "anon").trim();
  const historyPeer = activeDmPeer;

  try {
    await ensureDmKeyReady(activeDmThreadId, historyPeer);
  } catch (e) {
    console.warn("ensureDmKeyReady failed (history):", e);
  }

  for (const m of rows) {
    let user = m.username || null;

    // UD delivers base64url(utf8(JSON)); decryptDm expects JSON string
    let text = __udB64urlToUtf8Maybe(m.text || "");
    let msgReply = null;

    try {
      // If it looks like encrypted JSON -> decrypt
      if (typeof text === "string" && text.trim().startsWith("{")) {
        const histMsgTs = m.created_at || m.ts || null;
        const dec = await decryptDm(activeDmThreadId, text, historyPeer, histMsgTs);
        if (dec == null) continue;

        if (dec && typeof dec === "object" && dec.sealed) {
          const { text: _t, reply: _r } = parseV2Payload(dec.text);
          text = _t; msgReply = _r;
          if (!user && dec.sealedFrom) user = dec.sealedFrom;
          const meNameLower = String(meName || "").trim().toLowerCase();
          const senderLower = String(dec.sealedFrom || "").trim().toLowerCase();
          if (dec.sigValid === false && typeof addSigFailWarning === "function") {
            addSigFailWarning(dec.sealedFrom || user);
          } else if (dec.sigValid === null && dec.sealedFrom && senderLower !== meNameLower
              && !_sigUnverifiedShown.has(senderLower)
              && typeof addSigUnverifiedWarning === "function") {
            _sigUnverifiedShown.add(senderLower);
            addSigUnverifiedWarning(dec.sealedFrom);
          }
        } else {
          const raw = typeof dec === "string" ? dec : text;
          const { text: _t, reply: _r } = parseV2Payload(raw);
          text = _t; msgReply = _r;
        }
      }
    } catch (e) {
      console.warn("DM decrypt failed (history):", e);
    }

    // sealed-sender часто не даёт username -> используем peer треда
    if (!user) user = activeDmPeer || "unknown";

    const msgTs = m.created_at || m.ts || null;
    addMsg(
      user,
      text,
      String(user || "").trim().toLowerCase() === String(meName || "").trim().toLowerCase(),
      msgTs,
      msgReply
    );
  }
  if (appendOlder) __applyOlderScrollRestore("dm", Number(msg.thread_id));
  __dmOlderLoading = false;
  return;
}

if (msg.type === "dm_send_res") {
  if (!msg.ok) {
    console.warn("DM send failed:", msg.message);
    (async () => { await __ui.alert("DM send failed: " + (msg.message || "unknown error")); })();
  }
  return;
}

if (msg.type === "dm_message") {
  safePost({ type: "dm_list" });

  if (dmMode && Number(msg.thread_id) === Number(activeDmThreadId)) {
    if (__syncCryptoUiLockFromRuntime()) return;
    const livePeer = activeDmPeer;
    const __normUser = (v) => String(v || "").trim().toLowerCase();
    const meName = __normUser(currentRecentUser || nameInput?.value || "anon");
    let user = msg.username || null;
    let t = __udB64urlToUtf8Maybe(msg.text || "");
    let liveReply = null;
    try {
      if (t) {
        const liveMsgTs = msg.ts || Date.now();
        const dec = await decryptDm(activeDmThreadId, t, livePeer, liveMsgTs);
        if (dec == null) return;
        if (dec && typeof dec === "object" && dec.sealed) {
          const { text: _t, reply: _r } = parseV2Payload(dec.text);
          t = _t; liveReply = _r;
          if (!user && dec.sealedFrom) user = dec.sealedFrom;
          const _meL = String(meName || "").trim().toLowerCase();
          const _sndrL = String(dec.sealedFrom || "").trim().toLowerCase();
          if (dec.sigValid === false && typeof addSigFailWarning === "function") {
            addSigFailWarning(dec.sealedFrom || user);
          } else if (dec.sigValid === null && dec.sealedFrom && _sndrL !== _meL
              && !_sigUnverifiedShown.has(_sndrL)
              && typeof addSigUnverifiedWarning === "function") {
            _sigUnverifiedShown.add(_sndrL);
            addSigUnverifiedWarning(dec.sealedFrom);
          }
        } else {
          const raw = typeof dec === "string" ? dec : t;
          const { text: _t, reply: _r } = parseV2Payload(raw);
          t = _t; liveReply = _r;
        }
      }
    } catch (e) {
      console.warn("DM decrypt failed (live):", e);
    }
    if (!user) user = activeDmPeer || "unknown";
    const msgTs = msg.ts || Date.now();
    addMsg(user, t, __normUser(user) === meName, msgTs, liveReply);

// --- Key change check for DM peer (sealed sender safe) ---
const __peerForKeyCheck =
  (String(user || "").trim().toLowerCase() !== "unknown" ? user : (activeDmPeer || ""));

if (__peerForKeyCheck && __normUser(__peerForKeyCheck) !== meName && window.__keyChangeNotifications) {
  window.__keyChangeNotifications.checkAndAlertKeyChange(__peerForKeyCheck).then(changedUser => {
    if (changedUser && typeof addKeyChangeWarning === "function") {
      addKeyChangeWarning(changedUser);
    }
  }).catch(() => {});
}
  } else {
    // Unread dot for other DM threads (ignore our own echoed messages)
    const __normUser = (v) => String(v || "").trim().toLowerCase();
    const meName = __normUser(currentRecentUser || nameInput?.value || "anon");
    let fromMe = __normUser(msg.username) === meName;

    // Sealed-sender live events may carry username=null by design.
    // In that case, try to resolve sender locally from decrypted payload.
    if (!fromMe && !msg.username) {
      try {
        const tid = Number(msg.thread_id || 0);
        const peer = (dmItems || []).find(d => Number(d?.thread_id) === tid)?.peer_username || "";
        let t = __udB64urlToUtf8Maybe(msg.text || "");
        if (typeof t === "string" && t.trim().startsWith("{")) {
          const dec = await decryptDm(tid, t, peer, msg.ts || null);
          if (dec && typeof dec === "object" && dec.sealed && dec.sealedFrom) {
            fromMe = __normUser(dec.sealedFrom) === meName;
          }
        }
      } catch {}
    }

    if (!fromMe) __markDmUnread(msg.thread_id);
  }
  return;
}

if (msg.type === "dm_presence") {
  // --- Key change check for DM peer (Step 5) ---
  if (dmMode && activeDmPeer && window.__keyChangeNotifications) {
    window.__keyChangeNotifications.checkAndAlertKeyChange(activeDmPeer).then(changedUser => {
      if (changedUser && typeof addKeyChangeWarning === "function") {
        addKeyChangeWarning(changedUser);
      }
    }).catch(() => {});
  }
  return;
}

if (msg.type === "dm_status") {
  __dmWsOnline = !!msg.online;
  __dmWsThreadId = Number(msg.thread_id || __dmWsThreadId || 0);

  // If DM WS just came online for the active thread, refresh history once.
  if (__dmWsOnline && dmMode && activeDmThreadId && Number(activeDmThreadId) === __dmWsThreadId) {
    // If we had a pending dm reconnect due to crypto lock, clear it.
    if (__pendingDmThreadId && Number(__pendingDmThreadId) === Number(activeDmThreadId)) {
      __pendingDmThreadId = null;
      __pendingDmPeer = "";
      __pendingDmSince = 0;
    }
    try { safePost({ type: "dm_history", thread_id: Number(activeDmThreadId), limit: HISTORY_PAGE_SIZE }); } catch {}
  }
  return;
}

// B1: /ws-notify — cross-room unread badge from server push
if (msg.type === "notify_room_msg") {
  const rid = Number(msg.room_id || 0);
  if (rid && rid !== Number(activeRoomId || 0)) {
    // Not the currently open room — mark unread
    if (typeof __markRoomUnread === "function") __markRoomUnread(rid);
  }
  return;
}

// B1: /ws-notify — cross-DM unread badge from server push
if (msg.type === "notify_dm_msg") {
  const tid = Number(msg.thread_id || 0);
  if (tid && tid !== Number(activeDmThreadId || 0)) {
    // Not the currently open DM thread — mark unread
    if (typeof __markDmUnread === "function") __markDmUnread(tid);
  }
  return;
}

  if (msg.type === "context_room_progress") {
    if (createRoomResultEl) createRoomResultEl.textContent = msg.message || "Working -";
    return;
  }

  if (msg.type === "context_room_pending") {
    const p = msg.payload || {};
	__pendingCtxSelection = p;
    openCreateRoom();
    if (newRoomNameInput) newRoomNameInput.value = p.suggestedName || "";
    if (createRoomResultEl) {
      const preview = String(p.text || "").replace(/\s+/g, " ").slice(0, 180);
      const more = (p.text && p.text.length > 180) ? "-" : "";
      const url = p.url ? `\nURL: ${p.url}` : "";
      const err = p.error ? `\nNote: ${p.error}` : "";
      createRoomResultEl.textContent = `From selection: ${preview}${more}${url}${err}`;
    }
    if (newRoomNameInput) newRoomNameInput.focus();
  chrome.storage.local.remove(["pendingRoomFromSelection", "pendingRoomFromSelectionMode"]);
    return;
  }

if (msg.type === "dm_list_res") {
  if (!msg.ok) {
    console.warn(msg.message || "DM list failed");
    dmItems = [];
    renderDmList(dmItems);
    return;
  }
  dmItems = Array.isArray(msg.items) ? msg.items : [];
  renderDmList(dmItems);
  window.__refreshUnreadFromServer?.();
  requestGroupInvites();
  return;
}

if (msg.type === "rooms_create") {
  if (!msg.ok) {
    if (createRoomResultEl) createRoomResultEl.textContent = "";
    await __ui.alert(msg.message || "Create room failed");
    return;
  }
  const r = msg.room;

if (__pendingCtxSelection?.url || __pendingCtxSelection?.text) {
  const pin = {
    url: __pendingCtxSelection?.url ? String(__pendingCtxSelection.url) : null,
    text: __pendingCtxSelection?.text ? String(__pendingCtxSelection.text).slice(0, 4000) : null,
  };

  putRoomPin(Number(r.id), pin)
    .catch(e => console.warn("Failed to save room pin:", e?.message || e));

  __pendingCtxSelection = null;
}

if (pendingCreatedRoomKeyBase64) {
  const ok = await CM().loadRoomKey(
    Number(r.id),
    pendingCreatedRoomKeyBase64
  );
  if (!ok) {
    console.warn("Failed to cache newly created room key (loadRoomKey returned false)");
  }
  pendingCreatedRoomKeyBase64 = null;
}

  if (createRoomResultEl) {
    createRoomResultEl.textContent =
      `Created: id=${r.id} alias=${r.alias} (${r.has_password ? "\u2705" : "open"})`;
  }

  try {
    const pm = pendingNewRoomMeta;
    pendingNewRoomMeta = null;

    let logo_token = null;

    if (pm?.logoFile) {
      const f = pm.logoFile;
      console.log("Uploading logo for room", Number(r.id), "file size:", f.size);
      const up = await postRoomLogoUpload(Number(r.id), f);
      logo_token = up?.token || null;
      console.log("Logo upload result:", { token: logo_token, url: up?.url });
    }

    const desc = (pm?.description || "").trim() || null;
    const logo_url = (pm?.logoFile && !logo_token) ? `/rooms/${r.id}/logo` : null;

    // Save metadata if we have description OR logo (token or url)
    if (desc || logo_token || logo_url) {
      console.log("Saving metadata for room", Number(r.id), { description: desc, logo_token, logo_url });
      safePost({
        type: "rooms_meta_set",
        roomId: Number(r.id),
        description: desc,
        logo_token: logo_token,
        logo_url: logo_url,
      });
      const updatedMeta = await waitRoomMeta(Number(r.id), "set");
      
      console.log("waitRoomMeta returned:", updatedMeta);
      
      // Server doesn't return meta in response, so cache it manually
      const metaToCache = {
        description: desc,
        logo_token: logo_token,
        logo_url: logo_url,
      };
      __roomMetaCache.set(String(r.id), metaToCache);
      saveRoomMetaCache(); // Persist to storage
      
      // Update local room data with new metadata
      r.description = desc;
      r.logo_token = logo_token;
      r.logo_url = logo_url;
      console.log("Room metadata cached locally:", { id: r.id, logo_token: r.logo_token, logo_url: r.logo_url });
    }
  } catch (e) {
    console.warn("Failed to set room meta right after create:", e?.message || e);
  }

  // Request rooms list to update UI - metadata should now be included
  requestMyRooms();
  closeCreateRoom();
  const newRoomKey = r?.alias ? r.alias : String(r.id);
  roomInput.value = newRoomKey;
  if (msgInput) msgInput.focus();
  return;
}

if (msg.type === "rooms_meta_get") {
  const roomId = Number(msg.roomId || 0);
  const key = String(roomId) + ":get";
  const w = __roomMetaWaiters.get(key);
  if (w) {
    clearTimeout(w.t);
    __roomMetaWaiters.delete(key);
    if (msg.ok) w.resolve(msg.meta || null);
    else w.reject(new Error(msg.message || "Meta get failed"));
  }
  return;
}

if (msg.type === "rooms_meta_set") {
  console.log("rooms_meta_set response:", {
    ok: msg.ok,
    roomId: msg.roomId,
    meta: msg.meta,
    message: msg.message
  });
  
  const roomId = Number(msg.roomId || 0);
  const key = String(roomId) + ":set";
  const w = __roomMetaWaiters.get(key);
  if (w) {
    clearTimeout(w.t);
    __roomMetaWaiters.delete(key);
    if (msg.ok) w.resolve(msg.meta || null);
    else w.reject(new Error(msg.message || "Meta save failed"));
  }
  return;
}

if (msg.type === "change_password_res") {
  if (msg.ok) {
    if (typeof window.__changePassResolve === "function") window.__changePassResolve();
  } else {
    if (typeof window.__changePassReject === "function") window.__changePassReject(new Error(msg.message || "Password change failed"));
  }
  return;
}

if (msg.type === "rooms_change_password") {
  const roomId = Number(msg.roomId || 0);
  const w = __roomPassWaiters.get(String(roomId));
  if (w) {
    clearTimeout(w.t);
    __roomPassWaiters.delete(String(roomId));
    if (msg.ok) w.resolve(msg);
    else w.reject(new Error(msg.message || "Change password failed"));
  }
  return;
}

if (msg.type === "rooms_rename") {
  const roomId = Number(msg.roomId || 0);
  const w = __roomRenameWaiters.get(String(roomId));
  if (w) {
    clearTimeout(w.t);
    __roomRenameWaiters.delete(String(roomId));
    if (msg.ok) w.resolve(msg);
    else w.reject(new Error(msg.message || "Rename room failed"));
  }
  return;
}

if (msg.type === "room_logo_uploaded") {
  console.log("room_logo_uploaded response:", {
    ok: msg.ok,
    roomId: msg.roomId,
    token: msg.token,
    url: msg.url,
    url_full: msg.url_full,
    message: msg.message
  });
  
  const roomId = Number(msg.roomId || 0);
  const key = String(roomId);
  const w = __roomLogoWaiters.get(key);
  if (w) {
    clearTimeout(w.t);
    __roomLogoWaiters.delete(key);
    if (msg.ok) w.resolve({ token: msg.token, url: msg.url, url_full: msg.url_full });
    else w.reject(new Error(msg.message || "Logo upload failed"));
  }
  return;
}

if (msg.type === "token") {
  // never store token on window; keep only in module scope
  __tokenLast = typeof msg.token === "string" ? msg.token : "";
  const waiters = __tokenWaiters;
  __tokenWaiters = [];
  for (const w of waiters) {
    try { w(__tokenLast); } catch {}
  }

  // auto-load profile once token is available (async, after current handler)
  try { queueMicrotask(() => autoLoadProfileIfReady()); }
  catch { setTimeout(() => autoLoadProfileIfReady(), 0); }

  return;
}

if (msg.type === "sw_last_error") {
  const age = Date.now() - (msg.ts || 0);
  if (age < 5 * 60 * 1000) {
    console.warn("SW last error:", msg.kind, msg.msg, "ts:", msg.ts);
  }
  return;
}
} // End of handlePortMessage

// ---- start transport only after UI + Crypto modules are loaded ----
window.__lastPong = Date.now();
window.__lastAnyMsg = Date.now();

function __startPortLoopOnce() {
  if (window.__portLoopStarted) return;
  window.__portLoopStarted = true;

  initPort();

  setInterval(() => {
    safePost({ type: "ping" });
    const elapsed = Date.now() - (window.__lastPong || 0);
    if (elapsed > 40000) {
      console.warn(`No pong for ${elapsed}ms, forcing reconnect`);
      // Use rpcDisconnect (not port.disconnect()) so rpc.js's internal `port`
      // gets nulled. A direct local disconnect does NOT fire our own
      // onDisconnect listener, leaving rpc.js with a stale dead port and
      // wedging the next connectPort() behind its `if (port) return port`
      // guard. The rpcOnDisconnect subscriber (initPort) will null
      // panel.js's `port` and reset UI state.
      try { window.rpcDisconnect?.(); } catch {}
      setTimeout(() => initPort(), 100);
    }
  }, 18000);

  // Periodic notification poll: friend requests, room invites, DM unread badges.
  // Uses randomised delay (10–15 s) so requests don't form a detectable fixed-interval pattern.
  (function __scheduleNotifPoll() {
    const delay = 10000 + Math.random() * 5000;
    setTimeout(() => {
      if (isLoggedIn) {
        try { requestFriendsAll(); } catch {}
        try { safePost({ type: "dm_list" }); } catch {}
        // requestGroupInvites() is triggered automatically by dm_list_res handler
      }
      __scheduleNotifPoll();
    }, delay);
  })();
}

function __tryStartPortWhenReady() {

  if (window.__panelUiReady && window.__panelCryptoReady) {
    __startPortLoopOnce();
  }
}

__tryStartPortWhenReady();

window.addEventListener("ws_ui_ready", __tryStartPortWhenReady);
window.addEventListener("ws_crypto_ready", __tryStartPortWhenReady);

// ===== Connect / Send / File handling / Message rendering =====
async function connect(roomPassOverride = null) {
  setModeRoom();
  const roomName = roomInput.value.trim();
  const roomPass = roomPassOverride != null ? roomPassOverride : "";

  if (!roomName) {
    await __ui.alert("Room is required");
    return;
  }

  try {
    const okCrypto = await ensureCryptoReady({ interactive: true, reason: "Connect / open room" });
    if (!okCrypto) {
      await __ui.alert("Crypto is locked. Unlock cancelled.");
      return;
    }
  } catch (e) {
    await __ui.alert("Crypto unlock failed: " + (e?.message || e));
    return;
  }

  activeRoomId = null;
  activeRoomName = "";
  activeRoomKey = "";
  lastHistoryRoomId = null;
  renderedHistoryRoomId = null;
  clearChat();
  renderPresence([]);
  renderCurrentRoom({ online: false });

  chrome.storage.local.set({
    conn: { room: roomName }
  });

  safePost({
    type: "connect",
    roomName,
    roomPass,
    force: true
  });
}

async function send() {
  if (__syncCryptoUiLockFromRuntime()) {
    await __ui.alert("Crypto is locked. Unlock to send messages.");
    return;
  }
  const text = (msgInput.value || "").trim();
  if (!text) return;

  const payload = replyTo
    ? JSON.stringify({ v: 2, t: text, reply: { id: null, author: replyTo.author, text: replyTo.text } })
    : text;

  if (dmMode) {
    if (!activeDmThreadId) {
      await __ui.alert("Please open a conversation first");
      return;
    }

    const sendPeer = activeDmPeer;
    try {
      const enc = await encryptDm(activeDmThreadId, payload, sendPeer);
      safePost({ type: "dm_send", thread_id: activeDmThreadId, text: enc });
      __clearReplyTo();
      // Prevent "my own messages" from appearing as unread after logout/login.
      // We optimistically mark the active DM as seen on send (local + server if available).
      try { __markDmSeen?.(activeDmThreadId); } catch {}
    } catch (e) {
      await __ui.alert("DM encrypt/send failed: " + (e?.message || e));
    }

    msgInput.value = "";
    return;
  }

  if (!activeRoomId) {
    await __ui.alert("Please select or connect to a room first.");
    return;
  }
  if (!canPostToActiveRoom()) {
    await __ui.alert("This room is read-only. Only owner/admin can send messages.");
    return;
  }

  try {
    if (!activeRoomId) throw new Error("No active room");
    const encryptedText = await encryptMessageForRoom(activeRoomId, payload);
    safePost({ type: "send", room_id: Number(activeRoomId), text: encryptedText });
    __clearReplyTo();
    // Prevent "my own messages" from appearing as unread after logout/login.
    // We optimistically mark the active room as seen on send (local + server if available).
    try { __markRoomSeen?.(activeRoomId); } catch {}
  } catch (e) {
    await __ui.alert("Unable to encrypt the message. Unlock/room key is not ready. " + (e?.message || e));
    return;
  }
  msgInput.value = "";
}

function parseFileMarker(text) {
  if (typeof text !== "string") return null;
  if (!text.startsWith("FILE2::")) return null; // legacy FILE:: format is intentionally unsupported in beta

  const b64url = String(text.slice("FILE2::".length) || "").trim();
  if (!b64url) return null;

  try {
    let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const bin = atob(b64);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    const raw = new TextDecoder().decode(u8);
    const p = JSON.parse(raw);

    if (Number(p?.v) !== 2) return null;
    const token = String(p?.t || "").trim();
    const filename = String(p?.n || "file").replaceAll("\n", " ").trim().slice(0, 220);
    const sizeNum = (p?.s == null) ? null : Number(p.s);
    const sizeBytes = Number.isFinite(sizeNum) && sizeNum >= 0 ? sizeNum : null;

    // token should be url-safe token from backend
    if (!token || token.length > 256 || /[^A-Za-z0-9_\-]/.test(token)) return null;

    return { token, filename: filename || "file", sizeBytes };
  } catch {
    return null;
  }
}

async function downloadFileByToken(token, filename) {
  const jwt = await requestToken();
  if (!jwt) {
    await __ui.alert("No token (not logged in?)");
    return;
  }

  const r = await fetch(API_BASE + `/files/${encodeURIComponent(token)}`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + jwt }
  });

  if (!r.ok) {
    const body = await r.json().catch(() => ({}));
    throw new Error(body?.detail || `Download failed (${r.status})`);
  }

  const blob = await r.blob();
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename || "file";
  document.body.appendChild(a);
  a.click();
  a.remove();

  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function buildFileCard({ token, filename, sizeBytes }, me) {
  const wrap = document.createElement("div");
  wrap.className = "msg file" + (me ? " me" : "");

  const left = document.createElement("div");
  left.className = "file-meta";

  const nameEl = document.createElement("div");
  nameEl.className = "file-name";
  nameEl.textContent = filename || "file";

  const sizeEl = document.createElement("div");
  sizeEl.className = "file-size";
  sizeEl.textContent = (sizeBytes != null && Number.isFinite(sizeBytes))
    ? humanSize(sizeBytes)
    : "";

  left.appendChild(nameEl);
  if (sizeEl.textContent) left.appendChild(sizeEl);

  const btn = document.createElement("button");
  btn.className = "file-download";
  btn.type = "button";
  btn.textContent = "Download";
  btn.onclick = async () => {
    btn.disabled = true;
    const prev = btn.textContent;
    btn.textContent = "Downloading...";
    try {
      await downloadFileByToken(token, filename);
    } catch (e) {
      await __ui.alert(e?.message || e);
    } finally {
      btn.disabled = false;
      btn.textContent = prev;
    }
  };

  wrap.appendChild(left);
  wrap.appendChild(btn);
  return wrap;
}

function hashString(str) {
  // FNV-1a 32-bit
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function colorForUsername(username) {
  const s = String(username || "").trim().toLowerCase();
  const h = hashString(s);

  const hue = h % 360;                 // 0..359
  const sat = 60 + (h % 20);           // 60..79
  const lig = 55 + ((h >>> 8) % 10);   // 55..64

  return `hsl(${hue} ${sat}% ${lig}%)`;
}

function formatMsgTime(ts) {
  if (ts == null || ts === "") return "";
  
  let timestamp;
  
  // Handle different formats
  if (typeof ts === "string") {
    // Try ISO string first (e.g., "2025-01-21T16:37:00Z")
    const parsed = Date.parse(ts);
    if (!isNaN(parsed)) {
      timestamp = parsed;
    } else {
      // Try as number string
      timestamp = Number(ts);
    }
  } else {
    timestamp = ts;
  }
  
  if (isNaN(timestamp) || timestamp <= 0) return "";
  
  // If timestamp is in seconds (Unix), convert to milliseconds
  if (timestamp < 1e11) {
    timestamp = timestamp * 1000;
  }
  
  const d = new Date(timestamp);
  if (isNaN(d.getTime())) return "";
  
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  
  const hours = String(d.getHours()).padStart(2, "0");
  const mins = String(d.getMinutes()).padStart(2, "0");
  const time = `${hours}:${mins}`;
  
  if (isToday) {
    return time;
  }
  
  // If not today - show date
  const day = String(d.getDate()).padStart(2, "0");
  const month = String(d.getMonth() + 1).padStart(2, "0");
  return `${day}.${month} ${time}`;
}

// ===== Safe linkify (NO innerHTML) =====
const LINKIFY_MAX_URL_LEN = 2048;

const __TRAIL_RE = /[)\]}",.!?:;]+$/;

const __URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"']{2,2048})/gi;

function __splitTrailingPunct(token) {
  const raw = String(token || "");
  let s = raw;
  while (__TRAIL_RE.test(s)) s = s.slice(0, -1);
  return { core: s, tail: raw.slice(s.length) };
}

function __safeHttpUrlFromToken(token) {
  let s = String(token || "").trim();
  if (!s) return null;

  const { core } = __splitTrailingPunct(s);
  s = core.trim();
  if (!s) return null;

  // allow "www.example.com" -> treat as https
  if (/^www\./i.test(s)) s = "https://" + s;

  if (s.length > LINKIFY_MAX_URL_LEN) return null;

  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }

  // allowlist only http(s)
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;

  // block credentials in URL
  if (u.username || u.password) return null;

  // host must exist
  if (!u.hostname) return null;

  return u.toString();
}

function __isMixedScriptHostname(hostname) {

  const h = String(hostname || "");
  const hasLatin = /[a-zA-Z]/.test(h);
  const hasCyr   = /[а-яА-ЯЁё]/.test(h);
  return hasLatin && hasCyr;
}

function __isSuspiciousHostname(hostname) {
  const h = String(hostname || "").toLowerCase();
  if (!h) return false;

  if (h.includes("xn--")) return true;
  if (__isMixedScriptHostname(h)) return true;
  return false;
}

function __openExternalUrlSafe(url) {
  // Prefer chrome.tabs.create (extension-safe)
  try {
    if (chrome?.tabs?.create) {
      chrome.tabs.create({ url });
      return;
    }
  } catch {}
  // Fallback
  try {
    window.open(url, "_blank", "noopener,noreferrer");
  } catch {
    // last resort
    location.href = url;
  }
}

async function __confirmOpenLinkIfNeeded(href, { suspicious = false } = {}) {

  const CONFIRM_ALWAYS = false;
  if (!CONFIRM_ALWAYS && !suspicious) return true;

  const msg = suspicious
    ? `Open suspicious link?\n\n${href}`
    : `Open link?\n\n${href}`;

  try {
    if (typeof __ui?.confirm === "function") return await __ui.confirm(msg);
  } catch {}
  return confirm(msg);
}

function __appendTextWithLinks(containerEl, text) {
  const s = String(text ?? "");
  if (!containerEl) return;

  containerEl.textContent = "";

  if (!s) return;

  __URL_RE.lastIndex = 0;
  let last = 0;
  let m;

  while ((m = __URL_RE.exec(s)) !== null) {
    const start = m.index;
    const rawToken = m[1];

    if (start > last) {
      containerEl.appendChild(document.createTextNode(s.slice(last, start)));
    }

    const { core, tail } = __splitTrailingPunct(rawToken);
    const href = __safeHttpUrlFromToken(core);

    if (!href) {

      containerEl.appendChild(document.createTextNode(rawToken));
      last = start + rawToken.length;
      continue;
    }

    let suspicious = false;
    try {
      const host = new URL(href).hostname;
      suspicious = __isSuspiciousHostname(host);
    } catch {}

    const a = document.createElement("a");
    a.href = href;

    a.textContent = core;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.referrerPolicy = "no-referrer";
    a.className = "msg-link";
    a.title = href;

    if (suspicious) a.classList.add("msg-link-suspicious");

    a.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const ok = await __confirmOpenLinkIfNeeded(href, { suspicious });
      if (!ok) return;

      __openExternalUrlSafe(href);
    });

    containerEl.appendChild(a);

    if (tail) containerEl.appendChild(document.createTextNode(tail));

    last = start + rawToken.length;
  }

  if (last < s.length) {
    containerEl.appendChild(document.createTextNode(s.slice(last)));
  }
}

function addMsg(user, text, me = false, ts = null, reply = null) {
  if (text == null) return;

  if (user !== lastMsgAuthor) {
    const h = document.createElement("div");
    h.className = "msg-author" + (me ? " me" : "");
    h.textContent = user;
    h.style.color = colorForUsername(user);
    // click on author -> open profile
    h.style.cursor = "pointer";
    h.title = "Open profile";
    h.onclick = () => openProfile(user);
    chat.appendChild(h);
    lastMsgAuthor = user;
  }

  const fileInfo = parseFileMarker(text);

  if (fileInfo) {
    const card = buildFileCard(fileInfo, me);
    card.oncontextmenu = (e) => { e.preventDefault(); __showMsgCtxMenu(e, user, text); };
    chat.appendChild(card);
  } else {
    const div = document.createElement("div");
    div.className = "msg" + (me ? " me" : "");
    div.style.cssText = `display:flex;flex-direction:column;gap:2px;`;

    if (typeof text === "string" && text.startsWith("OK")) {
      div.style.opacity = "0.7";
      div.style.fontStyle = "italic";
    }

    // Reply quote block
    if (reply && reply.author) {
      const q = document.createElement("div");
      q.className = "msg-reply-quote";
      const bar = document.createElement("div");
      bar.className = "msg-reply-quote-bar";
      const body = document.createElement("div");
      body.className = "msg-reply-quote-body";
      const qa = document.createElement("span");
      qa.className = "msg-reply-quote-author";
      qa.textContent = reply.author;
      const qt = document.createElement("span");
      qt.className = "msg-reply-quote-text";
      qt.textContent = reply.text || "";
      body.appendChild(qa);
      body.appendChild(qt);
      q.appendChild(bar);
      q.appendChild(body);
      div.appendChild(q);
    }

    // Create container for text and time
    const textSpan = document.createElement("span");
    textSpan.className = "msg-text";
    __appendTextWithLinks(textSpan, text);
    div.appendChild(textSpan);

    // Add timestamp
    const timeStr = formatMsgTime(ts);
    if (timeStr) {
      const timeSpan = document.createElement("span");
      timeSpan.className = "msg-time";
      timeSpan.textContent = timeStr;
      timeSpan.style.cssText = `font-size:10px;color:#888;opacity:0.7;white-space:nowrap;user-select:none;align-self:${me ? "flex-start" : "flex-end"};`;
      div.appendChild(timeSpan);
    }

    // Right-click → Reply / Copy
    div.oncontextmenu = (e) => { e.preventDefault(); __showMsgCtxMenu(e, user, text); };

    chat.appendChild(div);
  }
  chat.scrollTop = chat.scrollHeight;
}

// One-time purge of legacy plaintext message cache (was never read by UI).
try { chrome.storage.local.remove(["historyByRoom"]); } catch {}

window.addEventListener("load", () => {
  try { if (typeof updateLeaveBtnState === "function") updateLeaveBtnState(); } catch {}
});
