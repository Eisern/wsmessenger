// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

(() => {
  if (window.__loginJsLoaded) return;
  window.__loginJsLoaded = true;

  // === Server config ===
  const DEFAULT_API_BASE = "https://imagine-1-ws.xyz";
  const DEFAULT_WS_BASE  = "wss://imagine-1-ws.xyz";
  let _apiBase = DEFAULT_API_BASE;
  let _wsBase  = DEFAULT_WS_BASE;

  function _deriveWsBase(apiBase) {
    return apiBase.replace(/^https:\/\//, "wss://").replace(/^http:\/\//, "ws://");
  }

  async function _loadServerConfig() {
    try {
      const r = await chrome.storage.local.get("server_config");
      const cfg = r.server_config;
      if (cfg?.apiBase) {
        _apiBase = cfg.apiBase.replace(/\/$/, "");
        _wsBase  = cfg.wsBase ? cfg.wsBase.replace(/\/$/, "") : _deriveWsBase(_apiBase);
      }
    } catch { /* storage unavailable, use defaults */ }
  }

  function _setSetupStatus(el, text, color) {
    if (!el) return;
    el.textContent = text;
    el.style.color = color || "";
  }

  function initServerSetupUI() {
    const toggle      = document.getElementById("serverSetupToggle");
    const panel       = document.getElementById("serverSetupPanel");
    const chevron     = document.getElementById("serverSetupChevron");
    const toggleState = document.getElementById("serverSetupToggleState");
    const apiInput    = document.getElementById("setupApiBase");
    const wsInput     = document.getElementById("setupWsBase");
    const testBtn     = document.getElementById("setupTestBtn");
    const saveBtn     = document.getElementById("setupSaveBtn");
    const reloadBtn   = document.getElementById("setupReloadBtn");
    const statusEl    = document.getElementById("serverSetupStatus");
    if (!toggle) return;

    // Reflect current config in UI
    const isCustom = _apiBase !== DEFAULT_API_BASE;
    if (toggleState) {
      toggleState.textContent = isCustom ? _apiBase : "Not configured";
      toggleState.style.color  = isCustom ? "#28a745" : "#dc3545";
    }
    if (apiInput) apiInput.value = isCustom ? _apiBase : "";
    if (wsInput)  wsInput.value  = isCustom ? _wsBase  : "";

    // Auto-derive WS base when API base is typed
    apiInput?.addEventListener("input", () => {
      const v = (apiInput.value || "").trim();
      if (v && wsInput) wsInput.value = _deriveWsBase(v);
    });

    // Toggle panel open/close
    toggle.addEventListener("click", () => {
      const closing = !panel.classList.contains("collapsed");
      panel.classList.toggle("collapsed", closing);
      panel.setAttribute("aria-hidden", String(closing));
      toggle.setAttribute("aria-expanded", String(!closing));
      if (chevron) chevron.textContent = closing ? "▾" : "▴";
      // Show default status hint when opening with no custom server configured
      // Check _apiBase at click time — not the stale isCustom captured at init
      if (!closing && statusEl && !statusEl.textContent && _apiBase === DEFAULT_API_BASE) {
        statusEl.textContent = "Server is not configured yet.";
        statusEl.style.color = "#dc3545";
      }
    });

    // Test connection
    testBtn?.addEventListener("click", async () => {
      const api = (apiInput?.value || "").trim().replace(/\/$/, "");
      if (!api) { _setSetupStatus(statusEl, "Enter API base URL first", ""); return; }
      _setSetupStatus(statusEl, "Testing…", "");
      try {
        const r = await fetch(api + "/health", { cache: "no-store", signal: AbortSignal.timeout(5000) });
        if (r.ok) _setSetupStatus(statusEl, "Connected ✓", "#28a745");
        else      _setSetupStatus(statusEl, `Server returned HTTP ${r.status}`, "#dc3545");
      } catch (e) {
        _setSetupStatus(statusEl, "Connection failed: " + e.message, "#dc3545");
      }
    });

    // Save
    saveBtn?.addEventListener("click", async () => {
      const api = (apiInput?.value || "").trim().replace(/\/$/, "");
      if (!api) {
        // Empty input = revert to default server
        await chrome.storage.local.remove("server_config");
        _apiBase = DEFAULT_API_BASE;
        _wsBase  = DEFAULT_WS_BASE;
        _setSetupStatus(statusEl, "Using default server", "");
        if (toggleState) { toggleState.textContent = "Not configured"; toggleState.style.color = "#dc3545"; }
        port?.postMessage?.({ type: "server_config_updated" });
        return;
      }
      let _parsed;
      try { _parsed = new URL(api); } catch {
        _setSetupStatus(statusEl, "Invalid URL", "#dc3545"); return;
      }
      if (!["https:", "http:"].includes(_parsed.protocol)) {
        _setSetupStatus(statusEl, "URL must start with https://", "#dc3545"); return;
      }
      if (_parsed.protocol === "http:" && !["localhost", "127.0.0.1"].includes(_parsed.hostname)) {
        _setSetupStatus(statusEl, "HTTP only allowed for localhost", "#dc3545"); return;
      }
      // Strip path/query — persist origin only
      const cleanApi = _parsed.origin;
      const ws = ((wsInput?.value || "").trim().replace(/\/$/, "")) || _deriveWsBase(cleanApi);
      // Request optional host permission before saving
      const origin = cleanApi + "/*";
      _setSetupStatus(statusEl, "Requesting permission…", "");
      let granted = false;
      try {
        granted = await chrome.permissions.request({ origins: [origin] });
      } catch (e) {
        _setSetupStatus(statusEl, "Permission error: " + e.message, "#dc3545"); return;
      }
      if (!granted) {
        _setSetupStatus(statusEl, "Permission denied — server not saved", "#dc3545"); return;
      }
      _apiBase = cleanApi;
      _wsBase  = ws;
      await chrome.storage.local.set({ server_config: { apiBase: cleanApi, wsBase: ws } });
      _setSetupStatus(statusEl, "Saved ✓", "#28a745");
      if (toggleState) { toggleState.textContent = cleanApi; toggleState.style.color = "#28a745"; }
      port?.postMessage?.({ type: "server_config_updated" });
    });

    // Reload page after config change
    reloadBtn?.addEventListener("click", () => window.location.reload());
  }

  let port = null;

//  async function stashUnlockKek(kekBase64) {
//    try {
//      const k = String(kekBase64 || "").trim();
//      if (!k) return;
//      await chrome.storage.session.set({
//        __tmp_unlock_kek: k, // one-shot AES key bytes (base64)
//        __tmp_unlock_ts: Date.now(),
//      });
//    } catch (e) {
//      console.warn("stashUnlockKek failed:", e);
//    }
//  }

function randomSessionKekBase64() {
  const u8 = crypto.getRandomValues(new Uint8Array(32));
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

const __uhTe = new TextEncoder();
function __uhB64Encode(bufOrU8) {
  const u8 = bufOrU8 instanceof Uint8Array ? bufOrU8 : new Uint8Array(bufOrU8);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function __uhB64DecodeToU8(b64) {
  const s = atob(String(b64 || ""));
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

function __unlockHandoffAad(meta) {
  return JSON.stringify({
    v: Number(meta?.v || 1),
    purpose: "unlock_handoff",
    req_id: String(meta?.req_id || ""),
    username: String(meta?.username || "").trim().toLowerCase(),
    ts: Number(meta?.ts || 0),
  });
}

function __waitPortResponse(portObj, matcher, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    let done = false;
    const finish = (err, value) => {
      if (done) return;
      done = true;
      try { portObj?.onMessage?.removeListener(onMsg); } catch {}
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
    const timer = setTimeout(() => finish(new Error("unlock handoff timeout")), timeoutMs);
    try {
      portObj.onMessage.addListener(onMsg);
    } catch (e) {
      finish(e);
    }
  });
}

async function secureUnlockHandoffToBackground({ username = "", masterB64 = "", sessionKekB64 = "" } = {}) {
  const p = initPort();
  if (!p?.postMessage) throw new Error("No port");

  const reqId = `uh:${Date.now()}:${Math.random().toString(16).slice(2)}`;
  const normUsername = normUser(username);

  const beginWait = __waitPortResponse(
    p,
    (msg) => msg?.type === "unlock_handoff_begin_res" && msg?.reqId === reqId,
    4000
  );
  p.postMessage({ type: "unlock_handoff_begin", reqId, username: normUsername, ts: Date.now() });
  const beginRes = await beginWait;
  if (!beginRes?.ok) throw new Error(beginRes?.error || "unlock_handoff_begin failed");

  const serverPubRaw = __uhB64DecodeToU8(beginRes.server_pub_b64);
  const nonceRaw = __uhB64DecodeToU8(beginRes.nonce_b64);
  const serverPubKey = await crypto.subtle.importKey(
    "raw",
    serverPubRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPubKey },
    eph.privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const hkdfSalt = await crypto.subtle.digest(
    "SHA-256",
    __uhTe.encode(`unlock-handoff-v1|${reqId}|${__uhB64Encode(nonceRaw)}`)
  );
  const transportKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: hkdfSalt, info: __uhTe.encode("wsapp-unlock-handoff-v1") },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );

  const ts = Date.now();
  const aadMeta = { v: 1, req_id: reqId, username: normUsername, ts };
  const aadBytes = __uhTe.encode(__unlockHandoffAad(aadMeta));
  const payload = {
    v: 1,
    req_id: reqId,
    username: normUsername,
    ts,
    exp: ts + 30_000,
    master_b64: String(masterB64 || "").trim(),
    kek_b64: String(sessionKekB64 || "").trim(),
  };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aadBytes },
    transportKey,
    __uhTe.encode(JSON.stringify(payload))
  );
  const clientPubRaw = await crypto.subtle.exportKey("raw", eph.publicKey);

  const commitWait = __waitPortResponse(
    p,
    (msg) => msg?.type === "unlock_handoff_commit_res" && msg?.reqId === reqId,
    4000
  );
  p.postMessage({
    type: "unlock_handoff_commit",
    reqId,
    client_pub_b64: __uhB64Encode(clientPubRaw),
    iv_b64: __uhB64Encode(iv),
    ct_b64: __uhB64Encode(ct),
    aad: aadMeta,
  });
  const commitRes = await commitWait;
  if (!commitRes?.ok) throw new Error(commitRes?.error || "unlock_handoff_commit failed");
  return true;
}

const LOCAL_IDENTITY_PREFIX = "e2ee_local_identity_v2:";
const LOCAL_ACTIVE_USER_KEY = "e2ee_active_user_v2";
const PENDING_MNEMONIC_KEY = "e2ee_pending_mnemonic_v1";

function normUser(u) {
  return String(u || "").trim().toLowerCase();
}

// Mirrors server-side RegisterRequest validation
// (main.py: ^[a-zA-Z][a-zA-Z0-9_]*$, length 3-32). Validating client-side
// prevents wasting Argon2id derivation (~0.5–2s) on names the server will
// reject with an opaque pydantic 422 error.
const REGISTER_USERNAME_RE = /^[a-zA-Z][a-zA-Z0-9_]*$/;
function validateUsernameForRegister(raw) {
  const u = String(raw || "").trim();
  if (!u) return "Username is required";
  if (u.length < 3) return "Username must be at least 3 characters";
  if (u.length > 32) return "Username must be at most 32 characters";
  if (!REGISTER_USERNAME_RE.test(u)) {
    return "Username must start with a letter and contain only letters, digits, or underscores";
  }
  return null;
}

// Pydantic v2 returns 422 detail as an array of {type, loc, msg, input, ...}
// rather than a string. Render it as a readable single-line message; fall
// back to the raw status when the body shape is unexpected.
function formatRegisterError(data, status) {
  const detail = data?.detail;
  if (typeof detail === "string" && detail.trim()) return detail;
  if (Array.isArray(detail) && detail.length) {
    const parts = detail
      .map((e) => {
        const field = Array.isArray(e?.loc) ? e.loc[e.loc.length - 1] : "";
        const msg = e?.msg || "invalid";
        return field ? `${field}: ${msg}` : msg;
      })
      .filter(Boolean);
    if (parts.length) return parts.join("; ");
  }
  return `Registration failed (${status})`;
}

async function setPendingMnemonicAck(username) {
  const u = normUser(username);
  if (!u) return;
  await chrome.storage.local.set({
    [PENDING_MNEMONIC_KEY]: { username: u, ts: Date.now() },
  });
}

async function clearPendingMnemonicAck() {
  await chrome.storage.local.remove(PENDING_MNEMONIC_KEY);
}

async function getPendingMnemonicAck() {
  const got = await chrome.storage.local.get([PENDING_MNEMONIC_KEY]);
  const v = got?.[PENDING_MNEMONIC_KEY];
  const u = normUser(v?.username);
  return u ? { username: u } : null;
}

// Re-derive BIP39 mnemonic from EPK for the case where register flow was
// interrupted before the user acknowledged the recovery phrase. Requires the
// password (so we can decrypt the EPK to raw private-key bytes). The raw
// bytes are wiped from memory immediately after deriving the mnemonic.
async function deriveMnemonicFromEpk(epk, password, expectedUsername) {
  const pkcs8B64 = await CryptoUtils.decryptPrivateKeyToPkcs8B64(epk, password, {
    expectedUsername: normUser(expectedUsername),
  });
  const pkcs8Bytes = new Uint8Array(CryptoUtils.base64ToArrayBuffer(pkcs8B64));
  const rawKey = CryptoUtils.extractRawKeyFromPkcs8(pkcs8Bytes);
  try {
    return CryptoUtils.bip39Encode(rawKey);
  } finally {
    try { rawKey.fill(0); } catch {}
    try { pkcs8Bytes.fill(0); } catch {}
  }
}

function localIdentityStorageKey(username) {
  return LOCAL_IDENTITY_PREFIX + normUser(username);
}

async function saveLocalIdentity(username, identity) {
  const key = localIdentityStorageKey(username);
  await chrome.storage.local.set({ [key]: identity });
}

async function loadLocalIdentity(username) {
  const key = localIdentityStorageKey(username);
  const got = await chrome.storage.local.get([key]);
  return got[key] || null;
}

async function setActiveUser(username) {
  const u = normUser(username);
  if (!u) return;
  await chrome.storage.session.set({ [LOCAL_ACTIVE_USER_KEY]: u });
}

  async function deriveUnlockKekBase64(password, encryptedPrivateKeyObj) {
    const p = String(password || "");
    if (!p) return "";
    const epk = encryptedPrivateKeyObj || {};
    const saltB64 = String(epk.salt || "").trim();
    if (!saltB64) return "";
    const kdf = epk.kdf || {};
    const derived = await CryptoUtils.deriveRawKeyFromPassword(p, saltB64, {
      name: kdf.name,
      iterations: kdf.iterations,
      hash: kdf.hash,
      time_cost: kdf.time_cost,
      memory_kib: kdf.memory_kib,
      parallelism: kdf.parallelism,
      version: kdf.version,
      preferArgon2: true,
    });
    return CryptoUtils.arrayBufferToBase64(derived.raw);
  }

function handoffUnlockKeysToBackground(masterB64, sessionKekB64, username = "") {
  return secureUnlockHandoffToBackground({ username, masterB64, sessionKekB64 });
}

async function handoffUnlockFromLocalIdentity(username, password, ctx = "") {
  const identity = await loadLocalIdentity(username);
  const epk = identity?.encrypted_private_key;
  if (!epk) throw new Error("Local private key not found for this user on this device");

  const masterB64 = await deriveUnlockKekBase64(password, epk);
  if (!masterB64) throw new Error("Failed to derive local unlock key");

  const sessionKekB64 = randomSessionKekBase64();
  await handoffUnlockKeysToBackground(masterB64, sessionKekB64, username);
  if (ctx) console.log(`Auto-unlock handoff (${ctx}) completed`);
}

function isMissingLocalKeyError(err) {
  const msg = String(err?.message || err || "").toLowerCase();
  return msg.includes("local private key not found");
}

async function handleMissingLocalKeyForLogin() {
  try {
    initPort()?.postMessage({ type: "auth_logout" });
  } catch {}
  try {
    await chrome.storage.session.remove([LOCAL_ACTIVE_USER_KEY]);
  } catch {}

  const errEl = document.getElementById("loginErr");
  if (errEl) {
    errEl.innerHTML =
      `<div style="padding:10px 12px;border:1px solid rgba(220,53,69,.45);` +
      `background:rgba(220,53,69,.12);border-radius:8px;line-height:1.35;">` +
      `<div style="font-weight:600;margin-bottom:4px;">Ключа на этом устройстве нет</div>` +
      `<div>Чтобы войти в аккаунт на этом устройстве, выполните Recovery по вашей recovery phrase.</div>` +
      `<div style="margin-top:8px;"><a href="#" id="openRecoveryFromMissingKey" style="color:#ffb3b3;text-decoration:underline;">Открыть Recovery</a></div>` +
      `</div>`;
    const link = document.getElementById("openRecoveryFromMissingKey");
    if (link) {
      link.addEventListener("click", (e) => {
        e.preventDefault();
        showRecoveryForm();
      });
    }
  }
}


function initPort() {
  if (port) return port;

  port = chrome.runtime.connect({ name: "ws-panel" });

  port.onDisconnect.addListener(() => {
    port = null;
  });

  port.onMessage.addListener(async (msg) => {
    if (!msg || !msg.type) return;

if (msg.type === "auth_state") {
  if (msg.loggedIn) {
    const passEl = document.getElementById("loginPass");
    const pw = passEl ? (passEl.value || "") : "";
    const username = normUser(msg.username || document.getElementById("loginName")?.value || "");

    if (pw) {
      try {
        await handoffUnlockFromLocalIdentity(username, pw, "auth_state");
      } catch (e) {
        if (isMissingLocalKeyError(e)) {
          await handleMissingLocalKeyForLogin();
          if (passEl) passEl.value = "";
          return;
        }
        console.warn("Auto-unlock handoff failed (auth_state):", e?.message || e);
      }
    }

    await setActiveUser(username);
    // Surface pending recovery-phrase modal (crash-recovery from register).
    // Defers the redirect until the user acknowledges the phrase. If nothing
    // is pending or the password is unavailable, fires onDone immediately.
    await surfacePendingMnemonicIfNeeded(username, pw, () => {
      if (passEl) passEl.value = "";
      location.href = "panel.html";
    });
  }
  return;
}

    if (msg.type === "banned") {
      const errEl = document.getElementById("loginErr");
      if (errEl) errEl.textContent = msg.message || "User is banned";
      const btn = document.getElementById("loginBtn");
      if (btn) btn.disabled = false;
      return;
    }

    if (msg.type === "auth_error") {
      const errEl = document.getElementById("loginErr");
      if (errEl) errEl.textContent = msg.message || "Login failed";
      const btn = document.getElementById("loginBtn");
      if (btn) btn.disabled = false;
      return;
    }

    // 2FA required — show TOTP input
    if (msg.type === "auth_2fa_required") {
      show2faInput(msg.temp_token, msg.username);
      return;
    }

    // 2FA verification failed
    if (msg.type === "auth_2fa_error") {
      const errEl = document.getElementById("twofa-err");
      if (errEl) errEl.textContent = msg.message || "Invalid code";
      const btn = document.getElementById("twofa-submit");
      if (btn) btn.disabled = false;
      const inp = document.getElementById("twofa-code");
      if (inp) { inp.disabled = false; inp.value = ""; inp.focus(); }
      return;
    }

if (msg.type === "auth_ok") {
  const passEl = document.getElementById("loginPass");
  const pw = passEl ? (passEl.value || "") : "";
  const username = normUser(msg.username || document.getElementById("loginName")?.value || "");

  if (pw) {
    try {
      await handoffUnlockFromLocalIdentity(username, pw, "auth_ok");
    } catch (e) {
      if (isMissingLocalKeyError(e)) {
        await handleMissingLocalKeyForLogin();
        if (passEl) passEl.value = "";
        return;
      }
      console.warn("Auto-unlock handoff failed (auth_ok):", e?.message || e);
    }
  }

  await setActiveUser(username);
  await surfacePendingMnemonicIfNeeded(username, pw, () => {
    if (passEl) passEl.value = "";
    location.href = "panel.html";
  });
  return;
}
  });

  return port;
}

  // ===== 2FA Input UI =====
  let _2faShown = false;

  function show2faInput(tempToken, username) {
    if (_2faShown) return;
    _2faShown = true;

    // Hide login form elements
    const loginBtn = document.getElementById("loginBtn");
    const regBtn = document.getElementById("registerBtn");
    const nameInput = document.getElementById("loginName");
    const passInput = document.getElementById("loginPass");
    if (loginBtn) loginBtn.style.display = "none";
    if (regBtn) regBtn.style.display = "none";
    if (nameInput) nameInput.style.display = "none";
    if (passInput) passInput.style.display = "none";
    // Hide labels if present
    if (nameInput?.previousElementSibling?.tagName === "LABEL") nameInput.previousElementSibling.style.display = "none";
    if (passInput?.previousElementSibling?.tagName === "LABEL") passInput.previousElementSibling.style.display = "none";

    const loginErrEl = document.getElementById("loginErr");
    if (loginErrEl) loginErrEl.textContent = "";

    // Create 2FA container
    const container = document.createElement("div");
    container.id = "twofa-container";
    container.style.cssText = "padding:16px; text-align:center;";
    container.innerHTML = `
      <div style="margin-bottom:12px;">
        <div style="font-size:28px;">&#128274;</div>
        <h3 style="margin:8px 0 4px; font-size:16px;">Two-Factor Authentication</h3>
        <p style="font-size:13px; opacity:0.7; margin:0;">Enter the 6-digit code or 8-character backup code</p>
      </div>
      <input id="twofa-code" type="text" inputmode="text" autocomplete="one-time-code"
        maxlength="8" pattern="[0-9a-fA-F]{6,8}" placeholder="000000"
        style="font-size:24px; letter-spacing:6px; text-align:center; width:220px; padding:10px;
               border:1px solid rgba(255,255,255,0.2); border-radius:8px; background:rgba(255,255,255,0.05);
               color:inherit; outline:none; font-family:monospace;" />
      <div id="twofa-err" style="color:#dc3545; font-size:12px; min-height:18px; margin-top:6px;"></div>
      <button id="twofa-submit" type="button"
        style="margin-top:8px; padding:8px 24px; border:none; border-radius:6px;
               background:#007bff; color:white; font-size:14px; cursor:pointer;">
        Verify
      </button>
      <div style="margin-top:12px;">
        <a href="#" id="twofa-back" style="font-size:12px; color:#6c757d; text-decoration:underline;">Back to login</a>
      </div>
    `;

    // Insert into page
    const insertTarget = loginErrEl?.parentElement || document.body;
    insertTarget.appendChild(container);

    const codeInput = document.getElementById("twofa-code");
    const submitBtn = document.getElementById("twofa-submit");
    const backLink = document.getElementById("twofa-back");
    const errEl = document.getElementById("twofa-err");

    // Auto-format: keep only hex chars (digits + a-f), uppercase for backup codes
    codeInput.addEventListener("input", () => {
      codeInput.value = codeInput.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 8);
    });

    function submit2fa() {
      const code = (codeInput.value || "").replace(/[^0-9a-fA-F]/g, "");
      if (code.length < 6 || code.length > 8) {
        errEl.textContent = "Enter a 6-digit code or 8-character backup code";
        return;
      }
      errEl.textContent = "";
      codeInput.disabled = true;
      submitBtn.disabled = true;

      initPort()?.postMessage({
        type: "auth_2fa_verify",
        temp_token: tempToken,
        code,
        username,
      });
    }

    submitBtn.addEventListener("click", submit2fa);
    codeInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submit2fa();
    });

    backLink.addEventListener("click", (e) => {
      e.preventDefault();
      container.remove();
      _2faShown = false;
      if (loginBtn) loginBtn.style.display = "";
      if (regBtn) regBtn.style.display = "";
      if (nameInput) nameInput.style.display = "";
      if (passInput) passInput.style.display = "";
      if (nameInput?.previousElementSibling?.tagName === "LABEL") nameInput.previousElementSibling.style.display = "";
      if (passInput?.previousElementSibling?.tagName === "LABEL") passInput.previousElementSibling.style.display = "";
    });

    codeInput.focus();
  }

  // ===== Direct REST helper (used before JWT exists, e.g. registration, recovery) =====
  async function apiJson(path, { method = "POST", body = null } = {}) {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(_apiBase + path, opts);
    const raw = await r.text().catch(() => "");
    let data = {};
    if (raw.trim()) { try { data = JSON.parse(raw); } catch (_) { data = {}; } }
    if (!r.ok) throw Object.assign(new Error(data.detail || `HTTP ${r.status}`), { status: r.status, data });
    return data;
  }

  // ===== Mnemonic display after registration =====

  function showMnemonicPrompt(mnemonic, onDone) {
    const words = mnemonic.split(" ");
    const loginErrEl = document.getElementById("loginErr");
    const insertTarget = loginErrEl?.parentElement || document.body;

    // Hide main form
    ["loginName","loginPass","loginBtn","registerBtn"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = "none";
      if (el?.previousElementSibling?.tagName === "LABEL") el.previousElementSibling.style.display = "none";
    });
    if (loginErrEl) loginErrEl.textContent = "";

    const container = document.createElement("div");
    container.id = "mnemonic-container";
    container.style.cssText = "padding:16px; text-align:center;";

    const grid = words.map((w, i) =>
      `<span style="display:inline-block;width:calc(33% - 4px);margin:2px;padding:4px 2px;
        background:rgba(255,255,255,0.06);border-radius:4px;font-family:monospace;font-size:12px;">
        <span style="opacity:0.5;font-size:10px;">${i+1}.</span> ${w}
      </span>`
    ).join("");

    container.innerHTML = `
      <div style="margin-bottom:10px;">
        <div style="font-size:28px;">&#128220;</div>
        <h3 style="margin:6px 0 4px;font-size:15px;">Save Your Recovery Phrase</h3>
        <p style="font-size:12px;opacity:0.65;margin:0 0 10px;">
          Write these 24 words down in order. They are the only way to recover your account if you forget your password.
        </p>
        <p style="font-size:12px;color:#ffb3b3;margin:0 0 10px;">
          Important: to use this same login on another device, you will need to perform Recovery with this phrase.
        </p>
      </div>
      <div style="text-align:left;margin-bottom:12px;">${grid}</div>
      <button id="mnemonic-done" type="button"
        style="padding:8px 20px;border:none;border-radius:6px;background:#28a745;color:white;font-size:14px;cursor:pointer;">
        I have saved my phrase
      </button>
    `;

    insertTarget.appendChild(container);

    document.getElementById("mnemonic-done").addEventListener("click", () => {
      container.remove();
      ["loginName","loginPass","loginBtn","registerBtn"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = "";
        if (el?.previousElementSibling?.tagName === "LABEL") el.previousElementSibling.style.display = "";
      });
      if (onDone) onDone();
    });
  }

  // Crash-recovery for the post-register mnemonic acknowledgement.
  //
  // If the register flow was interrupted (extension closed, browser crash)
  // before the user clicked "I have saved my phrase", the pending flag is
  // still set in chrome.storage.local. On the next successful login (where
  // the password is in hand), re-derive the mnemonic from the local EPK and
  // surface the same prompt before redirecting to the panel.
  //
  // If the pending flag belongs to a different user (e.g. user registered
  // account A, never ack'd, then logged into account B), drop the stale flag
  // — A's pending state has nothing to do with B's session.
  async function surfacePendingMnemonicIfNeeded(username, password, onDone) {
    const cont = () => { try { onDone?.(); } catch {} };
    try {
      const pending = await getPendingMnemonicAck();
      if (!pending) return cont();
      const u = normUser(username);
      if (!u || pending.username !== u) {
        // Stale flag from another account — drop it, don't show.
        await clearPendingMnemonicAck().catch(() => {});
        return cont();
      }
      const identity = await loadLocalIdentity(u);
      const epk = identity?.encrypted_private_key;
      if (!epk || !password) {
        // Can't re-derive without EPK + password — leave the flag for a
        // future login that has both, and continue.
        return cont();
      }
      let mnemonic = "";
      try {
        mnemonic = await deriveMnemonicFromEpk(epk, password, u);
      } catch (e) {
        console.warn("Pending mnemonic re-derivation failed:", e?.message || e);
        // Don't clear the flag — wrong password or transient failure;
        // the next successful unlock will retry.
        return cont();
      }
      showMnemonicPrompt(mnemonic, async () => {
        await clearPendingMnemonicAck().catch(() => {});
        cont();
      });
    } catch (e) {
      console.warn("surfacePendingMnemonicIfNeeded failed:", e?.message || e);
      cont();
    }
  }

  // ===== Recovery form =====

  let _recoveryShown = false;

  function showRecoveryForm() {
    if (_recoveryShown) return;
    _recoveryShown = true;

    const loginErrEl = document.getElementById("loginErr");
    const insertTarget = loginErrEl?.parentElement || document.body;

    ["loginName","loginPass","loginBtn","registerBtn"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = "none";
      if (el?.previousElementSibling?.tagName === "LABEL") el.previousElementSibling.style.display = "none";
    });
    const forgotLink = document.getElementById("forgotPasswordLink");
    if (forgotLink) forgotLink.style.display = "none";
    if (loginErrEl) loginErrEl.textContent = "";

    const prefillName = (document.getElementById("loginName")?.value || "").trim();

    const container = document.createElement("div");
    container.id = "recovery-container";
    container.style.cssText = "padding:16px; text-align:center;";
    container.innerHTML = `
      <div style="margin-bottom:10px;">
        <div style="font-size:28px;">&#128273;</div>
        <h3 style="margin:6px 0 4px;font-size:15px;">Recover Account</h3>
        <p style="font-size:12px;opacity:0.65;margin:0;">Enter your recovery phrase to reset your password.</p>
      </div>
      <input id="recovery-username" type="text" placeholder="Username" autocomplete="username"
        value="${prefillName.replace(/"/g,"")}"
        style="display:block;width:100%;box-sizing:border-box;margin-bottom:8px;padding:8px;
               border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(255,255,255,0.05);
               color:inherit;font-size:13px;outline:none;" />
      <textarea id="recovery-phrase" rows="4" placeholder="Enter your 24 recovery words separated by spaces"
        autocomplete="off" spellcheck="false"
        style="display:block;width:100%;box-sizing:border-box;margin-bottom:8px;padding:8px;
               border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(255,255,255,0.05);
               color:inherit;font-size:13px;font-family:monospace;resize:vertical;outline:none;"></textarea>
      <input id="recovery-newpass" type="password" placeholder="New password" autocomplete="new-password"
        style="display:block;width:100%;box-sizing:border-box;margin-bottom:8px;padding:8px;
               border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(255,255,255,0.05);
               color:inherit;font-size:13px;outline:none;" />
      <input id="recovery-newpass2" type="password" placeholder="Confirm new password" autocomplete="new-password"
        style="display:block;width:100%;box-sizing:border-box;margin-bottom:8px;padding:8px;
               border:1px solid rgba(255,255,255,0.2);border-radius:6px;background:rgba(255,255,255,0.05);
               color:inherit;font-size:13px;outline:none;" />
      <div id="recovery-err" style="color:#dc3545;font-size:12px;min-height:16px;margin-bottom:6px;"></div>
      <button id="recovery-submit" type="button"
        style="padding:8px 20px;border:none;border-radius:6px;background:#007bff;color:white;font-size:14px;cursor:pointer;">
        Recover Account
      </button>
      <div style="margin-top:10px;">
        <a href="#" id="recovery-back" style="font-size:12px;color:#6c757d;text-decoration:underline;">Back to login</a>
      </div>
    `;

    insertTarget.appendChild(container);

    const errEl = document.getElementById("recovery-err");
    const submitBtn = document.getElementById("recovery-submit");

    function showRecoveryErr(msg) { if (errEl) errEl.textContent = msg; }
    function clearRecoveryErr() { if (errEl) errEl.textContent = ""; }

    submitBtn.addEventListener("click", async () => {
      clearRecoveryErr();
      const username = (document.getElementById("recovery-username")?.value || "").trim();
      const phrase = (document.getElementById("recovery-phrase")?.value || "").trim().toLowerCase();
      const newPass = document.getElementById("recovery-newpass")?.value || "";
      const newPass2 = document.getElementById("recovery-newpass2")?.value || "";

      if (!username) { showRecoveryErr("Username is required"); return; }
      if (!phrase)   { showRecoveryErr("Recovery phrase is required"); return; }
      if (!newPass)  { showRecoveryErr("New password is required"); return; }
      if (newPass !== newPass2) { showRecoveryErr("Passwords do not match"); return; }

      submitBtn.disabled = true;
      showRecoveryErr("Verifying phrase…");

      try {
        // 1. Decode and verify phrase client-side (checksum)
        const rawKey = CryptoUtils.bip39Decode(phrase);

        // 2. Derive recovery_auth
        const recoveryAuth = await CryptoUtils.deriveRecoveryAuth(rawKey);
        const recoveryAuthB64 = btoa(String.fromCharCode(...recoveryAuth));

        // 3. Re-encrypt private key with new password (prepared, not saved yet)
        const pkcs8Bytes = CryptoUtils.buildPkcs8FromRawKey(rawKey);
        const pkcs8B64 = btoa(String.fromCharCode(...pkcs8Bytes));
        const newEncryptedPrivateKey = await encryptPrivateKey(pkcs8B64, newPass, { username });

        showRecoveryErr("Contacting server…");

        // 4. Get single-use nonce
        const { nonce } = await apiJson("/auth/recover-start", { body: { username } });

        // 5. Submit recovery — server updates password_hash
        await apiJson("/auth/recover", {
          body: { username, nonce, recovery_auth_b64: recoveryAuthB64, new_password: newPass }
        });

        // 6. Server confirmed — now safe to update local identity
        await saveLocalIdentity(username, {
          v: 3,
          username: normUser(username),
          public_key: null,
          encrypted_private_key: newEncryptedPrivateKey,
          updated_at: Date.now(),
        });

        // Success
        errEl.style.color = "#28a745";
        showRecoveryErr("Password reset! Please log in.");
        submitBtn.disabled = false;
        setTimeout(() => {
          container.remove();
          _recoveryShown = false;
          ["loginName","loginPass","loginBtn","registerBtn"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.style.display = "";
            if (el?.previousElementSibling?.tagName === "LABEL") el.previousElementSibling.style.display = "";
          });
          if (forgotLink) forgotLink.style.display = "";
          if (loginErrEl) loginErrEl.textContent = "";
        }, 2000);

      } catch (e) {
        errEl.style.color = "#dc3545";
        showRecoveryErr(e?.message || "Recovery failed");
        submitBtn.disabled = false;
      }
    });

    document.getElementById("recovery-back").addEventListener("click", (ev) => {
      ev.preventDefault();
      container.remove();
      _recoveryShown = false;
      ["loginName","loginPass","loginBtn","registerBtn"].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = "";
        if (el?.previousElementSibling?.tagName === "LABEL") el.previousElementSibling.style.display = "";
      });
      if (forgotLink) forgotLink.style.display = "";
      if (loginErrEl) loginErrEl.textContent = "";
    });
  }

  // init
  (async () => {
    await _loadServerConfig();
    initServerSetupUI();
    loadServerNotice();  // must run after config loads — uses _apiBase
  })();

  initPort();

  port.postMessage({ type: "auth_get" });

  // Wire up "Forgot password?" link
  const forgotPasswordLink = document.getElementById("forgotPasswordLink");
  if (forgotPasswordLink) {
    forgotPasswordLink.addEventListener("click", (e) => {
      e.preventDefault();
      showRecoveryForm();
    });
  }

  document.getElementById("loginBtn").onclick = async () => {
    const username = (document.getElementById("loginName").value || "").trim();
    const password = document.getElementById("loginPass").value || "";

    const err = document.getElementById("loginErr");
    if (err) err.textContent = "";

    if (!username || !password) {
      if (err) err.textContent = "Username and password are required";
      return;
    }

    port.postMessage({ type: "auth_login", username, password });
  };

  const registerBtn = document.getElementById("registerBtn");
  const loginErrEl = document.getElementById("loginErr");

  function setErr(text) {
    if (loginErrEl) loginErrEl.textContent = text || "";
  }

  function getCreds() {
    const username = (document.getElementById("loginName")?.value || "").trim();
    const password = (document.getElementById("loginPass")?.value || "");
    return { username, password };
  }

  /**
   * Generate X25519 identity key pair for new user
   */
  async function generateKeyPair() {
    return await CryptoUtils.generateIdentityKeyPair();
  }

  /**
   * Export X25519 public key as base64 (32 raw bytes)
   */
  async function exportPublicKeyB64(publicKey) {
    return await CryptoUtils.exportPublicKey(publicKey);
  }

  /**
   * Export X25519 private key as base64 (PKCS8)
   */
  async function exportPrivateKeyB64(privateKey) {
    return await CryptoUtils.exportPrivateKey(privateKey);
  }

  /**
   * Encrypt private key (base64 PKCS8) with password â†’ AES-GCM
   */
  async function encryptPrivateKey(privateKeyB64, password, { username = "" } = {}) {
    // Generate salt
    const salt = crypto.getRandomValues(new Uint8Array(16));

    // Derive AES key from password (Argon2id preferred)
    const derived = await CryptoUtils.deriveRawKeyFromPassword(
      password,
      CryptoUtils.arrayBufferToBase64(salt),
      { preferArgon2: true }
    );
    const aesKey = await crypto.subtle.importKey(
      "raw",
      derived.raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // Encrypt private key (base64 string â†’ bytes â†’ AES-GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(privateKeyB64);
    const createdAt = Date.now();
    let extVersion = "0";
    try {
      extVersion = String(chrome?.runtime?.getManifest?.()?.version || "0");
    } catch {}
    const container = {
      v: 3,
      alg: "AES-256-GCM",
      kdf: derived.kdf,
      salt: CryptoUtils.arrayBufferToBase64(salt),
      iv: CryptoUtils.arrayBufferToBase64(iv),
      created_at: createdAt,
      username: normUser(username),
      ext_version: extVersion,
    };
    const aad = new TextEncoder().encode(CryptoUtils.buildPrivateKeyContainerAAD(container));

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad },
      aesKey,
      encoded
    );

    return {
      ...container,
      data: CryptoUtils.arrayBufferToBase64(ciphertext),
    };
  }

  if (registerBtn) {
    registerBtn.onclick = async () => {
      setErr("");

      const { username, password } = getCreds();
      if (!username || !password) {
        setErr("Username and password are required");
        return;
      }

      // Mirrors server-side RegisterRequest validation
      // (main.py: ^[a-zA-Z][a-zA-Z0-9_]*$, length 3-32). Validating client-side
      // prevents wasting Argon2id derivation (~0.5–2s) on names the server
      // will reject with an opaque pydantic 422 error.
      const usernameErr = validateUsernameForRegister(username);
      if (usernameErr) {
        setErr(usernameErr);
        return;
      }
      if (password.length < 8) {
        setErr("Password must be at least 8 characters");
        return;
      }

      // Server normalises to lowercase; use the same form everywhere
      // downstream (EPK AAD, identity slot) so case-insensitive matches are
      // explicit, not accidental.
      const usernameLower = normUser(username);

      try {
        setErr("Generating encryption keys...");

        // âœ… Generate X25519 identity key pair
        const keyPair = await generateKeyPair();

        // Export keys
        const publicKeyB64 = await exportPublicKeyB64(keyPair.publicKey);
        const privateKeyB64 = await exportPrivateKeyB64(keyPair.privateKey);

        // Derive BIP39 mnemonic and recovery_key_hash from raw private key
        const pkcs8Bytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
        const rawKey = CryptoUtils.extractRawKeyFromPkcs8(pkcs8Bytes);
        const recoveryAuth = await CryptoUtils.deriveRecoveryAuth(rawKey);
        const recoveryKeyHash = await CryptoUtils.sha256Hex(recoveryAuth);
        const mnemonic = CryptoUtils.bip39Encode(rawKey);

        // Encrypt private key with password
        const encryptedPrivateKey = await encryptPrivateKey(privateKeyB64, password, { username: usernameLower });

        setErr("Registering...");

        // Register with public key + recovery hash (private key is device-only)
        const r = await fetch(_apiBase + "/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: usernameLower,
            password,
            public_key: publicKeyB64,
            recovery_key_hash: recoveryKeyHash,
          }),
        });

        const raw = await r.text().catch(() => "");
        let data = {};
        if (raw && raw.trim()) {
          try {
            data = JSON.parse(raw);
          } catch (e) {
            console.warn("WARNING! /auth/register returned non-JSON:", raw.slice(0, 300));
            data = { detail: "Server returned non-JSON response" };
          }
        }
        if (!r.ok) {
          setErr(formatRegisterError(data, r.status));
          return;
        }

        // Save identity to local storage only after successful server registration.
        // Must NOT be saved before the server request — if registration fails (e.g. 409),
        // a stale keypair would overwrite the existing identity and break E2EE for that account.
        await saveLocalIdentity(usernameLower, {
          v: 3,
          username: usernameLower,
          public_key: publicKeyB64,
          encrypted_private_key: encryptedPrivateKey,
          updated_at: Date.now(),
        });

        // Pending-ack flag — cleared only on user confirmation of the recovery
        // phrase. If the browser/extension is closed before ack, the next
        // unlocked panel session re-surfaces the modal (panel-crypto.js).
        await setPendingMnemonicAck(usernameLower);

        console.log("User registered with X25519 E2E encryption");

        // Show mnemonic before proceeding to login
        showMnemonicPrompt(mnemonic, async () => {
          // Clear pending FIRST so the panel does not re-show the modal.
          await clearPendingMnemonicAck().catch(() => {});
          setErr("User registered. Logging in…");
          initPort();
          setActiveUser(usernameLower).catch(() => {});
          port.postMessage({ type: "auth_login", username: usernameLower, password });
        });
        return;
      } catch (e) {
        console.error("Registration error:", e);
        setErr("Register failed: " + (e?.message || e));
      }
    };
  }

  // ===== Server broadcast notice =====
  function _escHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showServerNotice(message, type) {
    if (document.getElementById("srv-notice-overlay")) return;

    const palette = {
      info:        { bg: "#0d1f3a", border: "#1b5078", title: "ℹ️ Server Notice" },
      warning:     { bg: "#2a1a00", border: "#8a5a00", title: "⚠️ Warning" },
      maintenance: { bg: "#1a0a2e", border: "#6a1a9a", title: "🔧 Maintenance" },
    };
    const p = palette[type] || palette.info;

    const overlay = document.createElement("div");
    overlay.id = "srv-notice-overlay";
    overlay.style.cssText = [
      "position:fixed", "inset:0", "background:rgba(0,0,0,.75)",
      "display:flex", "align-items:center", "justify-content:center",
      "z-index:9999", "padding:20px", "box-sizing:border-box",
    ].join(";");

    overlay.innerHTML =
      `<div style="background:${p.bg};border:1px solid ${p.border};border-radius:14px;` +
      `padding:22px 20px;max-width:310px;width:100%;font-family:inherit;color:#e8eefc;">` +
      `<div style="font-size:15px;font-weight:700;margin-bottom:10px;">${p.title}</div>` +
      `<div style="font-size:13px;line-height:1.55;white-space:pre-wrap;word-break:break-word;">` +
      `${_escHtml(message)}</div>` +
      `<button id="srv-notice-ok" style="margin-top:18px;width:100%;padding:9px;` +
      `background:#1b3a66;border:1px solid #265089;border-radius:9px;` +
      `color:#e8eefc;cursor:pointer;font-size:13px;">OK</button>` +
      `</div>`;

    document.body.appendChild(overlay);
    document.getElementById("srv-notice-ok").onclick = () => overlay.remove();
  }

  async function loadServerNotice() {
    try {
      const r = await fetch(_apiBase + "/api/notice", { cache: "no-store" });
      if (!r.ok) return;
      const data = await r.json();
      if (data.active && data.message) showServerNotice(data.message, data.type || "info");
    } catch (_) {
      // Server unreachable — skip silently, the login error will handle it
    }
  }

})();
