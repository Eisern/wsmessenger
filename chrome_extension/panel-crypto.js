// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// ===== panel-crypto.js =====
// E2EE crypto: password unlock, key management, encrypt/decrypt

/**
 * Prompt user for password. Returns the raw string caller MUST
 * derive KEK immediately and discard the string.
 * Never caches the password.
 */
async function promptPassword({ reason = "" } = {}) {
  if (Date.now() < unlockBlockedUntil) {
    const waitSec = Math.ceil((unlockBlockedUntil - Date.now()) / 1000);
    await __ui.alert(`Too many failed unlock attempts. Try again in ${waitSec}s.`);
    return "";
  }
  const msg = reason ? `Unlock: ${reason}` : "Unlock session: Enter the password";

  const p = (await __ui.prompt(msg, {
    title: "Unlock",
    placeholder: "password",
    inputType: "password",
    okText: "Unlock",
    cancelText: "Cancel",
  }));
  return (typeof p === "string") ? p : "";
}

async function takeStashedUnlockKek() {
  try {
    const got = await chrome.storage.session.get(["__tmp_unlock_kek", "__tmp_unlock_ts"]);
    const kekB64 = String(got.__tmp_unlock_kek || "").trim();
    const ts = Number(got.__tmp_unlock_ts || 0);

    if (!kekB64) return "";
    if (ts && (Date.now() - ts > 2 * 60 * 1000)) {
      
      await chrome.storage.session.remove(["__tmp_unlock_kek", "__tmp_unlock_ts"]);
      return "";
    }

    try {
      await sendUnlockKekToBackground(kekB64, ts || Date.now());
    } catch (e) {
      console.warn("sendUnlockKekToBackground failed:", e);
     
    }

    await chrome.storage.session.remove(["__tmp_unlock_kek", "__tmp_unlock_ts"]);

    return kekB64;
  } catch (e) {
    console.warn("takeStashedUnlockKek failed:", e);
    return "";
  }
}

function getCryptoManager() {
  return globalThis.__wsCrypto?.manager || null;
}

function getCryptoUtils() {
  return globalThis.__wsCrypto?.utils || null;
}

function CM() { return globalThis.__wsCrypto?.manager || null; }
function CU() { return globalThis.__wsCrypto?.utils || null; }

// ── Ed25519 helpers ────────────────────────────────────────────────────────────
// username -> Uint8Array (pubkey) | null (no key on server) | undefined (not fetched)
// Emitting chained signatures is OFF until readers are deployed on both
// clients. A reader that only knows v1 rejects a v2 signature outright, which
// would show a forgery warning for an honest message. Flip this only after
// both clients ship the reader that landed in a3f7d33.
const CHAIN_WRITE_ENABLED = false;

const _threadChain = (globalThis.WSThreadChain || null) && globalThis.WSThreadChain.createThreadChain({
  sha256: async (bytes) => new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
});

// Where this device keeps a thread's two hash chains: the one it writes and
// the one it verifies. Not secret - these are hashes of bytes the peer already
// signed - so they sit in plain storage next to the rest of the thread state.
//
// Keyed by the island-scoped slot (`dmRid`), not by the thread id: thread 42
// exists on every island, and reusing one island's head for another island's
// thread makes the peer there see a BREAK - the red "this was tampered with"
// banner - on an honest message. Keys written under a bare thread id by a
// build running with CHAIN_WRITE_ENABLED are simply never read again.
const _chainPrefix = "__chain:";
function _chainKey(rid, who) {
  return _chainPrefix + String(rid) + ":" + String(who || "out");
}
async function _chainGet(rid, who) {
  const genesis = { seq: 0, hash: globalThis.WSThreadChain.GENESIS_HEX };
  try {
    const k = _chainKey(rid, who);
    const r = await chrome.storage.local.get(k);
    const v = r && r[k];
    if (v && typeof v.seq === "number" && /^[0-9a-f]{64}$/.test(v.hash || "")) {
      return { seq: v.seq, hash: v.hash };
    }
  } catch { /* unreadable state is the same as no state */ }
  return genesis;
}
async function _chainSet(rid, who, state) {
  if (!state || typeof state.seq !== "number") return;
  try {
    await chrome.storage.local.set({ [_chainKey(rid, who)]: { seq: state.seq, hash: state.hash } });
  } catch (e) {
    // Failing to persist means the next message reports a gap: noisy but
    // honest, and it must never block sending.
    console.warn("chain state save failed:", e?.message || e);
  }
}

const _ed25519PubKeyCache = new Map();

// Per-peer "earliest signed message timestamp" marker. Once we have ever
// verified a valid Ed25519 signature from a peer, any LATER unsigned message
// from them is treated as forgery (sigValid:false). Older unsigned messages
// (predating the earliest signed message we've seen) are treated as legacy
// (sigValid:null) — they may pre-date the peer's signing rollout.
//
// The marker is per-device, persistent. It is updated downward whenever we
// see a signed message older than the current marker. Time-aware TOFU avoids
// false positives when a thread mixes pre-rollout and post-rollout history.
//
// Storage layout: chrome.storage.local["__dm_signed_v2:<peerLower>"] = <ms>
// Mirrored in memory to avoid awaiting storage on the hot decrypt path.
// (The previous v1 layout stored only a boolean; we ignore those keys here,
// which downgrades any stale enforcement to "legacy until re-observed" — the
// next valid signed message will write a fresh v2 marker.)
const _DM_SIGNED_V2_PREFIX = "__dm_signed_v2:";
const _dmPeerSignedAtMem = new Map(); // peerLower -> earliest signed msg ts (ms)

function _normMsgTsMs(ts) {
  if (ts == null) return 0;
  let n = Number(ts);
  if (!Number.isFinite(n) || n <= 0) {
    // Allow ISO strings ("2024-01-02T...") as a fallback
    const parsed = Date.parse(String(ts));
    if (!Number.isFinite(parsed)) return 0;
    n = parsed;
  }
  // Heuristic: anything < 1e12 is almost certainly seconds — convert to ms.
  if (n > 0 && n < 1e12) n *= 1000;
  return n;
}

async function _getDmPeerSignedAt(peerLower) {
  if (!peerLower) return 0;
  const cached = _dmPeerSignedAtMem.get(peerLower);
  if (cached != null) return cached;
  try {
    const key = _DM_SIGNED_V2_PREFIX + peerLower;
    const got = await chrome.storage.local.get([key]);
    const v = Number(got?.[key]);
    if (Number.isFinite(v) && v > 0) {
      _dmPeerSignedAtMem.set(peerLower, v);
      return v;
    }
  } catch {}
  _dmPeerSignedAtMem.set(peerLower, 0);
  return 0;
}

async function _markDmPeerSignedAt(peerLower, msgTsMs) {
  if (!peerLower) return;
  const ts = _normMsgTsMs(msgTsMs) || Date.now();
  const existing = await _getDmPeerSignedAt(peerLower);
  // Track the EARLIEST signed message ts we've seen from this peer.
  // Earlier evidence shrinks the "must be signed" window only on the upper
  // side (later unsigned messages) — never enlarges false positives.
  if (existing && existing <= ts) return;
  _dmPeerSignedAtMem.set(peerLower, ts);
  try {
    await chrome.storage.local.set({ [_DM_SIGNED_V2_PREFIX + peerLower]: ts });
  } catch {}
}

/**
 * Decide whether an UNSIGNED sealed-sender DM should be treated as a forgery.
 * Returns true iff the peer has previously been observed signing AND this
 * message's timestamp is strictly later than the earliest signed ts we've
 * seen for them (so the lack of signature can't be explained by pre-rollout).
 */
async function _shouldFlagUnsignedAsForged(peerLower, msgTsMs) {
  if (!peerLower) return false;
  const markedAt = await _getDmPeerSignedAt(peerLower);
  if (!markedAt) return false; // never observed signing locally — legacy/yellow
  const ts = _normMsgTsMs(msgTsMs);
  // Without a usable timestamp, we cannot prove the message postdates signing.
  // Be lenient: treat as legacy rather than risk a false "forged" warning.
  if (!ts) return false;
  return ts > markedAt;
}

/** Register own Ed25519 public key with the server. Best-effort — errors are swallowed. */
async function ensureEd25519KeyRegistered() {
  const seed = CM()?.ed25519Seed;
  if (!seed) return;
  const token = await requestToken().catch(() => null);
  if (!token) return;
  try {
    const cu = CU();
    const pubKey = await cu.ed25519GetPublicKey(seed);
    const pubKeyB64 = btoa(String.fromCharCode(...pubKey));
    const r = await fetch(API_BASE + "/crypto/ed25519-key", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify({ public_key: pubKeyB64 }),
    });
    if (r.ok) {
      const username = await resolveActiveUsername();
      if (username) _ed25519PubKeyCache.set(username, { key: pubKey, ts: Date.now() });
      console.log("Ed25519 signing key registered");
    }
  } catch (e) {
    console.warn("Ed25519 key registration failed:", e?.message || e);
  }
}

/** Fetch and cache peer's Ed25519 public key. Returns Uint8Array or null if none. */
// "This peer has no Ed25519 key" is a real answer worth remembering, but only
// briefly: the peer may register one at any moment, and a stale negative
// silently downgrades every DM from them to unverified.
const ED25519_ABSENT_TTL_MS = 5 * 60 * 1000;

async function fetchPeerEd25519PubKey(username) {
  const cached = _ed25519PubKeyCache.get(username);
  if (cached) {
    if (cached.key) return cached.key;
    if (Date.now() - cached.ts < ED25519_ABSENT_TTL_MS) return null;
  }
  const token = await requestToken().catch(() => null);
  if (!token) return null;
  try {
    const r = await fetch(API_BASE + `/keys/${encodeURIComponent(username)}`, {
      headers: { "Authorization": "Bearer " + token },
    });
    // A failed request is NOT an answer. This used to cache the resulting null,
    // so one bad response disabled DM signature verification for the rest of
    // the session — degrading the check silently, and precisely when the
    // network was unreliable.
    if (!r.ok) return null;
    const body = await r.json().catch(() => null);
    if (!body) return null;
    const b64 = String(body.ed25519_public_key || "").trim();
    const pubKey = b64 ? new Uint8Array(CU().base64ToArrayBuffer(b64)) : null;
    _ed25519PubKeyCache.set(username, { key: pubKey, ts: Date.now() });
    return pubKey;
  } catch {
    return null;
  }
}
// ──────────────────────────────────────────────────────────────────────────────

const LOCAL_IDENTITY_PREFIX = "e2ee_local_identity_v2:";
const LOCAL_ACTIVE_USER_KEY = "e2ee_active_user_v2";
const PENDING_MNEMONIC_KEY = "e2ee_pending_mnemonic_v1";

function normUser(v) {
  return String(v || "").trim().toLowerCase();
}

function localIdentityStorageKey(username) {
  return LOCAL_IDENTITY_PREFIX + normUser(username);
}

async function getPendingMnemonicAck() {
  try {
    const got = await chrome.storage.local.get([PENDING_MNEMONIC_KEY]);
    const v = got?.[PENDING_MNEMONIC_KEY];
    const u = normUser(v?.username);
    return u ? { username: u } : null;
  } catch {
    return null;
  }
}

async function clearPendingMnemonicAck() {
  try { await chrome.storage.local.remove(PENDING_MNEMONIC_KEY); } catch {}
}

async function resolveActiveUsername() {
  const fromUi = (typeof getMeUsername === "function") ? normUser(getMeUsername()) : "";
  if (fromUi) return fromUi;
  try {
    const got = await chrome.storage.session.get([LOCAL_ACTIVE_USER_KEY]);
    return normUser(got[LOCAL_ACTIVE_USER_KEY] || "");
  } catch {
    return "";
  }
}

async function loadLocalIdentity(username) {
  const key = localIdentityStorageKey(username);
  const got = await chrome.storage.local.get([key]);
  return got[key] || null;
}

// Canonical KDF name for pin comparison. Mirrors the rules in
// CryptoUtils.deriveRawKeyFromPassword so we compare apples-to-apples.
function _canonicalKdfName(name) {
  const raw = String(name || "").trim();
  if (/^argon2id$/i.test(raw)) return "Argon2id";
  if (/^pbkdf2$/i.test(raw))   return "PBKDF2";
  return raw;
}

/**
 * Refuse to derive if the EPK's claimed KDF name doesn't match what this
 * device pinned on first successful unlock.
 *
 * The KDF parameters in epk.kdf are not authenticated end-to-end. If a
 * compromised server (or a tampered chrome.storage.local entry) flips a
 * user from Argon2id ↔ PBKDF2, derivation just silently fails — the user
 * has no way to tell "wrong password" from "the algorithm changed under me."
 * Pinning converts that silent DoS into a detected tamper.
 *
 * Returns nothing on success; throws on mismatch.
 */
function assertEpkKdfMatchesPin(localIdentity, epk) {
  const pinned = _canonicalKdfName(localIdentity?.kdf_name_pinned || "");
  if (!pinned) return; // first-time path — pin will be written after success
  const claimed = _canonicalKdfName(epk?.kdf?.name || "");
  if (!claimed) {
    console.error("Local identity has pinned KDF but server EPK is missing kdf.name");
    throw new Error("KDF identity tamper detected: server EPK has no algorithm name");
  }
  if (claimed !== pinned) {
    console.error(
      "KDF identity tamper detected: pinned =", pinned,
      "but EPK claims =", claimed
    );
    throw new Error(
      `KDF identity tamper detected (pinned ${pinned}, got ${claimed}). ` +
      `Refusing to derive. If you intentionally changed your password ` +
      `with a different KDF, re-import your account.`
    );
  }
}

/**
 * Persist the device's KDF pin if it isn't already set. Best-effort —
 * storage failures are non-fatal because the pin is a defense in depth,
 * not a unlock prerequisite.
 */
async function pinEpkKdfNameIfNeeded(username, localIdentity, epk) {
  const existing = _canonicalKdfName(localIdentity?.kdf_name_pinned || "");
  if (existing) return;
  const claimed = _canonicalKdfName(epk?.kdf?.name || "");
  if (!claimed) return;
  try {
    const key = localIdentityStorageKey(username);
    const fresh = (await chrome.storage.local.get([key]))[key] || localIdentity || {};
    if (_canonicalKdfName(fresh?.kdf_name_pinned || "")) return; // race-safe
    await chrome.storage.local.set({
      [key]: { ...fresh, kdf_name_pinned: claimed, updated_at: Date.now() },
    });
    console.log("KDF name pinned for device:", claimed);
  } catch (e) {
    console.warn("KDF pin write failed:", e?.message || e);
  }
}

async function fetchMyPublicKey(username) {
  const token = await requestToken();
  if (!token) throw new Error("No token");
  const r = await fetch(API_BASE + `/keys/${encodeURIComponent(username)}`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `Public key fetch failed (${r.status})`);
  const pk = String(body.public_key || "").trim();
  if (!pk) throw new Error("Own public key missing on server");
  return pk;
}

// ===== CRYPTO STATE =====
let cryptoInitialized = false;
let cryptoInitPromise = null;

// "Unlocked" session: we do NOT keep the password string after successful unlock.
// We only keep unlocked CryptoKey(s) in memory (non-extractable).
let cryptoUnlocked = false;
let cryptoLockTimer = null;
let unlockFailCount = 0;
let unlockBlockedUntil = 0;
let __cryptoLockNotifiedState = null;

const CRYPTO_IDLE_LOCK_KEY = "crypto_idle_lock_ms";
const CRYPTO_IDLE_LOCK_DEFAULT_MS = 5 * 60 * 1000;
const CRYPTO_IDLE_LOCK_ALLOWED_MS = [
  1 * 60 * 1000,
  5 * 60 * 1000,
  15 * 60 * 1000,
  30 * 60 * 1000,
];
let cryptoIdleLockMs = CRYPTO_IDLE_LOCK_DEFAULT_MS;

function normalizeCryptoIdleLockMs(ms) {
  const n = Number(ms || 0);
  if (!Number.isFinite(n)) return CRYPTO_IDLE_LOCK_DEFAULT_MS;
  return CRYPTO_IDLE_LOCK_ALLOWED_MS.includes(n) ? n : CRYPTO_IDLE_LOCK_DEFAULT_MS;
}

async function loadCryptoIdleLockMsFromStorage() {
  try {
    const got = await chrome.storage.local.get([CRYPTO_IDLE_LOCK_KEY]);
    cryptoIdleLockMs = normalizeCryptoIdleLockMs(got?.[CRYPTO_IDLE_LOCK_KEY]);
  } catch {
    cryptoIdleLockMs = CRYPTO_IDLE_LOCK_DEFAULT_MS;
  }
}

function applyCryptoIdleLockMs(ms) {
  cryptoIdleLockMs = normalizeCryptoIdleLockMs(ms);
  if (cryptoUnlocked) bumpCryptoIdleTimer();
  return cryptoIdleLockMs;
}

async function setCryptoIdleLockMs(ms) {
  const next = normalizeCryptoIdleLockMs(ms);
  try {
    await chrome.storage.local.set({ [CRYPTO_IDLE_LOCK_KEY]: next });
  } catch {}
  applyCryptoIdleLockMs(next);
  return next;
}

function getCryptoIdleLockMs() {
  return cryptoIdleLockMs;
}

function notifyCryptoLockState(locked, source = "") {
  const isLocked = !!locked;
  if (__cryptoLockNotifiedState === isLocked) return;
  __cryptoLockNotifiedState = isLocked;
  try {
    window.dispatchEvent(new CustomEvent("ws_crypto_lock_state", {
      detail: { locked: isLocked, source: String(source || "") }
    }));
  } catch {}
  try {
    window.dispatchEvent(new Event(isLocked ? "ws_crypto_locked" : "ws_crypto_unlocked"));
  } catch {}
}

function getUnlockBackoffMs() {
  if (unlockFailCount <= 0) return 0;
  return Math.min(30_000, 1000 * Math.pow(2, unlockFailCount - 1));
}

function markUnlockFailure() {
  unlockFailCount = Math.min(unlockFailCount + 1, 10);
  unlockBlockedUntil = Date.now() + getUnlockBackoffMs();
}

function markUnlockSuccess() {
  unlockFailCount = 0;
  unlockBlockedUntil = 0;
}

function isCryptoUsable() {
  const cm = getCryptoManager();
  return !!(cm && cm.userPrivateKey);
}

function lockCryptoSession() {
  cryptoUnlocked = false;
  cryptoInitialized = false;
  if (cryptoLockTimer) {
    clearTimeout(cryptoLockTimer);
    cryptoLockTimer = null;
  }
  _ed25519PubKeyCache.clear();
  try { CM()?.clearUnlocked?.(); } catch {}
  try { CM()?.clear?.(); } catch {}
  try { safePost?.({ type: "unlock_kek_clear" }); } catch {}
  notifyCryptoLockState(true, "idle-timeout");
  console.warn("Crypto session locked");
}

async function deriveUnlockKekB64FromPassword(password, encryptedPrivateKeyObj) {
  const saltB64 = encryptedPrivateKeyObj?.salt || "";
  const kdf = encryptedPrivateKeyObj?.kdf || {};
  if (!saltB64) throw new Error("No salt for KEK derivation");
  const derived = await CU().deriveRawKeyFromPassword(password, saltB64, {
    name: kdf.name,
    iterations: kdf.iterations,
    hash: kdf.hash,
    time_cost: kdf.time_cost,
    memory_kib: kdf.memory_kib,
    parallelism: kdf.parallelism,
    version: kdf.version,
    preferArgon2: true,
  });
  return CU().arrayBufferToBase64(derived.raw);
}

async function interactiveUnlockAndSendKek({ reason = "" } = {}) {
  // 1) ask password
  let password = await promptPassword({ reason: reason || "Unlock E2EE" });
  if (!password) return false;

  // 2) read local encrypted identity key
  const username = await resolveActiveUsername();
  if (!username) throw new Error("No active username");
  const localIdentity = await loadLocalIdentity(username);
  if (!localIdentity?.encrypted_private_key) throw new Error("No local encrypted private key on this device");

  // 2a) Refuse to derive if the EPK's KDF name doesn't match this device's pin.
  assertEpkKdfMatchesPin(localIdentity, localIdentity.encrypted_private_key);

  // 3) derive kek
  let kekB64 = "";
  try {
    kekB64 = await deriveUnlockKekB64FromPassword(password, localIdentity.encrypted_private_key);
  } catch (e) {
    markUnlockFailure();
    throw e;
  }

  // 4) send to background, then drop the local password reference.
  try {
    await sendUnlockKekToBackground(kekB64, Date.now());
    markUnlockSuccess();
    // Pin the KDF name on first successful unlock (best-effort).
    await pinEpkKdfNameIfNeeded(username, localIdentity, localIdentity.encrypted_private_key);
    // Crash-recovery surfacing: if the user registered but never ack'd the
    // mnemonic, login.js may have been unable to surface it (auth_state
    // path with no fresh password). Now that we have the password in hand,
    // re-derive and show before continuing.
    await _surfacePendingMnemonicIfNeeded(username, password, localIdentity.encrypted_private_key);
  } finally {
    // Note: JS strings are immutable, so there is no real "wipe" available
    // for `password`. The previous `password.fill?.(0)` was a no-op
    // (String.prototype has no `fill`). Dropping the reference is the
    // strongest action we can take from JS — the actual lifetime of the
    // bytes on the heap is governed by the garbage collector.
    password = "";
  }

  bumpCryptoIdleTimer();
  return true;
}

// Show the recovery phrase modal if the register flow was interrupted before
// the user acknowledged it. Stale flags (different username) are cleared.
async function _surfacePendingMnemonicIfNeeded(username, password, epk) {
  try {
    const pending = await getPendingMnemonicAck();
    if (!pending) return;
    const u = normUser(username);
    if (!u || pending.username !== u) {
      await clearPendingMnemonicAck();
      return;
    }
    if (!epk || !password) return;
    const pkcs8B64 = await CU().decryptPrivateKeyToPkcs8B64(epk, password, { expectedUsername: u });
    const pkcs8Bytes = new Uint8Array(CU().base64ToArrayBuffer(pkcs8B64));
    const rawKey = CU().extractRawKeyFromPkcs8(pkcs8Bytes);
    let mnemonic = "";
    try {
      mnemonic = CU().bip39Encode(rawKey);
    } finally {
      try { rawKey.fill(0); } catch {}
      try { pkcs8Bytes.fill(0); } catch {}
    }
    await new Promise((resolve) => {
      _showMnemonicOverlay(mnemonic, async () => {
        await clearPendingMnemonicAck();
        resolve();
      });
    });
  } catch (e) {
    console.warn("_surfacePendingMnemonicIfNeeded failed:", e?.message || e);
  }
}

// Modal overlay for the 24-word recovery phrase. Cannot be dismissed except
// by the explicit "I have saved my phrase" button — there is no other way to
// recover the account if the password is lost.
function _showMnemonicOverlay(mnemonic, onAck) {
  const words = String(mnemonic || "").split(/\s+/).filter(Boolean);
  if (words.length === 0) { try { onAck?.(); } catch {} return; }

  const overlay = document.createElement("div");
  overlay.id = "mnemonic-recovery-overlay";
  overlay.style.cssText = "position:fixed;inset:0;z-index:9999999;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;padding:16px;";

  const card = document.createElement("div");
  card.style.cssText = "max-width:480px;width:100%;background:#1a1d24;border:1px solid #2a2f38;border-radius:14px;padding:20px;color:#e6e6e6;font-family:system-ui,sans-serif;";

  const grid = words.map((w, i) =>
    `<span style="display:inline-block;width:calc(33% - 4px);margin:2px;padding:4px 2px;background:rgba(255,255,255,0.06);border-radius:4px;font-family:monospace;font-size:12px;text-align:left;box-sizing:border-box;">
      <span style="opacity:0.5;font-size:10px;">${i+1}.</span> ${w}
    </span>`
  ).join("");

  card.innerHTML = `
    <h3 style="margin:0 0 8px;font-size:16px;text-align:center;">Save Your Recovery Phrase</h3>
    <p style="font-size:12px;opacity:0.75;margin:0 0 12px;text-align:center;">
      Write these 24 words down in order. They are the only way to recover your account if you forget your password.
    </p>
    <div style="text-align:left;margin-bottom:14px;">${grid}</div>
    <div style="text-align:center;">
      <button id="mnemonic-recovery-done" type="button"
        style="padding:8px 24px;border:none;border-radius:6px;background:#28a745;color:white;font-size:14px;cursor:pointer;">
        I have saved my phrase
      </button>
    </div>
  `;

  overlay.appendChild(card);
  document.body.appendChild(overlay);

  document.getElementById("mnemonic-recovery-done").addEventListener("click", () => {
    overlay.remove();
    try { onAck?.(); } catch {}
  });
}

function bumpCryptoIdleTimer() {
  if (!cryptoUnlocked) return;
  if (cryptoLockTimer) clearTimeout(cryptoLockTimer);
  cryptoLockTimer = setTimeout(lockCryptoSession, cryptoIdleLockMs);
}

// treat any user activity as "still active"
if (!window.__cryptoIdleBound) {
  window.__cryptoIdleBound = true;
  document.addEventListener("click", bumpCryptoIdleTimer, true);
  document.addEventListener("keydown", bumpCryptoIdleTimer, true);
  document.addEventListener("mousemove", bumpCryptoIdleTimer, true);
}

window.__setCryptoIdleLockMs = setCryptoIdleLockMs;
window.__getCryptoIdleLockMs = getCryptoIdleLockMs;
void loadCryptoIdleLockMsFromStorage();

async function takeOneShotMasterFromBackground(expectedUsername = "") {
  return await new Promise((resolve) => {
    try {
      const reqId = "m" + Date.now() + ":" + Math.random().toString(16).slice(2);
      const reqUser = normUser(expectedUsername || "");

      // âœ… Ð±ÐµÑ€Ñ‘Ð¼ Ð¿Ð¾Ñ€Ñ‚ Ð¸Ð· rpc.js, Ð° ÐµÑÐ»Ð¸ Ð½ÐµÑ‚ â€” fallback Ð½Ð° legacy
      const port =
        (typeof window.rpcGetPort === "function" ? window.rpcGetPort() : null) ||
        globalThis.port;

      if (!port?.postMessage) return resolve("");

      const onMsg = (msg) => {
        if (msg?.type === "unlock_master_take_res" && msg?.reqId === reqId) {
          try { port.onMessage.removeListener(onMsg); } catch {}
          resolve(String(msg.master_b64 || "").trim());
        }
      };

      port.onMessage.addListener(onMsg);
      port.postMessage({ type: "unlock_master_take", reqId, username: reqUser });

      setTimeout(() => {
        try { port.onMessage.removeListener(onMsg); } catch {}
        resolve("");
      }, 800);
    } catch {
      resolve("");
    }
  });
}

async function ensureCryptoReady({ interactive = false, reason = "" } = {}) {
  // already unlocked and usable
  if (cryptoUnlocked && cryptoInitialized && isCryptoUsable()) {
    bumpCryptoIdleTimer();
    return true;
  }

// âœ… Variant 2+: auto-unlock ONLY via one-shot master from background (no UI, no storage)
  if (!interactive) {
  // already unlocked and usable
  if (cryptoUnlocked && cryptoInitialized && isCryptoUsable()) {
    bumpCryptoIdleTimer();
    return true;
  }

  // try one-shot master from background for the active user only
  const activeUsername = await resolveActiveUsername();
  if (!activeUsername) return false;
  const masterB64 = await takeOneShotMasterFromBackground(activeUsername);
  if (!masterB64) return false;

  try {
    const kekKey = await CU().importAesKeyFromRaw(masterB64, false, ["decrypt"]);
    const ok = await initializeCrypto({ interactive: false, reason: reason || "Auto unlock (login handoff)", kekKey });
    if (!ok || !isCryptoUsable()) return false;

    cryptoUnlocked = true;
    cryptoInitialized = true;
    notifyCryptoLockState(false, "auto-unlock");
    bumpCryptoIdleTimer();
    return true;
  } catch (e) {
    console.warn("Auto unlock from background master failed:", e?.message || e);
    return false;
  }
}

  if (cryptoInitPromise) return cryptoInitPromise;

  cryptoInitPromise = (async () => {
    // initializeCrypto(interactive:true) Ð´Ð¾Ð»Ð¶ÐµÐ½ ÑÐ°Ð¼:
    // - ÑÐ¿Ñ€Ð¾ÑÐ¸Ñ‚ÑŒ Ð¿Ð°Ñ€Ð¾Ð»ÑŒ/Ð¿Ð¸Ð½
    // - Ð¿Ð¾Ð»ÑƒÑ‡Ð¸Ñ‚ÑŒ salt/kdf
    // - derive KEK
    // - Ð¾Ñ‚Ð¿Ñ€Ð°Ð²Ð¸Ñ‚ÑŒ unlock_kek_set Ð² background (Ð¸Ð»Ð¸ ÑÐ´ÐµÐ»Ð°Ñ‚ÑŒ ÑÑ‚Ð¾ Ð²Ð½ÑƒÑ‚Ñ€Ð¸)
    const ok = await initializeCrypto({ interactive: true, reason });

    if (!ok || !isCryptoUsable()) {
      cryptoUnlocked = false;
      cryptoInitialized = false;
      throw new Error("crypto init failed");
    }

    cryptoUnlocked = true;
    cryptoInitialized = true;
    notifyCryptoLockState(false, "interactive-unlock");

    bumpCryptoIdleTimer();
    return true;
  })().finally(() => {
    cryptoInitPromise = null;
  });

  return cryptoInitPromise;
}


async function initializeCrypto({ interactive = false, reason = "", kekKey = null } = {}) {
  try {
    console.log("Initializing crypto...");
    const username = await resolveActiveUsername();
    if (!username) {
      console.warn("Active username is unknown");
      return false;
    }

    // 1. Load encrypted private key from local device storage
    const localIdentity = await loadLocalIdentity(username);
    let encryptedPrivateKey = localIdentity?.encrypted_private_key;
    if (!encryptedPrivateKey) {
      console.warn(`No local private key for "${username}" on this device`);
      return false;
    }

    // 1a. Refuse to derive if the EPK's KDF name doesn't match this device's pin.
    //     (Only meaningful when we'll actually run the KDF below — i.e. !kekKey.
    //     The auto-unlock kekKey path receives an already-derived AES key from
    //     background, so the algorithm name is irrelevant on this branch.)
    if (!kekKey) {
      assertEpkKdfMatchesPin(localIdentity, encryptedPrivateKey);
    }

    // 2. Obtain KEK (either provided, or derive from password)
    let effectiveKek = kekKey;

    if (!effectiveKek) {
      if (!interactive) {
        console.warn("No KEK and non-interactive mode, crypto disabled");
        return false;
      }

      // Prompt for password, derive KEK IMMEDIATELY, discard password
      let password = await promptPassword({ reason });
      if (!password) {
        console.warn("No password entered, crypto disabled");
        return false;
      }

      // Derive KEK from password + salt (PBKDF2, ~620k iterations)
      // After this line, only the non-extractable CryptoKey exists, no password string
      effectiveKek = await CU().deriveKeyFromPassword(password, encryptedPrivateKey.salt, {
        name: encryptedPrivateKey.kdf?.name,
        iterations: encryptedPrivateKey.kdf?.iterations,
        hash: encryptedPrivateKey.kdf?.hash,
        time_cost: encryptedPrivateKey.kdf?.time_cost,
        memory_kib: encryptedPrivateKey.kdf?.memory_kib,
        parallelism: encryptedPrivateKey.kdf?.parallelism,
        version: encryptedPrivateKey.kdf?.version,
        preferArgon2: true,
      });
      password = "";  // discard password string immediately
    }

    // One-shot migration: legacy v2 container -> v3 with AAD, then persist.
    if (Number(encryptedPrivateKey?.v || 2) !== 3) {
      try {
        const migrated = await CU().migrateLegacyPrivateKeyContainerV2ToV3WithAesKey(
          encryptedPrivateKey,
          effectiveKek,
          { username }
        );
        const nextIdentity = {
          ...localIdentity,
          v: 3,
          username,
          encrypted_private_key: migrated,
          updated_at: Date.now(),
        };
        await chrome.storage.local.set({ [localIdentityStorageKey(username)]: nextIdentity });
        encryptedPrivateKey = migrated;
        console.warn("Local identity migrated to key-container v3");
      } catch (e) {
        console.error("Failed to migrate legacy private key container:", e?.message || e);
        if (interactive) {
          markUnlockFailure();
        } else {
          try { safePost?.({ type: "unlock_master_clear" }); } catch {}
        }
        return false;
      }
    }

    // 3. Resolve own public key (local first, then server)
    let publicKeyB64 = String(localIdentity?.public_key || "").trim();
    if (!publicKeyB64) {
      try {
        publicKeyB64 = await fetchMyPublicKey(username);
        if (publicKeyB64) {
          await chrome.storage.local.set({
            [localIdentityStorageKey(username)]: {
              ...localIdentity,
              username,
              public_key: publicKeyB64,
              updated_at: Date.now(),
            },
          });
        }
      } catch (e) {
        console.warn("Failed to fetch own public key:", e?.message || e);
      }
    }
    if (!publicKeyB64) {
      console.warn("User public key unavailable, crypto disabled");
      return false;
    }

    // 4. Decrypt private key using KEK
    const cm = CM();
    if (!cm?.initializeUserKeyWithKek) {
      console.warn("Crypto manager not available");
      return false;
    }

    const success = await cm.initializeUserKeyWithKek(
      encryptedPrivateKey,
      effectiveKek,
      publicKeyB64,
      username
    );

    if (!success) {
      console.error(interactive
        ? "Failed to decrypt private key (wrong password?)"
        : "Failed to decrypt private key using auto-unlock master");
      if (interactive) {
        markUnlockFailure();
      } else {
        try { safePost?.({ type: "unlock_master_clear" }); } catch {}
      }
      cryptoUnlocked = false;
      cryptoInitialized = false;
      return false;
    }

    console.log("User key initialized");
    markUnlockSuccess();
    // Pin the KDF name on first successful unlock (only meaningful when we
    // actually exercised the KDF — auto-unlock with kekKey skips it).
    if (!kekKey) {
      pinEpkKdfNameIfNeeded(username, localIdentity, encryptedPrivateKey).catch(() => {});
    }
    ensureEd25519KeyRegistered().catch(() => {});
    return true;

  } catch (e) {
    console.warn("initializeCrypto error:", e?.name, e?.message || e);
    return false;
  }
}


async function createAndSaveRoomKeyForMe(roomId) {
  try {
    const rid = Number(roomId);
    console.log(`Creating room key for room ${rid} (owner/self)...`);

    await ensureCryptoReady({ interactive: true, reason: "Create room key" });

    const roomKeyBase64 = await CM().createRoomKey(rid);
    const keyId = await CU().fingerprintRoomKeyBase64(roomKeyBase64);

    const pub = CM()?.userPublicKeyPem;
    if (!pub) throw new Error("User public key not available");

    const encryptedForMe = await CU().encryptRoomKeyForUser(pub, roomKeyBase64);

    const token = await requestToken();
    if (!token) throw new Error("No token");

    const resp = await fetch(API_BASE + `/crypto/room-key`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ room_id: rid, encrypted_room_key: encryptedForMe, key_id: keyId })
      
    });

    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      CM().roomKeys.delete(rid);
      CM().roomKeysExportable.delete(rid);
      CM().roomKeyIds.delete(rid);
      throw new Error(body.detail || `Save room key failed (${resp.status})`);
    }

    console.log(`Room key saved for owner in room ${rid}`);
    return true;
  } catch (e) {
    console.error("createAndSaveRoomKeyForMe failed:", e);
    return false;
  }
}

// ============================
// Room Key Rotation (Step 6)
// ============================
//
// When a member is removed (kicked) from a room, the owner MUST
// generate a new room key and distribute it to all remaining members.
// Otherwise the kicked user could still decrypt future messages
// using the old key they already have.
//
// Flow:
//   1. Fetch current member list via GET /rooms/{roomId}/members
//   2. Generate new AES-256-GCM room key
//   3. Preflight each remaining member
//   4. Share the new key to every remaining member with retries
//   5. Save encrypted copy for self (owner) via POST /crypto/room-key
//   6. Load new key locally
//
// This is called automatically after a successful kick.

const KEY_ROTATION_SHARE_MAX_ATTEMPTS = 5;
const KEY_ROTATION_SHARE_RETRY_BASE_MS = 1200;
const KEY_ROTATION_OWNER_SAVE_MAX_ATTEMPTS = 3;

function waitMs(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Rotate the room key: generate a new key and distribute to all current members.
 * Should only be called by the room owner.
 *
 * @param {number} roomId
 * @param {object} opts
 * @param {string} [opts.kickedUsername] the kicked user (for logging)
 * @returns {Promise<{ok: boolean, shared: number, failed: string[], error?: string}>}
 */
async function rotateRoomKey(roomId, { kickedUsername = "" } = {}) {
  const rid = Number(roomId);
  if (!Number.isInteger(rid) || rid <= 0) {
    return { ok: false, shared: 0, failed: [], error: "Invalid roomId" };
  }

  console.log(`[KeyRotation] Starting room key rotation for room ${rid}` +
    (kickedUsername ? ` (after kicking ${kickedUsername})` : ""));

  try {
    // 1. Ensure crypto is unlocked
    await ensureCryptoReady({ interactive: true, reason: "Room key rotation" });

    const cu = CU();
    const cm = CM();
    if (!cu || !cm) throw new Error("Crypto not available");

    const myPub = cm.userPublicKeyPem;
    if (!myPub) throw new Error("Own public key not available");

    const meName = getMeUsername().toLowerCase();

    const token = await requestToken();
    if (!token) throw new Error("No token");

    // 2. Fetch current members (after the kick has been processed) before any
    // server-side key mutation so we can abort cleanly if distribution cannot
    // be prepared for every remaining member.
    const membersResp = await fetch(API_BASE + `/rooms/${encodeURIComponent(rid)}/members`, {
      method: "GET",
      headers: { "Authorization": "Bearer " + token }
    });

    if (!membersResp.ok) {
      console.warn(`[KeyRotation] Failed to fetch members for room ${rid}: ${membersResp.status}`);
      return { ok: false, shared: 0, failed: [], error: "Member list unavailable; old key remains active" };
    }

    const members = await membersResp.json().catch(() => []);
    if (!Array.isArray(members)) {
      return { ok: false, shared: 0, failed: [], error: "Member list invalid; old key remains active" };
    }

    // 3. Generate the new key material only after we know the member list.
    const tmp = await cu.generateRoomKey(true);
    const newKeyBase64 = await cu.exportRoomKey(tmp);
    const keyId = await cu.fingerprintRoomKeyBase64(newKeyBase64);
    console.log(`[KeyRotation] New room key generated for room ${rid}`);

    // 4. Preflight every recipient before mutating server state.
    const otherMembers = members.filter(m => {
      const uname = String(m.username || "").trim().toLowerCase();
      return uname && uname !== meName;
    });

    const preparedShares = [];
    const preflightFailed = [];
    console.log(`[KeyRotation] Preflighting new key distribution to ${otherMembers.length} members`);

    for (const member of otherMembers) {
      const uname = String(member.username || "").trim();
      try {
        const pkResp = await fetch(
          API_BASE + `/keys/${encodeURIComponent(uname)}`,
          { method: "GET", headers: { "Authorization": "Bearer " + token } }
        );
        const pkBody = await pkResp.json().catch(() => ({}));
        if (!pkResp.ok || !pkBody.public_key) {
          throw new Error("public key unavailable");
        }

        await assertPeerKeyTrustedForSharing(uname, "sharing room key", { peerPublicKeyB64: pkBody.public_key });
        const encryptedForMember = await cu.encryptRoomKeyForUser(pkBody.public_key, newKeyBase64);
        preparedShares.push({ uname, encryptedForMember });
      } catch (e) {
        console.warn(`[KeyRotation] Preflight failed for ${uname}:`, e?.message || e);
        preflightFailed.push(uname);
      }
    }

    if (preflightFailed.length > 0) {
      const pendingList = preflightFailed.join(", ");
      return {
        ok: false,
        shared: 0,
        failed: preflightFailed,
        error: `Rotation aborted before activation because some members cannot receive the new key (${pendingList})`,
      };
    }

    // 5. Share new key with each remaining member (excluding self). We only
    // activate the new key locally after every recipient has acknowledged it.
    console.log(`[KeyRotation] Distributing new key to ${preparedShares.length} members`);

    let shared = 0;
    let pendingShares = preparedShares.slice();

    for (let attempt = 1; attempt <= KEY_ROTATION_SHARE_MAX_ATTEMPTS && pendingShares.length > 0; attempt++) {
      const nextPending = [];

      for (const share of pendingShares) {
        const uname = share.uname;
        try {
          const shareResp = await fetch(
            API_BASE + `/crypto/room/${rid}/share?target_username=${encodeURIComponent(uname)}`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + token
              },
              body: JSON.stringify({ encrypted_room_key: share.encryptedForMember, key_id: keyId })
            }
          );

          const shareBody = await shareResp.json().catch(() => ({}));
          if (!shareResp.ok) {
            console.warn(`[KeyRotation] Share attempt ${attempt} to ${uname} failed:`, shareBody.detail || shareResp.status);
            nextPending.push(share);
            continue;
          }

          shared++;
          console.log(`[KeyRotation] Key shared to ${uname} on attempt ${attempt}`);
        } catch (e) {
          console.warn(`[KeyRotation] Share attempt ${attempt} to ${uname} errored:`, e?.message || e);
          nextPending.push(share);
        }
      }

      pendingShares = nextPending;

      if (pendingShares.length > 0 && attempt < KEY_ROTATION_SHARE_MAX_ATTEMPTS) {
        const retryDelay = KEY_ROTATION_SHARE_RETRY_BASE_MS * attempt;
        console.warn(
          `[KeyRotation] Retrying ${pendingShares.length} pending share(s) in ${retryDelay}ms:`,
          pendingShares.map(x => x.uname).join(", ")
        );
        await waitMs(retryDelay);
      }
    }

    const failed = pendingShares.map(x => x.uname);
    console.log(`[KeyRotation] Distribution finished for room ${rid}: ${shared} shared, ${failed.length} failed`);

    if (failed.length > 0) {
      const pendingList = failed.join(", ");
      return {
        ok: false,
        shared,
        failed,
        error: `Rotation not activated because not every member received the new key (${pendingList})`,
      };
    }

    // 6. Persist the new key for the owner only after all recipient shares
    // have succeeded, so the room switches generations as atomically as the
    // current API allows.
    const encryptedForMe = await cu.encryptRoomKeyForUser(myPub, newKeyBase64);
    let ownerSaved = false;
    let ownerSaveError = "";

    for (let attempt = 1; attempt <= KEY_ROTATION_OWNER_SAVE_MAX_ATTEMPTS; attempt++) {
      try {
        const saveResp = await fetch(API_BASE + "/crypto/room-key", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token
          },
          body: JSON.stringify({ room_id: rid, encrypted_room_key: encryptedForMe, key_id: keyId })
        });

        const saveBody = await saveResp.json().catch(() => ({}));
        if (!saveResp.ok) {
          throw new Error(saveBody.detail || `Save new room key failed (${saveResp.status})`);
        }

        ownerSaved = true;
        break;
      } catch (e) {
        ownerSaveError = e?.message || String(e);
        console.warn(`[KeyRotation] Owner save attempt ${attempt} failed:`, ownerSaveError);
        if (attempt < KEY_ROTATION_OWNER_SAVE_MAX_ATTEMPTS) {
          await waitMs(KEY_ROTATION_SHARE_RETRY_BASE_MS * attempt);
        }
      }
    }

    if (!ownerSaved) {
      return {
        ok: false,
        shared,
        failed: [],
        error: `All members received the new key, but owner activation failed: ${ownerSaveError}`,
      };
    }

    // 7. Load new key locally now that it has been distributed to all members.
    //    This ensures messages sent during distribution were encrypted with the old key,
    //    which every member still had at that point.
    await cm.loadRoomKey(rid, newKeyBase64);
    await saveRoomKeyArchive(rid);
    console.log(`[KeyRotation] New key activated locally for room ${rid}`);

    return { ok: true, shared, failed };
  } catch (e) {
    console.error(`[KeyRotation] Failed for room ${rid}:`, e);
    return { ok: false, shared: 0, failed: [], error: e?.message || String(e) };
  }
}

// ============================
// Key Archive Persistence (Step 6)
// ============================
// Old room keys are stored in chrome.storage.local so that
// after page reload / reconnect, historical messages encrypted
// with previous key versions can still be decrypted.
//
// Storage format:
//   key:   "__rka:{roomId}" for a room, "__rka:dm:{island}:{threadId}" for a DM
//   value: [ { kid: "hex16", b64: "base64..." }, ... ]

const _ARCHIVE_PREFIX = "__rka:";

/**
 * Normalize a key slot for use as an archive storage key.
 *
 * Room slots are numbers; DM slots are island-qualified strings
 * ("dm:<island>:<tid>", see `dmRid`). The blanket `Number(roomId)` these
 * functions used turns every DM slot into NaN — which is one shared slot for
 * every thread of every island, a worse version of the collision that made DM
 * slots island-scoped in the first place.
 */
function _archiveRid(roomId) {
  return typeof roomId === "string" && roomId.startsWith("dm:") ? roomId : Number(roomId);
}

/**
 * Read stored archive blob and return parsed entries.
 * Supports three formats:
 *   - legacy plaintext array  : [ { kid, b64 }, ... ]          (pre-A-C2)
 *   - encrypted v2 object     : { v: 2, iv, ct } where plaintext
 *                               is JSON of the entries array    (A-C2+)
 *   - undefined / empty       : returns []
 * Returns { entries, wasLegacy, sealed }.
 *   sealed = true means we found an encrypted blob but couldn't decrypt
 *            it (master key locked). Callers must NOT treat the archive
 *            as empty, to avoid destroying the blob on the next save.
 */
async function _readStoredArchive(storageKey) {
  const stored = await chrome.storage.local.get([storageKey]);
  const raw = stored[storageKey];

  if (Array.isArray(raw)) {
    // Legacy plaintext format: preserve and let the next save re-encrypt.
    return { entries: raw, wasLegacy: true, sealed: false };
  }

  if (raw && typeof raw === "object" && raw.v === 2 && raw.iv && raw.ct) {
    // Encrypted format: decrypt via background master key.
    if (typeof decryptFromStorage !== "function") {
      console.warn("[KeyArchive] decryptFromStorage unavailable; archive stays sealed");
      return { entries: [], wasLegacy: false, sealed: true };
    }
    try {
      const json = await decryptFromStorage({ iv: raw.iv, ct: raw.ct });
      if (!json) {
        // Master key locked or decrypt failed: leave the stored blob alone.
        return { entries: [], wasLegacy: false, sealed: true };
      }
      const parsed = JSON.parse(json);
      return {
        entries: Array.isArray(parsed) ? parsed : [],
        wasLegacy: false,
        sealed: false,
      };
    } catch (e) {
      console.warn("[KeyArchive] decrypt failed:", e?.message || e);
      return { entries: [], wasLegacy: false, sealed: true };
    }
  }

  return { entries: [], wasLegacy: false, sealed: false };
}

/**
 * Persist the in-memory key archive for a room to chrome.storage.local.
 * Since A-C2 the stored blob is encrypted with the background master key
 * (AES-256-GCM). Legacy plaintext archives are transparently upgraded on
 * the next save.
 */
async function saveRoomKeyArchive(roomId) {
  const rid = _archiveRid(roomId);
  const archiveB64 = CM()?.roomKeyArchiveB64?.get(rid);
  if (!archiveB64 || archiveB64.size === 0) return;

  const storageKey = _ARCHIVE_PREFIX + rid;
  try {
    // Merge with already-persisted entries so that flushArchiveB64 (which
    // wipes in-memory raw strings after each save) doesn't cause subsequent
    // saves to overwrite and lose older generation keys.
    const { entries: existing, sealed } = await _readStoredArchive(storageKey);
    if (sealed) {
      // Master key locked: merging would clobber entries we can't read.
      // Defer persistence until the next save when the master key is back.
      console.warn(`[KeyArchive] Skipping save for room ${rid}: stored archive is sealed`);
      return;
    }

    const merged = new Map(existing.map(e => [e.kid, e.b64]));
    for (const [kid, b64] of archiveB64) {
      if (b64) merged.set(kid, b64);
    }

    const entries = Array.from(merged.entries()).map(([kid, b64]) => ({ kid, b64 }));
    const json = JSON.stringify(entries);

    // Encrypt before persisting. If the master key is locked the RPC
    // returns null: refuse to fall back to plaintext so sensitive key
    // material never lands on disk unencrypted.
    if (typeof encryptForStorage !== "function") {
      console.warn(`[KeyArchive] encryptForStorage unavailable; NOT persisting room ${rid}`);
      return;
    }
    const encrypted = await encryptForStorage(json);
    if (!encrypted || !encrypted.iv || !encrypted.ct) {
      console.warn(`[KeyArchive] Master key locked; NOT persisting room ${rid}`);
      return;
    }

    await chrome.storage.local.set({
      [storageKey]: { v: 2, iv: encrypted.iv, ct: encrypted.ct }
    });
    console.log(`[KeyArchive] Saved ${entries.length} key(s) for room ${rid} (encrypted)`);
    // Flush raw base64 from memory; CryptoKey objects remain for decryption
    try { CM()?.flushArchiveB64?.(rid); } catch {}
  } catch (e) {
    console.warn("[KeyArchive] save failed:", e);
  }
}

/**
 * Restore archived keys from chrome.storage.local into memory.
 * Called after loadRoomKey so old messages can still be decrypted.
 */
async function loadRoomKeyArchive(roomId) {
  const rid = _archiveRid(roomId);
  const storageKey = _ARCHIVE_PREFIX + rid;

  try {
    const { entries, wasLegacy } = await _readStoredArchive(storageKey);
    if (!entries.length) return;

    let loaded = 0;
    for (const { kid, b64 } of entries) {
      if (!kid || !b64) continue;
      // Skip if already in archive
      const existing = CM()?.roomKeyArchive?.get(rid);
      if (existing && existing.has(kid)) continue;

      const ok = await CM().loadArchivedKey(rid, kid, b64);
      if (ok) loaded++;
    }

    if (loaded > 0) {
      console.log(`[KeyArchive] Restored ${loaded} archived key(s) for room ${rid}`);
    }

    // If the blob on disk was the legacy plaintext array, upgrade it in
    // place so sensitive key material doesn't keep living on disk in the
    // clear. saveRoomKeyArchive merges with in-memory archiveB64 which
    // has just been populated by loadArchivedKey(), so no data is lost.
    if (wasLegacy) {
      try {
        await saveRoomKeyArchive(rid);
        console.log(`[KeyArchive] Migrated room ${rid} archive to encrypted format`);
      } catch (e) {
        console.warn(`[KeyArchive] Migration save failed for room ${rid}:`, e?.message || e);
      }
    }
  } catch (e) {
    console.warn("[KeyArchive] load failed:", e);
  }
}

async function loadRoomKeyArchiveFromServer(roomId) {
  const rid = Number(roomId);
  const token = await requestToken();
  if (!token) return;

  try {
    const r = await fetch(API_BASE + `/crypto/room-key/${encodeURIComponent(rid)}/archive`, {
      method: "GET",
      headers: { "Authorization": "Bearer " + token },
    });
    if (!r.ok) return;
    const body = await r.json().catch(() => ({}));
    const keys = Array.isArray(body?.keys) ? body.keys : [];
    if (keys.length === 0) return;

    const cm = CM();
    const cu = CU();
    if (!cm?.userPrivateKey || !cu?.decryptRoomKeyForUser) return;

    let loaded = 0;
    const existing = cm.roomKeyArchive?.get(rid) || new Map();
    for (const entry of keys) {
      const encrypted = String(entry?.encrypted_room_key || "").trim();
      if (!encrypted) continue;
      const kidHint = String(entry?.key_id || "").trim().toLowerCase();
      if (kidHint && existing.has(kidHint)) continue;
      try {
        const keyBase64 = await cu.decryptRoomKeyForUser(cm.userPrivateKey, encrypted);
        const kid = kidHint || await cu.fingerprintRoomKeyBase64(keyBase64);
        if (existing.has(kid)) continue;
        const ok = await cm.loadArchivedKey(rid, kid, keyBase64);
        if (ok) loaded++;
      } catch (e) {
        console.warn(`[KeyArchive] Failed to decrypt archived key (kid=${kidHint || "?"}) for room ${rid}:`, e?.message || e);
      }
    }

    if (loaded > 0) {
      console.log(`[KeyArchive] Restored ${loaded} key(s) from server for room ${rid}`);
      await saveRoomKeyArchive(rid);
    }
  } catch (e) {
    console.warn("[KeyArchive] server load failed:", e);
  }
}

/**
 * Load this room's key into CryptoManager.
 *
 * Background-safe: never prompts.
 *
 * Returns a result object rather than a bare boolean because the three failure
 * modes need different handling and callers used to blame all of them on a
 * lock — which made a room we simply have no key for pop a password prompt.
 * Mirrors loadDmKey's shape.
 *
 * @returns {Promise<{ok: boolean, locked?: boolean, notFound?: boolean, error?: boolean}>}
 */
async function loadRoomKey(roomId) {
  const okCrypto = await ensureCryptoReady({ interactive: false });
  if (!okCrypto) {
    console.warn("Crypto locked; skip loadRoomKey");
    return { ok: false, locked: true };
  }

  try {
    const rid = Number(roomId);
    console.log(`Loading room key for room ${rid}...`);

    // Restore archived keys first (before loading current, so archive is preserved)
    await loadRoomKeyArchive(rid);

    const token = await requestToken();
    if (!token) return { ok: false, locked: true };

    const response = await fetch(API_BASE + `/crypto/room-key/${roomId}`, {
      method: "GET",
      headers: { Authorization: "Bearer " + token },
    });

    // --- no key on server: maybe owner can auto-create ---
    if (response.status === 404) {
      console.warn(`No room key found for room ${rid}`);

      const isOwner = !!roomOwnerById[String(rid)];
      if (!isOwner) {
        // Not a lock and not an error: a provider has yet to deliver our key.
        console.warn(`Not owner of room ${rid}, cannot create room key`);
        return { ok: false, notFound: true };
      }

      console.log(`We are owner of room ${rid}, creating room key...`);
      const created = await createAndSaveRoomKeyForMe(rid);
      if (created) {
        await loadRoomKeyArchiveFromServer(rid);
        console.log(`Room key auto-created for room ${rid}`);
        return { ok: true };
      }

      console.error(`Failed to auto-create room key for room ${rid}`);
      return { ok: false, error: true };
    }

    if (!response.ok) {
      console.warn("Failed to get room key:", response.status);
      return { ok: false, error: true };
    }

    const data = await response.json().catch(() => null);
    if (!data?.encrypted_room_key) {
      console.warn("room key response has no encrypted_room_key");
      return { ok: false, error: true };
    }

    const roomKeyBase64 = await CU().decryptRoomKeyForUser(
      CM().userPrivateKey,
      data.encrypted_room_key
    );

    await CM().loadRoomKey(rid, roomKeyBase64);

    // Persist updated archive (current key is now part of it)
    await saveRoomKeyArchive(rid);
    await loadRoomKeyArchiveFromServer(rid);

    console.log(`Room key loaded for room ${rid}`);
    return { ok: true };
  } catch (error) {
    console.error("loadRoomKey failed:", error);
    return { ok: false, error: true };
  }
}

// =======================
// DM E2EE helpers (thread key like room key)
// =======================
// Key slot for a DM thread, scoped by island — endpoints.js `threadRid` carries
// the reasoning. ISLAND_ID lives in panel.js and follows `server_config`, so a
// slot always names the server the thread was actually read from.
function dmRid(threadId) {
  const rid = globalThis.WSEndpoints?.threadRid?.(ISLAND_ID, threadId) || "";
  if (!rid) throw new Error(`Bad threadId ${threadId} or unknown island`);
  return rid;
}

// The slot this thread occupied before slots carried an island. Nothing writes
// here any more; only the one-time archive migration below reads it.
function legacyDmRid(threadId) {
  return globalThis.WSEndpoints?.legacyThreadRid?.(threadId) || 0;
}

async function fetchPeerPublicKey(peerUsername) {
  const token = await requestToken();
  if (!token) throw new Error("No token");

  const r = await fetch(API_BASE + `/keys/${encodeURIComponent(peerUsername)}`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `Public key fetch failed (${r.status})`);
  if (!body.public_key) throw new Error("peer public_key missing");
  return body.public_key;
}

// Trust failures carry a `code` so batch callers can tell "this peer needs a
// human to verify a safety number" from "we could not check right now". Before
// this, the only caller sniffed the message text with a regex, which does not
// survive a sweep over many peers: one flaky /keys/{u} fetch would be reported
// to the user as a security event.
function _trustError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

async function assertPeerKeyTrustedForSharing(
  peerUsername,
  actionLabel = "sharing encrypted key",
  { peerPublicKeyB64 = null } = {}
) {
  const peer = String(peerUsername || "").trim();
  if (!peer) throw new Error("Missing peer username");
  const keyCheck = await checkPeerKeyChanged(peer, { force: true, peerPublicKeyB64 });
  if (keyCheck === null) {
    // Pass peerPublicKeyB64 to keep this off the network: then null can only
    // mean crypto is unusable locally, not that a fetch flapped.
    throw _trustError("TRUST_UNVERIFIABLE",
      `Unable to verify trust state for "${peer}". ` +
      `Open Safety Number and verify before ${actionLabel}.`
    );
  }
  if (keyCheck.changed) {
    throw _trustError("TRUST_CHANGED",
      `Public key for "${peer}" has changed since last known. ` +
      `Verify safety numbers before ${actionLabel}.`
    );
  }

  // Check persistent :changed flag. Without this check, the block above only fires
  // in the narrow window of first detection — as soon as any call (checkPeerKeyChanged
  // or getSafetyNumber) updates the stored fingerprint, keyCheck.changed becomes false
  // and sharing is allowed even without user re-verification.
  const me = getMeUsername();
  if (me) {
    const changedKey = (await _fpBase(me, peer)) + ":changed";
    try {
      const stored = await chrome.storage.local.get([changedKey]);
      if (stored[changedKey]) {
        throw _trustError("TRUST_UNVERIFIED",
          `Public key for "${peer}" has recently changed and requires re-verification. ` +
          `Open Safety Numbers and verify before ${actionLabel}.`
        );
      }
    } catch (e) {
      if (e?.code === "TRUST_UNVERIFIED") throw e;
      // Storage read error — fail open (don't block on infrastructure error)
    }
  }
}

async function loadDmKeyArchiveFromServer(threadId) {
  const token = await requestToken();
  if (!token) return;

  const rid = dmRid(threadId);
  const cm = CM();
  const cu = CU();
  if (!cm?.userPrivateKey || !cu?.decryptRoomKeyForUser) return;

  try {
    const r = await fetch(API_BASE + `/crypto/dm-key/${encodeURIComponent(threadId)}/archive`, {
      method: "GET",
      headers: { "Authorization": "Bearer " + token }
    });
    if (!r.ok) return;
    const body = await r.json().catch(() => ({}));
    const keys = Array.isArray(body?.keys) ? body.keys : [];
    if (keys.length === 0) return;

    let loaded = 0;
    const existing = cm.roomKeyArchive?.get(rid) || new Map();
    for (const entry of keys) {
      const encrypted = String(entry?.encrypted_thread_key || "").trim();
      if (!encrypted) continue;
      const kidHint = String(entry?.key_id || "").trim().toLowerCase();
      if (kidHint && existing.has(kidHint)) continue;
      try {
        const keyBase64 = await cu.decryptRoomKeyForUser(cm.userPrivateKey, encrypted);
        const kid = kidHint || await cu.fingerprintRoomKeyBase64(keyBase64);
        if (existing.has(kid)) continue;
        const ok = await cm.loadArchivedKey(rid, kid, keyBase64);
        if (ok) loaded++;
      } catch (e) {
        console.warn(`[KeyArchive] Failed to decrypt DM archived key (kid=${kidHint || "?"}) for thread ${threadId}:`, e?.message || e);
      }
    }

    if (loaded > 0) {
      console.log(`[KeyArchive] Restored ${loaded} DM key(s) from server for thread ${threadId}`);
      await saveRoomKeyArchive(rid);
    }
  } catch (e) {
    console.warn("[KeyArchive] DM server load failed:", e);
  }
}

/**
 * Move a thread's stored key archive from the pre-island slot to this island's.
 *
 * The stored blob is already encrypted with the master key and its format did
 * not change, so this is a rename — no unlock needed, and a locked panel
 * migrates just as well as an unlocked one.
 *
 * If this island already has an archive for the thread, the old blob is left
 * where it is instead of being merged or deleted: it cannot be attributed to
 * any island, and adopting it everywhere would hand one island's old keys to
 * another. Left alone it is inert — nothing writes to the legacy slot again.
 */
async function migrateLegacyDmArchive(threadId) {
  const legacy = legacyDmRid(threadId);
  if (!legacy) return;
  const legacyKey = _ARCHIVE_PREFIX + legacy;
  let currentKey;
  try {
    currentKey = _ARCHIVE_PREFIX + dmRid(threadId);
  } catch {
    return;
  }

  try {
    const stored = await chrome.storage.local.get([legacyKey, currentKey]);
    if (stored[legacyKey] === undefined) return;
    if (stored[currentKey] !== undefined) return;

    await chrome.storage.local.set({ [currentKey]: stored[legacyKey] });
    await chrome.storage.local.remove(legacyKey);
    console.log(`[KeyArchive] Moved DM ${threadId} archive to island-scoped slot`);
  } catch (e) {
    console.warn("[KeyArchive] DM archive migration failed:", e?.message || e);
  }
}

async function loadDmKey(threadId, { interactive = false } = {}) {
  const okCrypto = await ensureCryptoReady({ interactive, reason: "DM key" });
  if (!okCrypto) return { ok: false, locked: true };

  // DM archives use the same local persistence format as room archives
  // (under an island-scoped slot), so restore older generations before loading
  // the current key from the server.
  await migrateLegacyDmArchive(threadId);
  await loadRoomKeyArchive(dmRid(threadId));

  const token = await requestToken();
  if (!token) throw new Error("No token");

  const r = await fetch(API_BASE + `/crypto/dm-key/${encodeURIComponent(threadId)}`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });

  if (r.status === 404) return { ok: false, notFound: true };

  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `DM key load failed (${r.status})`);
  if (!body.encrypted_thread_key) throw new Error("Encrypted_thread_key missing");

  const cm = CM();
  const cu = CU();
  if (!cm?.userPrivateKey) return { ok: false, locked: true };
  if (!cu?.decryptRoomKeyForUser) throw new Error("Crypto utils not available");

  const keyBase64 = await cu.decryptRoomKeyForUser(
    cm.userPrivateKey,
    body.encrypted_thread_key
  );

  await cm.loadRoomKey(dmRid(threadId), keyBase64);
  await loadDmKeyArchiveFromServer(threadId);
  return { ok: true };
}

async function createAndShareDmKey(threadId, peerUsername) {
  await ensureCryptoReady({ interactive: true, reason: "Create DM key" });
  const token = await requestToken();
  if (!token) throw new Error("No token");

  const utils = getCryptoUtils();
  if (!utils) throw new Error("CryptoUtils not available");
  const tmp = await utils.generateRoomKey(true);

  const keyBase64 = await CU().exportRoomKey(tmp);
  const keyId = await CU().fingerprintRoomKeyBase64(keyBase64);

  const myPub = CM().userPublicKeyPem;
  if (!myPub) throw new Error("No my public key");
  const encryptedForMe = await CU().encryptRoomKeyForUser(myPub, keyBase64);

  const peerPub = await fetchPeerPublicKey(peerUsername);
  await assertPeerKeyTrustedForSharing(peerUsername, "sharing DM key", { peerPublicKeyB64: peerPub });

  // Validate peer public key is valid X25519 (32 bytes raw)
  try {
    const raw = CU().base64ToArrayBuffer(peerPub);
    if (raw.byteLength !== 32) {
      throw new Error(
        `Peer "${peerUsername}" has an invalid public key (${raw.byteLength} bytes instead of 32). ` +
        `They may need to re-register to generate X25519 keys.`
      );
    }
  } catch (e) {
    if (e.message.includes("re-register")) throw e;
    throw new Error(`Peer "${peerUsername}" public key is not valid base64: ${e.message}`);
  }

  const encryptedForPeer = await CU().encryptRoomKeyForUser(peerPub, keyBase64);
  {
    const r = await fetch(API_BASE + `/crypto/dm-key`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ thread_id: Number(threadId), encrypted_thread_key: encryptedForMe, key_id: keyId })
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.detail || `DM key save failed (${r.status})`);
  }
  {
    const r = await fetch(API_BASE + `/crypto/dm/${encodeURIComponent(threadId)}/share`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({ username: peerUsername, encrypted_thread_key: encryptedForPeer, key_id: keyId })
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.detail || `DM key share failed (${r.status})`);
  }

  await CM().loadRoomKey(dmRid(threadId), keyBase64);
  await saveRoomKeyArchive(dmRid(threadId));
  return true;
}

const dmKeyLocks = new Map(); // rid -> Promise

/**
 * Error thrown by ensureDmKeyReady when the DM key can't be loaded because
 * crypto is locked and we're in non-interactive mode. Callers can detect
 * this via `err.code === "DM_KEY_LOCKED"` and react differently than they
 * would to a real failure (queue pending retry, show lock UI, etc.).
 */
class DmKeyLockedError extends Error {
  constructor(threadId) {
    super(`DM key locked for thread ${threadId}`);
    this.name = "DmKeyLockedError";
    this.code = "DM_KEY_LOCKED";
    this.threadId = threadId;
  }
}

async function ensureDmKeyReady(threadId, peerUsername, { interactive = false } = {}) {
  const rid = dmRid(threadId);

  if (CM()?.roomKeys?.has(rid)) return;

  if (dmKeyLocks.has(rid)) return dmKeyLocks.get(rid);

  const p = (async () => {
    let got;
    try {
      got = await loadDmKey(threadId, { interactive });
    } catch (e) {
      throw new Error("DM key load failed: " + (e?.message || e));
    }

    if (got?.locked) {
      // Previously: in the non-interactive branch we silently `return`ed
      // undefined, which made callers think the key was ready when it was
      // not — the root cause of "I press Send on a DM and nothing happens"
      // reports (A-M5). Always signal locked state explicitly so callers
      // can queue a pending retry or surface a clear UI state.
      if (!interactive) throw new DmKeyLockedError(threadId);
      throw new Error("DM key load requires unlock");
    }

    if (got?.ok) {
      if (!CM()?.roomKeys?.has(rid)) {
        throw new Error("DM key load ok, but key not in cache");
      }
      return;
    }

    if (got?.notFound) {
      if (!peerUsername) throw new Error("DM peer is unknown, can't create key");

      try {
        await createAndShareDmKey(threadId, peerUsername);
      } catch (e) {
        throw new Error("DM key create/share failed: " + (e?.message || e));
      }

      let got2;
      try {
        got2 = await loadDmKey(threadId, { interactive });
      } catch (e) {
        throw new Error("DM key reload failed: " + (e?.message || e));
      }

      if (!got2?.ok || !CM()?.roomKeys?.has(rid)) {
        throw new Error("DM key still missing after create/share");
      }
      return;
    }
    throw new Error(got?.error || ("DM key load returned: " + JSON.stringify(got)));
  })().finally(() => {
    dmKeyLocks.delete(rid);
  });

  dmKeyLocks.set(rid, p);
  return p;
}

async function encryptDm(threadId, plaintext, peerUsername) {
  await ensureDmKeyReady(threadId, peerUsername, { interactive: true });
  // Sealed Sender: embed sender identity inside the encrypted payload.
  // The server will NOT attach username to the broadcast — only the
  // recipient can learn who sent the message by decrypting this envelope.
  //
  // SECURITY: `from` MUST come from an authoritative source tied to login
  // state, not from arbitrary UI variables (e.g. currentRecentUser) that
  // can be mutated via DOM access or stale state. The Ed25519 signature
  // also feeds `from` into _dmSigMessage, so a forged value would also
  // break signature verification on the peer side.
  let myUsername = "";
  try {
    if (typeof getMeUsername === "function") {
      myUsername = String(getMeUsername() || "").trim();
    }
  } catch {}
  if (!myUsername) {
    try { myUsername = await resolveActiveUsername(); } catch {}
  }
  if (!myUsername) {
    throw new Error("encryptDm: cannot resolve sender identity (not logged in?)");
  }
  const envelopeObj = { ss: 1, from: myUsername, body: plaintext };

  // Ed25519 signature: proves `from` field was written by the true sender
  const seed = CM()?.ed25519Seed;
  if (seed && myUsername) {
    try {
      let sigMsg;
      let chained = null;
      if (CHAIN_WRITE_ENABLED && _threadChain) {
        const head = await _chainGet(dmRid(threadId), "out");
        chained = { seq: head.seq + 1, prev: head.hash };
        envelopeObj.sq = chained.seq;
        envelopeObj.pv = chained.prev;
        sigMsg = CU()._dmSigMessageV2(threadId, chained.seq, chained.prev, myUsername, plaintext);
      } else {
        sigMsg = CU()._dmSigMessage(threadId, myUsername, plaintext);
      }
      envelopeObj.sig = await CU().ed25519Sign(seed, sigMsg);

      if (chained) {
        // Advance at signing time, not at delivery: a failed send is queued
        // with this exact ciphertext and retried unchanged, so the seq it
        // carries is already spoken for. An abandoned send leaves a hole,
        // which the peer reports as a GAP - the survivable verdict.
        await _chainSet(dmRid(threadId), "out", {
          seq: chained.seq,
          hash: await _threadChain.linkFor(sigMsg),
        });
      }
    } catch (e) {
      // Having a seed and failing to sign with it is not a normal condition -
      // the "peer has no signing key yet" case never reaches here, it is the
      // `seed` guard above. Swallowing this sent the message unsigned, and the
      // only person who could have noticed was the recipient, as a quiet
      // "unverified" marker. Fail loudly instead: the sender gets to decide.
      console.warn("DM Ed25519 sign failed:", e?.message || e);
      throw new Error("Could not sign this message. Nothing was sent - unlock and try again.");
    }
  }

  const envelope = JSON.stringify(envelopeObj);
  return await CM().encryptMessage(dmRid(threadId), envelope);
}

async function decryptDm(threadId, text, peerUsername, msgTs) {
  // A cross-island thread has no key on this island and no peer here to share
  // one with. Left to the local path, a missing key becomes "the server has
  // none, so create and share one" - which would mint a key for a mailbox the
  // other side cannot read, and only the trust check stops it, by failing with
  // a message about a public key nobody here was ever going to have.
  const __foreignThread = await _foreignForThread(threadId);
  if (__foreignThread) {
    try {
      await ensureForeignKeysReady(__foreignThread);
    } catch (e) {
      console.warn("decryptDm: foreign keys not ready:", e?.message || e);
    }
  }

  try {
    if (!__foreignThread) await ensureDmKeyReady(threadId, peerUsername, { interactive: false });
  } catch (e) {
    // DM_KEY_LOCKED is the expected non-interactive failure mode — the
    // !CM()?.roomKeys?.has(rid) guard below handles it. Anything else is
    // worth surfacing so we don't silently swallow real errors.
    if (e?.code !== "DM_KEY_LOCKED") {
      console.warn("decryptDm: ensureDmKeyReady failed:", e?.message || e);
    }
  }

  if (typeof text !== "string") return text;

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return text;
  }

  if (!parsed?.encrypted || !parsed.iv || !parsed.data) {
    return text;
  }

  // If still locked / key not loaded, don't spam placeholders in chat.
  const rid = dmRid(threadId);
  if (!CM()?.roomKeys?.has(rid)) {
    return null;
  }

  const decrypted = await CM().decryptMessage(rid, parsed);

  // Sealed Sender: try to unwrap {ss:1, from, body, sig?} envelope
  try {
    if (typeof decrypted === "string" && decrypted.startsWith("{")) {
      const inner = JSON.parse(decrypted);
      if (inner && inner.ss === 1 && inner.body !== undefined) {
        const from = inner.from || null;
        const fromLower = from ? String(from).trim().toLowerCase() : "";
        let sigValid = null;
        let chainInfo = null;

        if (inner.sig && from) {
          try {
            // A cross-island contact has no entry in this island's key store,
            // and should not need one: their signing key came from the contact
            // card, out of band. Verifying against that is strictly stronger
            // than verifying against whatever a key server hands over - it is
            // what stops a dishonest island forging messages from them.
            // Our own copies in that thread are still ours, so they verify
            // against our own key like anywhere else.
            const __fc = await _foreignForThread(threadId);
            const __mine = fromLower && fromLower === String(getMeUsername() || "").toLowerCase();
            // Our own signing key needs no lookup: it is derived from the
            // identity that is already unlocked. Asking the server for it was
            // a round trip per message that could only ever agree with us or
            // be wrong - and on a cross-island thread it is a question this
            // island cannot answer at all.
            const peerPub = (__fc && !__mine && __fc.ed25519PubB64)
              ? new Uint8Array(CU().base64ToArrayBuffer(__fc.ed25519PubB64))
              : (__mine && CM()?.ed25519Seed)
                ? await CU().ed25519GetPublicKey(CM().ed25519Seed)
                : await fetchPeerEd25519PubKey(from);
            if (peerPub) {
              const cu = CU();
              // v2 when the envelope carries its place in the sender's chain,
              // v1 otherwise. Which one was signed is inside the signature (the
              // domain prefix differs), so stripping sq/pv to force a v1 check
              // does not downgrade anything - it just fails.
              const chained = Number.isInteger(inner.sq) && /^[0-9a-f]{64}$/.test(inner.pv || "");
              // A signature covers the thread the message was DELIVERED to.
              // In a cross-island conversation that is not always the thread it
              // is read in: our own copy of what we sent went to the peer's
              // mailbox on their island and is kept here only so the history is
              // whole. Verifying it against this thread's number fails -
              // correctly, on the wrong question - and accuses us of forging
              // our own messages.
              //
              // Our own messages can carry either number, because not every
              // path through this client goes abroad, so both are tried. That
              // costs nothing: an attacker who could produce either signature
              // would already hold our signing key.
              const __ownTids = [];
              if (__fc && __mine && __fc.outbox && __fc.outbox.threadId) {
                __ownTids.push(__fc.outbox.threadId);
              }
              __ownTids.push(threadId);

              const sigBytes = new Uint8Array(cu.base64ToArrayBuffer(inner.sig));
              let sigMsg = null;
              for (const tid of __ownTids) {
                sigMsg = chained
                  ? cu._dmSigMessageV2(tid, inner.sq, inner.pv, from, inner.body)
                  : cu._dmSigMessage(tid, from, inner.body);
                sigValid = await cu.ed25519Verify(peerPub, sigBytes, sigMsg);
                if (sigValid === true) break;
              }
              if (chained) {
                // Reported, not checked here: history arrives in pages and in
                // no particular order, so verifying message by message would
                // invent a gap on every load. The caller sorts a sender's run
                // and checks it with verifyRun. The link is computed only for
                // a verified signature, or a forgery could drag the chain on.
                chainInfo = { seq: inner.sq, prev: inner.pv, link: null };
                if (sigValid === true && _threadChain) {
                  try { chainInfo.link = await _threadChain.linkFor(sigMsg); } catch { /* stays null */ }
                }
              }
              if (sigValid === true && fromLower) {
                // Record the earliest signed-message ts we've seen from
                // this peer. Any LATER unsigned message will be flagged as
                // forgery; older ones are treated as pre-rollout legacy.
                await _markDmPeerSignedAt(fromLower, msgTs);
              }
            } else {
              // sig present but we can't fetch peer's public key — can't
              // verify. This is NOT the same as "signature is wrong" (the
              // peer may not have registered their key yet, or we have a
              // network issue). Leave sigValid=null → yellow "unverified".
              // sigValid = null (already the default)
            }
          } catch (e) {
            console.warn("DM Ed25519 verify error:", e?.message || e);
            // Crypto-level error (e.g., malformed key, bad sig format).
            // Leave sigValid=null — we can't prove forgery if the check
            // itself failed to run.
            // sigValid = null (already the default)
          }
        } else if (fromLower) {
          // No signature on the envelope. Flag as forgery ONLY if this
          // message postdates the earliest signed message we've locally
          // observed from this peer (time-aware TOFU). Pre-rollout
          // messages (older than the marker) stay sigValid === null
          // (yellow "unverified" warning, not red "forged").
          try {
            if (await _shouldFlagUnsignedAsForged(fromLower, msgTs)) {
              sigValid = false;
            }
          } catch {}
          // else: leave sigValid === null (legacy / first-seen, allowed but warned)
        }

        return { text: inner.body, sealedFrom: from, sealed: true, sigValid, chain: chainInfo };
      }
    }
  } catch {}

  // Legacy (non-sealed) message — return plain string
  return decrypted;
}

//Check if current user is owner of room
async function checkIfRoomOwner(roomId) {
  try {
    const token = await requestToken();
    if (!token) return false;
    
    const response = await fetch(API_BASE + "/rooms/list", {
      method: "GET",
      headers: { "Authorization": "Bearer " + token }
    });
    
    if (!response.ok) return false;
    
    const rooms = await response.json();
    if (!Array.isArray(rooms)) return false;
    
    const room = rooms.find(r => Number(r.id) === Number(roomId));
    if (!room) return false;
    
    return !!room.is_owner;
    
  } catch (error) {
    console.error("Failed to check room ownership:", error);
    return false;
  }
}

//Encrypt message before sending
async function encryptMessageForRoom(roomId, plaintext) {
  const okCrypto = await ensureCryptoReady({ interactive: true, reason: "Send message" });
  if (!okCrypto) throw new Error("Crypto locked");

  const rid = Number(roomId);
  if (!Number.isInteger(rid) || rid <= 0) throw new Error("Bad roomId");

  if (!CM()?.roomKeys?.has(rid)) {
    const res = await loadRoomKey(rid);
    if (!res.ok) throw new Error("No room key for this room");
  }

  // Re-check after async loadRoomKey — key could have been cleared by lock/logout
  const cm = CM();
  if (!cm || !cm.roomKeys?.has(rid)) {
    throw new Error("Room key unavailable (crypto was locked during send)");
  }
  return await cm.encryptMessage(rid, plaintext);
}

// --- transport helpers ---
function isPingPayloadText(text) {
  if (typeof text !== "string") return false;

  if (text === "ping" || text === "pong") return true;

  const t = text.trim();
  if (!t) return false;

  if (t[0] === "{") {
    try {
      const obj = JSON.parse(t);
      const ty = obj?.type;
      return ty === "ping" || ty === "pong";
    } catch {
      return false;
    }
  }

  return false;
}

//Decrypt received message
async function decryptMessageFromRoom(roomId, text) {
  if (isPingPayloadText(text)) return null;
  if (typeof text !== "string") return text;

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return text;
  }

  if (!parsed?.encrypted || !parsed.iv || !parsed.data) {
    return text;
  }

  try {
    const okCrypto = await ensureCryptoReady({ interactive: false });
    if (!okCrypto) throw new Error("locked");
  } catch {
    return null;
  }

  const rid = Number(roomId);

if (!CM()?.roomKeys?.has(rid)) {
  try {
    const res = await loadRoomKey(rid);
    if (!res.ok) {
      console.warn("Received encrypted message but room key not available", rid);
      return "[Encrypted message - key not available]";
    }
  } catch (e) {
    console.warn("Room key lazy-load failed:", e?.message || e);
    return "[Encrypted message - key not available]";
  }
}
  try {
    const decrypted = await CM().decryptMessage(rid, parsed);
    return decrypted;
} catch (error) {
  const name = error?.name || "";
  const msg  = error?.message || String(error);
  console.error("Decryption failed:", { name, msg, rid, ivLen: (parsed.iv||"").length, dataLen: (parsed.data||"").length });

  
  if (name === "OperationError") {
    console.warn("AES-GCM auth failed: wrong room key OR corrupted iv/data. rid=", rid);
  }

  return "[Encrypted message - decryption failed]";
}

}

/**
 * Wrap this room's key for one member and upload it.
 *
 * @param {number} roomId
 * @param {string} targetUsername
 * @param {object} [opts]
 * @param {boolean} [opts.interactive=true] prompt to unlock if locked. The key
 *   sweep passes false: an automatic trigger must never raise a password prompt.
 * @param {boolean} [opts.ifAbsent=false] fill a gap only, never replace a key
 *   the target already holds. The server forces this on for non-owners anyway.
 * @returns {Promise<{ok: true, written: boolean}>} written=false means the
 *   target already had a key — a success, not a failure.
 */
async function shareRoomKeyToUser(roomId, targetUsername, { interactive = true, ifAbsent = false } = {}) {
  const rid = Number(roomId);
  const uname = (targetUsername || "").trim();
  if (!rid || !uname) throw new Error("shareRoomKeyToUser: missing args");

  await ensureCryptoReady({ interactive, reason: "Share room key" });

  let roomKeyBase64 = await CM().exportRoomKeyForSharing(rid);

  if (!roomKeyBase64) {
    await loadRoomKey(rid);
    roomKeyBase64 = await CM().exportRoomKeyForSharing(rid);
  }

  if (!roomKeyBase64) {
    const isOwner = !!roomOwnerById[String(rid)];
    if (!isOwner) throw new Error("Not owner, and room key is not available");

    const ok = await createAndSaveRoomKeyForMe(rid);
    if (!ok) throw new Error("Failed to create/save room key for owner");

    roomKeyBase64 = await CM().exportRoomKeyForSharing(rid);
    if (!roomKeyBase64) throw new Error("Room key raw not available after create");
  }

  const token = await requestToken();
  const r1 = await fetch(API_BASE + `/keys/${encodeURIComponent(uname)}`, {
    method: "GET",
    headers: { "Authorization": "Bearer " + token }
  });

  const d1 = await r1.json().catch(() => ({}));
  if (!r1.ok) throw new Error(d1.detail || `Failed to get public key (${r1.status})`);

  const inviteePubKeyB64 = d1.public_key;
  if (!inviteePubKeyB64) throw new Error("Invitee public key is empty");

  // Validate invitee public key is valid X25519 (32 bytes raw)
  try {
    const raw = CU().base64ToArrayBuffer(inviteePubKeyB64);
    if (raw.byteLength !== 32) {
      throw new Error(
        `User "${uname}" has an invalid public key (${raw.byteLength} bytes instead of 32). ` +
        `They may need to re-register to generate X25519 keys.`
      );
    }
  } catch (e) {
    if (e.message.includes("re-register")) throw e;
    throw new Error(`User "${uname}" public key is not valid base64: ${e.message}`);
  }

  // TOFU hardening: require fresh trust verification before sharing.
  // null = skipped (cooldown / crypto not ready) — proceed; changed:true = block.
  await assertPeerKeyTrustedForSharing(uname, "sharing the room key", { peerPublicKeyB64: inviteePubKeyB64 });

  const encryptedForInvitee = await CU().encryptRoomKeyForUser(inviteePubKeyB64, roomKeyBase64);
  const keyId = CM()?.roomKeyIds?.get(rid) || await CU().fingerprintRoomKeyBase64(roomKeyBase64);

  const r2 = await fetch(
    API_BASE + `/crypto/room/${rid}/share?target_username=${encodeURIComponent(uname)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
      },
      body: JSON.stringify({
        encrypted_room_key: encryptedForInvitee,
        key_id: keyId,
        if_absent: !!ifAbsent,
      })
    }
  );

  const d2 = await r2.json().catch(() => ({}));
  if (!r2.ok) throw new Error(d2.detail || `Share failed (${r2.status})`);

  // Older servers answer {ok:true} with no `written`; treat that as written.
  return { ok: true, written: d2?.written !== false };
}

// ============================
// Room key backfill sweep
// ============================
//
// A member who accepts an invite while no provider is watching this room's
// socket used to end up with no key at all, permanently: delivery was a push
// that nothing retried, and a client holds one room socket at a time, so the
// owner of several rooms was listening to at most one of them.
//
// The sweep replaces that with a pull. The server derives "accepted member with
// no key row" and hands the list to anyone entitled to serve it (owner or
// admin); every provider drains it whenever it is alive and unlocked.
//
// It never prompts. A locked client defers to the unlock trigger instead — an
// automatic background task must not raise a password dialog.

const KEY_SWEEP_MIN_INTERVAL_MS  = 60_000;
const KEY_SWEEP_ERROR_BACKOFF_MS = 5 * 60_000;
const KEY_SWEEP_PAIR_COOLDOWN_MS = 10 * 60_000;
const KEY_SWEEP_TRUST_BLOCK_MS   = 30 * 60_000;
const KEY_SWEEP_MAX_PASSES       = 5;
const KEY_SWEEP_PAGE             = 100;
const KEY_SWEEP_MAX_TRANSIENT    = 3;
const KEY_SWEEP_PAIR_COOLDOWN_CAP = 500;

let __sweepRunning = false;
let __sweepRerunRooms = new Set();
let __sweepNextAllowedTs = 0;
let __sweepTimer = null;
let __sweepPendingRooms = new Set();
let __sweepWantGlobal = false;
const __sweepPairCooldown = new Map();   // "rid:username" -> ts
const __sweepTrustBlocked = new Map();   // username -> {ts, reason, rooms:Set}

function _sweepPairKey(rid, uname) {
  return String(rid) + ":" + String(uname).toLowerCase();
}

function _sweepNotePairCooldown(rid, uname) {
  if (__sweepPairCooldown.size >= KEY_SWEEP_PAIR_COOLDOWN_CAP) {
    // Map preserves insertion order, so the first key is the oldest.
    const oldest = __sweepPairCooldown.keys().next();
    if (!oldest.done) __sweepPairCooldown.delete(oldest.value);
  }
  __sweepPairCooldown.set(_sweepPairKey(rid, uname), Date.now());
}

function _sweepPairOnCooldown(rid, uname) {
  const ts = __sweepPairCooldown.get(_sweepPairKey(rid, uname));
  return !!ts && (Date.now() - ts) < KEY_SWEEP_PAIR_COOLDOWN_MS;
}

function _sweepTrustBlockedFor(uname) {
  const entry = __sweepTrustBlocked.get(String(uname).toLowerCase());
  if (!entry) return false;
  if ((Date.now() - entry.ts) >= KEY_SWEEP_TRUST_BLOCK_MS) {
    __sweepTrustBlocked.delete(String(uname).toLowerCase());
    return false;
  }
  return true;
}

/** Peers the sweep cannot serve until a human verifies their safety number. */
function getKeyShareTrustBlocked() {
  const out = [];
  for (const [uname, entry] of __sweepTrustBlocked.entries()) {
    if ((Date.now() - entry.ts) >= KEY_SWEEP_TRUST_BLOCK_MS) continue;
    out.push({ username: uname, reason: entry.reason, rooms: [...entry.rooms] });
  }
  return out;
}

/** Clear a peer's block once they have been verified. */
function clearKeyShareTrustBlock(uname) {
  __sweepTrustBlocked.delete(String(uname || "").toLowerCase());
}

async function fetchRoomKeyGaps({ roomId = 0, limit = KEY_SWEEP_PAGE } = {}) {
  const token = await requestToken();
  if (!token) throw new Error("No token");

  const qs = new URLSearchParams({ limit: String(limit) });
  if (roomId) qs.set("room_id", String(roomId));

  const r = await fetch(API_BASE + "/crypto/rooms/key-gaps?" + qs.toString(), {
    method: "GET",
    headers: { "Authorization": "Bearer " + token },
  });

  if (r.status === 429) {
    const retryAfter = Number(r.headers.get("Retry-After")) || 120;
    __sweepNextAllowedTs = Date.now() + retryAfter * 1000;
    throw new Error(`Rate limited (retry in ${retryAfter}s)`);
  }

  // Not a provider for this room, or the room is gone. Ordinary members hit
  // this on every membership event; it is an answer, not a failure, and must
  // not trip the error backoff.
  if (r.status === 403 || r.status === 404) {
    return { gaps: [], truncated: false, notProvider: true };
  }

  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail || `key-gaps failed (${r.status})`);

  return {
    gaps: Array.isArray(body.gaps) ? body.gaps : [],
    truncated: !!body.truncated,
  };
}

// Failures that will not change on an immediate retry: the gap is real but we
// cannot close it right now, so cool the pair down instead of spinning.
function _sweepIsPermanentish(msg) {
  return /not a member|not found|re-register|not valid base64|Not owner/i.test(msg);
}

/**
 * Close every room-key gap this account is entitled to close.
 *
 * @param {object} [opts]
 * @param {number} [opts.roomId=0] limit to one room (0 = every servable room)
 * @param {string} [opts.reason] what triggered this, for logs
 * @param {boolean} [opts.interactive=false] allow an unlock prompt. Only ever
 *   true for an explicit user gesture.
 * @returns {Promise<{ran: boolean, shared: number, alreadyHad: number,
 *   skipped: number, failed: number}>} ran=false means the sweep declined to
 *   start (already running, locked, or inside the backoff window).
 */
async function sweepRoomKeyGaps({ roomId = 0, reason = "", interactive = false } = {}) {
  const summary = { ran: false, shared: 0, alreadyHad: 0, skipped: 0, failed: 0 };

  if (__sweepRunning) {
    // 0 means "global"; either way the request is not lost.
    __sweepRerunRooms.add(Number(roomId) || 0);
    return summary;
  }

  const okCrypto = await ensureCryptoReady({ interactive });
  if (!okCrypto) {
    // Locked: defer. The unlock trigger re-enters, no prompt from here.
    return summary;
  }

  if (Date.now() < __sweepNextAllowedTs) return summary;

  __sweepRunning = true;
  summary.ran = true;
  let anyFailure = false;

  try {
    let pass = 0;
    let more = true;

    while (more && pass < KEY_SWEEP_MAX_PASSES) {
      pass += 1;
      more = false;

      let page;
      try {
        page = await fetchRoomKeyGaps({ roomId });
      } catch (e) {
        anyFailure = true;
        console.warn(`[KeySweep] gap fetch failed (${reason}):`, e?.message || e);
        break;
      }

      if (!page.gaps.length) break;

      const byRoom = new Map();
      for (const g of page.gaps) {
        const rid = Number(g?.room_id);
        const uname = String(g?.username || "").trim();
        if (!rid || !uname) continue;
        if (!byRoom.has(rid)) byRoom.set(rid, []);
        byRoom.get(rid).push(uname);
      }

      let transientRun = 0;
      let progressed = false;

      for (const [rid, unames] of byRoom.entries()) {
        // Refresh from the server before sharing: shareRoomKeyToUser only falls
        // back to loadRoomKey when no key is in memory at all, so a key that
        // predates a rotation would otherwise be handed out as current.
        try { await loadRoomKey(rid); } catch { /* share will report it */ }

        for (const uname of unames) {
          if (_sweepTrustBlockedFor(uname) || _sweepPairOnCooldown(rid, uname)) {
            summary.skipped += 1;
            continue;
          }

          try {
            // Fetch the peer key here so the trust check stays off the network
            // and a flaky fetch cannot masquerade as a trust failure.
            const peerPub = await fetchPeerPublicKey(uname);
            await assertPeerKeyTrustedForSharing(uname, "sharing the room key", { peerPublicKeyB64: peerPub });

            const res = await shareRoomKeyToUser(rid, uname, { interactive: false, ifAbsent: true });
            // written:false = another provider won the race. The gap is closed,
            // which is all we wanted — a success, not a failure.
            if (res?.written) {
              summary.shared += 1;
              console.log(`[KeySweep] room ${rid}: key delivered to ${uname} (${reason})`);
            } else {
              summary.alreadyHad += 1;
            }
            progressed = true;
            transientRun = 0;
          } catch (e) {
            const code = e?.code || "";
            const msg = e?.message || String(e);

            if (code === "TRUST_CHANGED" || code === "TRUST_UNVERIFIED") {
              const key = uname.toLowerCase();
              const entry = __sweepTrustBlocked.get(key) || { ts: 0, reason: code, rooms: new Set() };
              entry.ts = Date.now();
              entry.reason = code;
              entry.rooms.add(rid);
              __sweepTrustBlocked.set(key, entry);
              summary.skipped += 1;
              console.warn(`[KeySweep] ${uname} needs verification before key share:`, msg);
              continue;
            }

            summary.failed += 1;
            _sweepNotePairCooldown(rid, uname);

            if (code === "TRUST_UNVERIFIABLE" || !_sweepIsPermanentish(msg)) {
              // Only infrastructure trouble earns the long global backoff. One
              // member with, say, an unusable public key is already cooled down
              // per pair and must not throttle every other room.
              anyFailure = true;
              transientRun += 1;
              console.warn(`[KeySweep] room ${rid}/${uname} transient failure:`, msg);
              if (transientRun >= KEY_SWEEP_MAX_TRANSIENT) {
                console.warn("[KeySweep] too many transient failures, ending pass");
                break;
              }
            } else {
              console.warn(`[KeySweep] room ${rid}/${uname} skipped:`, msg);
            }
          }
        }

        if (transientRun >= KEY_SWEEP_MAX_TRANSIENT) break;
      }

      // Another page is only worth fetching if this one actually shrank the set.
      more = page.truncated && progressed && transientRun < KEY_SWEEP_MAX_TRANSIENT;
    }

  } finally {
    __sweepRunning = false;
    __sweepNextAllowedTs = Date.now() +
      (anyFailure ? KEY_SWEEP_ERROR_BACKOFF_MS : KEY_SWEEP_MIN_INTERVAL_MS);
  }

  if (summary.shared || summary.alreadyHad || summary.skipped || summary.failed) {
    console.log(`[KeySweep] ${reason || "sweep"} done:`, summary);
  }
  try { window.onKeyGapSweepDone?.(summary, getKeyShareTrustBlocked()); } catch {}

  // Triggers that arrived mid-run: re-arm the timer so they are not dropped.
  // The backoff clock set in `finally` still governs when this actually runs.
  if (__sweepRerunRooms.size) {
    const pending = [...__sweepRerunRooms];
    __sweepRerunRooms = new Set();
    for (const r of pending) scheduleRoomKeySweep("rerun", { roomId: r, delayMs: KEY_SWEEP_MIN_INTERVAL_MS });
  }

  return summary;
}

/**
 * The only entry point triggers should use: one timer, one in-flight flag and
 * one backoff clock, so a locked or failing client cannot hammer the endpoint.
 */
function scheduleRoomKeySweep(reason = "", { roomId = 0, delayMs = 0 } = {}) {
  if (roomId) __sweepPendingRooms.add(Number(roomId));
  else __sweepWantGlobal = true;

  if (__sweepTimer) return;

  __sweepTimer = setTimeout(() => {
    __sweepTimer = null;
    const rooms = [...__sweepPendingRooms];
    const wantGlobal = __sweepWantGlobal;
    __sweepPendingRooms = new Set();
    __sweepWantGlobal = false;

    // A global request supersedes the per-room ones queued behind it, and two
    // or more rooms are cheaper to serve as one unfiltered query than as N.
    const only = (!wantGlobal && rooms.length === 1) ? rooms[0] : 0;
    sweepRoomKeyGaps({ roomId: only, reason }).catch((e) => {
      console.warn("[KeySweep] sweep threw:", e?.message || e);
    });
  }, Math.max(0, delayMs));
}

// ============================
// Safety Numbers / Key Verification
// ============================
//
// Safety number = 60-digit code computed from both users' public keys.
// If either key changes, the number changes user can detect MITM.
//
// Known fingerprints are stored in chrome.storage.local:
//   key: "__known_fp_v2:{island}:{myUsername}:{peerUsername}"
//   value: hex fingerprint of peer's public key
//
// When a peer's key changes, we emit a "key_changed" event via window.
//
// The island is part of the address because a username only identifies a
// person within one island: "bob" on one server and "bob" on another are two
// different people. One slot for both means either a false "this key changed"
// warning on an honest peer or, worse, a stranger's key silently inheriting
// the trust the user granted to someone else.

const _knownFpPrefix = "__known_fp_v2:";
const _knownFpPrefixV1 = "__known_fp:";
const _fpMigrationFlag = "__known_fp_migrated_v2";

// Pins written before the address carried an island belong to whichever island
// this client was talking to when it wrote them - it only ever talks to one at
// a time - so they move onto the current one. Reading a pin before this has run
// would find nothing, record the key on offer as the trusted baseline and call
// it first contact, which is exactly the silent downgrade the pins exist to
// prevent. Every reader therefore awaits it, and it runs once per profile.
let _fpPinsReady = null;
function _ensureFpPinsMigrated() {
  if (!_fpPinsReady) _fpPinsReady = _migrateLegacyFpPins();
  return _fpPinsReady;
}

async function _migrateLegacyFpPins() {
  try {
    await __apiBaseReady;
  } catch { /* ISLAND_ID keeps whatever it resolved to */ }
  try {
    const flag = await chrome.storage.local.get([_fpMigrationFlag]);
    if (flag[_fpMigrationFlag]) return;

    const all = await chrome.storage.local.get(null);
    const moved = {};
    const drop = [];
    for (const k of Object.keys(all)) {
      if (!k.startsWith(_knownFpPrefixV1)) continue;
      moved[_knownFpPrefix + ISLAND_ID + ":" + k.slice(_knownFpPrefixV1.length)] = all[k];
      drop.push(k);
    }

    if (drop.length) {
      await chrome.storage.local.set(moved);
      await chrome.storage.local.remove(drop);
      console.log(`[SafetyNumbers] Moved ${drop.length} pin entr(ies) onto island ${ISLAND_ID}`);
    }
    await chrome.storage.local.set({ [_fpMigrationFlag]: true });
  } catch (e) {
    // Fail closed and let the next call retry: an unmigrated pin read as "no
    // pin" would record whatever key is on offer as the trusted baseline. A
    // caller that cannot check trust must not conclude there is nothing to
    // check - every caller of _fpBase either blocks the action or reports
    // "unverified", both of which are safe.
    console.warn("[SafetyNumbers] pin migration failed:", e?.message || e);
    _fpPinsReady = null;
    throw e;
  }
}

/**
 * Address of a pin, given the island the peer's name was read on.
 *
 * For a local peer that is this island and their username. For a cross-island
 * contact it is THEIR island and their kid: their name is not a name here, and
 * the kid is what their contact card bound the keys to.
 */
function _fpBaseOn(island, me, peer) {
  return _knownFpPrefix + String(island).trim().toLowerCase() + ":" +
    String(me).trim().toLowerCase() + ":" + String(peer).trim().toLowerCase();
}

/**
 * Address of a local peer's pin. Async because it waits for the one-time
 * migration above; every caller is already async.
 */
async function _fpBase(me, peer) {
  await _ensureFpPinsMigrated();
  return _fpBaseOn(ISLAND_ID, me, peer);
}

/**
 * Get the safety number for a peer user.
 * Returns { safetyNumber, peerFingerprint, keyChanged }
 *   - safetyNumber: "12345 67890 ..." (60 digits)
 *   - peerFingerprint: hex string
 *   - keyChanged: true if peer's key differs from last known
 */
async function getSafetyNumber(peerUsername) {
  const me = getMeUsername();
  if (!me) throw new Error("Not logged in");
  const peer = String(peerUsername || "").trim();
  if (!peer) throw new Error("No peer username");

  // Get my public key
  const myPub = CM()?.userPublicKeyPem;
  if (!myPub) throw new Error("Own public key not available (crypto locked?)");

  // A cross-island contact is not in this island's key store, and asking it
  // would be the wrong question anyway: their key came from their card, out of
  // band, which is what the number is meant to confirm. Their number is v2 -
  // keyed by kid rather than by names that mean nothing across the border.
  const foreign = (await listForeignContacts())
    .find((c) => String(c.displayName || "").toLowerCase() === peer.toLowerCase());
  if (foreign) {
    return {
      safetyNumber: await CU().computeSafetyNumberV2(myPub, foreign.x25519PubB64),
      peerFingerprint: foreign.kid,
      keyChanged: false,
      v2: true,
    };
  }

  // Get peer's public key from server
  const peerPub = await fetchPeerPublicKey(peer);

  // Compute safety number
  const safetyNumber = await CU().computeSafetyNumber(me, myPub, peer, peerPub);

  // Compute peer fingerprint
  const peerFp = await CU().fingerprintPublicKey(peerPub);

  // Check if key changed vs known
  const storageKey = await _fpBase(me, peer);
  let keyChanged = false;
  try {
    const stored = await chrome.storage.local.get([storageKey]);
    const knownFp = stored[storageKey] || null;

    if (!knownFp) {
      // First time we see this peer — TOFU. Safe to record the current FP
      // as the baseline.
      await chrome.storage.local.set({ [storageKey]: peerFp });
    } else if (knownFp !== peerFp) {
      // Silent migration from legacy (bugged) fingerprint format.
      // If the stored value matches the legacy hash of the same key,
      // treat it as an upgrade, not a key change.
      const legacyFp = await CU()._fingerprintPublicKeyLegacy(peerPub);
      if (knownFp === legacyFp) {
        // Same key, just upgrade the stored hash format.
        await chrome.storage.local.set({ [storageKey]: peerFp });
      } else {
        // Real key change. Do NOT overwrite the known FP — otherwise the
        // next call would see equal FPs and report keyChanged:false, and
        // the user only gets one chance to see the warning.
        // Park the new FP under :pending and let markKeyVerified() promote
        // it explicitly when the user confirms.
        keyChanged = true;
        await chrome.storage.local.set({ [storageKey + ":pending"]: peerFp });
        await _resetKeyVerification(peer);
      }
    }
  } catch (e) {
    console.warn("Safety number storage error:", e);
  }

  return { safetyNumber, peerFingerprint: peerFp, keyChanged };
}

/**
 * Mark a peer's current key as verified (trusted).
 * Called when user clicks "I verified this" in UI.
 */
async function markKeyVerified(peerUsername) {
  const me = getMeUsername();
  if (!me || !peerUsername) return;
  const peer = String(peerUsername).trim().toLowerCase();
  const storageKey = await _fpBase(me, peer);

  // Re-fetch and store current fingerprint. This is the *only* place that's
  // allowed to advance the known fingerprint after a real key change —
  // getSafetyNumber / checkPeerKeyChanged park new FPs under :pending.
  try {
    const peerPub = await fetchPeerPublicKey(peerUsername);
    const peerFp = await CU().fingerprintPublicKey(peerPub);
    await chrome.storage.local.set({
      [storageKey]: peerFp,
      [storageKey + ":verified"]: true,
      [storageKey + ":ts"]: Date.now(),
    });
    await chrome.storage.local.remove([
      storageKey + ":changed",
      storageKey + ":pending",
    ]);
    // The sweep refuses to share to a peer it flagged; verifying is exactly the
    // human step it was waiting for, so let the next sweep serve them.
    clearKeyShareTrustBlock(peer);
    scheduleRoomKeySweep("verified");
    return true;
  } catch (e) {
    console.warn("markKeyVerified error:", e);
    return false;
  }
}

/**
 * Check if a peer's key was previously verified by the user.
 */
async function isKeyVerified(peerUsername) {
  const me = getMeUsername();
  if (!me || !peerUsername) return false;
  const peer = String(peerUsername).trim().toLowerCase();
  const storageKey = (await _fpBase(me, peer)) + ":verified";
  try {
    const stored = await chrome.storage.local.get([storageKey]);
    return !!stored[storageKey];
  } catch {
    return false;
  }
}

/**
 * Reset verification status for a peer (called when key change detected).
 */
async function _resetKeyVerification(peerUsername) {
  const me = getMeUsername();
  if (!me || !peerUsername) return;
  const peer = String(peerUsername).trim().toLowerCase();
  const base = await _fpBase(me, peer);
  try {
    await chrome.storage.local.remove([base + ":verified", base + ":ts"]);
    // Persist a "key changed, needs re-verification" flag so that assertPeerKeyTrustedForSharing
    // keeps blocking even after the stored fingerprint has been updated.
    await chrome.storage.local.set({ [base + ":changed"]: true });
  } catch {}
}

// ============================
// Key Change Notifications (Step 5)
// ============================
//
// Proactively checks peer public keys against stored fingerprints.
// When a change is detected:
//   1. Resets verification status
//   2. Stores the new fingerprint
//   3. Dispatches a window event "peer_key_changed"
//   4. Returns info so the caller can show a chat warning
//
// Caching: each peer is checked at most once per _KC_CHECK_TTL_MS
// to avoid hammering the server on every message.

const _KC_CHECK_TTL_MS = 5 * 60 * 1000; // 5 min between re-checks per peer
const _kcLastChecked = new Map(); // peerUsername(lower) -> timestamp
const _kcAlerted = new Set();     // peerUsername(lower) already alerted in this session

/**
 * Check whether a single peer's public key fingerprint has changed
 * compared to what we have stored locally.
 *
 * Returns:
 *   { changed: true,  username }   key differs from stored fingerprint
 *   { changed: false, username }   same key or first time seeing this peer
 *   null                           skipped (cooldown unless force / crypto not ready / self)
 */
async function checkPeerKeyChanged(peerUsername, { force = false, peerPublicKeyB64 = null } = {}) {
  const me = getMeUsername();
  if (!me) return null;
  const peer = String(peerUsername || "").trim();
  if (!peer || peer.toLowerCase() === me.toLowerCase()) return null;

  // A cross-island contact is not a user here. Their key came from their
  // contact card and is pinned against their island, so this island's key
  // server has nothing to say about them - asking only produces a 404 per
  // message and a warning about a missing public key.
  try {
    const foreign = await listForeignContacts();
    if (foreign.some((c) => String(c.displayName || "").toLowerCase() === peer.toLowerCase())) {
      return null;
    }
  } catch { /* fall through to the normal check */ }

  // Cooldown: avoid hammering unless caller explicitly requests fresh verification.
  const peerLower = peer.toLowerCase();
  const now = Date.now();
  const lastTs = _kcLastChecked.get(peerLower) || 0;
  if (!force && (now - lastTs < _KC_CHECK_TTL_MS)) return null;
  _kcLastChecked.set(peerLower, now);

  // Need crypto to be ready (at least public key available)
  if (!isCryptoUsable()) return null;

  try {
    const peerPub = String(peerPublicKeyB64 || "").trim() || await fetchPeerPublicKey(peer);
    const peerFp = await CU().fingerprintPublicKey(peerPub);

    const storageKey = await _fpBase(me, peerLower);
    const stored = await chrome.storage.local.get([storageKey]);
    const knownFp = stored[storageKey] || null;

    if (!knownFp) {
      // First time we see this peer — store fingerprint and fire TOFU event for UI
      await chrome.storage.local.set({ [storageKey]: peerFp });
      try {
        window.dispatchEvent(new CustomEvent("peer_key_first_seen", {
          detail: { username: peer, fingerprint: peerFp }
        }));
      } catch {}
      return { changed: false, first: true, username: peer };
    }

    if (knownFp === peerFp) {
      // Same key — clear any stale :changed flag (e.g. key reverted after a DB rollback)
      try { await chrome.storage.local.remove([storageKey + ":changed"]); } catch {}
      return { changed: false, username: peer };
    }

    // Silent migration from legacy (bugged) fingerprint format.
    // If the stored value matches the legacy hash of the same key,
    // it's the same key — just upgrade the stored format and move on.
    const legacyFp = await CU()._fingerprintPublicKeyLegacy(peerPub);
    if (knownFp === legacyFp) {
      try {
        await chrome.storage.local.set({ [storageKey]: peerFp });
        await chrome.storage.local.remove([storageKey + ":changed"]);
      } catch {}
      return { changed: false, username: peer };
    }

    // *** KEY CHANGED ***
    // 1) Park the new FP as :pending. Do NOT overwrite the known FP —
    //    that would mask the warning on subsequent calls.
    await chrome.storage.local.set({ [storageKey + ":pending"]: peerFp });

    // 2) Reset verification status
    await _resetKeyVerification(peer);

    // 3) Dispatch window event for UI layer
    try {
      window.dispatchEvent(new CustomEvent("peer_key_changed", {
        detail: { username: peer, oldFingerprint: knownFp, newFingerprint: peerFp }
      }));
    } catch {}

    return { changed: true, username: peer };
  } catch (e) {
    console.warn("checkPeerKeyChanged failed for", peer, ":", e?.message || e);
    return null;
  }
}

/**
 * Batch-check multiple peers' keys (e.g. all online users in a room).
 * Returns array of usernames whose keys have changed.
 * Checks are done in parallel but with the per-peer cooldown respected.
 */
async function checkRoomPeersKeyChanges(usernames) {
  if (!Array.isArray(usernames) || !usernames.length) return [];
  if (!isCryptoUsable()) return [];

  const results = await Promise.allSettled(
    usernames.map(u => checkPeerKeyChanged(u))
  );

  const changed = [];
  for (const r of results) {
    if (r.status === "fulfilled" && r.value?.changed) {
      changed.push(r.value.username);
    }
  }
  return changed;
}

/**
 * Check a single peer and, if key changed AND not yet alerted this session,
 * return the username. Otherwise return null.
 * This is the main entry point for per-message checks.
 */
async function checkAndAlertKeyChange(peerUsername) {
  const peerLower = String(peerUsername || "").trim().toLowerCase();
  if (!peerLower) return null;

  // Already alerted this session, skip
  if (_kcAlerted.has(peerLower)) return null;

  const result = await checkPeerKeyChanged(peerUsername);
  if (result?.changed) {
    _kcAlerted.add(peerLower);
    return result.username;
  }
  return null;
}

/**
 * Clear the "already alerted" set AND cooldown cache
 * (e.g. when switching rooms, or for testing).
 */
function resetKeyChangeAlerts() {
  _kcAlerted.clear();
  _kcLastChecked.clear();
}

// Expose for UI
window.__safetyNumbers = {
  getSafetyNumber,
  markKeyVerified,
  isKeyVerified,
};

// Expose key change checking for panel.js / panel-ui.js
window.__keyChangeNotifications = {
  checkPeerKeyChanged,
  checkRoomPeersKeyChanges,
  checkAndAlertKeyChange,
  resetKeyChangeAlerts,
};

safePost({ type: "auth_get" });

window.__panelCryptoReady = true;
try { window.dispatchEvent(new Event("ws_crypto_ready")); } catch {}

// ============================
// Cross-island contacts
// ============================
//
// A contact on another island is reached through two mailboxes: one this
// client opened at home for their key, which is where their messages arrive,
// and one they opened for us on their island, which is where ours go. See
// foreign-dm.js for the protocol and
// docs/internal/cross-island-dm-assessment.md for why it is shaped this way.
//
// Everything below is panel-side on purpose. The worker addresses one island;
// these requests address another, and the delivery secret for it is held by
// this client rather than by either server.

const FD = () => globalThis.WSForeignDm || null;

// thread id -> contact, for the decrypt path: it runs per message and must not
// read storage to find out whether a thread is a cross-island one.
const _foreignThreadCache = new Map();

/**
 * The cross-island contact a thread belongs to, if any.
 *
 * Warms from storage on a miss rather than trusting the cache to be populated.
 * Decryption can run before anything has listed the contacts - history arrives
 * as soon as the thread opens - and a miss there is not harmless: the verifier
 * falls back to asking THIS island for the sender's key, gets a 404 because
 * the sender has no account here, and marks an honest message unverified.
 */
async function _foreignForThread(threadId) {
  const tid = Number(threadId);
  if (!tid) return null;
  if (_foreignThreadCache.has(tid)) return _foreignThreadCache.get(tid);
  try { await listForeignContacts(); } catch { /* stay with what we have */ }
  return _foreignThreadCache.get(tid) || null;
}

function _foreignDeps() {
  const cu = CU();
  return {
    fetchJson: async (url, opts = {}) => {
      const r = await fetch(url, opts);
      let body = null;
      try { body = await r.json(); } catch { /* empty body */ }
      return { ok: r.ok, status: r.status, body };
    },
    sign: async (bytes) => {
      const seed = CM()?.ed25519Seed;
      if (!seed) throw new Error("Locked: no signing key");
      return _u8FromB64url(await cu.ed25519Sign(seed, bytes));
    },
    verify: (pub, sig, msg) => cu.ed25519Verify(pub, sig, msg),
    sha256: async (bytes) => new Uint8Array(await cu.sha256Raw(bytes)),
    hmacSha256: async (keyBytes, msgBytes) => {
      const k = await crypto.subtle.importKey(
        "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
      );
      return new Uint8Array(await crypto.subtle.sign("HMAC", k, msgBytes));
    },
    randomBytes: (n) => crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
    // The relay answers with bytes, not JSON: the answer is sealed so the
    // relay cannot fake a delivery it did not make.
    fetchBytes: async (url, opts = {}) => {
      const r = await fetch(url, opts);
      let bytes = null;
      try { bytes = new Uint8Array(await r.arrayBuffer()); } catch { /* no body */ }
      return { ok: r.ok, status: r.status, bytes };
    },
    sealRelay: (transportKeyB64, inner) => cu.sealRelayEnvelope(transportKeyB64, inner),
    openRelayResponse: (key, bytes) => cu.openRelayResponse(key, bytes),
  };
}

function _u8FromB64url(s) {
  let b64 = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
  b64 += "=".repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function _b64FromU8(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

const _FOREIGN_INDEX = "__foreign_index:";

/**
 * Wait until the active island is known.
 *
 * Every contact is filed under it, so anything that reads or writes one before
 * `server_config` has been applied looks in the wrong drawer: it finds nothing
 * and concludes there are no cross-island contacts. That conclusion is not
 * harmless - it is what sends a foreign thread down the local key path.
 */
async function _islandSettled() {
  try { await __apiBaseReady; } catch { /* keep whatever we resolved to */ }
}

function _foreignIndexKey() {
  return _FOREIGN_INDEX + ISLAND_ID + ":" + String(getMeUsername() || "").toLowerCase();
}

/** Every cross-island contact this account has on this island. */
async function listForeignContacts() {
  await _islandSettled();
  try {
    // Reading the list is also how the decrypt path learns which threads are
    // foreign: the panel lists contacts before it can open one.

    const idxKey = _foreignIndexKey();
    const stored = await chrome.storage.local.get([idxKey]);
    const kids = Array.isArray(stored[idxKey]) ? stored[idxKey] : [];
    if (!kids.length) return [];
    const keys = kids.map((kid) => FD().contactKey(ISLAND_ID, getMeUsername(), kid));
    const blobs = await chrome.storage.local.get(keys);
    const out = keys.map((k) => blobs[k]).filter(Boolean);
    for (const c of out) _foreignThreadCache.set(foreignThreadId(c), c);
    return out;
  } catch (e) {
    console.warn("[Foreign] list failed:", e?.message || e);
    return [];
  }
}

async function getForeignContact(peerKid) {
  await _islandSettled();
  const key = FD().contactKey(ISLAND_ID, getMeUsername(), peerKid);
  const stored = await chrome.storage.local.get([key]);
  return stored[key] || null;
}

async function saveForeignContact(contact) {
  await _islandSettled();
  const key = FD().contactKey(ISLAND_ID, getMeUsername(), contact.kid);
  const idxKey = _foreignIndexKey();
  const stored = await chrome.storage.local.get([idxKey]);
  const kids = Array.isArray(stored[idxKey]) ? stored[idxKey] : [];
  if (!kids.includes(contact.kid)) kids.push(contact.kid);
  await chrome.storage.local.set({ [key]: contact, [idxKey]: kids });
}

/** The thread a foreign contact's conversation is displayed under. */
function foreignThreadId(contact) {
  return Number(contact?.inbox?.threadId || 0);
}

async function isForeignThread(threadId) {
  const tid = Number(threadId);
  if (!tid) return null;
  const all = await listForeignContacts();
  return all.find((c) => foreignThreadId(c) === tid) || null;
}

/**
 * The card this user hands to somebody on another island, out of band.
 *
 * It carries the island's signed entry points so the other side can reach this
 * island without being told where by a third party, and it is signed by this
 * user's own key, so nothing in it has to be taken on the island's word.
 */
async function buildMyContactBlobText() {
  const me = getMeUsername();
  const myPub = CM()?.userPublicKeyPem;
  if (!me || !myPub) throw new Error("Unlock first");

  const cu = CU();
  const kid = await cu.fingerprintPublicKey(myPub);
  const seed = CM()?.ed25519Seed;
  if (!seed) throw new Error("Unlock first");
  const edPub = _b64FromU8(await cu.ed25519GetPublicKey(seed));

  let islandId = ISLAND_ID;
  let signingKey = "";
  let entryPoints = [{ apiBase: API_BASE, wsBase: API_BASE.replace(/^http/, "ws"), label: "" }];
  try {
    const r = await fetch(API_BASE + "/.well-known/wsapp-island");
    if (r.ok) {
      const doc = await r.json();
      if (doc?.payload?.island_id) {
        islandId = doc.payload.island_id;
        signingKey = doc.signing_key_b64 || "";
        if (Array.isArray(doc.payload.entry_points) && doc.payload.entry_points.length) {
          entryPoints = doc.payload.entry_points;
        }
      }
    }
  } catch {
    // An island that publishes no list still works: the card then carries the
    // address this client is actually using, which is what the peer needs.
  }

  const blob = await FD().buildContactBlob(
    { kid, x25519PubB64: myPub, ed25519PubB64: edPub, displayName: me },
    { islandId, signingKeyB64: signingKey, entryPoints },
    _foreignDeps().sign,
  );
  return JSON.stringify(blob);
}

/**
 * Take somebody's card, open a mailbox for them here, and pin their keys.
 *
 * Opening the mailbox IS the consent: until this runs, nothing on this island
 * will accept a message addressed to this user from that key.
 */
async function addForeignContact(blobText) {
  const me = getMeUsername();
  if (!me) throw new Error("Not logged in");
  await ensureCryptoReady({ interactive: true, reason: "Add contact" });

  let blob;
  try {
    blob = JSON.parse(String(blobText || "").trim());
  } catch {
    throw new Error("That does not look like a contact card");
  }

  const seen = await FD().verifyContactBlob(blob, _foreignDeps());
  if (!seen.ok) throw new Error(`Card rejected: ${seen.reason}`);
  const c = seen.contact;

  // Delivering to their island means fetching a host this extension was never
  // granted. The request has to happen while the click that opened this dialog
  // still counts as a gesture, which is why it is here and not at send time.
  await _requestForeignOrigins(c.entryPoints);

  if (c.kid === await CU().fingerprintPublicKey(CM().userPublicKeyPem)) {
    throw new Error("That is your own card");
  }

  const token = await requestToken();
  if (!token) throw new Error("No token");

  // The key their messages to us will be encrypted with. We generate it
  // because we own the mailbox; they receive it when they claim.
  const cu = CU();
  const keyB64 = await cu.exportRoomKey(await cu.generateRoomKey(true));
  const keyId = await cu.fingerprintRoomKeyBase64(keyB64);

  const created = await fetch(API_BASE + "/foreign/box", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({
      peer_kid: c.kid,
      peer_x25519_pub: c.x25519PubB64,
      peer_ed25519_pub: c.ed25519PubB64,
      label: c.displayName,
      encrypted_thread_key: await cu.encryptRoomKeyForUser(CM().userPublicKeyPem, keyB64),
      key_id: keyId,
    }),
  });
  const createdBody = await created.json().catch(() => ({}));
  if (!created.ok) throw new Error(createdBody.detail || `Could not open mailbox (${created.status})`);
  const threadId = Number(createdBody.thread_id);

  const wrapped = await fetch(API_BASE + `/foreign/box/${threadId}/peer-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({
      peer_kid: c.kid,
      peer_x25519_pub: c.x25519PubB64,
      peer_ed25519_pub: c.ed25519PubB64,
      encrypted_thread_key: await cu.encryptRoomKeyForUser(c.x25519PubB64, keyB64),
      key_id: keyId,
    }),
  });
  if (!wrapped.ok) throw new Error(`Could not leave the key for them (${wrapped.status})`);

  // Pin both halves of their identity, on their island rather than ours: the
  // name means nothing here, and the kid is what the card bound the keys to.
  await chrome.storage.local.set({
    [_fpBaseOn(c.islandId, me, c.kid)]: c.kid,
    [_fpBaseOn(c.islandId, me, c.kid) + ":ed"]: c.ed25519PubB64,
  });

  const contact = {
    v: 1,
    kid: c.kid,
    displayName: c.displayName || c.kid.slice(0, 8),
    x25519PubB64: c.x25519PubB64,
    ed25519PubB64: c.ed25519PubB64,
    island: { islandId: c.islandId, signingKeyB64: c.islandSigningKeyB64, entryPoints: c.entryPoints },
    inbox: { threadId, keyB64, keyId },
    outbox: null,
    addedAt: Date.now(),
  };
  await saveForeignContact(contact);

  // Their mailbox may not exist yet - they add us in their own time - so a
  // failure here is normal and retried whenever the conversation is opened.
  try {
    await claimForeignOutbox(contact);
  } catch (e) {
    console.log("[Foreign] outbox not claimable yet:", e?.message || e);
  }
  return await getForeignContact(c.kid);
}

/**
 * Collect the address, delivery secret and thread key of the mailbox this
 * contact opened for us on their island.
 */
async function claimForeignOutbox(contact, { retried = false } = {}) {
  const cu = CU();
  const myKid = await cu.fingerprintPublicKey(CM().userPublicKeyPem);
  const bases = (contact.island?.entryPoints || []).map((e) => e.apiBase).filter(Boolean);
  if (!bases.length) throw new Error("Contact card carries no address");

  let last = null;
  for (const base of bases) {
    // An address that cannot be reached at all - blocked by the extension's
    // CSP, dead host, wrong scheme - throws rather than answering. Letting
    // that escape would abandon the remaining entry points, which is the whole
    // reason a card carries more than one.
    let r;
    try {
      r = await FD().claimMailbox(_foreignDeps(), base, myKid);
    } catch (e) {
      console.warn(`[Foreign] ${base} unreachable:`, e?.message || e);
      last = { status: 0 };
      continue;
    }
    if (r.ok) {
      let keyB64 = null;
      if (r.encryptedThreadKey) {
        try {
          keyB64 = await cu.decryptRoomKeyForUser(CM().userPrivateKey, r.encryptedThreadKey);
        } catch (e) {
          console.warn("[Foreign] their key did not unwrap:", e?.message || e);
        }
      }
      const updated = {
        ...contact,
        lastClaim: null,
        outbox: {
          apiBase: base,
          threadId: r.threadId,
          secretB64: r.deliverySecretB64,
          expiresAt: r.expiresAt,
          keyB64,
          keyId: r.keyId,
        },
      };
      await saveForeignContact(updated);
      return updated;
    }
    last = r;
    // 403 is the island's single answer to every refusal, including "no
    // mailbox here yet". Trying the next entry point is still worth it: this
    // one may simply be unreachable.
  }

  // Remember why, so the contact can say which of the two it was. They need
  // different things from the user - wait for the other person, or fix the
  // address - and until now both showed the same "waiting for them" line.
  // Every address we know either refused us or did not answer. Before calling
  // it a failure, ask their island for its current list - that is the case the
  // signed list exists for, and the pin from their card is what makes the
  // answer safe to believe.
  if (!retried) {
    const moved = await refreshForeignIsland(contact, { force: true }).catch(() => ({ ok: false }));
    if (moved.ok && moved.changed) {
      const fresh = await getForeignContact(contact.kid);
      if (fresh) return await claimForeignOutbox(fresh, { retried: true });
    }
  }

  const failure = {
    at: Date.now(),
    status: last?.status ?? null,
    kind: (last?.status === 403) ? "not-added-yet"
      : (last?.status === 0 || last?.status == null) ? "unreachable"
      : "refused",
  };
  try { await saveForeignContact({ ...contact, lastClaim: failure }); } catch { /* best effort */ }
  throw new Error(
    failure.kind === "not-added-yet"
      ? "They have not added your card yet"
      : `Could not reach their server (${last?.status || "no answer"})`,
  );
}

/**
 * Put both directions' keys where decryption will find them.
 *
 * The conversation holds ciphertext under two keys - theirs for what they
 * wrote, ours for the copies we kept - and every message names the key it used,
 * so both simply go into the same slot's archive.
 */
async function ensureForeignKeysReady(contact) {
  _foreignThreadCache.set(foreignThreadId(contact), contact);
  const rid = dmRid(foreignThreadId(contact));
  const cm = CM();
  if (!cm) throw new Error("Locked");

  if (contact.inbox?.keyB64) {
    await cm.loadRoomKey(rid, contact.inbox.keyB64);
    if (contact.inbox.keyId) {
      await cm.loadArchivedKey(rid, contact.inbox.keyId, contact.inbox.keyB64);
    }
  }
  if (contact.outbox?.keyB64 && contact.outbox?.keyId) {
    await cm.loadArchivedKey(rid, contact.outbox.keyId, contact.outbox.keyB64);
  }
  await saveRoomKeyArchive(rid);
}

/**
 * Encrypt for a cross-island contact and deliver it twice: to their island,
 * which is where they will read it, and to ours, so our own outgoing messages
 * survive a reinstall. Both copies are the same ciphertext under their
 * mailbox's key.
 */
async function sendForeignMessage(contact, plaintext) {
  let c = contact;
  if (!c.outbox || !c.outbox.keyB64) c = await claimForeignOutbox(c);
  if (!c.outbox?.keyB64) throw new Error("No key for this contact yet");

  const cu = CU();
  const me = getMeUsername();
  const seed = CM()?.ed25519Seed;
  const envelope = { ss: 1, from: me, body: plaintext };
  if (seed) {
    envelope.sig = await cu.ed25519Sign(
      seed, cu._dmSigMessage(c.outbox.threadId, me, plaintext),
    );
  }

  // Built by hand rather than through CM().encryptMessage, because that
  // encrypts with the key in the slot - the inbox key - and this has to go out
  // under the mailbox key of the island it is addressed to. The shape must
  // match the manager's byte for byte: `encrypted: true` is what the receiving
  // panel keys on, and the kid is bound as AAD, so a message cannot be
  // re-labelled with another key's id.
  const key = await cu.importRoomKey(c.outbox.keyB64);
  const kid = c.outbox.keyId || await cu.fingerprintRoomKeyBase64(c.outbox.keyB64);
  const aad = new TextEncoder().encode(String(kid));
  const enc = await cu.encryptMessage(key, JSON.stringify(envelope), aad);
  const ciphertext = JSON.stringify({
    encrypted: true, iv: enc.iv, data: enc.data, kid, aad_v1: true,
  });

  const box = () => ({
    apiBase: c.outbox.apiBase,
    threadId: c.outbox.threadId,
    secretB64: c.outbox.secretB64,
  });

  let res;
  try {
    res = c.useRelay
      ? await deliverForeignViaRelay(c, box(), ciphertext)
      : await FD().deliver(_foreignDeps(), box(), ciphertext);
  } catch (e) {
    // Their island did not answer at all. Nothing about this message is wrong,
    // so it goes in the queue rather than being announced as a failure.
    res = { ok: false, status: 0, nonceB64: null, transport: e?.message || "unreachable" };
  }

  // A delivery secret lasts a day. An expired one is refused with the same
  // 403 as everything else, so re-claim once before believing it.
  if (!res.ok && (res.status === 403 || res.status === 401)) {
    try {
      c = await claimForeignOutbox(c);
      res = await FD().deliver(_foreignDeps(), box(), ciphertext);
    } catch { /* fall through to the queue */ }
  }

  // Our own copy goes to our own island either way: if that is unreachable,
  // the user is looking at a client that cannot do anything at all, which is
  // the case the queue is explicitly NOT for.
  safePost({ type: "dm_send", thread_id: foreignThreadId(c), text: ciphertext });

  if (res.ok) {
    // A successful send is also the best moment to try whatever is waiting:
    // their island is evidently up.
    drainForeignOutbox().catch(() => {});
    return { ok: true };
  }

  const ob = foreignOutbox();
  if (ob && (res.status === 0 || res.status === 429 || res.status >= 500)) {
    await ob.enqueue({
      threadId: c.outbox.threadId,
      // The envelope as it goes on the wire. deliver() encodes it; the field
      // name is the queue's, and it never looks inside.
      ciphertextB64: ciphertext,
      nonceB64: res.nonceB64 || FD()._b64url(_foreignDeps().randomBytes(16)),
      meta: { kid: c.kid },
    });
    return { ok: false, queued: true };
  }

  throw new Error(`Delivery refused (${res.status})`);
}

/**
 * Forget a cross-island contact and close the mailbox their messages arrive
 * in. Closing the mailbox is what actually stops them: the delivery secret
 * they hold opens nothing once the box is gone.
 */
async function removeForeignContact(peerKid) {
  const contact = await getForeignContact(peerKid);
  if (!contact) return false;

  const token = await requestToken();
  if (token && foreignThreadId(contact)) {
    const r = await fetch(API_BASE + `/foreign/box/${foreignThreadId(contact)}`, {
      method: "DELETE",
      headers: { Authorization: "Bearer " + token },
    });
    // A mailbox already gone is the state we wanted; anything else is a real
    // failure and must not leave the local half pointing at a live box.
    if (!r.ok && r.status !== 404) throw new Error(`Could not close the mailbox (${r.status})`);
  }

  const key = FD().contactKey(ISLAND_ID, getMeUsername(), peerKid);
  const idxKey = _foreignIndexKey();
  const stored = await chrome.storage.local.get([idxKey]);
  const kids = (Array.isArray(stored[idxKey]) ? stored[idxKey] : []).filter((k) => k !== peerKid);
  await chrome.storage.local.set({ [idxKey]: kids });
  await chrome.storage.local.remove([key]);
  _foreignThreadCache.delete(foreignThreadId(contact));
  return true;
}

/**
 * Ask for host access to a contact's island.
 *
 * Chrome gates fetch on host permissions but not WebSocket, so skipping this
 * yields a client that looks connected and fails every delivery - the same
 * trap the entry-point work documented for the worker.
 */
async function _requestForeignOrigins(entryPoints) {
  const origins = [];
  for (const ep of entryPoints || []) {
    try {
      const u = new URL(ep.apiBase);
      if (u.protocol !== "https:") continue;   // http is refused by the CSP anyway
      origins.push(u.origin + "/*");
    } catch { /* skip an address we cannot parse */ }
  }
  if (!origins.length) return true;
  try {
    if (await chrome.permissions.contains({ origins })) return true;
    const granted = await chrome.permissions.request({ origins });
    if (!granted) {
      throw new Error("Access to their server was declined, so nothing could be delivered there");
    }
    return true;
  } catch (e) {
    if (e && /declined/.test(e.message || "")) throw e;
    // Older Chrome, or a call outside a gesture: let the delivery attempt be
    // what reports the problem rather than blocking the contact here.
    console.warn("[Foreign] permission request failed:", e?.message || e);
    return false;
  }
}

// ============================
// Cross-island outbox
// ============================
//
// Until now a cross-island message that could not be delivered was lost: the
// send threw, an alert appeared, and the input box was cleared anyway. Your own
// island being down is something you notice immediately, because nothing else
// works either. Somebody else's island being down looks like nothing at all -
// you are online, your server is fine, and the message is simply gone.
//
// outbox.js holds the queue and decides what each failure means; this is the
// part that knows where a message was going and how to say it again.

const _OUTBOX_KEY_PREFIX = "__foreign_outbox:";

function _outboxKey() {
  return _OUTBOX_KEY_PREFIX + ISLAND_ID + ":" + String(getMeUsername() || "").toLowerCase();
}

let _foreignOutbox = null;

function foreignOutbox() {
  if (_foreignOutbox) return _foreignOutbox;
  const OB = globalThis.WSOutbox;
  if (!OB) return null;
  _foreignOutbox = OB.createOutbox({
    storage: {
      load: async () => {
        const key = _outboxKey();
        const got = await chrome.storage.local.get([key]);
        return Array.isArray(got[key]) ? got[key] : [];
      },
      save: async (items) => {
        await chrome.storage.local.set({ [_outboxKey()]: items });
      },
    },
    now: () => Date.now(),
    log: (msg, data) => console.log("[Outbox]", msg, data || ""),
  });
  return _foreignOutbox;
}

/**
 * Try every queued message that is due.
 *
 * The nonce is the item's, never a fresh one: the island de-duplicates on
 * (thread_id, nonce), which is what makes repeating a message that already
 * arrived answer 409 instead of delivering it twice.
 */
async function drainForeignOutbox() {
  const ob = foreignOutbox();
  if (!ob) return null;
  try {
    return await ob.drain(async (item) => {
      const kid = item?.meta?.kid;
      const contact = kid ? await getForeignContact(kid) : null;
      if (!contact) return { status: 400 };          // the contact is gone; drop it

      let c = contact;
      if (!c.outbox?.secretB64 || item.secretRefreshed) {
        try { c = await claimForeignOutbox(c); } catch { return { status: 0 }; }
      }
      if (!c.outbox?.secretB64) return { status: 0 };

      try {
        return await FD().deliver(
          _foreignDeps(),
          { apiBase: c.outbox.apiBase, threadId: c.outbox.threadId, secretB64: c.outbox.secretB64 },
          item.ciphertextB64,
          { nonce: _u8FromB64url(item.nonceB64) },
        );
      } catch (e) {
        // Unreachable rather than refused: keep it and back off.
        return { name: e?.name || "TypeError" };
      }
    });
  } catch (e) {
    console.warn("[Outbox] drain failed:", e?.message || e);
    return null;
  }
}

/** How many messages are still waiting, for the UI. */
async function foreignOutboxSize() {
  const ob = foreignOutbox();
  if (!ob) return 0;
  try { return await ob.size(); } catch { return 0; }
}

// ============================
// Keeping a contact's island reachable
// ============================
//
// A contact card freezes the addresses of the other island at the moment it
// was handed over. Islands move: a domain changes, a bridge is added, the one
// address in the card stops answering - and the contact is then lost for good,
// with no way back except meeting again in person.
//
// The card carries the island's signing key precisely so that need not happen.
// The island publishes a signed list of its own entry points; the key pinned
// from the card says whether a list we are handed is really theirs. So the
// addresses can be refreshed without trusting whoever answered.

const _ISLAND_RECHECK_MS = 6 * 60 * 60 * 1000;

function _islandVerifier() {
  const IL = globalThis.WSIslandList;
  if (!IL) return null;
  return IL.createIslandListVerifier({
    ed25519Verify: (pub, sig, msg) => CU().ed25519Verify(pub, sig, msg),
    b64decode: (s) => _u8FromB64url(s),
    utf8Encode: (s) => new TextEncoder().encode(s),
    now: () => Date.now(),
  });
}

/**
 * Ask a contact's island where it lives now, and believe the answer only if it
 * is signed by the key their card pinned.
 *
 * @param {object} contact
 * @param {object} [opts] { force } - skip the recheck interval
 * @returns {Promise<{ok:boolean, reason?:string, changed?:boolean}>}
 */
async function refreshForeignIsland(contact, { force = false } = {}) {
  const verifier = _islandVerifier();
  if (!verifier) return { ok: false, reason: "verifier unavailable" };

  const last = Number(contact.island?.lastCheckedAt || 0);
  if (!force && last && Date.now() - last < _ISLAND_RECHECK_MS) {
    return { ok: true, reason: "checked recently", changed: false };
  }

  // The pin starts as what the card said. `version: 0` because the card does
  // not carry one - the first list we verify sets the floor for every later
  // one, and the verifier refuses anything older afterwards.
  const pin = contact.island?.pin || {
    signingKeyB64: contact.island?.signingKeyB64 || "",
    islandId: contact.island?.islandId || "",
    version: 0,
  };
  if (!pin.signingKeyB64) return { ok: false, reason: "card carried no signing key" };

  const bases = [];
  if (contact.outbox?.apiBase) bases.push(contact.outbox.apiBase);
  for (const e of contact.island?.entryPoints || []) {
    if (e.apiBase && !bases.includes(e.apiBase)) bases.push(e.apiBase);
  }

  let lastReason = "unreachable";
  for (const base of bases) {
    let doc;
    try {
      const r = await fetch(String(base).replace(/\/+$/, "") + "/.well-known/wsapp-island");
      if (!r.ok) { lastReason = `http ${r.status}`; continue; }
      doc = await r.json();
    } catch (e) {
      lastReason = "unreachable";
      continue;
    }

    const res = await verifier.verify(doc, pin);
    if (!res.ok) {
      // Signed by the wrong key, or a replay of an older list. Not a network
      // problem and not something to shop around for at the next address: an
      // island that answers with somebody else's signature is exactly what the
      // pin exists to catch.
      console.warn(`[Foreign] ${base} served a list we cannot trust: ${res.reason}`);
      lastReason = res.reason;
      if (res.reason === "bad signature" || res.reason === "different island" || res.reason === "rollback") {
        return { ok: false, reason: res.reason };
      }
      continue;
    }

    const fresh = res.payload.entryPoints.map((e) => ({
      apiBase: e.apiBase, wsBase: e.wsBase || "", label: e.label || "",
    }));
    const before = (contact.island?.entryPoints || []).map((e) => e.apiBase).join("|");
    const after = fresh.map((e) => e.apiBase).join("|");

    const updated = {
      ...contact,
      island: {
        ...contact.island,
        entryPoints: fresh,
        relays: res.payload.relays || [],
        // Only ever from the signed list. GET /relay/key is a development
        // convenience, and whoever substitutes that key reads the metadata of
        // every envelope sent through a relay.
        transportKeys: res.payload.transportKeys || [],
        pin: res.pin,
        lastCheckedAt: Date.now(),
      },
    };

    // If the address we have been delivering to is gone from their own list,
    // move to one that is there. The delivery secret is per mailbox, not per
    // address, so nothing else has to change.
    if (updated.outbox?.apiBase && !fresh.some((e) => e.apiBase === updated.outbox.apiBase)) {
      updated.outbox = { ...updated.outbox, apiBase: fresh[0].apiBase };
    }

    await saveForeignContact(updated);
    _foreignThreadCache.set(foreignThreadId(updated), updated);
    if (before !== after) {
      console.log(`[Foreign] ${contact.displayName}: island now reachable at ${after}`);
    }
    return { ok: true, changed: before !== after };
  }

  return { ok: false, reason: lastReason };
}

/**
 * Send one message through one of the contact's island's relays.
 *
 * Direct delivery tells the recipient's island the sender's address and the
 * time they typed - to a server the sender does not trust and has no account
 * with. That is the metadata leak this design accepts by default, and the
 * relay is what closes it; the choice is per contact and made by the user,
 * because it is a trade against reliability, not a free win.
 *
 * Falls back to nothing: if the relays fail, the caller queues the message. A
 * silent fallback to direct delivery would hand over the address the user
 * asked to withhold.
 */
async function deliverForeignViaRelay(contact, box, ciphertext, opts) {
  const relays = contact.island?.relays || [];
  const key = (contact.island?.transportKeys || [])[0]?.publicKeyB64;
  if (!relays.length || !key) {
    // Their island publishes no relay, or we have not verified its list yet.
    // Saying so beats quietly sending the thing the user asked not to send.
    throw new Error("No relay is available for this contact yet");
  }

  let last = { ok: false, status: 0 };
  for (const relay of relays) {
    last = await FD().deliverThroughRelay(
      _foreignDeps(),
      { url: relay.url, islandId: contact.island.islandId, transportKeyB64: key },
      box,
      ciphertext,
      opts,
    );
    // A relay that failed us says nothing about the island; try the next one.
    // An answer FROM the island - even a refusal - is final.
    if (!last.relayFailed) return last;
    console.warn(`[Foreign] relay ${relay.id} did not carry it (${last.status})`);
  }
  return last;
}
