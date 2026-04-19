// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * NetworkService.js — замена background.js (MV3 service worker) для React Native
 *
 * Что изменилось vs background.js:
 *   chrome.storage.session     → in-memory Map (_session)
 *   chrome.storage.local       → StorageService (AsyncStorage / SecureStore)
 *   chrome.runtime.connect()   → mitt EventEmitter (on/off/emit)
 *   safePortPost(port, msg)    → this._post(msg)
 *   chrome.tabs.create(url)    → Linking.openURL(url)
 *   chrome.runtime.onSuspend   → AppState 'background' event
 *   keepalive interval         → не нужен (JS thread не убивается как SW)
 *   chrome.sidePanel           → не нужен (само приложение и есть панель)
 *   chrome.contextMenus        → не нужен
 *
 * Использование (в компонентах):
 *   import NetworkService from '../services/NetworkService';
 *   NetworkService.on('message', handler);     // новое сообщение в комнате
 *   NetworkService.on('presence', handler);    // список онлайн
 *   NetworkService.on('status', handler);      // ws online/offline
 *   NetworkService.on('auth_state', handler);  // вход/выход
 *   NetworkService.on('dm_message', handler);  // новое DM
 *   NetworkService.on('dm_presence', handler); // DM peer online
 *   NetworkService.on('dm_status', handler);   // DM ws статус
 *
 *   await NetworkService.login(username, password)
 *   await NetworkService.connectRoom(roomId, roomPass)
 *   await NetworkService.sendMessage(text)
 *   await NetworkService.getRooms()
 *   // ... etc
 */

import mitt from 'mitt';
import { AppState, Linking } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import StorageService from './StorageService';

// @noble/hashes — used for HMAC-SHA256 in sendDmUd
// (react-native-quick-crypto does not support HMAC via subtle.sign)
const { hmac: _nobleHmac } = require('@noble/hashes/hmac');
const { sha256: _nobleSha256 } = require('@noble/hashes/sha2');

// Lazy proxy — reads globalThis.crypto at call time, not at module init time.
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

const DEFAULT_API_BASE = 'https://imagine-1-ws.xyz';
const DEFAULT_WS_BASE  = 'wss://imagine-1-ws.xyz';
const SERVER_CONFIG_KEY = 'com.wsmessenger.server_config';

let _apiBase = DEFAULT_API_BASE;
let _wsBase  = DEFAULT_WS_BASE;

// ============================
// Helpers
// ============================

function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    if (!part) return null;
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return JSON.parse(atob(padded));
  } catch (_e) {
    return null;
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ============================
// Rate limiter
// ============================

class RateLimiter {
  /**
   * @param {number} maxAttempts - max attempts in window
   * @param {number} windowMs    - rolling window in ms
   * @param {number} lockoutMs   - how long to lock after exceeding (default = windowMs)
   */
  constructor(maxAttempts, windowMs, lockoutMs) {
    this._max       = maxAttempts;
    this._window    = windowMs;
    this._lockout   = lockoutMs ?? windowMs;
    this._attempts  = []; // timestamps
    this._lockedUntil = 0;
  }

  /** Returns true if the action is allowed; records the attempt. */
  allow() {
    const now = Date.now();
    if (now < this._lockedUntil) return false;
    // prune old entries outside rolling window
    this._attempts = this._attempts.filter(t => now - t < this._window);
    if (this._attempts.length >= this._max) {
      this._lockedUntil = now + this._lockout;
      this._attempts = [];
      return false;
    }
    this._attempts.push(now);
    return true;
  }

  /** Seconds remaining in lockout, 0 if not locked. */
  secondsRemaining() {
    const rem = this._lockedUntil - Date.now();
    return rem > 0 ? Math.ceil(rem / 1000) : 0;
  }

  reset() {
    this._attempts = [];
    this._lockedUntil = 0;
  }
}

// ============================
// NetworkService (singleton)
// ============================

class NetworkService {
  constructor() {
    this._emitter = mitt();

    // --- Auth state (in-memory; persisted to SecureStore on change) ---
    this._username    = '';
    this._token       = '';
    this._refreshToken = '';

    // --- Room WebSocket ---
    this._ws              = null;
    this._wsRoomId        = null;
    this._wsRoomTarget    = null;
    this._wsRoomName      = '';
    this._wsRoomPass      = '';
    this._wsConnectedAt   = 0;
    this._wsPingInterval  = null;
    this._reconnectTimer  = null;
    this._reconnectAttempts = 0;
    this._manualDisconnect  = false;
    this._autoConnectTs     = 0; // timestamp of last auto-connect (0 = manual)
    this._roomGeneration    = 0;

    // --- DM WebSocket ---
    this._dmWs            = null;
    this._dmThreadId      = null;
    this._dmPeer          = '';
    this._dmReconnectTimer = null;
    this._dmReconnectAttempts = 0;
    this._dmGeneration    = 0; // стражник от устаревших событий
    this._manualDmDisconnect = false;

    // --- Token refresh ---
    this._refreshTimer      = null;
    this._refreshInProgress = false;
    this._refreshWaiters    = [];

    // --- Session: in-memory (не персистируется) ---
    this._masterKey   = null; // CryptoKey AES-GCM
    this._masterKeyTs = 0;
    this._kekKey      = null; // CryptoKey AES-GCM (KEK)
    this._kekTs       = 0;
    this._deliverySecretCache = new Map(); // threadId → { secret, ts }
    this._deliverySecretPending = new Map(); // threadId → Promise

    // --- Notification WebSocket (/ws-notify) ---
    this._notifyWs = null;
    this._notifyPingInterval = null;
    this._notifyReconnectTimer = null;
    this._notifyReconnectAttempts = 0;
    this._manualNotifyDisconnect = false;
    this._notifyGeneration = 0; // стражник от гонки concurrent open (как _roomGeneration/_dmGeneration)

    // --- AppState ---
    this._appStateSub = null;
    this._isBackground = false;

    // --- Rate limiters ---
    // 5 login attempts per 60 s; lockout 5 minutes
    this._loginRateLimit = new RateLimiter(5, 60_000, 5 * 60_000);
    // 5 register attempts per 60 s; lockout 5 minutes
    this._registerRateLimit = new RateLimiter(5, 60_000, 5 * 60_000);
    // 5 2FA code attempts per 60 s; lockout 5 minutes
    this._twoFaRateLimit = new RateLimiter(5, 60_000, 5 * 60_000);

    this._init();
  }

  // ============================
  // Init
  // ============================

  _init() {
    this._appStateSub = AppState.addEventListener('change', (state) => {
      if (state === 'background' || state === 'inactive') {
        this._onBackground();
      } else if (state === 'active') {
        this._onForeground();
      }
    });
  }

  async loadPersistedAuth() {
    /**
     * Вызвать при старте приложения — восстанавливает сессию из SecureStore.
     * Возвращает true если сессия восстановлена.
     */
    try {
      const auth = await StorageService.getAuth();
      if (!auth?.token) return false;
      this._username     = auth.username    || '';
      this._token        = auth.token       || '';
      this._refreshToken = auth.refreshToken || '';
      this._scheduleTokenRefresh();
      this._post({ type: 'auth_state', loggedIn: true, username: this._username });
      return true;
    } catch (e) {
      console.warn('[NS] loadPersistedAuth error:', e?.message);
      return false;
    }
  }

  /**
   * Синхронно устанавливает токен из уже восстановленной сессии
   * (вызывается из App.tsx после StorageService.getAuth()).
   */
  setRestoredAuth(username, token, refreshToken = '') {
    this._username     = username     || '';
    this._token        = token        || '';
    this._refreshToken = refreshToken || '';
    if (token) this._scheduleTokenRefresh();
  }

  _getAccessTokenRemainingMs(token = this._token) {
    if (!token) return -Infinity;
    const payload = decodeJwtPayload(token);
    const expMs = Number(payload?.exp || 0) * 1000;
    if (!Number.isFinite(expMs) || expMs <= 0) return Infinity;
    return expMs - Date.now();
  }

  /**
   * Validate the current session: check if the access token is still valid,
   * attempt refresh if expired. Returns true if session is usable.
   * Used at startup to verify restored auth before showing AppTabs.
   */
  async validateSession() {
    if (!this._token) return false;
    const remaining = this._getAccessTokenRemainingMs();
    if (remaining > 30_000) return true; // token still valid
    if (!this._refreshToken) return remaining > 0;
    // Token expired — try refresh (suppress _handleSessionExpired here,
    // caller will handle the failure)
    const ok = await this._doRefresh();
    return ok;
  }

  async _ensureFreshAccessToken(minValidityMs = 30_000) {
    if (!this._token) return false;

    const remainingMs = this._getAccessTokenRemainingMs();
    if (remainingMs > minValidityMs) return true;

    if (!this._refreshToken) {
      if (remainingMs <= 0) this._handleSessionExpired();
      return remainingMs > 0;
    }

    const refreshed = await this._doRefresh();
    if (refreshed) return !!this._token;

    return this._getAccessTokenRemainingMs() > 0;
  }

  // ============================
  // EventEmitter (замена chrome.runtime port)
  // ============================

  on(event, handler)  { this._emitter.on(event, handler); return () => this._emitter.off(event, handler); }
  off(event, handler) { this._emitter.off(event, handler); }

  /** Отправить событие всем UI-подписчикам (замена safePortPost) */
  _post(msg) {
    this._emitter.emit('message', msg);
    // Отдельные события для удобства подписки в компонентах
    if (msg?.type && msg.type !== 'message') {
      this._emitter.emit(msg.type, msg);
    }
  }

  // ============================
  // AppState (замена chrome.runtime.onSuspend)
  // ============================

  _onBackground() {
    this._isBackground = true;
    // Сохраняем состояние перед уходом в фон
    if (this._wsRoomId) {
      StorageService.setLastConn({
        room: this._wsRoomId,
        roomName: this._wsRoomName,
      }).catch(() => {});
    }
  }

  _onForeground() {
    if (!this._isBackground) return;
    this._isBackground = false;
    // Reconnect room WS if connection was lost while in background
    if ((this._wsRoomTarget || this._wsRoomId) && (!this._ws || this._ws.readyState > 1)) {
      this._reconnectAttempts = 0;
      this._scheduleReconnect(true);
    }
    // Reconnect DM WS if connection was lost while in background
    if (this._dmThreadId && (!this._dmWs || this._dmWs.readyState > 1)) {
      this._dmReconnectAttempts = 0;
      this.connectDm(this._dmThreadId, this._dmPeer);
    }
    // Reconnect notify WS if connection was lost while in background
    if (this._token && !this._manualNotifyDisconnect && (!this._notifyWs || this._notifyWs.readyState > 1)) {
      this._notifyReconnectAttempts = 0;
      this._notifyGeneration++;
      this._openNotifyWs(this._notifyGeneration).catch(() => {});
    }
    // Connectivity ping: if WS appears connected but may be stale, send a ping
    // to trigger close event faster if the network changed while backgrounded
    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      try { this._ws.send(JSON.stringify({ type: 'ping' })); } catch (_e) { this._scheduleReconnect(true); }
    }
    if (this._dmWs && this._dmWs.readyState === WebSocket.OPEN) {
      try { this._dmWs.send(JSON.stringify({ type: 'ping' })); } catch (_e) { this._dmReconnectAttempts = 0; this.connectDm(this._dmThreadId, this._dmPeer); }
    }
    if (this._notifyWs && this._notifyWs.readyState === WebSocket.OPEN) {
      try { this._notifyWs.send(JSON.stringify({ type: 'ping' })); } catch (_e) { this._notifyReconnectAttempts = 0; this._openNotifyWs(); }
    }
  }

  // ============================
  // Auth: login / logout / refresh
  // ============================

  async login(username, password) {
    if (!this._loginRateLimit.allow()) {
      const s = this._loginRateLimit.secondsRemaining();
      throw Object.assign(new Error(`Too many login attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
    }
    const resp = await this._fetch('/auth/login', {
      method: 'POST',
      body: { username, password },
      noAuth: true,
    });

    if (resp.requires_2fa) {
      return { requires_2fa: true, temp_token: resp.temp_token };
    }

    await this._setSession(resp);
    this._loginRateLimit.reset();
    return { ok: true, username: resp.username || username, token: this._token, refreshToken: this._refreshToken };
  }

  async register(username, password, publicKeyB64, encryptedPrivKey, recoveryKeyHash) {
    if (!this._registerRateLimit.allow()) {
      const s = this._registerRateLimit.secondsRemaining();
      throw Object.assign(new Error(`Too many registration attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
    }
    try {
      const body = { username, password, public_key: publicKeyB64, encrypted_private_key: encryptedPrivKey };
      if (recoveryKeyHash) body.recovery_key_hash = recoveryKeyHash;
      await this._fetch('/auth/register', {
        method: 'POST',
        body,
        noAuth: true,
      });
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e?.message || 'Registration failed' };
    }
  }

  async verify2fa(tempToken, code) {
    if (!this._twoFaRateLimit.allow()) {
      const s = this._twoFaRateLimit.secondsRemaining();
      throw Object.assign(new Error(`Too many 2FA attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
    }
    const resp = await this._fetch('/auth/totp/verify', {
      method: 'POST',
      body: { temp_token: tempToken, code: String(code) },
      noAuth: true,
    });

    await this._setSession(resp);
    this._twoFaRateLimit.reset();
    return {
      ok: true,
      token: this._token,
      username: this._username,
      refreshToken: this._refreshToken,
    };
  }

  // ----------------------------
  // BIP39 account recovery
  // ----------------------------
  // Reuses _loginRateLimit since a flood here is equivalent to password-guess attempts.

  async recoverStart(username) {
    if (!this._loginRateLimit.allow()) {
      const s = this._loginRateLimit.secondsRemaining();
      throw Object.assign(new Error(`Too many attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
    }
    return this._fetch('/auth/recover-start', {
      method: 'POST',
      body: { username },
      noAuth: true,
    });
  }

  async recover(username, nonce, recoveryAuthB64, newPassword) {
    if (!this._loginRateLimit.allow()) {
      const s = this._loginRateLimit.secondsRemaining();
      throw Object.assign(new Error(`Too many attempts. Try again in ${s} seconds.`), { code: 'RATE_LIMITED' });
    }
    const resp = await this._fetch('/auth/recover', {
      method: 'POST',
      body: {
        username,
        nonce,
        recovery_auth_b64: recoveryAuthB64,
        new_password: newPassword,
      },
      noAuth: true,
    });
    this._loginRateLimit.reset();
    return resp;
  }

  async logout() {
    const savedToken = this._token;
    this._clearSession();

    // Закрываем WS
    this.disconnectRoom();
    this.disconnectDm();
    this.disconnectNotify();

    // Уведомляем UI
    this._post({ type: 'auth_state', loggedIn: false });

    await StorageService.removeAuth();

    // Server-side revoke (best effort)
    if (savedToken) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5000);
      try {
        await fetch(`${_apiBase}/auth/logout`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${savedToken}` },
          signal: controller.signal,
        });
      } catch (_e) {
      } finally {
        clearTimeout(timer);
      }
    }
  }

  async _setSession(resp) {
    this._token        = resp.access_token  || resp.token || '';
    this._refreshToken = resp.refresh_token || '';
    this._username     = resp.username      || '';

    await StorageService.setAuth({
      username:     this._username,
      token:        this._token,
      refreshToken: this._refreshToken,
    });

    this._scheduleTokenRefresh();
    this._post({ type: 'auth_state', loggedIn: true, username: this._username });
    this._post({ type: 'token', token: this._token });
  }

  _clearSession() {
    clearTimeout(this._refreshTimer);
    this._refreshTimer   = null;
    this._token          = '';
    this._refreshToken   = '';
    this._username       = '';
    this._masterKey      = null;
    this._masterKeyTs    = 0;
    this._kekKey         = null;
    this._kekTs          = 0;
    this._deliverySecretCache.clear();
    this._deliverySecretPending.clear();
  }

  _handleSessionExpired() {
    this._clearSession();
    this.disconnectRoom();
    this.disconnectDm();
    this.disconnectNotify();
    StorageService.removeAuth().catch(() => {});
    this._post({ type: 'auth_state', loggedIn: false, reason: 'expired' });
  }

  _scheduleTokenRefresh() {
    clearTimeout(this._refreshTimer);
    if (!this._token) return;
    const payload = decodeJwtPayload(this._token);
    if (!payload?.exp) return;
    const expMs  = Number(payload.exp) * 1000;
    const nowMs  = Date.now();
    const delay  = Math.max(0, expMs - nowMs - 60_000); // 60s до истечения
    this._refreshTimer = setTimeout(() => this._doRefresh(), delay);
  }

  async _doRefresh() {
    if (!this._refreshToken) return false;
    if (this._refreshInProgress) {
      // Ждём пока текущий refresh завершится
      return new Promise((res) => {
        const timer = setTimeout(() => { res(false); }, 8000);
        this._refreshWaiters.push((ok) => { clearTimeout(timer); res(ok); });
      });
    }

    this._refreshInProgress = true;
    let ok = false;
    try {
      const resp = await this._fetch('/auth/refresh', {
        method: 'POST',
        body: { refresh_token: this._refreshToken },
        noAuth: true,
      });
      // If _clearSession() was called while the refresh was in flight (i.e. logout
      // happened concurrently), discard the result — do NOT re-save to Keychain.
      if (!this._username) return false;
      this._token        = resp.access_token  || resp.token || this._token;
      this._refreshToken = resp.refresh_token || this._refreshToken;

      await StorageService.setAuth({
        username:     this._username,
        token:        this._token,
        refreshToken: this._refreshToken,
      });

      this._scheduleTokenRefresh();
      this._post({ type: 'token', token: this._token });
      ok = true;
    } catch (e) {
      console.warn('[NS] token refresh failed: status', e?.status || 'unknown');
      if (e?.status === 401) this._handleSessionExpired();
    } finally {
      this._refreshInProgress = false;
      this._refreshWaiters.forEach(fn => fn(ok));
      this._refreshWaiters = [];
    }
    return ok;
  }

  // ============================
  // Core fetch (замена apiCall в background.js)
  // ============================

  async _fetch(path, {
    method  = 'GET',
    body    = null,
    headers = {},
    noAuth  = false,
    formData = null,
    _retried = false,
    timeoutMs = 30_000,
  } = {}) {
    const url = _apiBase + path;
    const reqHeaders = { ...headers };

    if (!noAuth && this._token) {
      reqHeaders['Authorization'] = `Bearer ${this._token}`;
    }

    let fetchBody = undefined;
    if (formData) {
      fetchBody = formData; // FormData — не устанавливаем Content-Type (браузер/RN сам)
    } else if (body !== null && body !== undefined) {
      reqHeaders['Content-Type'] = 'application/json';
      fetchBody = JSON.stringify(body);
    }

    // Abort controller with timeout — prevents hanging requests from blocking the app
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let resp;
    try {
      resp = await fetch(url, { method, headers: reqHeaders, body: fetchBody, signal: controller.signal });
    } catch (e) {
      const msg = controller.signal.aborted ? `Request timed out (${timeoutMs}ms)` : (e?.message || 'network_error');
      const err = new Error(msg);
      err.status = 0;
      throw err;
    } finally {
      clearTimeout(timer);
    }

    // 401 → попытка обновить токен, один раз
    if (resp.status === 401 && !_retried && !noAuth) {
      const refreshed = await this._doRefresh();
      if (refreshed) {
        return this._fetch(path, { method, body, headers, noAuth, formData, _retried: true });
      }
      this._handleSessionExpired();
      const err = new Error('session_expired');
      err.status = 401;
      throw err;
    }

    let data;
    const ct = resp.headers.get('content-type') || '';
    try {
      data = ct.includes('application/json') ? await resp.json() : await resp.text();
    } catch (_e) {
      data = null;
    }

    if (!resp.ok) {
      let rawMsg = (typeof data === 'object' ? data?.detail || data?.reason || data?.message : data) ||
        `HTTP ${resp.status}`;
      // Sanitize server error messages — strip stack traces, SQL, internal paths
      if (typeof rawMsg === 'string' && rawMsg.length > 200) rawMsg = rawMsg.slice(0, 200);
      if (typeof rawMsg === 'string' && /\b(traceback|sqlalchemy|psycopg|internal server|stack trace|file\s)/i.test(rawMsg)) {
        rawMsg = `Request failed (${resp.status})`;
      }
      const err = new Error(rawMsg);
      err.status  = resp.status;
      err.body    = data;
      throw err;
    }

    return data;
  }

  // ============================
  // Room WebSocket
  // ============================

  async connectRoom(roomIdOrAlias, roomPass = '') {
    this.disconnectRoom(); // Закрываем предыдущее соединение

    const isNumeric = /^\d+$/.test(String(roomIdOrAlias));
    const qp = isNumeric
      ? `room_id=${encodeURIComponent(roomIdOrAlias)}`
      : `room_alias=${encodeURIComponent(roomIdOrAlias)}`;
    const url = `${_wsBase}/ws?${qp}`;

    this._wsRoomTarget    = roomIdOrAlias;
    this._wsRoomPass      = roomPass;
    this._manualDisconnect  = false;
    this._reconnectAttempts = 0;
    this._autoConnectTs     = 0; // manual connect — no auto-connect suppression
    this._roomGeneration++;
    const gen = this._roomGeneration;

    this._openWs(url, gen).catch(() => {});
  }

  /**
   * Auto-connect to last saved room (e.g. on app startup).
   * If server closes with 1008 (forbidden) within 15 s, the error popup is
   * suppressed and the stored connection is cleared (stale room defence).
   */
  async connectRoomAuto(roomIdOrAlias, roomPass = '') {
    console.log('[NS] connectRoomAuto:', roomIdOrAlias);
    this.disconnectRoom();

    const isNumeric = /^\d+$/.test(String(roomIdOrAlias));
    const qp = isNumeric
      ? `room_id=${encodeURIComponent(roomIdOrAlias)}`
      : `room_alias=${encodeURIComponent(roomIdOrAlias)}`;
    const url = `${_wsBase}/ws?${qp}`;

    this._wsRoomTarget    = roomIdOrAlias;
    this._wsRoomPass      = roomPass;
    this._manualDisconnect  = false;
    this._reconnectAttempts = 0;
    this._autoConnectTs     = Date.now(); // mark as auto-connect
    this._roomGeneration++;
    const gen = this._roomGeneration;

    this._openWs(url, gen).catch(() => {});
  }

  async _openWs(url, gen = this._roomGeneration) {
    if (gen !== this._roomGeneration || this._manualDisconnect) return;
    const tokenReady = await this._ensureFreshAccessToken();
    if (gen !== this._roomGeneration || this._manualDisconnect) return;
    if (!tokenReady) {
      if (this._token && this._wsRoomTarget) this._scheduleReconnect();
      return;
    }

    console.log('[NS] _openWs:', url);
    try {
      const ws = new WebSocket(url, null, { headers: { Origin: 'react-native://com.wsmessenger' } });
      this._ws = ws;
      this._wsConnectedAt = 0;

      ws.onopen = () => {
        if (gen !== this._roomGeneration || ws !== this._ws) { ws.close(); return; }
        console.log('[NS] ws onopen:', url);
        this._wsConnectedAt = Date.now();
        this._reconnectAttempts = 0;

        // Auth handshake
        ws.send(JSON.stringify({
          type: 'auth',
          token: this._token,
          room_pass: this._wsRoomPass || undefined,
        }));

        // Ping каждые 25 секунд
        this._wsPingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25_000);
      };

      ws.onmessage = (event) => {
        // Guard against oversized messages (OOM prevention)
        if (typeof event.data === 'string' && event.data.length > 512_000) {
          console.warn('[NS] Room WS: oversized message dropped, length:', event.data.length);
          return;
        }
        let msg;
        try { msg = JSON.parse(event.data); } catch (_e) { return; }

        if (msg.type === 'presence') {
          if (msg.room_id) {
            this._wsRoomId = msg.room_id;
            this._wsRoomTarget = msg.room_id;
          }
          if (msg.room_name) this._wsRoomName = msg.room_name;
          this._post({ type: 'presence', online: msg.online || [], room_id: msg.room_id, room_name: msg.room_name });
          return;
        }

        if (msg.type === 'auth_ok' || msg.type === 'connected') {
          console.log('[NS] ws auth_ok/connected room_id:', msg.room_id, 'room_name:', msg.room_name);
          if (msg.room_id) {
            this._wsRoomId = msg.room_id;
            this._wsRoomTarget = msg.room_id;
          }
          if (msg.room_name) this._wsRoomName = msg.room_name;
          // Persist room for auto-reconnect on next launch
          StorageService.setLastConn({
            room: this._wsRoomId,
            roomName: this._wsRoomName,
          }).catch(() => {});
          this._post({ type: 'status', online: true, room_id: msg.room_id, room_name: msg.room_name });
          return;
        }

        if (msg.type === 'banned') {
          this._handleSessionExpired();
          this._post({ type: 'banned', message: msg.message || msg.detail || 'Banned' });
          return;
        }

        if (msg.type === 'error') {
          this._post({ type: 'error', code: msg.code, message: msg.message || msg.detail });
          return;
        }

        if (msg.type === 'pong') {
          return; // keep-alive, не пробрасываем
        }

        // Обычное сообщение чата — гарантируем наличие room_id для счётчиков непрочитанных
        if (msg.from !== undefined || msg.text !== undefined) {
          this._post({ type: 'message', room_id: this._wsRoomId, room_name: this._wsRoomName, ...msg });
          return;
        }

        // Whitelist allowed server-initiated message types to prevent state injection
        const _WS_ALLOWED_TYPES = ['members_changed', 'room_updated', 'room_deleted',
          'key_rotation', 'room_key_share', 'invite_accepted', 'join_request'];
        if (msg.type && _WS_ALLOWED_TYPES.includes(msg.type)) {
          this._post(msg);
        } else {
          console.warn('[NS] unknown WS message type dropped:', msg.type);
        }
      };

      ws.onerror = (e) => {
        console.warn('[NS] ws error:', e?.message || e);
        this._post({ type: 'status', online: false, error: true });
      };

      ws.onclose = (event) => {
        // Stale connection: a new WS was already opened, ignore this close
        if (ws !== this._ws) return;
        console.log('[NS] ws onclose code:', event.code, 'reason:', event.reason);
        clearInterval(this._wsPingInterval);
        this._wsPingInterval = null;
        this._post({ type: 'status', online: false, code: event.code, reason: event.reason });

        if (this._manualDisconnect) return;

        // Auto-connect 1008 suppression: if we got a 1008 (policy violation) quickly
        // after an auto-connect, the saved room is stale — suppress the error popup
        // and clear the saved connection instead of showing "Access denied".
        if (event.code === 1008 && this._autoConnectTs > 0) {
          const elapsed = Date.now() - this._autoConnectTs;
          const reason = String(event.reason || '').toLowerCase();
          const isStaleRoom = elapsed < 15000 && (
            reason.includes('forbidden') ||
            reason.includes('no access') ||
            reason.includes('room not found') ||
            reason.includes('bad room password')
          );
          if (isStaleRoom) {
            this._autoConnectTs = 0;
            StorageService.removeLastConn().catch(() => {});
            return; // suppress popup
          }
        }
        this._autoConnectTs = 0;

        // Коды, при которых не переподключаемся
        const fatal = [1008 /* policy */, 1009 /* too large */];
        if (fatal.includes(event.code)) {
          this._post({ type: 'ws_closed', fatal: true, code: event.code });
          return;
        }

        // 1006 с коротким uptime → вероятно неверный пароль комнаты
        const uptime = Date.now() - this._wsConnectedAt;
        if (event.code === 1006 && this._wsConnectedAt > 0 && uptime < 5000) {
          this._post({ type: 'ws_closed', likely_bad_pass: true });
          return;
        }

        this._scheduleReconnect();
      };
    } catch (e) {
      console.warn('[NS] WebSocket open error:', e?.message);
      this._scheduleReconnect();
    }
  }

  _scheduleReconnect(immediate = false) {
    clearTimeout(this._reconnectTimer);
    const roomTarget = this._wsRoomTarget ?? this._wsRoomId;
    if (this._manualDisconnect || !roomTarget) return;

    const MAX_RECONNECT_ATTEMPTS = 20;
    const attempts = this._reconnectAttempts++;
    if (attempts >= MAX_RECONNECT_ATTEMPTS) {
      console.warn('[NS] Room WS: max reconnect attempts reached, giving up');
      this._post({ type: 'status', online: false, reconnecting: false, gaveUp: true });
      return;
    }
    const base  = immediate ? 0 : Math.min(30_000, 1000 * Math.pow(2, attempts));
    const jitter = Math.floor(Math.random() * 500);
    const delay  = base + jitter;

    this._post({ type: 'status', online: false, reconnecting: true, delay });

    this._reconnectTimer = setTimeout(() => {
      const target = this._wsRoomTarget ?? this._wsRoomId;
      if (!target || this._manualDisconnect) return;
      const gen = this._roomGeneration;
      const isNumeric = /^\d+$/.test(String(target));
      const qp = isNumeric
        ? `room_id=${encodeURIComponent(target)}`
        : `room_alias=${encodeURIComponent(target)}`;
      this._openWs(`${_wsBase}/ws?${qp}`, gen).catch(() => {});
    }, delay);
  }

  disconnectRoom() {
    this._manualDisconnect = true;
    this._roomGeneration++;
    clearTimeout(this._reconnectTimer);
    clearInterval(this._wsPingInterval);
    this._reconnectTimer  = null;
    this._wsPingInterval  = null;
    this._reconnectAttempts = 0;
    if (this._ws) {
      try { this._ws.close(); } catch (_e) {}
      this._ws = null;
    }
    this._wsRoomTarget = null;
  }

  sendMessage(text) {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected to a room');
    }
    // Server expects the raw message body (plain text or encrypted JSON string),
    // not a JSON-wrapped envelope. Wrapping causes the server to broadcast the
    // entire JSON object as the text field for other clients.
    try {
      this._ws.send(text);
    } catch (e) {
      // Guard against native WebSocket crashes (e.g. stale socket, JNI error).
      // Re-throw as a clean JS error so ChatScreen's try-catch can handle it.
      console.warn('[NS] ws.send() native error:', e?.message);
      throw new Error('Send failed: ' + (e?.message || 'WebSocket error'));
    }
  }

  // ============================
  // DM WebSocket
  // ============================

  async connectDm(threadId, peer) {
    console.log('[DM-WS] connectDm gen:', this._dmGeneration);
    this.disconnectDm();
    this._dmThreadId = threadId;
    this._dmPeer     = peer;
    this._dmReconnectAttempts = 0;
    this._manualDmDisconnect = false;
    this._dmGeneration++;
    const gen = this._dmGeneration;
    console.log('[DM-WS] connectDm new gen:', gen);
    this._openDmWs(gen).catch(() => {});
  }

  async _openDmWs(gen) {
    if (gen !== this._dmGeneration) {
      console.log('[DM-WS] _openDmWs stale gen:', gen, 'current:', this._dmGeneration, '— skipped');
      return;
    }

    const tokenReady = await this._ensureFreshAccessToken();
    if (gen !== this._dmGeneration || this._manualDmDisconnect || !this._dmThreadId) return;
    if (!tokenReady) {
      if (this._token) this._scheduleDmReconnect(gen);
      return;
    }

    const url = `${_wsBase}/ws-dm?thread_id=${encodeURIComponent(this._dmThreadId)}`;
    console.log('[DM-WS] opening WS url:', url);
    try {
      const ws = new WebSocket(url, null, { headers: { Origin: 'react-native://com.wsmessenger' } });
      this._dmWs = ws;

      ws.onopen = () => {
        console.log('[DM-WS] onopen gen:', gen, 'current:', this._dmGeneration);
        if (gen !== this._dmGeneration) { ws.close(); return; }
        ws.send(JSON.stringify({ type: 'auth', token: this._token }));
        this._dmReconnectAttempts = 0;
        this._post({ type: 'dm_status', online: true, thread_id: this._dmThreadId });
        // Ping every 15s to keep connection alive (server may close idle connections <25s)
        this._dmPingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 15_000);
        // Server creates delivery secret when processing WS auth — prefetch after short delay
        const tid = this._dmThreadId;
        setTimeout(() => this._prefetchDeliverySecret(tid), 600);
      };

      ws.onmessage = (event) => {
        if (gen !== this._dmGeneration) return;
        if (typeof event.data === 'string' && event.data.length > 512_000) {
          console.warn('[DM-WS] oversized message dropped, length:', event.data.length);
          return;
        }
        let msg;
        try { msg = JSON.parse(event.data); } catch (_e) {
          console.warn('[DM-WS] invalid JSON in message, dropped');
          return;
        }

        console.log('[DM-WS] msg type:', msg.type);

        if (msg.type === 'dm_message') {
          this._post({ type: 'dm_message', thread_id: this._dmThreadId, ...msg });
          return;
        }
        if (msg.type === 'dm_presence' || msg.type === 'presence') {
          this._post({ type: 'dm_presence', thread_id: this._dmThreadId, ...msg });
          return;
        }
        this._post({ ...msg, thread_id: this._dmThreadId });
      };

      ws.onerror = (e) => {
        console.warn('[DM-WS] onerror gen:', gen, 'msg:', e?.message, 'type:', e?.type);
        if (gen !== this._dmGeneration) return;
        this._post({ type: 'dm_status', online: false, error: true, thread_id: this._dmThreadId });
      };

      ws.onclose = (event) => {
        console.log('[DM-WS] onclose gen:', gen, 'code:', event?.code, 'reason:', event?.reason, 'wasClean:', event?.wasClean);
        clearInterval(this._dmPingInterval);
        this._dmPingInterval = null;
        if (gen !== this._dmGeneration) return;
        this._post({ type: 'dm_status', online: false, code: event.code, thread_id: this._dmThreadId });
        if (!this._manualDmDisconnect) {
          this._scheduleDmReconnect(gen);
        }
      };
    } catch (e) {
      console.warn('[DM-WS] WebSocket constructor threw:', e?.message);
      this._scheduleDmReconnect(gen);
    }
  }

  _scheduleDmReconnect(gen) {
    clearTimeout(this._dmReconnectTimer);
    const MAX_DM_RECONNECT = 20;
    if (this._dmReconnectAttempts >= MAX_DM_RECONNECT) {
      console.warn('[DM-WS] max reconnect attempts reached, giving up');
      this._post({ type: 'dm_status', online: false, reconnecting: false, gaveUp: true });
      return;
    }
    const delay = Math.min(30_000, 1000 * Math.pow(2, this._dmReconnectAttempts++)) +
                  Math.floor(Math.random() * 500);
    this._dmReconnectTimer = setTimeout(() => this._openDmWs(gen).catch(() => {}), delay);
  }

  /** Returns true if DM WebSocket is open and subscribed to the given threadId. */
  isDmReady(threadId) {
    return this._dmWs?.readyState === 1 && this._dmThreadId === threadId;
  }

  disconnectDm() {
    this._manualDmDisconnect = true;
    this._dmGeneration++;
    clearTimeout(this._dmReconnectTimer);
    clearInterval(this._dmPingInterval);
    this._dmPingInterval = null;
    if (this._dmWs) {
      try { this._dmWs.close(); } catch (_e) {}
      this._dmWs = null;
    }
    this._dmThreadId = null;
    this._dmPeer     = '';
  }

  // ============================
  // Notification WebSocket (/ws-notify)
  // ============================
  // Single per-user WS that receives lightweight notifications for ALL rooms & DMs.
  // No ciphertext — only metadata (room_id, room_name, author, ts, thread_id).

  connectNotify() {
    if (this._notifyWs?.readyState === WebSocket.OPEN ||
        this._notifyWs?.readyState === WebSocket.CONNECTING) return;
    this._manualNotifyDisconnect = false;
    this._notifyReconnectAttempts = 0;
    this._notifyGeneration++;
    this._openNotifyWs(this._notifyGeneration).catch(() => {});
  }

  async _openNotifyWs(gen = this._notifyGeneration) {
    if (gen !== this._notifyGeneration || this._manualNotifyDisconnect) return;
    if (!this._token) return;

    const tokenReady = await this._ensureFreshAccessToken();
    if (gen !== this._notifyGeneration || this._manualNotifyDisconnect || !this._token) return;
    if (!tokenReady) {
      if (this._token) this._scheduleNotifyReconnect(gen);
      return;
    }

    const url = `${_wsBase}/ws-notify`;
    console.log('[NOTIFY-WS] opening:', url);
    try {
      const ws = new WebSocket(url, null, { headers: { Origin: 'react-native://com.wsmessenger' } });
      this._notifyWs = ws;

      ws.onopen = () => {
        // Stale connection: a newer notify WS is already opening or open, close this one
        if (gen !== this._notifyGeneration || ws !== this._notifyWs) { ws.close(); return; }
        console.log('[NOTIFY-WS] onopen');
        this._notifyReconnectAttempts = 0;
        ws.send(JSON.stringify({ type: 'auth', token: this._token }));
        // Ping every 25s
        this._notifyPingInterval = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25_000);
      };

      ws.onmessage = (event) => {
        let msg;
        try { msg = JSON.parse(event.data); } catch (_e) { return; }
        if (!msg || !msg.type) return;
        if (msg.type === 'pong' || msg.type === 'notify_ready') return;
        // Handle ban from notify WS (mirrors room WS behaviour)
        if (msg.type === 'banned') {
          this._handleSessionExpired();
          this._post({ type: 'banned', message: msg.message || msg.detail || 'Banned' });
          return;
        }
        // Emit via the standard event bus — App.tsx handles these
        this._post(msg);
      };

      ws.onerror = (e) => {
        console.warn('[NOTIFY-WS] onerror:', e?.message);
      };

      ws.onclose = (event) => {
        // Stale connection: a newer notify WS is already active, ignore this close
        if (gen !== this._notifyGeneration || ws !== this._notifyWs) return;
        console.log('[NOTIFY-WS] onclose code:', event?.code, 'reason:', event?.reason);
        clearInterval(this._notifyPingInterval);
        this._notifyPingInterval = null;
        if (!this._manualNotifyDisconnect) {
          this._scheduleNotifyReconnect(gen);
        }
      };
    } catch (e) {
      console.warn('[NOTIFY-WS] constructor threw:', e?.message);
      this._scheduleNotifyReconnect(gen);
    }
  }

  _scheduleNotifyReconnect(gen = this._notifyGeneration) {
    clearTimeout(this._notifyReconnectTimer);
    const MAX_NOTIFY_RECONNECT = 20;
    if (this._notifyReconnectAttempts >= MAX_NOTIFY_RECONNECT) {
      console.warn('[NOTIFY-WS] max reconnect attempts reached, giving up');
      return;
    }
    const delay = Math.min(30_000, 1000 * Math.pow(2, this._notifyReconnectAttempts++)) +
                  Math.floor(Math.random() * 500);
    this._notifyReconnectTimer = setTimeout(() => this._openNotifyWs(gen).catch(() => {}), delay);
  }

  disconnectNotify() {
    this._manualNotifyDisconnect = true;
    this._notifyGeneration++; // инвалидирует все in-flight _openNotifyWs
    clearTimeout(this._notifyReconnectTimer);
    clearInterval(this._notifyPingInterval);
    this._notifyPingInterval = null;
    if (this._notifyWs) {
      try { this._notifyWs.close(); } catch (_e) {}
      this._notifyWs = null;
    }
  }

  /** Check if room WS is currently connected to a specific room. */
  isConnectedToRoom(roomId) {
    return this._ws?.readyState === WebSocket.OPEN &&
           String(this._wsRoomId) === String(roomId);
  }

  /** Check if DM WS is currently connected to a specific thread. */
  isConnectedToDm(threadId) {
    return this._dmWs?.readyState === WebSocket.OPEN &&
           String(this._dmThreadId) === String(threadId);
  }

  // ============================
  // Rooms API
  // ============================

  async getRooms() {
    return this._fetch('/rooms/list');
  }

  async getPublicRooms(search = '') {
    const q = search ? `?search=${encodeURIComponent(search)}` : '';
    return this._fetch(`/rooms/public/list${q}`);
  }

  async createRoom({ name, is_private, is_public, is_readonly, password, encrypted_room_key }) {
    // UI sends is_private; server expects is_public (inverted)
    const pub = is_public != null ? !!is_public : !is_private;
    return this._fetch('/rooms', {
      method: 'POST',
      body: {
        name,
        is_public: pub,
        is_readonly: !!is_readonly,
        password: password || undefined,
        encrypted_room_key: encrypted_room_key || null,
      },
    });
  }

  async renameRoom(roomId, name) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/name`, {
      method: 'PUT',
      body: { name },
    });
  }

  async deleteRoom(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}`, { method: 'DELETE' });
  }

  async leaveRoom(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/leave`, { method: 'POST' });
  }

  async getRoomHistory(roomId, { limit = 50, before_id = null } = {}) {
    const q = new URLSearchParams({ limit });
    if (before_id) q.set('before_id', before_id);
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/history?${q}`);
    // → { messages: [...], has_more: bool, oldest_id: int }
  }

  async getRoomMembers(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/members`);
  }

  async getRoomMeta(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/meta`);
  }

  /**
   * Build a React Native Image `source` object for an authenticated image URL.
   * @param {string} path — server path like "/rooms/123/logo"
   * @returns {{ uri: string, headers: object } | null}
   */
  getAuthImageSource(path) {
    if (!path || !this._token) return null;
    return {
      uri: _apiBase + path,
      headers: { Authorization: `Bearer ${this._token}` },
    };
  }

  async setRoomMeta(roomId, { description, logo_url, logo_token } = {}) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/meta`, {
      method: 'PUT',
      body: { description, logo_url, logo_token },
    });
  }

  async fetchRoomPin(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/pin`);
  }

  async putRoomPin(roomId, { url, text }) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/pin`, {
      method: 'PUT',
      body: { url: url || null, text: text || null },
    });
  }

  async inviteToRoom(roomId, username) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/invite`, {
      method: 'POST',
      body: { username },
    });
  }

  async kickFromRoom(roomId, username) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/kick`, {
      method: 'POST',
      body: { username },
    });
  }

  async setMemberRole(roomId, username, role) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/members/${encodeURIComponent(username)}/role`, {
      method: 'POST',
      body: { role },
    });
  }

  async sendJoinRequest(roomAlias) {
    return this._fetch(`/rooms/${encodeURIComponent(roomAlias)}/join-request`, {
      method: 'POST',
    });
  }

  async getJoinRequests(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/join-requests`);
  }

  // Fetch join requests across all rooms where user is owner/admin
  async getJoinRequestsAll() {
    const rooms = await this._fetch('/rooms/list');
    const ownedRooms = (Array.isArray(rooms) ? rooms : []).filter(
      r => r.role === 'owner' || r.role === 'admin' || r.is_owner,
    );
    const results = await Promise.all(
      ownedRooms.map(async r => {
        try {
          const items = await this.getJoinRequests(r.id);
          return (Array.isArray(items) ? items : []).map(req => ({
            ...req,
            room_id: r.id,
            room_name: r.name || r.alias || String(r.id),
          }));
        } catch (_e) { return []; }
      }),
    );
    return results.flat();
  }

  async approveJoinRequest(roomId, username) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/join-requests/${encodeURIComponent(username)}/approve`, {
      method: 'POST',
    });
  }

  async rejectJoinRequest(roomId, username) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/join-requests/${encodeURIComponent(username)}/reject`, {
      method: 'POST',
    });
  }

  // --- Room invites ---

  async getIncomingRoomInvites() {
    return this._fetch('/rooms/invites');
  }

  async acceptRoomInvite(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/invites/accept`, { method: 'POST' });
  }

  async declineRoomInvite(roomId) {
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/invites/decline`, { method: 'POST' });
  }

  // ============================
  // Friends API
  // ============================

  async sendFriendRequest(username) {
    return this._fetch('/friends/request', { method: 'POST', body: { username } });
  }

  async getFriends() {
    return this._fetch('/friends/list');
  }

  async getIncomingFriendRequests() {
    return this._fetch('/friends/requests/incoming');
  }

  async getOutgoingFriendRequests() {
    return this._fetch('/friends/requests/outgoing');
  }

  async acceptFriendRequest(username) {
    return this._fetch('/friends/requests/accept', { method: 'POST', body: { username } });
  }

  async declineFriendRequest(username) {
    return this._fetch('/friends/requests/decline', { method: 'POST', body: { username } });
  }

  async removeFriend(username) {
    return this._fetch('/friends/remove', { method: 'POST', body: { username } });
  }

  // ============================
  // Reports API
  // ============================

  async reportUser(targetUsername, reason, comment = '') {
    return this._fetch('/reports', {
      method: 'POST',
      body: { target_type: 'user', target_username: targetUsername, reason, comment },
    });
  }

  // ============================
  // DM API
  // ============================

  async openDmThread(peerUsername) {
    return this._fetch('/dm/open', { method: 'POST', body: { username: peerUsername } });
    // → { thread_id, peer_username }
  }

  // Alias used by DMListScreen "New DM" modal
  async startDmThread(peerUsername) {
    return this.openDmThread(peerUsername);
  }

  async getDmList() {
    return this._fetch('/dm/list');
  }

  // Alias used by AppContext.loadDmThreads
  async getDmThreads() {
    return this.getDmList();
  }

  async deleteDmThread(threadId, scope = 'self') {
    return this._fetch(`/dm/${encodeURIComponent(threadId)}/delete`, {
      method: 'POST',
      body: { scope },
    });
  }

  async getDmHistory(threadId, { limit = 50, before_id = null } = {}) {
    const q = new URLSearchParams({ limit });
    if (before_id) q.set('before_id', before_id);
    return this._fetch(`/dm/${encodeURIComponent(threadId)}/history?${q}`);
    // → { messages: [...], has_more: bool, oldest_id: int }
  }

  /**
   * Отправить зашифрованное DM-сообщение через UD (Unsealed Delivery).
   *
   * @param {number} threadId
   * @param {string} plaintext      - зашифрованный JSON-текст (output of CryptoService.encryptDm)
   * @param {string} deliverySecret - base64url delivery secret (из getDeliverySecret)
   */
  async sendDmUd(threadId, plaintext, deliverySecret) {
    const ts    = Date.now();
    const nonce = this._randomBytes(16);

    // Кодируем plaintext → bytes → base64url (точно как Chrome Extension)
    const ptBytes      = new TextEncoder().encode(String(plaintext));
    const ciphertextB64 = this._toBase64Url(ptBytes);

    // SHA-256 от bytes plaintext — @noble/hashes (sync, no Web Crypto)
    const h = _nobleSha256(ptBytes);

    // HMAC input = binary concat: utf8(threadId)|utf8(ts)|nonce_raw|sha256_raw
    // (точно как Chrome Extension: concatU8(tidB, sep, tsB, sep, nonce, sep, h))
    const sep  = new Uint8Array([0x7c]); // "|"
    const tidB = new TextEncoder().encode(String(threadId));
    const tsB  = new TextEncoder().encode(String(ts));
    const total = tidB.length + 1 + tsB.length + 1 + nonce.length + 1 + h.length;
    const msgU8 = new Uint8Array(total);
    let off = 0;
    msgU8.set(tidB, off); off += tidB.length;
    msgU8.set(sep,  off); off += 1;
    msgU8.set(tsB,  off); off += tsB.length;
    msgU8.set(sep,  off); off += 1;
    msgU8.set(nonce, off); off += nonce.length;
    msgU8.set(sep,  off); off += 1;
    msgU8.set(h,    off);

    // HMAC-SHA256 — @noble/hashes (react-native-quick-crypto не поддерживает HMAC в subtle)
    const secretBytes = new Uint8Array(this._fromBase64(deliverySecret));
    const tag = _nobleHmac(_nobleSha256, secretBytes, msgU8);

    // POST без Authorization header (sealed sender — no JWT)
    const _udCtrl = new AbortController();
    const _udTimer = setTimeout(() => _udCtrl.abort(), 30_000);
    let resp;
    try {
      resp = await fetch(`${_apiBase}/ud/dm/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        signal: _udCtrl.signal,
        body: JSON.stringify({
          thread_id:      Number(threadId),
          ts,
          nonce_b64:      this._toBase64Url(nonce),
          ciphertext_b64: ciphertextB64,
          tag_b64:        this._toBase64Url(tag),
        }),
      });
    } finally {
      clearTimeout(_udTimer);
    }

    if (!resp.ok) {
      const raw = await resp.text().catch(() => '');
      let detail = raw;
      try { detail = JSON.parse(raw)?.detail || raw; } catch (_e) {}

      // Delivery secret expired/invalid — invalidate cache so next call fetches fresh
      if (resp.status === 401 || resp.status === 403) {
        this._deliverySecretCache.delete(String(threadId));
      }

      const err = new Error(`UD send failed: ${detail || `HTTP ${resp.status}`}`);
      err.status = resp.status;
      throw err;
    }
    return true;
  }

  /**
   * Send a DM message via the authenticated DM WebSocket (fallback for UD).
   * Used when the server hasn't created a delivery secret for this user.
   * @param {number|string} threadId
   * @param {string} body - encrypted JSON or plaintext
   * @returns {boolean} true if the message was queued on the socket
   */
  sendDmViaWs(threadId, body) {
    if (this._dmWs && this._dmWs.readyState === 1) {
      this._dmWs.send(JSON.stringify({
        type: 'dm_message',
        body,
        text: body,
        thread_id: Number(threadId),
      }));
      console.log('[NS] sendDmViaWs: sent via WS');
      return true;
    }
    console.warn('[NS] sendDmViaWs: WS not open (readyState:', this._dmWs?.readyState, ')');
    return false;
  }

  // Helper: parse expires_at from server response → ms timestamp.
  // Falls back to 23h from now if the field is missing (old server without TTL support).
  _parseSecretExpiry(data) {
    const raw = data?.expires_at;
    if (raw) {
      const t = new Date(raw).getTime();
      if (!isNaN(t)) return t;
    }
    return Date.now() + 23 * 60 * 60 * 1000;
  }

  // Called from WS onopen to cache delivery secret as soon as server creates it.
  // Returns a promise so callers can await it before sending DMs.
  _prefetchDeliverySecret(threadId) {
    if (!threadId) return Promise.resolve();
    const tid = String(threadId);
    const p = this._fetch(`/dm/${encodeURIComponent(threadId)}/delivery-secret`).then(data => {
      const secret = data?.delivery_secret_b64 || data?.delivery_secret || data?.secret;
      if (secret) {
        this._deliverySecretCache.set(tid, { secret, expiresAt: this._parseSecretExpiry(data) });
        console.log('[NS] delivery-secret prefetched');
      }
    }).catch(() => {
      // Silent: prefetch is best-effort; getDeliverySecret() will retry on demand
    }).finally(() => {
      if (this._deliverySecretPending?.get(tid) === p) this._deliverySecretPending.delete(tid);
    });
    this._deliverySecretPending.set(tid, p);
    return p;
  }

  // peer is passed explicitly to avoid relying on this._dmPeer being set
  async getDeliverySecret(threadId, peer = null) {
    const tid = String(threadId);

    // Wait for any in-flight prefetch to complete before checking cache
    const pending = this._deliverySecretPending?.get(tid);
    if (pending) await pending.catch(() => {});

    const cached = this._deliverySecretCache.get(tid);
    // Valid if expiresAt is set and has >60s left; fall back to old ts-based check for
    // entries written before this change.
    const cacheValid = cached && (
      cached.expiresAt
        ? cached.expiresAt > Date.now() + 60_000
        : (Date.now() - cached.ts) < 10 * 60 * 1000
    );
    if (cacheValid) return cached.secret;

    const peerToUse = peer || this._dmPeer;
    console.log('[NS] getDeliverySecret: fetching');

    // POST /dm/open so server initialises this user's slot in the thread
    if (peerToUse) {
      try {
        const r = await this.openDmThread(peerToUse);
        // Server might return delivery secret directly in POST /dm/open response
        const secretFromOpen = r?.delivery_secret_b64 || r?.delivery_secret || r?.secret;
        if (secretFromOpen) {
          this._deliverySecretCache.set(String(threadId), { secret: secretFromOpen, expiresAt: this._parseSecretExpiry(r) });
          return secretFromOpen;
        }
      } catch (e) {
        console.warn('[NS] openDmThread failed: status', e?.status || 'unknown');
      }
    }

    try {
      const data = await this._fetch(`/dm/${encodeURIComponent(threadId)}/delivery-secret`);
      const secret = data?.delivery_secret_b64 || data?.delivery_secret || data?.secret;
      if (secret) {
        this._deliverySecretCache.set(String(threadId), { secret, expiresAt: this._parseSecretExpiry(data) });
        return secret;
      }
      throw new Error('delivery secret field missing in response');
    } catch (e) {
      console.warn('[NS] delivery-secret fetch failed: status', e?.status || 'unknown');
      throw e;
    }
  }

  // ============================
  // DM crypto key endpoints
  // ============================

  async getDmKey(threadId) {
    return this._fetch(`/crypto/dm-key/${encodeURIComponent(threadId)}`);
    // → { encrypted_thread_key } или 404
  }

  async postDmKey(threadId, encryptedKey, keyId) {
    const body = { thread_id: Number(threadId), encrypted_thread_key: encryptedKey };
    if (keyId) body.key_id = keyId;
    return this._fetch('/crypto/dm-key', { method: 'POST', body });
  }

  async shareDmKey(threadId, peerUsername, encryptedKey, keyId) {
    const body = { username: peerUsername, encrypted_thread_key: encryptedKey };
    if (keyId) body.key_id = keyId;
    return this._fetch(`/crypto/dm/${encodeURIComponent(threadId)}/share`, { method: 'POST', body });
  }

  /**
   * Fetch peer's active X25519 public key from keyring.
   * Legacy alias — delegates to fetchPeerKey().
   * @deprecated Use fetchPeerKey() instead.
   */
  async getCryptoUserPublicKey(username) {
    return this.fetchPeerKey(username);
  }

  // Алиас для обратной совместимости с компонентами
  async getPeerPublicKey(username) {
    return this.fetchPeerKey(username);
    // → { kid, public_key }
  }

  // ============================
  // Profile / User
  // ============================

  async getMyProfile() {
    return this._fetch('/profile/me');
  }

  async updateProfile({ about, privacy } = {}) {
    return this._fetch('/profile/me', { method: 'PUT', body: { about, privacy } });
  }

  async getUserProfile(username) {
    return this._fetch(`/profile/${encodeURIComponent(username)}`);
  }

  async deleteAccount() {
    return this._fetch('/auth/delete-account', { method: 'POST' });
  }

  // ============================
  // 2FA (TOTP)
  // ============================

  async totpStatus() {
    return this._fetch('/auth/totp/status');
  }

  async totpSetup() {
    return this._fetch('/auth/totp/setup', { method: 'POST' });
  }

  async totpVerifySetup(code) {
    return this._fetch('/auth/totp/verify-setup', { method: 'POST', body: { code: String(code) } });
  }

  async totpDisable(code) {
    return this._fetch('/auth/totp/disable', { method: 'POST', body: { code: String(code) } });
  }

  // ============================
  // Files
  // ============================

  static MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB
  static MAX_LOGO_SIZE = 5 * 1024 * 1024;  // 5 MB

  async _validateFileSize(uri, maxBytes) {
    try {
      const RNFS = require('react-native-fs');
      const stat = await RNFS.stat(uri.replace(/^file:\/\//, ''));
      if (stat.size > maxBytes) {
        throw new Error(`File too large (${Math.round(stat.size / 1024 / 1024)}MB). Maximum: ${Math.round(maxBytes / 1024 / 1024)}MB`);
      }
    } catch (e) {
      if (e.message?.includes('too large')) throw e;
      // stat failed — let server enforce the limit
    }
  }

  async uploadFile(roomId, { filename, mimeType, fileBlob }) {
    await this._validateFileSize(fileBlob, NetworkService.MAX_FILE_SIZE);
    const form = new FormData();
    form.append('file', { uri: fileBlob, name: filename, type: mimeType });
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/files`, {
      method: 'POST',
      formData: form,
    });
    // → { token, filename, size_bytes }
  }

  async uploadDmFile(threadId, { filename, mimeType, fileBlob }) {
    await this._validateFileSize(fileBlob, NetworkService.MAX_FILE_SIZE);
    const form = new FormData();
    form.append('file', { uri: fileBlob, name: filename, type: mimeType });
    return this._fetch(`/dm/${encodeURIComponent(threadId)}/files`, {
      method: 'POST',
      formData: form,
    });
    // → { token, filename, size_bytes, url }
  }

  async uploadRoomLogo(roomId, { filename, mimeType, fileBlob }) {
    await this._validateFileSize(fileBlob, NetworkService.MAX_LOGO_SIZE);
    const form = new FormData();
    form.append('logo', { uri: fileBlob, name: filename, type: mimeType });
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/logo`, {
      method: 'POST',
      formData: form,
    });
  }

  getFileUrl(token) {
    return `${_apiBase}/files/${encodeURIComponent(token)}`;
  }

  getFileHeaders() {
    return this._token ? { Authorization: `Bearer ${this._token}` } : {};
  }

  // ============================
  // E2EE key endpoints
  // ============================

  async publishMyKey({ kid, publicKeyB64, alg = 'x25519' }) {
    return this._fetch('/keys/me', {
      method: 'POST',
      body: { kid, alg, public_key: publicKeyB64 },
    });
  }

  async fetchPeerKey(username) {
    return this._fetch(`/keys/${encodeURIComponent(username)}`);
    // → { kid, public_key, ed25519_public_key? }
  }

  async registerEd25519Key(publicKeyB64) {
    return this._fetch('/crypto/ed25519-key', {
      method: 'POST',
      body: { public_key: publicKeyB64 },
    });
    // → { ok: true, kid }
  }

  async changePassword(oldPassword, newPassword) {
    return this._fetch('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
  }

  /**
   * @deprecated Server returns 410. Identity is device-only now.
   * Kept for backward compat — callers should migrate to local StorageService.getIdentity().
   */
  async getCryptoKeys() {
    return this._fetch('/crypto/keys');
  }

  async shareRoomKey(roomId, targetUsername, encryptedRoomKey, keyId) {
    const body = { encrypted_room_key: encryptedRoomKey };
    if (keyId) body.key_id = keyId;
    return this._fetch(`/crypto/room/${encodeURIComponent(roomId)}/share?target_username=${encodeURIComponent(targetUsername)}`, {
      method: 'POST',
      body,
    });
  }

  async getRoomKey(roomId) {
    return this._fetch(`/crypto/room-key/${encodeURIComponent(roomId)}`);
    // → { encrypted_room_key } или 404
  }

  async getRoomKeyArchive(roomId) {
    return this._fetch(`/crypto/room-key/${encodeURIComponent(roomId)}/archive`);
    // → [{ encrypted_room_key, key_id }, ...] или 404
  }

  async postRoomKey(roomId, encryptedRoomKey, keyId) {
    const body = { room_id: roomId, encrypted_room_key: encryptedRoomKey };
    if (keyId) body.key_id = keyId;
    return this._fetch('/crypto/room-key', {
      method: 'POST',
      body,
    });
  }

  // ============================
  // Crypto session helpers (in-memory, без chrome.storage.session)
  // ============================

  setMasterKey(key) {
    this._masterKey   = key;
    this._masterKeyTs = Date.now();
  }

  getMasterKey(maxAgeMs = 10 * 60 * 1000) {
    if (!this._masterKey) return null;
    if (Date.now() - this._masterKeyTs > maxAgeMs) {
      this._masterKey = null;
      return null;
    }
    return this._masterKey;
  }

  clearMasterKey() {
    this._masterKey   = null;
    this._masterKeyTs = 0;
  }

  setKek(key) {
    this._kekKey = key;
    this._kekTs  = Date.now();
  }

  getKek(maxAgeMs = 20 * 60 * 1000) {
    if (!this._kekKey) return null;
    if (Date.now() - this._kekTs > maxAgeMs) {
      this._kekKey = null;
      return null;
    }
    return this._kekKey;
  }

  clearKek() {
    this._kekKey = null;
    this._kekTs  = 0;
  }

  // ============================
  // Getters
  // ============================

  get username()    { return this._username; }
  get token()       { return this._token; }
  get isLoggedIn()  { return !!this._token; }
  get activeRoomId()  { return this._wsRoomId; }
  get activeRoomName(){ return this._wsRoomName; }
  get activeDmThreadId() { return this._dmThreadId; }
  get activeDmPeer()     { return this._dmPeer; }

  // ============================
  // Feedback
  // ============================

  async sendFeedback(message, meta = {}) {
    return this._fetch('/feedback/send', {
      method: 'POST',
      body: { message, meta: { ts: Date.now(), client: 'android', ...meta } },
    });
  }

  // ============================
  // Утилиты
  // ============================

  _randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  _toBase64(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s);
  }

  _toBase64Url(buf) {
    return this._toBase64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  _fromBase64(b64) {
    let s = String(b64 || '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    const bin = atob(s);
    const u8  = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8.buffer;
  }

  openUrl(url) {
    // замена chrome.tabs.create({ url })
    Linking.openURL(url).catch(e => console.warn('[NS] openUrl error:', e?.message));
  }

  // ============================
  // Aliases for screen compatibility
  // ============================

  // Profile alias
  async getProfile() {
    return this.getMyProfile();
  }

  // 2FA aliases
  async get2faStatus() {
    return this.totpStatus();
  }

  async setup2fa() {
    return this.totpSetup();
  }

  async confirm2fa(code) {
    return this.totpVerifySetup(code);
  }

  async disable2fa(code) {
    if (!code) throw new Error('2FA code is required');
    return this.totpDisable(code);
  }

  // Room join aliases
  // POST /rooms/{roomId}/join-request — works for public rooms
  async joinPublicRoom(roomId, password) {
    const body = {};
    if (password) body.password = password;
    return this._fetch(`/rooms/${encodeURIComponent(roomId)}/join-request`, {
      method: 'POST',
      body,
    });
  }

  async requestJoinRoom(roomId) {
    return this.joinPublicRoom(roomId);
  }

  /** Fetch server broadcast notice (MOTD). Returns {active, message, type} or null. */
  async fetchNotice() {
    try {
      const _ctrl = new AbortController();
      const _t = setTimeout(() => _ctrl.abort(), 10_000);
      const r = await fetch(`${_apiBase}/api/notice`, { cache: 'no-store', signal: _ctrl.signal });
      clearTimeout(_t);
      if (!r.ok) return null;
      const data = await r.json();
      if (data.active && data.message) return data;
      return null;
    } catch (_e) {
      return null;
    }
  }

  // ============================
  // Server config (self-host support)
  // ============================

  /** Apply server config in-memory (does not persist). */
  setServerConfig(apiBase, wsBase) {
    _apiBase = (apiBase || DEFAULT_API_BASE).replace(/\/$/, '');
    _wsBase  = (wsBase  || _apiBase.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://')).replace(/\/$/, '');
  }

  /** Persist config to AsyncStorage and apply it. Disconnects all WebSockets (they belong to the old server). */
  async saveServerConfig(apiBase, wsBase) {
    this.setServerConfig(apiBase, wsBase);
    // Delivery secrets are scoped to a server — invalidate them on config change
    this._deliverySecretCache.clear();
    this._deliverySecretPending.clear();
    // Close all WS connections — they point to the old server
    this.disconnectRoom();
    this.disconnectDm();
    this.disconnectNotify();
    await AsyncStorage.setItem(SERVER_CONFIG_KEY, JSON.stringify({ apiBase: _apiBase, wsBase: _wsBase }));
  }

  /** Load persisted config from AsyncStorage and apply it. Call once at startup. */
  async loadServerConfig() {
    try {
      const raw = await AsyncStorage.getItem(SERVER_CONFIG_KEY);
      if (raw) {
        const cfg = JSON.parse(raw);
        if (cfg?.apiBase) this.setServerConfig(cfg.apiBase, cfg.wsBase || '');
      }
    } catch { /* use defaults */ }
  }

  /** Reset to the official server and remove persisted config. */
  async clearServerConfig() {
    _apiBase = DEFAULT_API_BASE;
    _wsBase  = DEFAULT_WS_BASE;
    // Delivery secrets are scoped to a server — invalidate them on config change
    this._deliverySecretCache.clear();
    this._deliverySecretPending.clear();
    await AsyncStorage.removeItem(SERVER_CONFIG_KEY);
  }

  /** Returns the currently active server config. */
  getServerConfig() {
    return { apiBase: _apiBase, wsBase: _wsBase, isDefault: _apiBase === DEFAULT_API_BASE };
  }

  // FCM token registration stub (endpoint may not exist on backend)
  async registerFcmToken(fcmToken) {
    try {
      return await this._fetch('/auth/fcm-token', {
        method: 'POST',
        body: { token: fcmToken },
      });
    } catch (_e) {
      // Silently ignore — FCM not required for core functionality
    }
  }
}

// Экспортируем синглтон
export default new NetworkService();
