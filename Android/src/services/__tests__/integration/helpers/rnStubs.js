// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Platform stubs so the real NetworkService can run under node against a real
// backend. Only the React Native surface is replaced; fetch, WebSocket and all
// of the service's own logic are the genuine article.

const _mem = new Map();

const AsyncStorage = {
  async getItem(k) { return _mem.has(k) ? _mem.get(k) : null; },
  async setItem(k, v) { _mem.set(k, String(v)); },
  async removeItem(k) { _mem.delete(k); },
  async getAllKeys() { return [..._mem.keys()]; },
  async multiRemove(keys) { for (const k of keys) _mem.delete(k); },
  async clear() { _mem.clear(); },
  __dump: () => Object.fromEntries(_mem),
};

const _kc = new Map();
const Keychain = {
  async setGenericPassword(username, password, opts = {}) {
    _kc.set(opts.service || '__default', { username, password });
    return true;
  },
  async getGenericPassword(opts = {}) {
    return _kc.get(opts.service || '__default') || false;
  },
  async resetGenericPassword(opts = {}) { _kc.delete(opts.service || '__default'); return true; },
  async getAllGenericPasswordServices() { return [..._kc.keys()]; },
  ACCESSIBLE: { WHEN_UNLOCKED_THIS_DEVICE_ONLY: 'WhenUnlockedThisDeviceOnly' },
  ACCESS_CONTROL: {},
  SECURITY_LEVEL: {},
  STORAGE_TYPE: {},
};

const AppState = {
  currentState: 'active',
  addEventListener: () => ({ remove() {} }),
};

const Linking = { openURL: async () => {} };

// Recorded rather than shown: a test that unlocks the real CryptoService can
// reach a path that alerts, and swallowing it silently would hide that.
const _alerts = [];
const Alert = {
  alert(title, message) { _alerts.push({ title, message }); },
};

module.exports = { AsyncStorage, Keychain, AppState, Linking, Alert, _alerts, _mem, _kc };
