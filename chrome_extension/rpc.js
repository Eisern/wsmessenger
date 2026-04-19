// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// rpc.js (transport + RPC)
// Единственный источник правды про chrome.runtime.connect({name:"ws-panel"})
// Используется и в login.html, и в panel.html.
(() => {
  "use strict";

  /** @type {chrome.runtime.Port|null} */
  let port = null;
  let connecting = false;

  // Subscribers for ALL incoming messages
  /** @type {Set<(msg:any)=>void>} */
  const subscribers = new Set();

  // Connection status callbacks
  /** @type {Set<()=>void>} */
  const onConnectCbs = new Set();
  /** @type {Set<()=>void>} */
  const onDisconnectCbs = new Set();

  // Outgoing queue (for safePost) while disconnected
  /** @type {any[]} */
  const outbox = [];

  let reconnectAttempts = 0;
  let reconnectTimer = null;

  function _notifyConnect() {
    try { onConnectCbs.forEach((fn) => { try { fn(); } catch {} }); } catch {}
  }
  function _notifyDisconnect() {
    try { onDisconnectCbs.forEach((fn) => { try { fn(); } catch {} }); } catch {}
  }

  function _scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectAttempts++;
    const base = Math.min(30000, 1000 * Math.pow(2, reconnectAttempts - 1));
    const jitter = Math.floor(Math.random() * 500);
    const delay = base + jitter;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connectPort();
    }, delay);
  }

  function _flushOutbox() {
    if (!port) return;
    while (outbox.length) {
      const msg = outbox.shift();
      try { port.postMessage(msg); } catch (e) {
        // Port died mid-flush; put message back and reconnect
        outbox.unshift(msg);
        try { port.disconnect(); } catch {}
        port = null;
        _notifyDisconnect();
        _scheduleReconnect();
        return;
      }
    }
  }

  function connectPort() {
    if (port) return port;
    if (connecting) return port;
    connecting = true;

    try {
      port = chrome.runtime.connect({ name: "ws-panel" });

      port.onMessage.addListener((msg) => {
        // First inbound message proves the port can actually round-trip
        // (chrome.runtime.connect returns synchronously and failures arrive
        // async via onDisconnect, so resetting the backoff inside connectPort
        // resets it before we know whether the connection actually works).
        // Defer the reset until we have proof of liveness.
        if (reconnectAttempts) reconnectAttempts = 0;

        // Fan out to subscribers
        subscribers.forEach((fn) => {
          try { fn(msg); } catch (e) {
            // never break others
            try { console.warn("rpc subscriber failed:", e); } catch {}
          }
        });
      });

port.onDisconnect.addListener(() => {
  const le = chrome.runtime?.lastError;
  if (le?.message) console.warn("port disconnected:", le.message);

  port = null;
  connecting = false;
  _notifyDisconnect();
  _scheduleReconnect();
});

      // NOTE: reconnectAttempts is reset only after we receive the first
      // inbound message (see port.onMessage listener above). Resetting here
      // would defeat exponential backoff in the SW-flapping case.
      connecting = false;
      _notifyConnect();
      _flushOutbox();

      return port;
} catch (e) {
  const le = chrome.runtime?.lastError;
  console.warn("connectPort failed:", e?.message || e, { lastError: le?.message || le });
  port = null;
  connecting = false;
  _scheduleReconnect();
  return null;
}

  }

  function disconnectPort() {
    if (!port) return;
    try { port.disconnect(); } catch {}
    port = null;
    connecting = false;
    _notifyDisconnect();
  }

  function onMessage(handler) {
    if (typeof handler === "function") subscribers.add(handler);
  }

  function offMessage(handler) {
    try { subscribers.delete(handler); } catch {}
  }

  function onConnect(handler) {
    if (typeof handler === "function") onConnectCbs.add(handler);
  }

  function onDisconnect(handler) {
    if (typeof handler === "function") onDisconnectCbs.add(handler);
  }

  function safePost(msg) {
    // never throw to callers; queue and attempt reconnect
    if (!port) {
      outbox.push(msg);
      connectPort();
      return;
    }
    try {
      port.postMessage(msg);
    } catch (e) {
      outbox.push(msg);
      try { port.disconnect(); } catch {}
      port = null;
      _notifyDisconnect();
      _scheduleReconnect();
    }
  }

  // Public API
  window.connectPort = connectPort;
  window.safePost = safePost;
  window.rpcOnMessage = onMessage;
  window.rpcOffMessage = offMessage;
  window.rpcOnConnect = onConnect;
  window.rpcOnDisconnect = onDisconnect;
  window.rpcDisconnect = disconnectPort;
  window.rpcGetPort = () => port;
})();
