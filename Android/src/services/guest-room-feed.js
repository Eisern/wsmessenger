// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// The message feed of a room on another island, as one open view sees it.
//
// A guest room is read from two sources at once: the island's history, and
// the room socket the client holds to it. Each is simple alone. Together they
// decide whether a message is lost, shown twice, shown out of order, or shown
// in a view that was already closed - and none of that is visible to any
// crypto test. So the ordering lives here, once, for both clients, with the
// socket, the island and the crypto injected; each client only draws.
//
// What it guarantees:
//
//   * Nothing written while the view opens is lost. The socket is connected
//     before the history is read, so a message is either in the history or
//     arrives on the socket afterwards. One that is both - stored before the
//     read, broadcast after it - is shown once: live frames carry no message
//     id, but a ciphertext is unique (random IV), so it is the identity.
//   * Nothing written while the socket was down is lost: the history is read
//     again when it comes back, and when it was first read without it.
//   * Everything that changes what is shown runs one step at a time, in the
//     order it was asked for. Decrypting is async; without this a live message
//     could overtake the one before it, or land in the middle of a history
//     redraw.
//   * After stop(), nothing reaches the view: every step checks that its feed
//     is still the open one.
//
// No chrome.*, no React Native, no DOM - as foreign-dm.js and guest-rooms.js.

(function (root) {
  "use strict";

  const SOCKET_WAIT_MS = 5000;
  const KEY_RETRY_MS = 30000;

  function noticeText(kind, detail) {
    switch (kind) {
      case "refused": return "Their server no longer lets you into this room.";
      case "history": return "Could not load this room from their server: " + String(detail || "no answer");
      case "server": return "Their server: " + String(detail || "").slice(0, 200);
      case "key-notFound":
        return "Waiting for this room's key. A moderator there sends it the next time their client " +
          "is open; it will show up here by itself.";
      case "key-refused":
        return "Their server offered a key for this room that nobody in it could have given you, so it was not used.";
      case "key-denied": return "Their server no longer lets you into this room.";
      case "key-unreachable": return "Their server did not answer. Messages will appear once it does.";
      case "key-locked": return "Unlock to read this room.";
      default: return "This room's key could not be loaded yet.";
    }
  }

  function keyNoticeKind(res) {
    if (res.notFound) return "key-notFound";
    if (res.refused) return "key-refused";
    if (res.denied) return "key-denied";
    if (res.unreachable) return "key-unreachable";
    if (res.locked) return "key-locked";
    return "key-error";
  }

  /**
   * @param {object} o
   * @param {function} o.openSocket   ({onMessage, onStatus}) => { send(text), close(), online }
   * @param {function} o.loadKey      async () => {ok, notFound?, refused?, denied?, unreachable?, locked?}
   * @param {function} o.fetchHistory async () => {messages:[{username, text, ts}]}; throws with .status
   * @param {function} o.decrypt      async (ciphertext, claimedAuthor) => string | {text, from, sigValid, mismatch} | null
   * @param {function} o.isMe         (username) => boolean
   * @param {function} o.onReset      (items) => void   - replace everything shown
   * @param {function} o.onAppend     (item) => void    - one more, at the end
   * @param {function} o.onNotice     ({kind, text}) => void
   * @param {function} [o.onStatus]   ({online}) => void
   * @param {object}   [o.timers]     { setTimeout, clearTimeout, setInterval, clearInterval }
   * @param {function} [o.now]
   * @param {function} [o.log]
   */
  function createFeed(o) {
    // Wrapped, not passed bare: a browser's setTimeout throws "Illegal
    // invocation" when called as a method of anything but the window.
    const T = o.timers || {
      setTimeout: (fn, ms) => setTimeout(fn, ms),
      clearTimeout: (h) => clearTimeout(h),
      setInterval: (fn, ms) => setInterval(fn, ms),
      clearInterval: (h) => clearInterval(h),
    };
    const now = o.now || (() => Date.now());
    const log = o.log || (() => {});

    let open = true;
    let started = false;
    let chain = Promise.resolve();
    const seen = new Set();
    let sock = null;
    let socketUp = false;
    let needResync = false;
    let keyTimer = null;
    // The last notice shown since the view was last redrawn: the same thing
    // said twice in a row - the socket and the history both refused - is
    // said once.
    let lastNotice = "";

    // One step at a time, and none after stop().
    function step(fn) {
      const run = chain.then(async () => {
        if (open) await fn();
      });
      chain = run.catch((e) => log("feed step failed", e && e.message ? e.message : e));
      return chain;
    }

    function notice(kind, detail) {
      if (!open) return;
      const text = noticeText(kind, detail);
      if (text === lastNotice) return;
      lastNotice = text;
      o.onNotice({ kind: kind, text: text });
    }

    async function item(user, ciphertext, ts) {
      const dec = await o.decrypt(ciphertext, user);
      if (!open || dec == null) return null;
      const isObj = typeof dec === "object";
      return {
        key: ciphertext,
        user: user,
        text: isObj ? String(dec.text == null ? "" : dec.text) : String(dec),
        ts: ts,
        mine: !!o.isMe(user),
        from: isObj ? (dec.from || null) : null,
        sigValid: isObj && dec.sigValid !== undefined ? dec.sigValid : null,
        mismatch: isObj ? !!dec.mismatch : false,
      };
    }

    async function readHistory() {
      let page;
      try {
        page = await o.fetchHistory();
      } catch (e) {
        const st = e && e.status;
        if (st === 401 || st === 403) notice("refused");
        else notice("history", e && e.message);
        return false;
      }
      if (!open) return false;
      const rows = (page && Array.isArray(page.messages)) ? page.messages : [];
      const items = [];
      for (const m of rows) {
        const ct = String((m && m.text) || "");
        seen.add(ct);
        const it = await item((m && m.username) || "unknown", ct, (m && m.ts) || null);
        if (!open) return false;
        if (it) items.push(it);
      }
      o.onReset(items);
      lastNotice = "";   // the redraw took whatever was said with it
      return true;
    }

    // A key load that throws is a failed key load - never a reason to skip
    // the history read that follows it.
    async function safeLoadKey() {
      try {
        return (await o.loadKey()) || { ok: false, error: true };
      } catch (e) {
        log("key load threw", e && e.message ? e.message : e);
        return { ok: false, error: true };
      }
    }

    function start() {
      if (started || !open) return chain;
      started = true;

      let markConnected;
      const connected = new Promise((resolve) => { markConnected = resolve; });

      sock = o.openSocket({
        onMessage: (m) => {
          step(async () => {
            const ct = String((m && m.text) || "");
            if (seen.has(ct)) return;
            seen.add(ct);
            const it = await item((m && m.from) || "unknown", ct, (m && m.ts) || now());
            if (it && open) o.onAppend(it);
          });
        },
        onStatus: (s) => {
          if (!open) return;
          const online = !!(s && s.online);
          if (o.onStatus) o.onStatus({ online: online });
          if (online && !socketUp) {
            socketUp = true;
            markConnected();
            if (needResync) {
              needResync = false;
              step(readHistory);
            }
          } else if (!online && socketUp) {
            socketUp = false;
            needResync = true;
          }
          if (s && s.error === "refused") {
            markConnected();
            step(async () => notice("refused"));
          } else if (online && s && s.error) {
            const said = s.error;
            step(async () => notice("server", said));
          }
        },
      });

      return step(async () => {
        let waited = null;
        await Promise.race([connected, new Promise((r) => { waited = T.setTimeout(r, SOCKET_WAIT_MS); })]);
        T.clearTimeout(waited);
        if (!open) return;
        if (!socketUp) needResync = true;
        const keyRes = await safeLoadKey();
        if (!open) return;
        await readHistory();
        if (!open || keyRes.ok) return;

        notice(keyNoticeKind(keyRes));
        // Worth asking again unless the answer was final: a key nobody could
        // have given (refused), a room we are no longer in (denied), or a lock -
        // the unlock re-reads the page and loads the key on its own.
        if (!keyRes.refused && !keyRes.denied && !keyRes.locked) {
          // Nothing tells a guest that its key has arrived - the island's
          // notify socket is not ours - so look again while the room is open.
          keyTimer = T.setInterval(async () => {
            if (!open) return;
            const again = await safeLoadKey();
            if (!again.ok || !open) return;
            T.clearInterval(keyTimer);
            keyTimer = null;
            step(readHistory);
          }, KEY_RETRY_MS);
        }
      });
    }

    function stop() {
      open = false;
      if (keyTimer) {
        T.clearInterval(keyTimer);
        keyTimer = null;
      }
      try { if (sock) sock.close(); } catch { /* already closed */ }
      sock = null;
    }

    /** Read the history again - after an unlock, say. */
    function refresh() {
      return step(readHistory);
    }

    function send(text) {
      if (!open || !sock) throw new Error("The room was closed");
      sock.send(text);
    }

    return {
      start: start,
      stop: stop,
      refresh: refresh,
      send: send,
      get open() { return open; },
      get online() { return !!(open && sock && sock.online); },
      /** Resolves once every step asked for so far has run. */
      idle: () => chain,
    };
  }

  const API = {
    SOCKET_WAIT_MS: SOCKET_WAIT_MS,
    KEY_RETRY_MS: KEY_RETRY_MS,
    createFeed: createFeed,
    noticeText: noticeText,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSGuestRoomFeed = API;
})(this);
