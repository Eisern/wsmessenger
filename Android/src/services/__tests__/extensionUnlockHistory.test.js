// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * What the extension does with the open room when the crypto session is
 * unlocked again (chrome_extension/panel.js, retryPendingHistoryAfterUnlock
 * and the "ws_crypto_unlocked" listener).
 *
 * While locked, a message that arrives cannot be decrypted and is dropped, and
 * a history that comes back clears the chat without drawing it. So unlocking
 * has to read the page again - for years this called a function that did not
 * exist, inside a try/catch that hid it, and only from the overlay's button;
 * the room stayed empty or short of what came in meanwhile until it was opened
 * again. The real code runs here, with the panel's surroundings replaced.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PANEL = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'panel.js');
const panelSource = () => fs.readFileSync(PANEL, 'utf8').split('\r\n').join('\n');

/** The source from `head` up to and including the first line that is just `close`. */
function block(head, close) {
  const src = panelSource();
  const start = src.indexOf(head);
  if (start < 0) throw new Error(`${head} not found in panel.js`);
  const end = src.indexOf('\n' + close + '\n', start);
  return src.slice(start, end + close.length + 2);
}

function make({ active = 7, pending = 7, keyOk = true, dmMode = false, activeGuestRoom = null } = {}) {
  const posts = [];
  const sandbox = {
    console: { log() {}, warn() {} },
    setTimeout: (fn) => fn(),
    refreshGuestRoomAfterUnlock: () => {},
    loadRoomKey: async () => ({ ok: keyOk }),
    safePost: (m) => posts.push(m),
    HISTORY_PAGE_SIZE: 50,
    activeRoomId: active,
    dmMode,
    activeGuestRoom,
    renderedHistoryRoomId: active,   // what was drawn before the lock
    __pendingHistoryRoomId: pending,
    __pendingHistorySince: 0,
  };
  vm.createContext(sandbox);
  vm.runInContext(block('async function retryPendingHistoryAfterUnlock()', '}'), sandbox, { filename: 'panel.js' });
  return { sandbox, posts, run: () => vm.runInContext('retryPendingHistoryAfterUnlock()', sandbox) };
}

describe('unlocking with a room open', () => {
  test('reads the room again, past the "already drawn" guard', async () => {
    const P = make();
    await P.run();
    expect(P.posts).toEqual([{ type: 'history_get', roomId: 7, limit: 50 }]);
    expect(P.sandbox.renderedHistoryRoomId).toBeNull();
    expect(P.sandbox.__pendingHistoryRoomId).toBeNull();
  });

  test('a key that still does not load keeps the room pending and asks for nothing', async () => {
    const P = make({ keyOk: false });
    await P.run();
    expect(P.posts).toEqual([]);
    expect(P.sandbox.__pendingHistoryRoomId).toBe(7);
  });

  test('a room left meanwhile is not drawn into the one now open', async () => {
    const P = make({ active: 8, pending: 7 });
    await P.run();
    expect(P.posts).toEqual([]);
  });

  test('nor into a direct conversation, or a room on another island', async () => {
    const dm = make({ dmMode: true });
    await dm.run();
    expect(dm.posts).toEqual([]);
    const guest = make({ activeGuestRoom: { id: 1 } });
    await guest.run();
    expect(guest.posts).toEqual([]);
  });

  test('nothing pending, nothing asked', async () => {
    const P = make({ pending: null });
    await P.run();
    expect(P.posts).toEqual([]);
  });
});

describe('every way of unlocking', () => {
  // The overlay's button is one way; a password asked for by an action is
  // another. Both end in "ws_crypto_unlocked", so that is where the open room
  // and conversation are read again.
  test('reads the open room and conversation again', () => {
    const handlers = {};
    const calls = [];
    const sandbox = {
      window: { addEventListener: (name, fn) => { handlers[name] = fn; } },
      __setCryptoUiLocked: (v) => calls.push(`locked:${v}`),
      retryPendingHistoryAfterUnlock: async () => { calls.push('history'); },
      retryPendingDmAfterUnlock: async () => { calls.push('dm'); },
    };
    vm.createContext(sandbox);
    vm.runInContext(block('window.addEventListener("ws_crypto_unlocked"', '});'), sandbox, { filename: 'panel.js' });
    handlers.ws_crypto_unlocked();
    expect(calls).toEqual(['locked:false', 'history', 'dm']);
  });
});
