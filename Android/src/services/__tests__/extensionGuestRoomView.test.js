// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The order of things in the extension's view of a room on another island.
 *
 * The view (chrome_extension/panel-ui.js, "Rooms on other servers, as a
 * guest", over guest-room-feed.js) juggles a socket, a history read and async
 * decryption. Each is easy
 * to get right alone; together they decide whether a message is lost, drawn
 * twice, drawn out of order, or drawn into a view that was closed - none of
 * which any crypto test would notice. So the section runs here for real, with
 * the socket, the island and the crypto replaced by things the test steps
 * through by hand. Nothing waits on a clock.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PANEL_UI = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'panel-ui.js');
const FEED = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'guest-room-feed.js');
const MARKER = '// Rooms on other servers, as a guest';

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

const flush = async (n = 20) => {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
};

function makeView() {
  const src = fs.readFileSync(PANEL_UI, 'utf8');
  const at = src.indexOf(MARKER);
  if (at < 0) throw new Error('guest view section not found in panel-ui.js');
  const section = src.slice(src.lastIndexOf('\n', at - 2) + 1);

  const log = [];        // what the chat area shows, in order
  const sockets = [];
  const island = {
    history: [],         // ciphertexts, oldest first
    historyGate: null,   // a promise the next history read waits for
    decryptGate: {},     // ciphertext -> promise its decryption waits for
    keyRes: { ok: true },
  };

  const sandbox = {
    console, setTimeout, clearTimeout, setInterval, clearInterval, Promise, String, Number, Array, Set,
    document: { getElementById: () => null, createElement: () => ({ style: {}, classList: { add() {} }, appendChild() {} }) },
    __ui: { alert: async () => {}, confirm: async () => true, prompt: async () => '' },
    ensureCryptoReady: async () => true,
    safePost: () => {},
    setInviteVisible: () => {},
    clearChat: () => { log.push('|clear|'); },
    renderPresence: () => {},
    renderCurrentRoom: () => {},
    highlightActiveRoom: () => {},
    parseV2Payload: (t) => ({ text: t, reply: null }),
    addMsg: (user, text) => { log.push(text); },
    __warnAboutRoomSignature: () => {},
    formatMsgTime: () => '',
    listGuestRooms: async () => [],
    loadGuestRoomKey: async () => island.keyRes,
    fetchGuestRoomHistory: async () => {
      const gate = island.historyGate;
      const snapshot = island.history.slice();
      if (gate) await gate;
      return { messages: snapshot.map((text, i) => ({ id: i + 1, username: 'carol', text, ts: i })) };
    },
    decryptFromGuestRoom: async (room, ct) => {
      if (island.decryptGate[ct]) await island.decryptGate[ct];
      return { text: ct, from: 'carol', sigValid: true, mismatch: false };
    },
    openGuestRoomSocket: (room, handlers) => {
      const sock = {
        room, handlers, closed: false,
        close() { this.closed = true; },
        send() {},
        get online() { return false; },
        up() { if (!this.closed) handlers.onStatus({ online: true }); },
        down() { if (!this.closed) handlers.onStatus({ online: false }); },
        deliver(text) { if (!this.closed) handlers.onMessage({ type: 'message', room_id: room.roomId, from: 'carol', text }); },
      };
      sockets.push(sock);
      return sock;
    },
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(`
    let activeGuestRoom = null;
    let __guestFeed = null;
    let activeRoomId = null, activeRoomName = "", activeRoomKey = "";
    let lastHistoryRoomId = null, renderedHistoryRoomId = null;
    const __apiBaseReady = Promise.resolve();
    const GR = () => ({ sameRoom: (a, b) => !!a && !!b && a.islandId === b.islandId && a.roomId === b.roomId });
    function setModeRoom() { closeGuestRoomView(); }
    function setModeDm() { closeGuestRoomView(); }
  `, sandbox);
  vm.runInContext(fs.readFileSync(FEED, 'utf8'), sandbox, { filename: 'guest-room-feed.js' });
  vm.runInContext(section, sandbox, { filename: 'panel-ui.js#guest' });

  return {
    sandbox, log, sockets, island,
    open: (room) => sandbox.openGuestRoomView(room),
    openDm: () => vm.runInContext('setModeDm()', sandbox),
    // What the chat area shows now: everything after the last clear.
    screen: () => log.slice(log.lastIndexOf('|clear|') + 1),
    live: () => sockets.filter((s) => !s.closed),
  };
}

const ROOM = { islandId: 'island-r', roomId: 42, roomName: 'Book club', guestName: 'alice@g~1' };

describe('a guest room being opened', () => {
  test('reads the history only once the socket is up, so nothing written in between is lost', async () => {
    const V = makeView();
    V.island.history = ['h1', 'h2'];
    const opened = V.open(ROOM);
    await flush();
    expect(V.screen()).toEqual([]);   // still waiting for the socket

    // Written now: before the socket, so it must come from the history read.
    V.island.history.push('m3');
    V.sockets[0].up();
    await opened;
    await flush();
    expect(V.screen()).toEqual(['h1', 'h2', 'm3']);
  });

  test('draws a message that is both in the history and on the socket once', async () => {
    const V = makeView();
    V.island.history = ['h1'];
    const gate = deferred();
    V.island.historyGate = gate.promise;
    const opened = V.open(ROOM);
    await flush();
    V.sockets[0].up();
    await flush();

    // Stored before the history read, broadcast while it is in flight.
    V.island.history.push('m2');   // too late for this read's snapshot
    V.sockets[0].deliver('m2');
    V.island.history = ['h1', 'm2'];
    gate.resolve();
    await opened;
    await flush();
    expect(V.screen()).toEqual(['h1', 'm2']);

    // And the history reading it too, then the live copy arriving late.
    V.island.historyGate = null;
    V.island.history = ['h1', 'm2', 'm3'];
    V.sockets[0].down();
    V.sockets[0].up();           // resync: history now has m3
    await flush();
    V.sockets[0].deliver('m3');  // its live copy, late
    await flush();
    expect(V.screen()).toEqual(['h1', 'm2', 'm3']);
  });

  test('after the socket drops, what was written meanwhile is read from the history', async () => {
    const V = makeView();
    V.island.history = ['h1'];
    const opened = V.open(ROOM);
    await flush();
    V.sockets[0].up();
    await opened;
    await flush();

    V.sockets[0].down();
    V.island.history.push('while-away');
    V.sockets[0].up();
    await flush();
    expect(V.screen()).toEqual(['h1', 'while-away']);
  });

  test('live messages keep their order when the first takes longer to decrypt', async () => {
    const V = makeView();
    const opened = V.open(ROOM);
    await flush();
    V.sockets[0].up();
    await opened;
    await flush();

    const slow = deferred();
    V.island.decryptGate.l1 = slow.promise;
    V.sockets[0].deliver('l1');
    V.sockets[0].deliver('l2');
    await flush();
    expect(V.screen()).toEqual([]);
    slow.resolve();
    await flush();
    expect(V.screen()).toEqual(['l1', 'l2']);
  });
});

describe('a guest room being closed or replaced', () => {
  test('opening the same room twice leaves one socket, and one copy of each message', async () => {
    const V = makeView();
    V.island.history = ['h1'];
    const first = V.open(ROOM);
    const second = V.open(ROOM);
    await flush();
    for (const s of V.sockets) s.up();
    await Promise.all([first, second]);
    await flush();

    expect(V.live()).toHaveLength(1);
    expect(V.sockets.length).toBe(2);
    for (const s of V.sockets) s.deliver('x');   // the closed one delivers nothing
    await flush();
    expect(V.screen()).toEqual(['h1', 'x']);
  });

  test('a history read that finishes after the view closed draws nothing', async () => {
    const V = makeView();
    V.island.history = ['h1'];
    const gate = deferred();
    V.island.historyGate = gate.promise;
    const opened = V.open(ROOM);
    await flush();
    V.sockets[0].up();
    await flush();

    V.openDm();
    const shown = V.log.length;
    gate.resolve();
    await opened;
    await flush();
    expect(V.log.length).toBe(shown);
    expect(V.live()).toHaveLength(0);
    expect(vm.runInContext('activeGuestRoom', V.sandbox)).toBeNull();
  });

  test('a message decrypting while another room is opened lands in neither', async () => {
    const V = makeView();
    const opened = V.open(ROOM);
    await flush();
    V.sockets[0].up();
    await opened;
    await flush();

    const slow = deferred();
    V.island.decryptGate.late = slow.promise;
    V.sockets[0].deliver('late');
    await flush();

    const other = V.open({ ...ROOM, roomId: 43 });
    await flush();
    V.sockets[1].up();
    slow.resolve();
    await other;
    await flush();
    expect(V.log).not.toContain('late');
  });
});
