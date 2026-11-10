// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * What the extension does right after an invitation goes out
 * (chrome_extension/panel.js, the "rooms_invite" answer).
 *
 * It used to hand the room key to the invitee at once. The island gives keys
 * to members only, and an invitee is not one until they accept, so that share
 * was refused every time and the owner saw "Invite OK, but key share failed"
 * after every invitation. The key goes over when they accept, through the
 * sweep the island wakes; here the sweep is only asked to look at the room.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PANEL = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'panel.js');

function inviteHandler() {
  const src = fs.readFileSync(PANEL, 'utf8').split('\r\n').join('\n');
  const head = 'if (msg.type === "rooms_invite") {';
  const start = src.indexOf(head);
  if (start < 0) throw new Error('rooms_invite handler not found in panel.js');
  const end = src.indexOf('\n}\n', start);
  return `async function handle(msg) {\n${src.slice(start, end + 2)}\n}`;
}

function make() {
  const seen = { alerts: [], shares: [], sweeps: [], refreshed: 0 };
  const sandbox = {
    console: { log() {}, warn() {} },
    __ui: { alert: async (t) => { seen.alerts.push(t); } },
    shareRoomKeyToUser: async (rid, name) => { seen.shares.push(`${rid}:${name}`); throw new Error('Target user is not a member of this room'); },
    scheduleRoomKeySweep: (reason, opts) => { seen.sweeps.push({ reason, roomId: opts && opts.roomId }); },
    requestMyRooms: () => { seen.refreshed += 1; },
    roomOwnerById: { 7: true },
    activeRoomId: 7,
    __lastInviteRoomId: null,
  };
  vm.createContext(sandbox);
  vm.runInContext(inviteHandler(), sandbox, { filename: 'panel.js' });
  return { sandbox, seen };
}

const flush = async () => { for (let i = 0; i < 10; i++) await new Promise((r) => setImmediate(r)); };

test('an invitation says it was sent, and nothing about a key it could not share yet', async () => {
  const P = make();
  vm.runInContext('handle({ type: "rooms_invite", ok: true, roomId: 7, username: "bob" })', P.sandbox);
  await flush();
  expect(P.seen.alerts).toEqual(['Invited: bob']);
  expect(P.seen.shares).toEqual([]);
  expect(P.seen.sweeps).toEqual([{ reason: 'invite', roomId: 7 }]);
  expect(P.seen.refreshed).toBe(1);
});

test('a refused invitation says why, and asks nothing else', async () => {
  const P = make();
  vm.runInContext('handle({ type: "rooms_invite", ok: false, message: "User does not accept group invites" })', P.sandbox);
  await flush();
  expect(P.seen.alerts).toEqual(['User does not accept group invites']);
  expect(P.seen.sweeps).toEqual([]);
});
