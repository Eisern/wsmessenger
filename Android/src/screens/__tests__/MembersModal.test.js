// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The two room-key and guest controls in a room's member list (ChatScreen's
 * MembersModal): "Send missing keys" and "Invite someone from another
 * server". Owners and admins see them, members do not; each calls the service
 * with this room, and says what came of it.
 */

import React from 'react';
import ReactTestRenderer, { act } from 'react-test-renderer';
import { Alert } from 'react-native';

jest.mock('@react-navigation/native', () => ({ useFocusEffect: () => {} }));
jest.mock('react-native-keyboard-controller', () => {
  const { View } = require('react-native');
  return { KeyboardAvoidingView: View };
});
jest.mock('react-native-safe-area-context', () => ({ useSafeAreaInsets: () => ({ top: 0, bottom: 0 }) }));
jest.mock('@react-native-clipboard/clipboard', () => ({ setString: () => {} }));
jest.mock('@react-native-documents/picker', () => ({ pick: async () => [], types: {} }));
jest.mock('../../contexts/AppContext', () => ({ useApp: () => ({ state: {}, dispatch: () => {} }) }));
jest.mock('../../components/FileCard', () => () => null);
jest.mock('../../components/RoomLogo', () => () => null);
jest.mock('../../services/NetworkService', () => ({ __esModule: true, default: { on: () => () => {}, off: () => {} } }));
jest.mock('../../services/StorageService', () => ({ __esModule: true, default: {} }));
jest.mock('../../services/CryptoService', () => ({ __esModule: true, default: { on: () => () => {} } }));
jest.mock('../../services/ForeignService', () => ({
  __esModule: true,
  default: {
    listContacts: jest.fn(async () => [
      { kid: 'k1', displayName: 'Alice', island: { islandId: 'island-g.test' } },
    ]),
  },
}));
jest.mock('../../services/GuestRoomService', () => ({
  __esModule: true,
  default: { inviteContact: jest.fn(async () => ({ guestName: 'Alice@island-g.test~k1', status: 'pending', queued: false })) },
}));
jest.mock('../../services/KeySweepService', () => ({
  __esModule: true,
  default: {
    run: jest.fn(async () => ({ ran: true, shared: 2, alreadyHad: 0, skipped: 1, failed: 0 })),
    trustBlocked: jest.fn(() => [{ username: 'carl', reason: 'TRUST_CHANGED', rooms: [7] }, { username: 'dee', rooms: [8] }]),
    schedule: () => {},
    onDone: () => () => {},
  },
}));

import { MembersModal } from '../ChatScreen';
import KeySweepService from '../../services/KeySweepService';
import GuestRoomService from '../../services/GuestRoomService';

const alerts = [];
const mounted = [];
beforeEach(() => {
  alerts.length = 0;
  jest.spyOn(Alert, 'alert').mockImplementation((title, msg) => { alerts.push([title, msg]); });
  KeySweepService.run.mockClear();
  GuestRoomService.inviteContact.mockClear();
});
afterEach(async () => {
  // Unmounted inside act: a list left mounted keeps rendering after the test.
  await act(async () => { while (mounted.length) mounted.pop().unmount(); });
  jest.restoreAllMocks();
});

async function render(myRole) {
  let tree;
  await act(async () => {
    tree = ReactTestRenderer.create(
      <MembersModal
        visible
        onClose={() => {}}
        members={[]}
        onlineUsers={[]}
        roomId={7}
        roomName="Book club"
        myUsername="mod"
        myRole={myRole}
        onMembersChanged={() => {}}
        onLeaveRoom={() => {}}
        onSystemMessage={() => {}}
      />,
    );
  });
  mounted.push(tree);
  return tree;
}

const textOf = (tree) => tree.root.findAll((n) => typeof n.props.children === 'string').map((n) => n.props.children);
function press(tree, label) {
  const btn = tree.root.findAll((n) => typeof n.props.onPress === 'function'
    && n.findAll((c) => c.props.children === label).length > 0)[0];
  if (!btn) throw new Error(`no button "${label}"`);
  return btn.props.onPress();
}

test('a member sees neither control', async () => {
  const tree = await render('member');
  expect(textOf(tree)).not.toContain('Send missing keys');
  expect(textOf(tree)).not.toContain('Invite someone from another server');
});

test.each(['owner', 'admin'])('an %s sends missing keys for this room, and is told who waits for verification', async (role) => {
  const tree = await render(role);
  await act(async () => { await press(tree, 'Send missing keys'); });
  expect(KeySweepService.run).toHaveBeenCalledWith({ roomId: 7, reason: 'manual', interactive: true });
  expect(alerts).toHaveLength(1);
  const [, msg] = alerts[0];
  expect(msg).toMatch(/Delivered to 2 member/);
  expect(msg).toMatch(/1 skipped/);
  expect(msg).toMatch(/Verify the safety number of carl first/);
  expect(msg).not.toMatch(/dee/);   // blocked in another room
});

test('a run that could not get the list says so, instead of "everyone has the key"', async () => {
  KeySweepService.run.mockResolvedValueOnce({ ran: true, shared: 0, alreadyHad: 0, skipped: 0, failed: 0, incomplete: true });
  const tree = await render('owner');
  await act(async () => { await press(tree, 'Send missing keys'); });
  expect(alerts[0][1]).toMatch(/Could not get the list of missing keys/);
  expect(alerts[0][1]).not.toMatch(/Everyone/);
});

test('a run that did not start says so instead of reporting zeros', async () => {
  KeySweepService.run.mockResolvedValueOnce({ ran: false, shared: 0, alreadyHad: 0, skipped: 0, failed: 0 });
  const tree = await render('owner');
  await act(async () => { await press(tree, 'Send missing keys'); });
  expect(alerts[0][1]).toMatch(/Already running, locked, or tried a moment ago/);
});

test('inviting from another server: pick a contact, and this room is what they are invited into', async () => {
  const tree = await render('admin');
  await act(async () => { await press(tree, 'Invite someone from another server'); });
  expect(textOf(tree)).toContain('Alice');
  await act(async () => { await press(tree, 'Alice'); });
  expect(GuestRoomService.inviteContact).toHaveBeenCalledWith(7, 'k1', 'Book club');
  expect(alerts[0][0]).toBe('Invited');
  expect(alerts[0][1]).toMatch(/Alice is invited as Alice@island-g\.test~k1/);
  // The picker closes on success.
  expect(textOf(tree)).toContain('Invite someone from another server');
});
