// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * GuestRoomScreen draws what its feed hands it and sends through it - and
 * nothing more. The feed's ordering has its own tests (guestRoomFeed.test.js);
 * this holds the screen to its half: the feed is opened with the room and
 * closed with the screen, items are drawn oldest at the top in the order they
 * came, a file is not offered as something this app could open, a message goes
 * out only through the room's own socket and only while it is up.
 */

import React from 'react';
import ReactTestRenderer, { act } from 'react-test-renderer';

const mockFeed = {
  handlers: null,
  started: 0,
  stopped: 0,
  sent: [],
  refreshed: 0,
};
const mockUnlocked = { listener: null, removed: 0 };

jest.mock('@react-navigation/native', () => {
  const R = require('react');
  return { useFocusEffect: (cb) => R.useEffect(() => cb(), []) };
});
jest.mock('react-native-keyboard-controller', () => {
  const { View } = require('react-native');
  return { KeyboardAvoidingView: View };
});
jest.mock('react-native-safe-area-context', () => ({
  useSafeAreaInsets: () => ({ top: 0, bottom: 0, left: 0, right: 0 }),
}));
jest.mock('../../components/RoomLogo', () => () => null);
jest.mock('../ChatScreen', () => {
  const { Text } = require('react-native');
  return {
    MessageBubble: ({ msg }) => (
      <Text testID="bubble">{`${msg.author}|${msg._decrypted}|${msg._roomSigFailed ? 'sigfail' : 'ok'}`}</Text>
    ),
    chatStyles: {},
  };
});
jest.mock('../../services/CryptoService', () => ({
  __esModule: true,
  default: {
    on: (event, fn) => {
      if (event === 'unlocked') mockUnlocked.listener = fn;
      return () => { mockUnlocked.removed += 1; };
    },
  },
}));
jest.mock('../../services/GuestRoomService', () => ({
  __esModule: true,
  default: {
    createFeed: (room, handlers) => {
      mockFeed.handlers = handlers;
      mockFeed.room = room;
      return {
        start: () => { mockFeed.started += 1; return Promise.resolve(); },
        stop: () => { mockFeed.stopped += 1; },
        refresh: () => { mockFeed.refreshed += 1; },
        send: (t) => { mockFeed.sent.push(t); },
      };
    },
    encrypt: jest.fn(async (room, text) => `ct(${text})`),
    leave: jest.fn(async () => true),
  },
}));

import GuestRoomScreen from '../GuestRoomScreen';
import GuestRoomService from '../../services/GuestRoomService';
import { makeFileMarker } from '../../utils/fileMarker';

const ROOM = { islandId: 'island-r.test', roomId: 42, roomName: 'Book club', guestName: 'Alice@g~ab' };

function item(text, extra = {}) {
  return { key: text, user: 'carol', text, ts: 1700000000, mine: false, from: 'carol', sigValid: true, mismatch: false, ...extra };
}

function bubbles(tree) {
  // The list is inverted: index 0 is the newest. Read it back oldest-first.
  return tree.root.findAll((n) => n.props.testID === 'bubble' && typeof n.type === 'string')
    .map((n) => n.props.children)
    .reverse();
}

async function render() {
  let tree;
  await act(async () => {
    tree = ReactTestRenderer.create(
      <GuestRoomScreen navigation={{ goBack: jest.fn() }} route={{ params: { room: ROOM } }} />,
    );
  });
  return tree;
}

beforeEach(() => {
  Object.assign(mockFeed, { handlers: null, started: 0, stopped: 0, sent: [], refreshed: 0 });
  Object.assign(mockUnlocked, { listener: null, removed: 0 });
  GuestRoomService.encrypt.mockClear();
});

test('opens the feed with the room, and closes it with the screen', async () => {
  const tree = await render();
  expect(mockFeed.room).toBe(ROOM);
  expect(mockFeed.started).toBe(1);
  await act(async () => { tree.unmount(); });
  expect(mockFeed.stopped).toBe(1);
  expect(mockUnlocked.removed).toBe(1);
});

test('draws oldest at the top, in the order the feed hands things over', async () => {
  const tree = await render();
  await act(async () => {
    mockFeed.handlers.onReset([item('h1'), item('h2', { sigValid: false })]);
    mockFeed.handlers.onAppend(item('live'));
    mockFeed.handlers.onNotice({ kind: 'server', text: 'Their server: rate limited' });
  });
  expect(bubbles(tree)).toEqual([
    'carol|h1|ok', 'carol|h2|sigfail', 'carol|live|ok', 'System|Their server: rate limited|ok',
  ]);

  // A redraw replaces what is shown - it does not add to it.
  await act(async () => { mockFeed.handlers.onReset([item('only')]); });
  expect(bubbles(tree)).toEqual(['carol|only|ok']);
});

test('a file is not offered as something this app could open; a reply shows its text', async () => {
  const tree = await render();
  const file = makeFileMarker('tok', 'a.pdf', 10);
  await act(async () => {
    mockFeed.handlers.onReset([
      item(file),
      item(JSON.stringify({ v: 2, t: 'answer', reply: { author: 'bob', text: 'q' } })),
    ]);
  });
  const [first, second] = bubbles(tree);
  expect(first).toMatch(/files in rooms on other servers cannot be opened/i);
  expect(second).toBe('carol|answer|ok');
});

test('sends through the room\'s socket only while it is up', async () => {
  const tree = await render();
  const input = tree.root.findByProps({ multiline: true });
  const sendBtn = () => tree.root.findAll((n) => n.props.onPress && n.props.disabled !== undefined).at(-1);

  await act(async () => { input.props.onChangeText('hello'); });
  expect(sendBtn().props.disabled).toBe(true);   // not connected yet

  await act(async () => { mockFeed.handlers.onStatus({ online: true }); });
  expect(sendBtn().props.disabled).toBe(false);
  await act(async () => { await sendBtn().props.onPress(); });
  expect(GuestRoomService.encrypt).toHaveBeenCalledWith(ROOM, 'hello');
  expect(mockFeed.sent).toEqual(['ct(hello)']);
  expect(tree.root.findByProps({ multiline: true }).props.value).toBe('');
});

test('reads the page again after an unlock', async () => {
  await render();
  await act(async () => { mockUnlocked.listener(); });
  expect(mockFeed.refreshed).toBe(1);
});
