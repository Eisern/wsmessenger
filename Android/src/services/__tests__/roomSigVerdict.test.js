// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * What a room message's signature result puts on its bubble on Android
 * (src/utils/roomSig.js, used by ChatScreen and GuestRoomScreen).
 *
 * A forgery or a moved author is a warning; no signature, or no key to check
 * one, is a quieter note - but never nothing, because every client signs and
 * an unsigned message under somebody's name is how words get put in their
 * mouth. A placeholder ("key not available") has no verdict and gets none.
 */

import { roomSigVerdict } from '../../utils/roomSig';

test('a signature that holds adds nothing', () => {
  expect(roomSigVerdict({ text: 'x', from: 'bob', sigValid: true, mismatch: false })).toEqual({});
});

test('a signature that fails is a failure', () => {
  expect(roomSigVerdict({ from: 'bob', sigValid: false, mismatch: false })).toEqual({ _roomSigFailed: true });
});

test('an envelope naming somebody else says who signed it', () => {
  expect(roomSigVerdict({ from: 'bob', sigValid: true, mismatch: true }))
    .toEqual({ _roomSigMismatch: true, _signedBy: 'bob' });
});

test('no signature at all is marked unsigned', () => {
  expect(roomSigVerdict({ text: 'x', from: null, sigValid: null, mismatch: false, unsigned: true }))
    .toEqual({ _roomUnsigned: true });
});

test('signed but nothing to check it against is marked unverified', () => {
  expect(roomSigVerdict({ from: 'dave', sigValid: null, mismatch: false })).toEqual({ _roomSigUnknown: true });
});

test('a placeholder, or no result, says nothing', () => {
  expect(roomSigVerdict('[Encrypted message - key not available]')).toEqual({});
  expect(roomSigVerdict(null)).toEqual({});
  // A guest-room feed item made from a placeholder: no name, not unsigned.
  expect(roomSigVerdict({ from: null, sigValid: null, mismatch: false, unsigned: false })).toEqual({});
});
