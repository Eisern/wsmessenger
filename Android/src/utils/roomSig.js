// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * What a room message's signature result puts on its bubble.
 *
 * `r` is what CryptoService._openRoomEnvelope returns, or a guest-room feed
 * item carrying the same fields (guest-room-feed.js). One place, so the room
 * screen and the guest room screen say the same thing about the same result:
 *
 *   - _roomSigFailed:   the signature does not hold, or the envelope is one no
 *                       client writes (no signature, unreadable signature)
 *   - _roomSigMismatch: the envelope names somebody other than the server's
 *                       author (_signedBy says who)
 *   - _roomUnsigned:    no signature at all
 *   - _roomSigUnknown:  signed, but no signing key is known to check it
 *
 * "No key to check it" always names its signer; with no name and no
 * `unsigned` there is no verdict to show - a placeholder such as "key not
 * available" - and nothing is added.
 */
export function roomSigVerdict(r) {
  if (!r || typeof r !== 'object') return {};
  const v = {};
  if (r.sigValid === false) v._roomSigFailed = true;
  if (r.mismatch) {
    v._roomSigMismatch = true;
    v._signedBy = r.from || null;
  }
  if (r.sigValid === null && !r.mismatch) {
    if (r.unsigned) v._roomUnsigned = true;
    else if (r.from) v._roomSigUnknown = true;
  }
  return v;
}
