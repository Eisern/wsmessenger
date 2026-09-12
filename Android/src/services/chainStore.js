// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Where each thread's hash chains live on this device.
 *
 * Two chains per thread: the one this device writes (outgoing) and the one it
 * verifies (incoming, per peer). See thread-chain.js for what they are for.
 *
 * Deliberately NOT secret, and deliberately not in the Keychain: these are
 * hashes of bytes the peer already signed, so they reveal nothing a thief of
 * the device would not get from the message store next to them. They are
 * integrity-relevant rather than confidential — an attacker who can rewrite
 * them can hide a break — but such an attacker already holds the keys, and
 * encrypting a value against someone who has the key buys nothing.
 *
 * A chain is per (thread, writer). Losing this state is survivable: the chain
 * resynchronises from the next message, at the cost of one reported gap.
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import TC from './thread-chain';

const PREFIX = 'chain_v1:';

function keyFor(threadId, who) {
  return `${PREFIX}${String(threadId)}:${String(who || 'out')}`;
}

const ChainStore = {
  /** Current head for a writer in a thread; genesis when nothing is stored. */
  async get(threadId, who) {
    try {
      const raw = await AsyncStorage.getItem(keyFor(threadId, who));
      if (!raw) return { seq: 0, hash: TC.GENESIS_HEX };
      const parsed = JSON.parse(raw);
      if (typeof parsed?.seq === 'number' && /^[0-9a-f]{64}$/.test(parsed?.hash || '')) {
        return { seq: parsed.seq, hash: parsed.hash };
      }
    } catch (_e) { /* unreadable state is the same as no state */ }
    return { seq: 0, hash: TC.GENESIS_HEX };
  },

  async set(threadId, who, state) {
    if (!state || typeof state.seq !== 'number') return;
    try {
      await AsyncStorage.setItem(
        keyFor(threadId, who),
        JSON.stringify({ seq: state.seq, hash: state.hash }),
      );
    } catch (e) {
      // Failing to persist means the next message reports a gap, which is
      // noisy but honest. It must never block sending.
      console.warn('[ChainStore] save failed:', e?.message);
    }
  },

  /** Forget a thread's chains — used when its history is deleted. */
  async clearThread(threadId) {
    try {
      const keys = await AsyncStorage.getAllKeys();
      const mine = keys.filter((k) => k.startsWith(`${PREFIX}${String(threadId)}:`));
      if (mine.length) await AsyncStorage.multiRemove(mine);
    } catch (_e) { /* best effort */ }
  },

  keyFor,
};

export default ChainStore;
