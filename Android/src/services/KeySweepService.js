// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * KeySweepService.js — hand the room key to every accepted member who has none.
 *
 * Until this, Android shared a key only from the room screen of an owner who
 * happened to have that room open when somebody accepted. Everybody else -
 * a member who accepted while the owner was away, an admin's rooms, a guest
 * from another island - waited for somebody's browser extension to do it.
 *
 * When to run, how often and what a failure means is key-sweep.js, shared with
 * the extension byte for byte. This file supplies the Android halves - how to
 * fetch the list of gaps and how to share one key - and the triggers: unlock,
 * the notify socket's `notify_key_gap`, a membership change seen on a room
 * socket, a room opened by its owner or an admin, a peer verified, and the
 * manual "Send missing keys".
 *
 * It never prompts: a locked app defers to the unlock trigger.
 */

import NetworkService from './NetworkService';
import CryptoService from './CryptoService';
import KS from './key-sweep';

const _listeners = new Set();

/** Infrastructure trouble - worth the global backoff - as opposed to one pair. */
function isTransient(e) {
  if (e?.code === 'TRUST_UNVERIFIABLE') return true;
  const st = e?.status;
  return st === 0 || st === 429 || (typeof st === 'number' && st >= 500);
}

const _sweep = KS.createKeySweep({
  isReady: async ({ interactive }) => {
    // Signed out: nothing to serve, and a request would only run into the
    // session-expired path.
    if (!NetworkService._token) return false;
    if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: !!interactive });
    return CryptoService.isReady();
  },
  fetchGaps: async ({ roomId, limit }) => {
    let body;
    try {
      body = await NetworkService.getRoomKeyGaps({ roomId, limit });
    } catch (e) {
      // Not a provider for this room, or it is gone: an answer, not a failure.
      if (e?.status === 403 || e?.status === 404) return { gaps: [], truncated: false, notProvider: true };
      throw e;
    }
    return { gaps: Array.isArray(body?.gaps) ? body.gaps : [], truncated: !!body?.truncated };
  },
  refreshRoomKey: async (roomId) => {
    await CryptoService._loadRoomKey(roomId);
  },
  share: async (roomId, username) => {
    const res = await CryptoService.shareRoomKeyToUser(roomId, username, { ifAbsent: true });
    // `false` is "locked" - not an answer about this member.
    if (res === false) throw Object.assign(new Error('Locked'), { status: 0 });
    return res;
  },
  isTransient,
  onDone: (summary, blocked) => {
    for (const fn of _listeners) {
      try { fn(summary, blocked); } catch (_e) { /* a listener's problem */ }
    }
  },
  log: (...args) => console.log('[KeySweep]', ...args),
});

let _started = false;
const _unsubs = [];

/** Subscribe to the triggers. Idempotent; the app calls it once at start. */
function start() {
  if (_started) return;
  _started = true;

  _unsubs.push(CryptoService.on('unlocked', () => _sweep.schedule('unlock', { delayMs: 2500 })));
  // The key going away also ends whatever this session learned: cooldowns and
  // blocks are cheap to learn again, and stale ones would outlive an account.
  _unsubs.push(CryptoService.on('locked', () => _sweep.reset()));
  _unsubs.push(CryptoService.on('peer_verified', ({ username } = {}) => {
    _sweep.clearTrustBlock(username);
    _sweep.schedule('verified');
  }));

  const onGap = (msg) => {
    const rid = Number(msg?.room_id) || 0;
    _sweep.schedule('notify', rid ? { roomId: rid } : {});
  };
  const onMembers = (msg) => {
    const action = String(msg?.action || '');
    const rid = Number(msg?.room_id) || 0;
    // Somebody just became an accepted member, so they hold no key yet. The
    // sweep asks the island who is actually missing one; a non-provider is
    // answered with nothing.
    if (rid && (action === 'invite_accepted' || action === 'join_approved')) {
      _sweep.schedule(action, { roomId: rid });
    }
  };
  NetworkService.on('notify_key_gap', onGap);
  NetworkService.on('members_changed', onMembers);
  _unsubs.push(() => NetworkService.off('notify_key_gap', onGap));
  _unsubs.push(() => NetworkService.off('members_changed', onMembers));

  if (CryptoService.isReady()) _sweep.schedule('startup', { delayMs: 2500 });
}

function stop() {
  while (_unsubs.length) {
    try { _unsubs.pop()(); } catch (_e) { /* already gone */ }
  }
  _sweep.reset();
  _started = false;
}

/** Listen for finished runs: (summary, trustBlocked) => void. Returns an unsubscribe. */
function onDone(fn) {
  _listeners.add(fn);
  return () => _listeners.delete(fn);
}

const KeySweepService = {
  start,
  stop,
  onDone,
  /** An automatic trigger: one timer, the run's own clock applies. */
  schedule: (reason, opts) => _sweep.schedule(reason, opts),
  /** A run now - for "Send missing keys", which may ask to unlock. */
  run: (opts) => _sweep.run(opts),
  trustBlocked: () => _sweep.trustBlocked(),
  clearTrustBlock: (name) => _sweep.clearTrustBlock(name),
  isTransient,
};

export default KeySweepService;
