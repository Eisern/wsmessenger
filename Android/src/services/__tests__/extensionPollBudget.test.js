// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The extension's background poll (chrome_extension/panel.js) against the
 * island's rate limit for the friends lists (server/main.py).
 *
 * The three lists share one limit per user. Asked every 10-15 s, one idle
 * panel spent it in about four minutes and got 429 from then on - friend
 * requests stopped arriving, and nothing said so. Found on a live server; the
 * test stand raises every limit, so no integration suite could see it. The
 * limit is read from the server here, so changing either side re-checks both.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..', '..', '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8').split('\r\n').join('\n');

function serverLimit(name) {
  const m = read('server/main.py').match(new RegExp(`${name}\\s*=\\s*_env_int\\("${name}",\\s*(\\d+)\\)`));
  if (!m) throw new Error(`${name} not found in server/main.py`);
  return Number(m[1]);
}

function pollLoop() {
  const src = read('chrome_extension/panel.js');
  const start = src.indexOf('  const FRIENDS_POLL_EVERY');
  if (start < 0) throw new Error('the notification poll was not found in panel.js');
  const end = src.indexOf('\n  })();\n', start);
  return src.slice(start, end + '\n  })();\n'.length);
}

/** Ten minutes of the poll, every delay at its shortest. */
function simulate(minutes = 10) {
  const counts = { friends: 0, dmList: 0 };
  let pending = null;
  const sandbox = {
    isLoggedIn: true,
    Math: { random: () => 0 },
    setTimeout: (fn, ms) => { pending = { fn, ms }; },
    requestFriendsAll: () => { counts.friends += 1; },
    safePost: (m) => { if (m && m.type === 'dm_list') counts.dmList += 1; },
  };
  vm.createContext(sandbox);
  vm.runInContext(pollLoop(), sandbox, { filename: 'panel.js' });
  let t = 0;
  while (pending && t + pending.ms <= minutes * 60_000) {
    const { fn, ms } = pending;
    pending = null;
    t += ms;
    fn();
  }
  return counts;
}

test('the friends lists stay within half the island\'s limit, the rest for a second panel and a click', () => {
  const perUser = serverLimit('RL_FRIENDS_LIST_USER_PER_10MIN');
  const { friends } = simulate();
  // requestFriendsAll asks for three lists, all counted against the same limit.
  expect(friends * 3).toBeLessThanOrEqual(perUser / 2);
  expect(friends).toBeGreaterThan(0);
});

test('the DM list and room invitations keep the short cycle', () => {
  const { dmList } = simulate();
  expect(dmList).toBeGreaterThanOrEqual(10 * 60 / 15);
});
