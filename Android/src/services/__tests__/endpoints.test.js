// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

const EP = require('../endpoints');

const DEFAULTS = { defaultApiBase: 'https://default.example', defaultWsBase: 'wss://default.example' };

function cfgOf(hosts, activeIdx) {
  return EP.normalizeServerConfig(
    {
      schema: 2,
      endpoints: hosts.map((h) => ({ apiBase: `https://${h}` })),
      activeIdx: activeIdx || 0,
    },
    DEFAULTS,
  );
}

describe('normalizeServerConfig', () => {
  it('upgrades the legacy {apiBase, wsBase} shape in place', () => {
    const cfg = EP.normalizeServerConfig(
      { apiBase: 'https://alpha.example', wsBase: 'wss://alpha.example' },
      DEFAULTS,
    );
    expect(cfg.schema).toBe(2);
    expect(cfg.endpoints).toHaveLength(1);
    expect(cfg.endpoints[0].apiBase).toBe('https://alpha.example');
    expect(cfg.activeIdx).toBe(0);
    // The mirror is what every pre-existing reader consumes.
    expect(cfg.apiBase).toBe('https://alpha.example');
    expect(cfg.wsBase).toBe('wss://alpha.example');
  });

  it('falls back to the supplied default for null and for garbage', () => {
    for (const raw of [null, undefined, 42, 'nonsense', {}, { endpoints: 'x' }]) {
      const cfg = EP.normalizeServerConfig(raw, DEFAULTS);
      expect(cfg.endpoints).toHaveLength(1);
      expect(cfg.apiBase).toBe('https://default.example');
    }
  });

  it('derives wsBase when missing and keeps an explicit one', () => {
    const cfg = EP.normalizeServerConfig(
      {
        schema: 2,
        endpoints: [{ apiBase: 'https://a.example' }, { apiBase: 'https://b.example', wsBase: 'wss://ws.b.example' }],
      },
      DEFAULTS,
    );
    expect(cfg.endpoints[0].wsBase).toBe('wss://a.example');
    expect(cfg.endpoints[1].wsBase).toBe('wss://ws.b.example');
  });

  it('strips path and query down to the origin', () => {
    const cfg = EP.normalizeServerConfig({ apiBase: 'https://a.example/api/v2?x=1#frag' }, DEFAULTS);
    expect(cfg.endpoints[0].apiBase).toBe('https://a.example');
  });

  it('drops unparseable and non-http entries', () => {
    const cfg = EP.normalizeServerConfig(
      {
        schema: 2,
        endpoints: [
          { apiBase: 'not a url' },
          { apiBase: 'ftp://a.example' },
          null,
          { apiBase: 'https://good.example' },
        ],
      },
      DEFAULTS,
    );
    expect(cfg.endpoints.map((e) => e.apiBase)).toEqual(['https://good.example']);
  });

  it('dedupes by apiBase and caps the list', () => {
    const dupes = EP.normalizeServerConfig(
      {
        schema: 2,
        endpoints: [{ apiBase: 'https://a.example' }, { apiBase: 'https://a.example/other' }],
      },
      DEFAULTS,
    );
    expect(dupes.endpoints).toHaveLength(1);

    const many = EP.normalizeServerConfig(
      {
        schema: 2,
        endpoints: Array.from({ length: 20 }, (_, i) => ({ apiBase: `https://h${i}.example` })),
      },
      DEFAULTS,
    );
    expect(many.endpoints).toHaveLength(EP.MAX_ENDPOINTS);
  });

  it('clamps activeIdx into range and keeps the mirror in sync with it', () => {
    const hosts = ['https://a.example', 'https://b.example'];
    const mk = (idx) =>
      EP.normalizeServerConfig({ schema: 2, endpoints: hosts.map((h) => ({ apiBase: h })), activeIdx: idx }, DEFAULTS);

    expect(mk(1).apiBase).toBe('https://b.example');
    expect(mk(1).wsBase).toBe('wss://b.example');
    for (const bad of [-1, 5, NaN, 'x', null]) {
      expect(mk(bad).activeIdx).toBe(0);
      expect(mk(bad).apiBase).toBe('https://a.example');
    }
  });
});

describe('classifyConfigChange', () => {
  it('reports island when the entry-point sets are disjoint', () => {
    expect(EP.classifyConfigChange(cfgOf(['a.example']), cfgOf(['z.example']))).toBe('island');
  });

  it('reports endpoints when the sets overlap — the session must survive', () => {
    expect(EP.classifyConfigChange(cfgOf(['a.example']), cfgOf(['a.example', 'b.example']))).toBe('endpoints');
    expect(EP.classifyConfigChange(cfgOf(['a.example', 'b.example']), cfgOf(['b.example']))).toBe('endpoints');
  });

  it('reports none for an identical list at the same active index', () => {
    expect(EP.classifyConfigChange(cfgOf(['a.example', 'b.example']), cfgOf(['a.example', 'b.example']))).toBe('none');
  });

  it('treats a reordered list and a moved activeIdx as an endpoint change, never as an island change', () => {
    expect(EP.classifyConfigChange(cfgOf(['a.example', 'b.example']), cfgOf(['b.example', 'a.example']))).toBe(
      'endpoints',
    );
    expect(EP.classifyConfigChange(cfgOf(['a.example', 'b.example'], 0), cfgOf(['a.example', 'b.example'], 1))).toBe(
      'endpoints',
    );
  });

  it('treats an empty side as an island change', () => {
    expect(EP.classifyConfigChange({ endpoints: [] }, cfgOf(['a.example']))).toBe('island');
  });
});

describe('classifyHttpFailure', () => {
  const cases = [
    ['network failure normalized by Android _fetch', { status: 0 }, 'rotate'],
    ['fetch TypeError in the extension', { name: 'TypeError', message: 'Failed to fetch' }, 'rotate'],
    ['request aborted on timeout', { name: 'AbortError' }, 'rotate'],
    ['no status at all', {}, 'rotate'],
    ['401 — the server spoke', { status: 401 }, 'ignore'],
    ['403 — the server spoke', { status: 403 }, 'ignore'],
    ['429 — the server spoke', { status: 429 }, 'ignore'],
    ['500 with an application body', { status: 500, body: { detail: 'boom' } }, 'ignore'],
    ['503 with an empty body — edge up, backend unreachable', { status: 503, body: '' }, 'strike'],
    ['502 with no body', { status: 502 }, 'strike'],
    ['504 carrying a JSON detail', { status: 504, body: '{"detail":"upstream"}' }, 'ignore'],
  ];

  it.each(cases)('%s', (_label, err, expected) => {
    expect(EP.classifyHttpFailure(err)).toBe(expected);
  });
});

describe('classifyWsClose', () => {
  const cases = [
    ['1006 before onopen — the entry point never answered', { code: 1006, opened: false }, 'rotate'],
    ['1006 after a short life — suspicious only', { code: 1006, opened: true, uptimeMs: 4000 }, 'strike'],
    ['1006 after a long session — ordinary drop', { code: 1006, opened: true, uptimeMs: 600000 }, 'ignore'],
    ['1008 policy close (wrong room password)', { code: 1008, opened: true, uptimeMs: 200 }, 'ignore'],
    ['1009 message too large', { code: 1009, opened: true, uptimeMs: 100 }, 'ignore'],
    ['1013 rate limited', { code: 1013, opened: false }, 'ignore'],
    ['1000 normal close', { code: 1000, opened: true, uptimeMs: 10 }, 'ignore'],
  ];

  it.each(cases)('%s', (_label, info, expected) => {
    expect(EP.classifyWsClose(info)).toBe(expected);
  });

  it('escalates to a rotation on the second consecutive strike', async () => {
    const sel = EP.createSelector({ cfg: cfgOf(['a.example', 'b.example']), probe: () => Promise.resolve(true) });
    expect((await sel.reportFailure('strike', 0)).rotated).toBe(false);
    expect((await sel.reportFailure('strike', 0)).rotated).toBe(true);
  });
});

describe('createSelector', () => {
  let t;
  const now = () => t;

  beforeEach(() => {
    t = 1000;
  });

  function make(hosts, probeImpl, activeIdx) {
    const probe = jest.fn(probeImpl);
    const sel = EP.createSelector({ cfg: cfgOf(hosts, activeIdx), probe, now });
    return { sel, probe };
  }

  it('starts on the persisted active index and does not probe', () => {
    const { sel, probe } = make(['a.example', 'b.example'], () => Promise.resolve(true), 1);
    expect(sel.activeEndpoint().apiBase).toBe('https://b.example');
    expect(probe).not.toHaveBeenCalled();
  });

  it('rotates to the next reachable entry point and updates the mirror', async () => {
    const { sel } = make(['a.example', 'b.example'], (e) => Promise.resolve(e.apiBase === 'https://b.example'));
    const r = await sel.reportFailure('rotate', 0);
    expect(r.rotated).toBe(true);
    expect(sel.activeEndpoint().apiBase).toBe('https://b.example');
    expect(sel.config().apiBase).toBe('https://b.example');
    expect(sel.config().wsBase).toBe('wss://b.example');
    expect(sel.config().activeIdx).toBe(1);
    expect(sel.epGen()).toBe(1);
  });

  it('ignores an ignore-class report and stays put', async () => {
    const { sel, probe } = make(['a.example', 'b.example'], () => Promise.resolve(true));
    const r = await sel.reportFailure('ignore', 0);
    expect(r.rotated).toBe(false);
    expect(probe).not.toHaveBeenCalled();
    expect(sel.activeIndex()).toBe(0);
  });

  // The rotation-storm invariant: all three sockets die together, and that is
  // ONE dead entry point, not three.
  it('collapses three simultaneous failures into exactly one rotation', async () => {
    const { sel, probe } = make(
      ['a.example', 'b.example', 'c.example'],
      (e) => Promise.resolve(e.apiBase === 'https://b.example'),
    );

    const results = await Promise.all([
      sel.reportFailure('rotate', 0),
      sel.reportFailure('rotate', 0),
      sel.reportFailure('rotate', 0),
    ]);

    expect(probe).toHaveBeenCalledTimes(1);
    expect(sel.epGen()).toBe(1);
    expect(sel.activeIndex()).toBe(1);
    expect(results.filter((r) => r.rotated)).toHaveLength(3); // one rotation, one shared promise
  });

  it('drops a report that describes an entry point we already left', async () => {
    const { sel, probe } = make(['a.example', 'b.example'], () => Promise.resolve(true));
    await sel.reportFailure('rotate', 0);
    probe.mockClear();

    const stale = await sel.reportFailure('rotate', 0); // gen is 1 now
    expect(stale.stale).toBe(true);
    expect(probe).not.toHaveBeenCalled();
  });

  it('refuses a second rotation inside the cooldown', async () => {
    const { sel } = make(['a.example', 'b.example', 'c.example'], () => Promise.resolve(true));
    await sel.reportFailure('rotate', 0);

    t += EP.ROTATE_COOLDOWN_MS - 1;
    const blocked = await sel.reportFailure('rotate', sel.epGen());
    expect(blocked.rotated).toBe(false);
    expect(blocked.cooldown).toBe(true);

    t += 2;
    const allowed = await sel.reportFailure('rotate', sel.epGen());
    expect(allowed.rotated).toBe(true);
  });

  // A verdict that re-trying cannot change ("this entry point rejected our
  // session") must not be pinned by the cooldown of the rotation that landed
  // us there. It cannot storm: the entry point is blacklisted first.
  it('lets a forced report bypass the cooldown', async () => {
    const { sel } = make(['a.example', 'b.example', 'c.example'], () => Promise.resolve(true));
    await sel.reportFailure('rotate', 0);
    expect(sel.activeIndex()).toBe(1);

    sel.markUnusable('https://b.example', 'foreignIsland');
    const forced = await sel.reportFailure('rotate', sel.epGen(), { force: true });
    expect(forced.rotated).toBe(true);
    // Back to the preferred entry point, not merely the next one in the list.
    expect(sel.activeEndpoint().apiBase).toBe('https://a.example');
    expect(sel.isUnusable('https://b.example')).toBe('foreignIsland');
  });

  it('reports exhaustion with a growing backoff and never moves or clears anything', async () => {
    const { sel } = make(['a.example', 'b.example'], () => Promise.resolve(false));

    const first = await sel.reportFailure('rotate', 0);
    expect(first.rotated).toBe(false);
    expect(first.exhausted).toBe(true);
    expect(first.retryAfterMs).toBe(EP.EXHAUST_BACKOFF_MS[0]);
    expect(sel.activeIndex()).toBe(0); // still on the last known-good entry point

    const second = await sel.reportFailure('rotate', 0);
    expect(second.retryAfterMs).toBe(EP.EXHAUST_BACKOFF_MS[1]);
  });

  it('resets the strike and exhaustion counters when the endpoint proves alive', async () => {
    const { sel } = make(['a.example', 'b.example'], () => Promise.resolve(false));
    await sel.reportFailure('strike', 0);
    expect(sel.state().strikes).toBe(1);

    sel.noteAlive(sel.epGen());
    expect(sel.state().strikes).toBe(0);
    expect(sel.state().exhaustCount).toBe(0);
  });

  it('ignores noteAlive from a stale generation', async () => {
    const { sel } = make(['a.example', 'b.example'], () => Promise.resolve(true));
    await sel.reportFailure('strike', 0);
    expect(sel.noteAlive(99)).toBe(false);
    expect(sel.state().strikes).toBe(1);
  });

  it('comes home to a preferred entry point, but not before the interval', async () => {
    const { sel } = make(['a.example', 'b.example'], () => Promise.resolve(true));
    await sel.reportFailure('rotate', 0);
    expect(sel.activeIndex()).toBe(1);

    const tooSoon = await sel.maybeComeHome();
    expect(tooSoon.rotated).toBe(false);
    expect(tooSoon.throttled).toBe(true);

    t += EP.COME_HOME_INTERVAL_MS + 1;
    const home = await sel.maybeComeHome();
    expect(home.rotated).toBe(true);
    expect(sel.activeIndex()).toBe(0);
  });

  it('stays put when coming home finds the preferred entry point still dead', async () => {
    const { sel } = make(['a.example', 'b.example'], (e) => Promise.resolve(e.apiBase === 'https://b.example'));
    await sel.reportFailure('rotate', 0);

    t += EP.COME_HOME_INTERVAL_MS + 1;
    const r = await sel.maybeComeHome();
    expect(r.rotated).toBe(false);
    expect(sel.activeIndex()).toBe(1);
  });

  it('skips entry points marked unusable (foreign island, missing permission)', async () => {
    const { sel, probe } = make(
      ['a.example', 'b.example', 'c.example'],
      () => Promise.resolve(true),
    );
    sel.markUnusable('https://b.example', 'foreignIsland');
    expect(sel.isUnusable('https://b.example')).toBe('foreignIsland');

    await sel.reportFailure('rotate', 0);
    expect(sel.activeEndpoint().apiBase).toBe('https://c.example');
    expect(probe).toHaveBeenCalledTimes(1);
    expect(probe.mock.calls[0][0].apiBase).toBe('https://c.example');
  });

  it('survives a probe that throws', async () => {
    const { sel } = make(['a.example', 'b.example', 'c.example'], (e) => {
      if (e.apiBase === 'https://b.example') return Promise.reject(new Error('boom'));
      return Promise.resolve(true);
    });
    const r = await sel.reportFailure('rotate', 0);
    expect(r.rotated).toBe(true);
    expect(sel.activeEndpoint().apiBase).toBe('https://c.example');
  });

  it('setConfig reports the change class and clears blacklists only on an island change', () => {
    const { sel } = make(['a.example', 'b.example'], () => Promise.resolve(true));
    sel.markUnusable('https://b.example', 'foreignIsland');

    expect(sel.setConfig(cfgOf(['a.example', 'b.example', 'x.example']))).toBe('endpoints');
    expect(sel.isUnusable('https://b.example')).toBe('foreignIsland');

    expect(sel.setConfig(cfgOf(['z.example']))).toBe('island');
    expect(sel.isUnusable('https://b.example')).toBe(null);
  });
});

describe('per-thread key slots', () => {
  it('gives two islands different slots for the same thread id', () => {
    const a = EP.threadRid(EP.islandIdOf(cfgOf(['alpha.example'])), 42);
    const b = EP.threadRid(EP.islandIdOf(cfgOf(['beta.example'])), 42);
    expect(a).toBe('dm:alpha.example:42');
    expect(b).toBe('dm:beta.example:42');
    expect(a).not.toBe(b);
  });

  // The slot is a key slot: a room id must never be able to reach a DM slot,
  // and vice versa, whatever the numbers happen to be.
  it('cannot collide with a room slot', () => {
    expect(EP.threadRid('alpha.example', 7)).not.toBe(7);
    expect(typeof EP.threadRid('alpha.example', 7)).toBe('string');
  });

  it('rotating to another entry point of the same island keeps the slot', () => {
    const cfg = cfgOf(['alpha.example', 'bridge.example']);
    const rotated = { ...cfg, activeIdx: 1, apiBase: 'https://bridge.example' };
    expect(EP.threadRid(EP.islandIdOf(rotated), 42)).toBe(
      EP.threadRid(EP.islandIdOf(cfg), 42),
    );
  });

  it('refuses a slot it cannot qualify rather than inventing a shared one', () => {
    expect(EP.threadRid('', 42)).toBe('');
    expect(EP.threadRid('alpha.example', 0)).toBe('');
    expect(EP.threadRid('alpha.example', -1)).toBe('');
    expect(EP.threadRid('alpha.example', 1.5)).toBe('');
    expect(EP.threadRid('alpha.example', 'nope')).toBe('');
  });

  it('is case- and whitespace-insensitive, so one island is one slot', () => {
    expect(EP.threadRid('  Alpha.Example  ', '42')).toBe('dm:alpha.example:42');
  });

  it('falls back to the active host for a config written before islandId', () => {
    expect(EP.islandIdOf({ apiBase: 'https://Legacy.Example/api' })).toBe('legacy.example');
    expect(EP.islandIdOf(null)).toBe('');
  });

  it('still names the slot that stored archives were written under', () => {
    expect(EP.legacyThreadRid(42)).toBe(1000000042);
    expect(EP.legacyThreadRid(0)).toBe(0);
    expect(EP.legacyThreadRid('x')).toBe(0);
  });
});
