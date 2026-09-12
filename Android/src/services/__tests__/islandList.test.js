// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

const { ed25519 } = require('@noble/curves/ed25519');
const IL = require('../island-list');

// Real signatures, not mocks: a verifier tested against a stubbed "yes" would
// pass no matter what it checked.
const PRIV = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 7));
const PUB = ed25519.getPublicKey(PRIV);
const PUB_B64 = Buffer.from(PUB).toString('base64');

const OTHER_PRIV = Uint8Array.from(Array.from({ length: 32 }, (_, i) => 200 - i));
const OTHER_PUB_B64 = Buffer.from(ed25519.getPublicKey(OTHER_PRIV)).toString('base64');

const utf8Encode = (s) => new TextEncoder().encode(s);
const b64decode = (s) =>
  Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));

let now = 1_700_000_000_000;
const verifier = IL.createIslandListVerifier({
  ed25519Verify: (pub, sig, msg) => ed25519.verify(sig, msg, pub),
  b64decode,
  utf8Encode,
  now: () => now,
});

function makePayload(over = {}) {
  return {
    island_id: 'island-test',
    version: 3,
    issued_at: Math.floor(now / 1000),
    entry_points: [
      { apiBase: 'https://alpha.example', wsBase: 'wss://alpha.example', label: 'primary' },
      { apiBase: 'https://beta.example', wsBase: 'wss://beta.example', label: 'mirror' },
    ],
    relays: [{ id: 'relay-alpha', url: 'https://relay.example' }],
    transport_keys: [{ kid: 'q7dQJQ==', public_key_b64: PUB_B64 }],
    ...over,
  };
}

function sign(payload, priv = PRIV) {
  const msg = IL.signingMessage(payload, utf8Encode);
  return Buffer.from(ed25519.sign(msg, priv)).toString('base64');
}

function makeDoc(over = {}, { priv = PRIV, keyB64 = PUB_B64 } = {}) {
  const payload = makePayload(over);
  return { payload, sig_b64: sign(payload, priv), signing_key_b64: keyB64 };
}

const PIN = { signingKeyB64: PUB_B64, islandId: 'island-test', version: 3 };

describe('canonical JSON', () => {
  it('sorts keys, drops whitespace and recurses', () => {
    expect(IL.canonicalJson({ b: 1, a: [2, { d: 4, c: 3 }] })).toBe('{"a":[2,{"c":3,"d":4}],"b":1}');
  });

  it('emits non-ASCII string values raw, which is what the island signs', () => {
    // The island canonicalizes with ensure_ascii=False for exactly this reason;
    // escaping on one side and not the other would break every signature the
    // moment a label stopped being English.
    expect(IL.canonicalJson({ label: 'основной' })).toBe('{"label":"основной"}');
  });

  it('skips undefined members the way the island omits absent ones', () => {
    expect(IL.canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe('verification', () => {
  it('accepts a correctly signed document and returns a pin', async () => {
    const r = await verifier.verify(makeDoc(), null);
    expect(r.ok).toBe(true);
    expect(r.pin).toEqual({ signingKeyB64: PUB_B64, islandId: 'island-test', version: 3 });
    expect(r.payload.entryPoints).toHaveLength(2);
    expect(r.payload.relays[0].id).toBe('relay-alpha');
    expect(r.payload.transportKeys[0].publicKeyB64).toBe(PUB_B64);
  });

  it('rejects a document whose payload was altered after signing', async () => {
    const doc = makeDoc();
    doc.payload.entry_points.push({ apiBase: 'https://attacker.example', wsBase: 'wss://attacker.example' });
    const r = await verifier.verify(doc, PIN);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('bad signature');
  });

  it('rejects a document signed by a different key once the real one is pinned', async () => {
    // The attack this exists to stop: ship your own key alongside your own
    // signature and the document verifies against itself.
    const doc = makeDoc({}, { priv: OTHER_PRIV, keyB64: OTHER_PUB_B64 });
    expect((await verifier.verify(doc, PIN)).reason).toBe('bad signature');

    // ...and without a pin it WOULD be accepted, which is precisely why the
    // first contact has to be honest and the key has to be pinned.
    expect((await verifier.verify(doc, null)).ok).toBe(true);
  });

  it('refuses to roll back to an older version', async () => {
    const r = await verifier.verify(makeDoc({ version: 2 }), PIN);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('rollback');
  });

  it('accepts the same version and newer ones', async () => {
    expect((await verifier.verify(makeDoc({ version: 3 }), PIN)).ok).toBe(true);
    expect((await verifier.verify(makeDoc({ version: 4 }), PIN)).ok).toBe(true);
  });

  it('refuses a document for a different island', async () => {
    const r = await verifier.verify(makeDoc({ island_id: 'somewhere-else' }), PIN);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('different island');
  });

  it('refuses malformed input without throwing', async () => {
    for (const bad of [null, {}, { payload: null }, { payload: {} }, { payload: makePayload(), sig_b64: 'zz' }]) {
      const r = await verifier.verify(bad, PIN);
      expect(r.ok).toBe(false);
      expect(typeof r.reason).toBe('string');
    }
  });

  it('refuses a document with no usable entry point', async () => {
    const r = await verifier.verify(makeDoc({ entry_points: [] }), PIN);
    expect(r.ok).toBe(false);
    expect(r.reason).toBe('no entry points');
  });

  it('flags a stale document but still accepts it', async () => {
    // A client cut off from every entry point cannot refresh. Refusing the last
    // known list would turn a censorship event into a total outage.
    const old = makeDoc({ issued_at: Math.floor((now - IL.STALE_AFTER_MS - 1000) / 1000) });
    const r = await verifier.verify(old, PIN);
    expect(r.ok).toBe(true);
    expect(r.stale).toBe(true);
  });
});

describe('payload normalization', () => {
  it('bounds the lists and drops duplicates and junk', () => {
    const p = IL.normalizePayload({
      island_id: 'x',
      version: 1,
      entry_points: [
        { apiBase: 'https://a.example/' },
        { apiBase: 'https://a.example' },     // duplicate after trailing-slash strip
        { noApiBase: true },
        ...Array.from({ length: 20 }, (_, i) => ({ apiBase: `https://h${i}.example` })),
      ],
      relays: Array.from({ length: 40 }, (_, i) => ({ id: `r${i}`, url: `https://r${i}.example` })),
      transport_keys: Array.from({ length: 10 }, (_, i) => ({ kid: `k${i}`, public_key_b64: 'AA==' })),
    });
    expect(p.entryPoints.length).toBe(IL.MAX_ENTRY_POINTS);
    expect(p.entryPoints[0].apiBase).toBe('https://a.example');
    expect(p.relays.length).toBe(IL.MAX_RELAYS);
    expect(p.transportKeys.length).toBe(4);
  });

  it('derives wsBase nothing and keeps labels short', () => {
    const p = IL.normalizePayload({
      island_id: 'x',
      version: 1,
      entry_points: [{ apiBase: 'https://a.example', label: 'x'.repeat(200) }],
    });
    expect(p.entryPoints[0].wsBase).toBe('');    // the island states it; we do not invent it
    expect(p.entryPoints[0].label.length).toBe(40);
  });
});
