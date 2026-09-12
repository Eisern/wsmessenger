// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Relay prototype: a direct message delivered through a node that cannot read it.
 *
 * Topology under test — the real one, not a simulation:
 *   test client  ->  relay (separate process, own config)  ->  island (container)
 *
 * Requires both running; see integration/README.md.
 * Run with: npm run test:relay
 */

const crypto = require('crypto');
const { sealEnvelope, openResponse, envelopeFields } = require('./helpers/relayEnvelope');

const ISLAND = process.env.RELAY_TEST_ISLAND || 'http://127.0.0.1:8000';
const RELAY = process.env.RELAY_TEST_RELAY || 'http://127.0.0.1:18800';
const ISLAND_ID = 'island-test';

const SUFFIX = 'rl1';
const USER_A = `relay_a_${SUFFIX}`;
const USER_B = `relay_b_${SUFFIX}`;
const PASS = 'Testpass!12345';

let islandPubB64;
let threadId;
let deliverySecret;
let tokenA;

const b64 = (b) => Buffer.from(b).toString('base64');

function b64urlToBuf(s) {
  return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

async function api(path, { method = 'GET', body, token } = {}) {
  const r = await fetch(ISLAND + path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: r.status, data };
}

/** The transport HMAC the island checks — server/main.py hmac_tag(). */
function dmTag(secret, tid, ts, nonce, ciphertext) {
  const h = crypto.createHash('sha256').update(ciphertext).digest();
  const msg = Buffer.concat([
    Buffer.from(String(tid), 'utf8'), Buffer.from('|'),
    Buffer.from(String(ts), 'utf8'), Buffer.from('|'),
    nonce, Buffer.from('|'),
    h,
  ]);
  return crypto.createHmac('sha256', secret).update(msg).digest();
}

/** One ready-to-seal /ud/dm/send body for a fresh message. */
function makeDmBody(text) {
  const ciphertext = Buffer.from(text, 'utf8');
  const nonce = crypto.randomBytes(16);
  const ts = Date.now();
  return {
    thread_id: threadId,
    ts,
    nonce_b64: b64(nonce),
    ciphertext_b64: b64(ciphertext),
    tag_b64: b64(dmTag(deliverySecret, threadId, ts, nonce, ciphertext)),
  };
}

async function sendThroughRelay(body, { next = ISLAND_ID } = {}) {
  const inner = { ...body, ...envelopeFields() };
  const { envelope, keyResp } = sealEnvelope(islandPubB64, inner);
  const r = await fetch(RELAY + '/forward', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ next, blob: envelope.toString('base64') }),
  });
  const raw = Buffer.from(await r.arrayBuffer());
  return { httpStatus: r.status, raw, keyResp, envelope };
}

beforeAll(async () => {
  const health = await fetch(`${ISLAND}/health`).then((r) => r.json()).catch(() => null);
  if (!health || health.status !== 'ok') throw new Error(`island not reachable at ${ISLAND}`);

  const relayHealth = await fetch(`${RELAY}/health`).then((r) => r.json()).catch(() => null);
  if (!relayHealth || relayHealth.status !== 'ok') throw new Error(`relay not reachable at ${RELAY}`);

  const key = await api('/relay/key');
  if (key.status !== 200) throw new Error('island has relay ingress disabled');
  islandPubB64 = key.data.public_key_b64;

  for (const u of [USER_A, USER_B]) {
    await api('/auth/register', {
      method: 'POST',
      body: { username: u, password: PASS, public_key: b64(crypto.randomBytes(32)) },
    });
    const login = await api('/auth/login', { method: 'POST', body: { username: u, password: PASS } });
    const tok = login.data?.access_token;
    if (u === USER_A) tokenA = tok;
    if (tok) {
      await api('/profile/me', {
        method: 'PUT',
        token: tok,
        body: {
          about: '',
          privacy: { allow_group_invites_from_non_friends: true, allow_dm_from_non_friends: true },
        },
      });
    }
  }

  const thread = await api('/dm/open', { method: 'POST', token: tokenA, body: { username: USER_B } });
  if (thread.status !== 200) throw new Error('dm/open failed: ' + JSON.stringify(thread.data));
  threadId = thread.data.thread_id;

  const sec = await api(`/dm/${threadId}/delivery-secret`, { token: tokenA });
  if (sec.status !== 200) throw new Error('delivery-secret failed: ' + JSON.stringify(sec.data));
  deliverySecret = b64urlToBuf(sec.data.delivery_secret_b64);
}, 60000);

describe('relay prototype', () => {
  jest.setTimeout(60000);

  it('delivers a direct message through the relay', async () => {
    const text = `through-the-relay-${Date.now()}`;
    const { httpStatus, raw, keyResp } = await sendThroughRelay(makeDmBody(text));

    expect(httpStatus).toBe(200);
    const answer = openResponse(keyResp, raw);   // only the client can open this
    expect(answer.status).toBe(200);
    expect(answer.ok).toBe(true);

    const history = await api(`/dm/${threadId}/history?limit=20`, { token: tokenA });
    expect(history.status).toBe(200);
    const rows = history.data.messages || history.data.items || history.data;
    const texts = (Array.isArray(rows) ? rows : []).map((m) => m.text);
    expect(texts).toContain(b64(Buffer.from(text, 'utf8')));
  });

  it('stores the relayed message with no sender, exactly like a direct one', async () => {
    const text = `sealed-through-relay-${Date.now()}`;
    const { raw, keyResp } = await sendThroughRelay(makeDmBody(text));
    expect(openResponse(keyResp, raw).status).toBe(200);

    const history = await api(`/dm/${threadId}/history?limit=20`, { token: tokenA });
    const rows = history.data.messages || history.data.items || history.data;
    const row = (Array.isArray(rows) ? rows : []).find(
      (m) => m.text === b64(Buffer.from(text, 'utf8')),
    );
    expect(row).toBeTruthy();
    // Sealed sender must survive the detour: the island still records nobody.
    expect(row.user_id == null).toBe(true);
    expect(row.username == null).toBe(true);
  });

  it('hands the relay nothing it could correlate on', async () => {
    const body = makeDmBody('metadata-check');
    const inner = { ...body, ...envelopeFields() };
    const { envelope } = sealEnvelope(islandPubB64, inner);

    // Everything the relay receives: a destination NAME and opaque bytes.
    const asSeen = { next: ISLAND_ID, blob: envelope.toString('base64') };
    expect(Object.keys(asSeen).sort()).toEqual(['blob', 'next']);

    // Nothing the relay could correlate on survives in the wire bytes.
    // (A bare thread_id is too short to assert on — a one-digit string turns
    //  up in random ciphertext by chance. The long fields are the real test.)
    const wire = envelope.toString('latin1');
    expect(wire).not.toContain(body.nonce_b64);
    expect(wire).not.toContain(body.ciphertext_b64);
    expect(wire).not.toContain(body.tag_b64);
    expect(wire).not.toContain('thread_id');

    // Only the 49-byte header is in the clear; everything after it is sealed
    // to the island, and a relay holds no key that opens it.
    expect(envelope[0]).toBe(0x03);
    expect(envelope.length).toBeGreaterThan(49);
    const sealedPart = envelope.subarray(49);
    expect(() => {
      const d = crypto.createDecipheriv('aes-256-gcm', crypto.randomBytes(32), envelope.subarray(37, 49));
      d.setAAD(envelope.subarray(0, 37));
      d.setAuthTag(sealedPart.subarray(sealedPart.length - 16));
      Buffer.concat([d.update(sealedPart.subarray(0, sealedPart.length - 16)), d.final()]);
    }).toThrow();
  });

  it('rejects a replayed envelope before it reaches the database', async () => {
    const body = makeDmBody(`replay-me-${Date.now()}`);
    const inner = { ...body, ...envelopeFields() };
    const { envelope, keyResp } = sealEnvelope(islandPubB64, inner);

    const post = () =>
      fetch(RELAY + '/forward', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ next: ISLAND_ID, blob: envelope.toString('base64') }),
      }).then(async (r) => Buffer.from(await r.arrayBuffer()));

    expect(openResponse(keyResp, await post()).status).toBe(200);

    // Same bytes again: caught by the envelope's own nonce, in memory, not by
    // the DM-level dedup behind a database transaction.
    const second = openResponse(keyResp, await post());
    expect(second.status).toBe(409);
    expect(String(second.detail)).toContain('replay');
  });

  it('refuses a destination the relay operator has not listed', async () => {
    const { httpStatus } = await sendThroughRelay(makeDmBody('nowhere'), { next: 'http://evil.example' });
    expect(httpStatus).toBe(404);
  });

  it('refuses an unsigned or wrongly signed relay request at the island', async () => {
    const body = makeDmBody('unsigned');
    const inner = { ...body, ...envelopeFields() };
    const { envelope } = sealEnvelope(islandPubB64, inner);

    const bare = await fetch(`${ISLAND}/relay/in`, {
      method: 'POST',
      headers: { 'content-type': 'application/octet-stream' },
      body: envelope,
    });
    expect(bare.status).toBe(403);

    const forged = await fetch(`${ISLAND}/relay/in`, {
      method: 'POST',
      headers: {
        'content-type': 'application/octet-stream',
        'x-relay-id': 'relay-alpha',
        'x-relay-ts': String(Date.now()),
        'x-relay-nonce': b64(crypto.randomBytes(16)),
        'x-relay-sig': b64(crypto.randomBytes(32)),
      },
      body: envelope,
    });
    expect(forged.status).toBe(403);
  });

  it('refuses an envelope sealed to the wrong transport key', async () => {
    const { x25519 } = require('@noble/curves/ed25519');
    const strangerPub = Buffer.from(x25519.getPublicKey(x25519.utils.randomSecretKey()));

    const inner = { ...makeDmBody('wrong-key'), ...envelopeFields() };
    const { envelope } = sealEnvelope(strangerPub.toString('base64'), inner);

    const r = await fetch(RELAY + '/forward', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ next: ISLAND_ID, blob: envelope.toString('base64') }),
    });
    // The island answers in the clear here: it could not derive a response key.
    expect(r.status).toBe(400);
  });
});
