// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Tampering with stored messages, against a real island.
 *
 * The messages are built with the real client crypto, sent through the real
 * send path, stored in a real database — and then altered by reaching into
 * that database directly, which is exactly what the operator of an island can
 * do and what no amount of transport security prevents.
 *
 * What this demonstrates is the difference between the two guarantees:
 * AES-GCM makes altering a message's CONTENT impossible, and the chain makes
 * altering its PLACE detectable. Neither prevents an operator from deleting a
 * row; the point is that it stops being invisible.
 *
 * Requires island A and docker; see integration/README.md.
 */

const crypto = require('crypto');
const { execFileSync } = require('child_process');

import AND_UTILS from '../../../crypto/CryptoUtils';
const TC = require('../../thread-chain');

const ISLAND = process.env.RELAY_TEST_ISLAND || 'http://127.0.0.1:8000';
const CONTAINER = process.env.ISLAND_A_CONTAINER || 'wsapp-test';

const SUFFIX = 'chain1';
const USER_A = `chain_a_${SUFFIX}`;
const USER_B = `chain_b_${SUFFIX}`;
const PASS = 'Testpass!12345';

const chain = TC.createThreadChain({
  sha256: (bytes) => new Uint8Array(crypto.createHash('sha256').update(Buffer.from(bytes)).digest()),
});

const b64 = (b) => Buffer.from(b).toString('base64');
const b64urlToBuf = (s) =>
  Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

let threadId;
let deliverySecret;
let tokenA;
let seed;
let myPub;

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

function sql(statement) {
  return execFileSync('docker', [
    'exec', CONTAINER, 'su', 'postgres', '-c', `psql -qtAX -d wsapp -c ${JSON.stringify(statement)}`,
  ], { encoding: 'utf8' }).trim();
}

/**
 * One chained message, signed exactly the way the client will once the writer
 * flag is flipped, and sent down the real path.
 */
async function sendChained(seq, prev, text) {
  const sigMsg = AND_UTILS._dmSigMessageV2(threadId, seq, prev, USER_A, text);
  const sig = AND_UTILS.ed25519Sign(seed, sigMsg);
  const envelope = JSON.stringify({ ss: 1, from: USER_A, body: text, sq: seq, pv: prev, sig });

  const ciphertext = Buffer.from(envelope, 'utf8');
  const nonce = crypto.randomBytes(16);
  const ts = Date.now();
  const r = await fetch(`${ISLAND}/ud/dm/send`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      thread_id: Number(threadId),
      ts,
      nonce_b64: b64(nonce),
      ciphertext_b64: b64(ciphertext),
      tag_b64: b64(dmTag(deliverySecret, threadId, ts, nonce, ciphertext)),
    }),
  });
  if (!r.ok) throw new Error(`send failed: ${r.status} ${await r.text()}`);
  return { seq, prev, link: await chain.linkFor(sigMsg), text };
}

/** Read the thread back the way a client would, and rebuild the sender's run. */
async function runFromHistory() {
  const h = await api(`/dm/${threadId}/history?limit=50`, { token: tokenA });
  const rows = h.data.messages || h.data.items || h.data;
  const out = [];
  for (const m of (Array.isArray(rows) ? rows : [])) {
    let envelope;
    try {
      envelope = JSON.parse(b64urlToBuf(m.text).toString('utf8'));
    } catch { continue; }
    if (!envelope || envelope.ss !== 1 || !Number.isInteger(envelope.sq)) continue;

    const sigMsg = AND_UTILS._dmSigMessageV2(
      threadId, envelope.sq, envelope.pv, envelope.from, envelope.body,
    );
    const sigOk = AND_UTILS.ed25519Verify(
      myPub,
      Uint8Array.from(b64urlToBuf(envelope.sig)),
      sigMsg,
    );
    out.push({
      seq: envelope.sq,
      prev: envelope.pv,
      // A link is only meaningful for a message whose signature verified.
      link: sigOk ? await chain.linkFor(sigMsg) : null,
      body: envelope.body,
      sigOk,
    });
  }
  return out.sort((a, b) => a.seq - b.seq);
}

beforeAll(async () => {
  const health = await fetch(`${ISLAND}/health`).then((r) => r.json()).catch(() => null);
  if (!health || health.status !== 'ok') throw new Error(`island not reachable at ${ISLAND}`);

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
  threadId = thread.data.thread_id;

  const sec = await api(`/dm/${threadId}/delivery-secret`, { token: tokenA });
  deliverySecret = b64urlToBuf(sec.data.delivery_secret_b64);

  // A fresh thread each run, so earlier runs cannot leave a chain behind.
  sql(`DELETE FROM chat_dm_messages WHERE thread_id = ${Number(threadId)}`);

  const priv = new Uint8Array(32).map((_, i) => (i * 3 + 11) & 0xff);
  seed = await AND_UTILS.deriveEd25519Seed(priv);
  myPub = await AND_UTILS.ed25519GetPublicKey(seed);
}, 90000);

describe('an untouched thread', () => {
  jest.setTimeout(90000);

  it('verifies end to end after a real round trip through the island', async () => {
    let prev = TC.GENESIS_HEX;
    for (let i = 1; i <= 4; i++) {
      const sent = await sendChained(i, prev, `chained message ${i}`);
      prev = sent.link;
    }

    const run = await runFromHistory();
    expect(run).toHaveLength(4);
    expect(run.every((m) => m.sigOk)).toBe(true);

    const r = chain.verifyRun(chain.genesis(), run);
    expect(r.ok).toBe(true);
    expect(r.state.seq).toBe(4);
  });
});

describe('an operator reaching into the database', () => {
  jest.setTimeout(90000);

  it('cannot alter a message without breaking its signature', async () => {
    // The content guarantee: AES-GCM is not in play here (the test stores the
    // envelope directly), but the Ed25519 signature is, and it covers the body.
    const before = await runFromHistory();
    const target = before[1];

    const row = sql(`SELECT id FROM chat_dm_messages WHERE thread_id = ${Number(threadId)} ORDER BY id LIMIT 1 OFFSET 1`);
    const tampered = JSON.stringify({
      ss: 1, from: USER_A, body: 'this is not what was said',
      sq: target.seq, pv: target.prev, sig: 'AA',
    });
    const b64url = Buffer.from(tampered, 'utf8').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    sql(`UPDATE chat_dm_messages SET text = '${b64url}' WHERE id = ${row}`);

    const after = await runFromHistory();
    const altered = after.find((m) => m.seq === target.seq);
    expect(altered.body).toBe('this is not what was said');
    expect(altered.sigOk).toBe(false);          // the forgery is visible at once
    expect(altered.link).toBe(null);            // and never enters the chain

    // ...and because it never enters the chain, the run does not verify.
    const r = chain.verifyRun(chain.genesis(), after);
    expect(r.ok).toBe(false);
  });

  it('cannot delete a message without leaving a gap', async () => {
    sql(`DELETE FROM chat_dm_messages WHERE thread_id = ${Number(threadId)}`);
    let prev = TC.GENESIS_HEX;
    for (let i = 1; i <= 4; i++) {
      const sent = await sendChained(i, prev, `deletable ${i}`);
      prev = sent.link;
    }
    expect((await runFromHistory())).toHaveLength(4);

    // Whoever holds the database can always drop a row. What they cannot do is
    // drop it quietly.
    const victim = sql(`SELECT id FROM chat_dm_messages WHERE thread_id = ${Number(threadId)} ORDER BY id LIMIT 1 OFFSET 1`);
    sql(`DELETE FROM chat_dm_messages WHERE id = ${victim}`);

    const after = await runFromHistory();
    expect(after).toHaveLength(3);
    expect(after.every((m) => m.sigOk)).toBe(true);   // each survivor is genuine

    const r = chain.verifyRun(chain.genesis(), after);
    expect(r.ok).toBe(false);
    expect(r.problems[0].verdict).toBe(TC.VERDICT_GAP);
    expect(r.problems[0].missing).toBe(1);
  });

  it('cannot re-file a genuine message at another position', async () => {
    sql(`DELETE FROM chat_dm_messages WHERE thread_id = ${Number(threadId)}`);
    let prev = TC.GENESIS_HEX;
    const sent = [];
    for (let i = 1; i <= 3; i++) {
      const s = await sendChained(i, prev, `answer ${i}`);
      sent.push(s);
      prev = s.link;
    }

    // Serve message 3 in position 2's place: its own signature is perfectly
    // valid, so only the chain notices.
    const run = await runFromHistory();
    const reordered = [run[0], run[2], run[1]];
    expect(reordered.every((m) => m.sigOk)).toBe(true);

    const r = chain.verifyRun(chain.genesis(), reordered);
    expect(r.ok).toBe(false);
    expect(r.problems.map((p) => p.verdict))
      .toEqual(expect.arrayContaining([TC.VERDICT_DUPLICATE]));
    expect(sent).toHaveLength(3);
  });
});
