// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev87 <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * What the service worker promises about the password-derived key.
 *
 * It is the one thing in the extension that holds key material for a living:
 * the KEK used to encrypt small things at rest, handed over from the panel at
 * unlock and supposed to stop answering after ten idle minutes. The handover
 * has its own thirty-second window, is single use, and the old direct route -
 * posting the key as a message - is refused outright.
 *
 * Every one of those is invisible when it breaks. A key that outlives its TTL,
 * a handoff session that can be replayed, a fallback that quietly accepts the
 * key in the clear: the client keeps working in all three cases, and the only
 * difference is what a compromised page could take.
 *
 * Needs no island - this is entirely between the panel and the worker.
 */

const { startWorker } = require('./helpers/workerHarness');

const USER = 'unlock_test_user';

const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Uint8Array.from(Buffer.from(String(s), 'base64'));

/**
 * The panel's half of the handoff, done the way panel-crypto does it: a fresh
 * P-256 pair, ECDH against the worker's, HKDF salted with the request id and
 * the worker's nonce, and the payload bound to the same AAD.
 */
async function panelSide({ serverPubB64, nonceB64, reqId, username, masterB64, kekB64 }) {
  const subtle = globalThis.crypto.subtle;
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const clientPubB64 = b64(new Uint8Array(await subtle.exportKey('raw', kp.publicKey)));

  const serverPub = await subtle.importKey(
    'raw', unb64(serverPubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, [],
  );
  const sharedBits = await subtle.deriveBits({ name: 'ECDH', public: serverPub }, kp.privateKey, 256);
  const hkdfKey = await subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const salt = await subtle.digest(
    'SHA-256', new TextEncoder().encode(`unlock-handoff-v1|${reqId}|${nonceB64}`),
  );
  const transportKey = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('wsapp-unlock-handoff-v1') },
    hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );

  const ts = Date.now();
  const aad = new TextEncoder().encode(JSON.stringify({
    v: 1, purpose: 'unlock_handoff', req_id: reqId, username: String(username).toLowerCase(), ts,
  }));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  // The sealed payload repeats what the AAD binds, and carries its own expiry:
  // the worker checks both, so neither the envelope nor the contents can be
  // lifted into another request.
  const payload = new TextEncoder().encode(JSON.stringify({
    v: 1,
    req_id: reqId,
    username: String(username).toLowerCase(),
    ts,
    exp: ts + 30_000,
    master_b64: masterB64,
    kek_b64: kekB64,
  }));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, transportKey, payload);

  return {
    type: 'unlock_handoff_commit',
    reqId,
    client_pub_b64: clientPubB64,
    iv_b64: b64(iv),
    ct_b64: b64(new Uint8Array(ct)),
    aad: { v: 1, req_id: reqId, username, ts },
  };
}

async function handOverAKey(w, { username = USER, reqId = `req_${Date.now()}` } = {}) {
  const master = b64(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const kek = b64(globalThis.crypto.getRandomValues(new Uint8Array(32)));

  w.clear();
  await w.send({ type: 'unlock_handoff_begin', reqId, username });
  const begun = await w.waitFor('unlock_handoff_begin_res');
  expect(begun.ok).toBe(true);

  const commit = await panelSide({
    serverPubB64: begun.server_pub_b64 || begun.serverPubB64,
    nonceB64: begun.nonce_b64 || begun.nonceB64,
    reqId, username, masterB64: master, kekB64: kek,
  });
  w.clear();
  await w.send(commit);
  return { master, kek, reqId, commit };
}

jest.setTimeout(60000);

describe('who the worker will talk to at all', () => {
  it('refuses a port that cannot prove it is one of the extension pages', async () => {
    // This one is not hypothetical: the check used to accept a sender with no
    // URL, and unlock_master_take would have handed the key to it.
    const w = startWorker();
    const anonymous = w.connect({ url: '' });
    expect(anonymous.accepted).toBe(false);

    const contentScript = w.connect({ url: 'chrome-extension://test-extension/panel.html', tab: { id: 7 } });
    expect(contentScript.accepted).toBe(false);

    const foreign = w.connect({ id: 'another-extension' });
    expect(foreign.accepted).toBe(false);
  });
});

describe('handing the key from the panel to the worker', () => {
  it('accepts a key sealed to a key exchange, and then uses it', async () => {
    const w = startWorker();
    await handOverAKey(w);

    const ok = await w.waitFor('unlock_kek_set_ok');
    expect(ok.ok).toBe(true);
    // Not a detail: it says the key arrived over the exchange rather than in
    // the clear, which is the whole difference this protocol exists to make.
    expect(ok.via).toBe('secure_handoff');

    // A room password is exactly what this key is for: small things that must
    // not sit in extension storage in the clear.
    w.clear();
    await w.send({ type: 'storage_encrypt', reqId: 'e1', plaintext: 'комната-пароль' });
    const enc = await w.waitFor('storage_crypto_res');
    expect(enc.ok).toBe(true);
    expect(enc.result.ct).toBeTruthy();

    w.clear();
    await w.send({ type: 'storage_decrypt', reqId: 'd1', iv: enc.result.iv, ct: enc.result.ct });
    const dec = await w.waitFor('storage_crypto_res');
    expect(dec.ok).toBe(true);
    expect(dec.result).toBe('комната-пароль');
  });

  it('refuses the same handoff twice', async () => {
    // One shot, and refused twice over: the session is consumed on use, and a
    // repeated request id on a sensitive message is dropped before it is even
    // looked at - so the replay gets no answer at all rather than a refusal.
    const w = startWorker();
    const { commit } = await handOverAKey(w);
    await w.waitFor('unlock_kek_set_ok');

    w.clear();
    await w.send(commit);
    await new Promise((r) => setTimeout(r, 200));
    const accepted = w.posted.filter((m) => m.type === 'unlock_kek_set_ok' && m.ok);
    expect(accepted).toHaveLength(0);
  });

  it('refuses a replayed handoff under a fresh request id too', async () => {
    // Without the request-id guard this is the same envelope, and it must
    // still fail: the exchange it was sealed to is gone.
    const w = startWorker();
    const { commit } = await handOverAKey(w);
    await w.waitFor('unlock_kek_set_ok');

    w.clear();
    await w.send({ ...commit, reqId: `${commit.reqId}_again` });
    const res = await w.waitFor('unlock_handoff_commit_res');
    expect(res.ok).toBe(false);
    expect(String(res.error)).toMatch(/not found|expired|mismatch/i);
  });

  it('refuses a handoff that sat unused past its window', async () => {
    const w = startWorker();
    const reqId = 'slow_one';
    w.clear();
    await w.send({ type: 'unlock_handoff_begin', reqId, username: USER });
    const begun = await w.waitFor('unlock_handoff_begin_res');

    // Thirty seconds is the whole window. Two minutes is not a slow network.
    w.advance(2 * 60 * 1000);

    const commit = await panelSide({
      serverPubB64: begun.server_pub_b64 || begun.serverPubB64,
      nonceB64: begun.nonce_b64 || begun.nonceB64,
      reqId, username: USER, masterB64: b64(new Uint8Array(32)), kekB64: b64(new Uint8Array(32)),
    });
    w.clear();
    await w.send(commit);
    const res = await w.waitFor('unlock_handoff_commit_res');
    expect(res.ok).toBe(false);
    expect(String(res.error)).toMatch(/expired|not found/i);
  });

  it('refuses the key posted directly, the way it used to be sent', async () => {
    // The legacy route. It has to stay refused: a page that can post to this
    // port could otherwise install a key of its own choosing.
    const w = startWorker();
    w.clear();
    await w.send({ type: 'unlock_kek_set', kek_b64: b64(new Uint8Array(32)), username: USER });
    const res = await w.waitFor('unlock_kek_set_ok');
    expect(res.ok).toBe(false);
  });
});

describe('how long the key stays', () => {
  it('stops answering once it has been idle for its TTL', async () => {
    const w = startWorker();
    await handOverAKey(w);
    await w.waitFor('unlock_kek_set_ok');

    w.clear();
    await w.send({ type: 'storage_encrypt', reqId: 'warm', plaintext: 'ещё тёплый' });
    expect((await w.waitFor('storage_crypto_res')).ok).toBe(true);

    // Ten minutes of nobody asking for anything. The clock is idle-based, so
    // this only expires because nothing touched the key in between.
    w.advance(11 * 60 * 1000);

    w.clear();
    await w.send({ type: 'storage_encrypt', reqId: 'cold', plaintext: 'уже нет' });
    const cold = await w.waitFor('storage_crypto_res');
    expect(cold.ok).toBe(false);
  });

  it('keeps the key while it is being used', async () => {
    // The other half of the same rule. An expiry that ignored use would drop
    // the key in the middle of a working session, and the honest fix for that
    // is a longer timeout, not no timeout.
    const w = startWorker();
    await handOverAKey(w);
    await w.waitFor('unlock_kek_set_ok');

    for (let i = 0; i < 3; i++) {
      w.advance(8 * 60 * 1000);
      w.clear();
      await w.send({ type: 'storage_encrypt', reqId: `use${i}`, plaintext: 'ещё работаю' });
      const res = await w.waitFor('storage_crypto_res');
      expect(res.ok).toBe(true);
    }
  });

  it('forgets the key when asked to', async () => {
    const w = startWorker();
    await handOverAKey(w);
    await w.waitFor('unlock_kek_set_ok');

    w.clear();
    await w.send({ type: 'unlock_master_clear' });
    await w.send({ type: 'storage_encrypt', reqId: 'after-clear', plaintext: 'после очистки' });
    const res = await w.waitFor('storage_crypto_res');
    expect(res.ok).toBe(false);
  });
});
