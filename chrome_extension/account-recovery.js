// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Recovering an account with its recovery phrase - the part both clients must
// do identically, byte-identical in chrome_extension/ and Android/src/services/.
//
// A recovery used to send recovery_auth: a fixed secret derived from the
// identity key, the same on every recovery, so whoever saw one request could
// reset the password again whenever they liked. Now the account holds the
// public half of a signing key derived from the identity key (the platform's
// CryptoUtils.deriveRecoverySigningSeed, HKDF info "ws-recovery-sign-v1"), and
// a recovery signs the server's nonce together with the account name and the
// new password (challengeBytes). The server checks the same bytes
// (_recovery_challenge in server/main.py).
//
// An account from before has only the hash of the old secret. recover() tries
// the signature first and falls back to the old secret on a refusal - which
// gives a server nothing once the account has a key, since the server then
// accepts nothing but a signature. migrate() moves such an account over when
// its owner unlocks: one proof of the old secret, and the key is set.
//
// Platform-free: crypto, encoding and the network are injected.

(function (root) {
  "use strict";

  const DOMAIN = "ws-recover-v1";

  function utf8(s) {
    return new TextEncoder().encode(String(s == null ? "" : s));
  }

  function concat(parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }

  /**
   * What a recovery signs:
   *   "ws-recover-v1" 0x00 lower(username) 0x00 nonce 0x00 sha256(newPassword)
   * @param {function} sha256 async (Uint8Array) => Uint8Array
   */
  async function challengeBytes(sha256, username, nonce, newPassword) {
    const zero = new Uint8Array([0]);
    const h = await sha256(utf8(newPassword));
    return concat([
      utf8(DOMAIN), zero,
      utf8(String(username || "").trim().toLowerCase()), zero,
      utf8(nonce), zero,
      h instanceof Uint8Array ? h : new Uint8Array(h),
    ]);
  }

  /**
   * @param {object} d
   * @param {function} d.start   async (username) => nonce string
   * @param {function} d.send    async (body) => {ok, status, detail?}
   * @param {function} d.sign    async (Uint8Array message) => base64 signature
   * @param {function} d.sha256  async (Uint8Array) => Uint8Array
   * @param {function} [d.legacyAuthB64] async () => base64 recovery_auth, for an
   *                             account that has only the hash from before
   * @returns {Promise<{ok: boolean, method?: "key"|"legacy", status?: number, detail?: string}>}
   */
  async function recover(d, { username, newPassword }) {
    const name = String(username || "").trim();
    const nonce = await d.start(name);
    if (!nonce) throw new Error("The server did not return a recovery nonce");
    const signature_b64 = await d.sign(await challengeBytes(d.sha256, name, nonce, newPassword));
    const r = await d.send({ username: name, nonce: nonce, signature_b64: signature_b64, new_password: newPassword });
    if (r && r.ok) return { ok: true, method: "key" };
    // Only a refusal can mean "this account still has the hash": anything else
    // (a limit, a server down) is an answer about the request, not the account.
    if (!r || r.status !== 401 || typeof d.legacyAuthB64 !== "function") {
      return { ok: false, status: r && r.status, detail: r && r.detail };
    }
    const nonce2 = await d.start(name);
    if (!nonce2) throw new Error("The server did not return a recovery nonce");
    const r2 = await d.send({
      username: name, nonce: nonce2, recovery_auth_b64: await d.legacyAuthB64(), new_password: newPassword,
    });
    if (r2 && r2.ok) return { ok: true, method: "legacy" };
    return { ok: false, status: r2 && r2.status, detail: r2 && r2.detail };
  }

  /**
   * After an unlock: if the account still has only the hash, prove the old
   * secret once and set the recovery key. Nothing is sent unless the server
   * says the account needs it - the old secret is not to travel for nothing.
   *
   * @param {object} d
   * @param {function} d.state  async () => "key" | "hash" | "none"
   * @param {function} d.post   async ({recovery_auth_b64, recovery_pub}) => {ok, status}
   * @param {function} d.proof  async () => {authB64, pubB64}
   * @returns {Promise<string>} "key" | "none" | "moved" | "failed"
   */
  async function migrate(d) {
    const state = await d.state();
    if (state !== "hash") return state;
    const p = await d.proof();
    const r = await d.post({ recovery_auth_b64: p.authB64, recovery_pub: p.pubB64 });
    return r && r.ok ? "moved" : "failed";
  }

  const API = { DOMAIN: DOMAIN, challengeBytes: challengeBytes, recover: recover, migrate: migrate };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSAccountRecovery = API;
})(this);
