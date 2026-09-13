// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Direct messages between people on two independent islands.
//
// The two servers never speak to each other. Each direction is a one-way
// mailbox on the RECIPIENT's island, opened by the recipient for one specific
// key, and the sender delivers into it personally:
//
//     Alice@A ──write──> [mailbox Bob opened on B] ──read──> Bob@B
//     Bob@B   ──write──> [mailbox Alice opened on A] ──read──> Alice@A
//
// So each person still reads only from their own island, over the same /ws-dm
// they already use. A mailbox is an ordinary DM thread whose only member is
// its owner; nothing in the read path knows this feature exists.
//
// Three consequences shape everything below:
//
//   * Identity is a key, not an account. `kid` = sha256(x25519 public key)[:32]
//     - the same identifier the key store already verifies - travels between
//     islands. A username never does: it means nothing on the other side, and
//     two people may share one.
//
//   * Consent is structural. A mailbox exists only because its owner created
//     it from a contact blob handed over out of band. There is no way to
//     address a stranger, so there is no spam to filter.
//
//   * Each direction has its own thread key. The mailbox owner generates it
//     and wraps it for the peer, who receives it when claiming. A conversation
//     therefore holds ciphertext under two keys, which needs no new format:
//     messages already carry `kid`, and the archive already selects by it.
//
// This file is protocol only: no chrome.*, no fetch, no WebCrypto, no React
// Native. Everything platform-shaped is injected, for the same reason
// endpoints.js and island-list.js are written that way - it is the half that
// must behave identically in both clients, so it must be testable without
// either of them.
//
// See docs/internal/cross-island-dm-assessment.md for the design and its
// threat model.

(function (root) {
  "use strict";

  const BLOB_V = 1;
  const CLAIM_DOMAIN = "ws-foreign-claim-v1";

  function str(v) {
    return String(v == null ? "" : v).trim();
  }

  function utf8(s) {
    return new TextEncoder().encode(String(s));
  }

  function concatBytes(list) {
    let n = 0;
    for (const a of list) n += a.length;
    const out = new Uint8Array(n);
    let at = 0;
    for (const a of list) { out.set(a, at); at += a.length; }
    return out;
  }

  function b64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function unb64(s) {
    const clean = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(clean + "=".repeat((4 - (clean.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64url(bytes) {
    return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // Byte-for-byte what both clients' crypto-utils `_stableJson` produces and
  // what the island signs in Python. A contact blob is signed, so the two
  // sides must serialise it identically or every signature fails.
  function stableJson(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(stableJson).join(",") + "]";
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const k of keys) {
      const v = value[k];
      if (v === undefined) continue;
      parts.push(JSON.stringify(k) + ":" + stableJson(v));
    }
    return "{" + parts.join(",") + "}";
  }

  // What a contact blob signs. Domain-separated so a signature made over a
  // contact can never be replayed as a signature over a message.
  function contactSigBytes(payload) {
    return concatBytes([utf8("ws-contact-v1"), utf8(stableJson(payload))]);
  }

  // What a claim signs: the island it is addressed to, the key it speaks for,
  // and that island's one-time nonce. Binding all three is what stops a
  // signature collected on one island from being replayed on another.
  function claimSigBytes(islandId, kid, nonceBytes) {
    return concatBytes([
      utf8(CLAIM_DOMAIN),
      utf8(str(islandId)),
      utf8(str(kid).toLowerCase()),
      nonceBytes,
    ]);
  }

  /**
   * The blob a person hands to someone on another island, out of band.
   *
   * It is its own root of trust: the kid is checkable against the key beside
   * it, and the signature ties the X25519 identity to the Ed25519 signing key,
   * so the recipient has to trust neither island's key server. That is the
   * property that makes a dishonest island unable to forge messages from a
   * cross-island contact - a guarantee local pairs do not have.
   *
   * @param {object} me          { kid, x25519PubB64, ed25519PubB64, displayName }
   * @param {object} island      { islandId, signingKeyB64, entryPoints }
   * @param {function} sign      async (bytesToSign) => signature bytes
   */
  async function buildContactBlob(me, island, sign) {
    const payload = {
      v: BLOB_V,
      kid: str(me.kid).toLowerCase(),
      x25519_pub_b64: str(me.x25519PubB64),
      ed25519_pub_b64: str(me.ed25519PubB64),
      display_name: str(me.displayName).slice(0, 64),
      island_id: str(island.islandId),
      island_signing_key_b64: str(island.signingKeyB64),
      entry_points: (island.entryPoints || []).map((e) => ({
        apiBase: str(e.apiBase),
        wsBase: str(e.wsBase),
        label: str(e.label).slice(0, 40),
      })),
    };
    const sig = await sign(contactSigBytes(payload));
    return { payload: payload, sig_b64: b64(sig) };
  }

  /**
   * Check a contact blob against itself. Nothing here consults a server: the
   * blob either hangs together or it does not.
   *
   * @param {object} blob
   * @param {object} deps  { sha256(bytes)->bytes, verify(pubBytes, sigBytes, msgBytes)->bool }
   * @returns {Promise<{ok:boolean, reason?:string, contact?:object}>}
   */
  async function verifyContactBlob(blob, deps) {
    const p = blob && blob.payload;
    if (!p || typeof p !== "object") return { ok: false, reason: "malformed" };
    if (Number(p.v) !== BLOB_V) return { ok: false, reason: "version" };

    const kid = str(p.kid).toLowerCase();
    const xPub = str(p.x25519_pub_b64);
    const edPub = str(p.ed25519_pub_b64);
    const islandId = str(p.island_id);
    if (!kid || !xPub || !edPub || !islandId) return { ok: false, reason: "malformed" };

    let xRaw, edRaw, sigRaw;
    try {
      xRaw = unb64(xPub);
      edRaw = unb64(edPub);
      sigRaw = unb64(blob.sig_b64);
    } catch {
      return { ok: false, reason: "malformed" };
    }
    if (xRaw.length !== 32 || edRaw.length !== 32 || sigRaw.length !== 64) {
      return { ok: false, reason: "malformed" };
    }

    // The kid must be the hash of the key printed next to it. Without this a
    // blob could name one person and carry another's key.
    const digest = await deps.sha256(xRaw);
    let hex = "";
    for (let i = 0; i < digest.length; i++) hex += digest[i].toString(16).padStart(2, "0");
    if (hex.slice(0, 32) !== kid) return { ok: false, reason: "kid mismatch" };

    const okSig = await deps.verify(edRaw, sigRaw, contactSigBytes(p));
    if (!okSig) return { ok: false, reason: "bad signature" };

    const entryPoints = Array.isArray(p.entry_points) ? p.entry_points : [];
    if (!entryPoints.length) return { ok: false, reason: "no entry points" };

    return {
      ok: true,
      contact: {
        kid: kid,
        x25519PubB64: xPub,
        ed25519PubB64: edPub,
        displayName: str(p.display_name),
        islandId: islandId,
        islandSigningKeyB64: str(p.island_signing_key_b64),
        entryPoints: entryPoints.map((e) => ({
          apiBase: str(e.apiBase),
          wsBase: str(e.wsBase),
          label: str(e.label),
        })),
      },
    };
  }

  /**
   * Prove possession of the key a mailbox was opened for and collect its
   * address, delivery secret and thread key.
   *
   * The island answers 403 to everything that fails - no mailbox, wrong
   * signature, spent nonce - so the caller learns nothing it did not already
   * know, and neither does anybody probing with someone else's kid.
   *
   * @param {object} deps { fetchJson(url, opts), sign(bytes) }
   * @param {string} apiBase   an entry point of the PEER's island
   * @param {string} kid       my own kid: the mailbox was opened for me
   */
  async function claimMailbox(deps, apiBase, kid) {
    const base = str(apiBase).replace(/\/+$/, "");
    const ch = await deps.fetchJson(base + "/foreign/challenge", { method: "GET" });
    if (!ch.ok) return { ok: false, reason: "challenge failed", status: ch.status };

    const islandId = str(ch.body && ch.body.island_id);
    const nonceB64 = str(ch.body && ch.body.nonce_b64);
    if (!islandId || !nonceB64) return { ok: false, reason: "malformed challenge" };

    const sig = await deps.sign(claimSigBytes(islandId, kid, unb64(nonceB64)));
    const res = await deps.fetchJson(base + "/foreign/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kid: str(kid).toLowerCase(), nonce_b64: nonceB64, sig_b64: b64(sig) }),
    });
    if (!res.ok) return { ok: false, reason: "claim refused", status: res.status };

    const body = res.body || {};
    if (!body.thread_id || !body.delivery_secret_b64) {
      return { ok: false, reason: "malformed claim" };
    }
    return {
      ok: true,
      islandId: islandId,
      threadId: Number(body.thread_id),
      deliverySecretB64: str(body.delivery_secret_b64),
      expiresAt: body.expires_at || null,
      encryptedThreadKey: body.encrypted_thread_key || null,
      keyId: body.key_id || null,
    };
  }

  /**
   * Deliver one already-encrypted message into a mailbox.
   *
   * This is the existing sealed-sender path, unchanged and pointed at another
   * island: the tag proves possession of that mailbox's delivery secret, and
   * the island stores the row with no sender at all. What is new is only where
   * the request goes.
   *
   * @param {object} deps { fetchJson, hmacSha256(keyBytes,msgBytes), sha256(bytes), randomBytes(n), now() }
   * @param {object} box  { apiBase, threadId, secretB64 }
   * @param {string} ciphertextJson  the encrypted envelope, exactly as stored
   */
  // The body the island accepts, built once so the direct and relayed paths
  // cannot drift apart: a relayed message is the same message, carried by
  // somebody who cannot read it.
  async function buildWireBody(deps, box, ciphertextJson, opts) {
    const ptBytes = utf8(ciphertextJson);
    const ts = deps.now ? deps.now() : Date.now();
    // A retry MUST reuse the nonce of the attempt it repeats. The island
    // de-duplicates on (thread_id, nonce), so the same nonce turns a repeat of
    // a message that did arrive into a 409 instead of a second copy - while the
    // timestamp and the tag are recomputed, because the island only accepts a
    // few minutes either side of now. Callers that queue a message keep the
    // nonce returned below and hand it back here.
    const nonce = (opts && opts.nonce) ? opts.nonce : deps.randomBytes(16);
    const digest = await deps.sha256(ptBytes);
    const msg = concatBytes([
      utf8(String(box.threadId)), utf8("|"),
      utf8(String(ts)), utf8("|"),
      nonce, utf8("|"),
      digest,
    ]);
    const tag = await deps.hmacSha256(unb64(box.secretB64), msg);
    return {
      nonce: nonce,
      body: {
        thread_id: Number(box.threadId),
        ts: ts,
        nonce_b64: b64url(nonce),
        ciphertext_b64: b64url(ptBytes),
        tag_b64: b64url(tag),
      },
    };
  }

  async function deliver(deps, box, ciphertextJson, opts) {
    const built = await buildWireBody(deps, box, ciphertextJson, opts);
    const res = await deps.fetchJson(str(box.apiBase).replace(/\/+$/, "") + "/ud/dm/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(built.body),
    });
    return {
      ok: !!res.ok, status: res.status, body: res.body,
      nonce: built.nonce, nonceB64: b64url(built.nonce),
    };
  }

  /**
   * Deliver through a relay, so the recipient's island never sees the sender's
   * address or the timing of their typing.
   *
   * Direct delivery hands both to a server the sender does not trust and has no
   * account with - the one metadata leak this design accepts by default. A
   * relay carries the message without being able to read it: the envelope is
   * sealed to the island's transport key, which must come from the SIGNED
   * island list, because whoever substitutes that key reads every envelope's
   * metadata.
   *
   * The answer is sealed too. A relay that could forge "delivered" would be
   * able to swallow messages silently, and one that could forge a 409 would
   * stop the sender retrying anywhere else.
   *
   * @param {object} deps   as `deliver`, plus sealRelay / openRelayResponse / fetchBytes
   * @param {object} relay  { url, islandId, transportKeyB64 }
   */
  async function deliverThroughRelay(deps, relay, box, ciphertextJson, opts) {
    const built = await buildWireBody(deps, box, ciphertextJson, opts);
    const envNonce = deps.randomBytes(16);
    const inner = {
      thread_id: built.body.thread_id,
      ts: built.body.ts,
      nonce_b64: built.body.nonce_b64,
      ciphertext_b64: built.body.ciphertext_b64,
      tag_b64: built.body.tag_b64,
      env_ts: deps.now ? deps.now() : Date.now(),
      env_nonce_b64: b64(envNonce),
    };

    const sealed = await deps.sealRelay(relay.transportKeyB64, inner);
    const res = await deps.fetchBytes(str(relay.url).replace(/\/+$/, "") + "/forward", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ next: str(relay.islandId), blob: b64(sealed.envelope) }),
    });

    const out = { nonce: built.nonce, nonceB64: b64url(built.nonce), viaRelay: true };
    if (!res.ok || !res.bytes) {
      // The relay itself refused or did not answer. Nothing was learned about
      // the island, so this is a transport failure and the caller may retry -
      // through another relay, or directly.
      return Object.assign(out, { ok: false, status: res.status || 0, relayFailed: true });
    }

    let answer;
    try {
      answer = await deps.openRelayResponse(sealed.responseKey, res.bytes);
    } catch (e) {
      // Unopenable: either not the island we sealed for, or the relay made it
      // up. Either way it is not an answer about our message.
      return Object.assign(out, { ok: false, status: 0, relayFailed: true });
    }

    const status = Number(answer && answer.status) || 0;
    return Object.assign(out, { ok: status >= 200 && status < 300, status: status, body: answer });
  }

  // Where a contact's state lives on this device. Island-scoped like every
  // other per-peer slot: two islands can hand out the same thread numbers, and
  // one person may know two people who share a display name.
  function contactKey(myIsland, me, peerKid) {
    return "__foreign:" + str(myIsland).toLowerCase() + ":" +
      str(me).toLowerCase() + ":" + str(peerKid).toLowerCase();
  }

  const API = {
    BLOB_V: BLOB_V,
    CLAIM_DOMAIN: CLAIM_DOMAIN,
    stableJson: stableJson,
    contactSigBytes: contactSigBytes,
    claimSigBytes: claimSigBytes,
    buildContactBlob: buildContactBlob,
    verifyContactBlob: verifyContactBlob,
    claimMailbox: claimMailbox,
    deliver: deliver,
    deliverThroughRelay: deliverThroughRelay,
    contactKey: contactKey,
    _b64: b64,
    _unb64: unb64,
    _b64url: b64url,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSForeignDm = API;
})(this);
