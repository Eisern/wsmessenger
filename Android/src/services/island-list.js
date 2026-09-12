// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Verification of an island's signed list: its entry points, its relays and
// the transport keys a relayed message may be sealed to.
//
// This is the trust root for two features at once. Without it, failover would
// follow whatever address answered first, and a relayed direct message would be
// sealed to whatever transport key the network handed over — and whoever
// substitutes that key reads the metadata of every envelope, which is the
// entire property the relay network exists to protect.
//
// Trust-on-first-use: the signing key is pinned on first contact and every
// later document must be signed by it. TOFU's weakness is TOFU's weakness — the
// first contact has to be honest — but from then on an attacker needs the key,
// not merely a position on the network.
//
// This file is duplicated byte-for-byte in two places:
//   chrome_extension/island-list.js
//   Android/src/services/island-list.js
// Keep them identical; island-list-parity.test.js enforces it. That is why it
// takes no platform imports: Ed25519 verification, canonical JSON and base64
// decoding are all injected, because the two clients implement them on
// different crypto stacks.

// `root` is passed in rather than read from `self`/`globalThis` inside: the two
// clients lint under different environments, and a bare reference to either
// name is an error in one of them.
(function (root) {
  "use strict";

  // Domain separation: a signature made over an island list can never be
  // replayed as a signature over anything else.
  const SIGN_DOMAIN = "ws-island-list-v1";

  const MAX_ENTRY_POINTS = 8;
  const MAX_RELAYS = 16;
  const MAX_TRANSPORT_KEYS = 4;

  // A document older than this is stale, but staleness is NOT fatal: a client
  // cut off from every entry point cannot refresh, and refusing to use the last
  // known list would turn a censorship event into a total outage. Callers are
  // told, and decide.
  const STALE_AFTER_MS = 30 * 24 * 60 * 60 * 1000;

  function isPlainObject(v) {
    return !!v && typeof v === "object" && !Array.isArray(v);
  }

  function str(v) {
    return typeof v === "string" ? v.trim() : "";
  }

  /**
   * An address the client may actually dial.
   *
   * The document is signed, so a bad value here means the island is attacking
   * its own users - but "signed" is not "safe to hand to fetch()". Only http
   * and https get through, which keeps javascript:, file: and data: out of a
   * list that a caller might use without looking.
   */
  function safeUrl(raw, schemes) {
    const v = str(raw).replace(/\/+$/, "");
    if (!v) return "";
    let u;
    try { u = new URL(v); } catch (e) { return ""; }
    if (schemes.indexOf(u.protocol) < 0) return "";
    return u.origin;
  }

  /**
   * Canonical JSON — must be byte-identical to what the island signed.
   *
   * Constraints the island enforces on its side and this mirrors: no floats
   * (JSON.stringify(1.0) is "1", Python would write "1.0") and ASCII object
   * keys (JS sorts keys by UTF-16 code unit, Python by code point). String
   * values may be any Unicode.
   */
  function canonicalJson(value) {
    if (value === null || typeof value !== "object") return JSON.stringify(value);
    if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
    const keys = Object.keys(value).sort();
    const parts = [];
    for (let i = 0; i < keys.length; i++) {
      const v = value[keys[i]];
      if (v === undefined) continue;
      parts.push(JSON.stringify(keys[i]) + ":" + canonicalJson(v));
    }
    return "{" + parts.join(",") + "}";
  }

  function signingMessage(payload, utf8Encode) {
    return utf8Encode(SIGN_DOMAIN + canonicalJson(payload));
  }

  /**
   * createIslandListVerifier({ ed25519Verify, b64decode, utf8Encode, now })
   *
   *   ed25519Verify(pubBytes, sigBytes, msgBytes) -> Promise<boolean> | boolean
   *   b64decode(s) -> Uint8Array        (tolerant of base64url and no padding)
   *   utf8Encode(s) -> Uint8Array
   *   now() -> ms
   */
  function createIslandListVerifier(deps) {
    const d = deps || {};
    const ed25519Verify = d.ed25519Verify;
    const b64decode = d.b64decode;
    const utf8Encode = d.utf8Encode;
    const now = d.now || function () { return Date.now(); };
    if (!ed25519Verify || !b64decode || !utf8Encode) {
      throw new Error("createIslandListVerifier: ed25519Verify, b64decode and utf8Encode are required");
    }

    /**
     * @param {object} doc      what the island served
     * @param {object} pin      { signingKeyB64, islandId, version } or null on first contact
     * @returns {Promise<{ok, reason?, payload?, pin?, stale?}>}
     */
    async function verify(doc, pin) {
      if (!isPlainObject(doc) || !isPlainObject(doc.payload)) {
        return { ok: false, reason: "malformed" };
      }
      const payload = doc.payload;

      const islandId = str(payload.island_id);
      const version = Number(payload.version);
      if (!islandId) return { ok: false, reason: "malformed" };
      if (!isFinite(version) || version < 1 || Math.floor(version) !== version) {
        return { ok: false, reason: "malformed" };
      }

      // Which key must have signed this. On first contact the document carries
      // its own key and we are trusting the channel; afterwards the embedded
      // key is ignored entirely, because an attacker would just ship theirs.
      const firstContact = !pin || !str(pin.signingKeyB64);
      const keyB64 = firstContact ? str(doc.signing_key_b64) : str(pin.signingKeyB64);
      if (!keyB64) return { ok: false, reason: "no signing key" };

      if (!firstContact) {
        if (str(pin.islandId) && str(pin.islandId) !== islandId) {
          return { ok: false, reason: "different island" };
        }
        // Rollback protection: a replayed older document could reinstate a
        // retired relay or drop an entry point that was added since.
        const pinnedVersion = Number(pin.version || 0);
        if (isFinite(pinnedVersion) && version < pinnedVersion) {
          return { ok: false, reason: "rollback" };
        }
      }

      let keyBytes;
      let sigBytes;
      try {
        keyBytes = b64decode(keyB64);
        sigBytes = b64decode(str(doc.sig_b64));
      } catch (e) {
        return { ok: false, reason: "malformed" };
      }
      if (!keyBytes || keyBytes.length !== 32) return { ok: false, reason: "malformed" };
      if (!sigBytes || sigBytes.length !== 64) return { ok: false, reason: "bad signature" };

      let good = false;
      try {
        good = await ed25519Verify(keyBytes, sigBytes, signingMessage(payload, utf8Encode));
      } catch (e) {
        good = false;
      }
      if (!good) return { ok: false, reason: "bad signature" };

      const normalized = normalizePayload(payload);
      if (!normalized.entryPoints.length) return { ok: false, reason: "no entry points" };

      const issuedAtMs = Number(payload.issued_at || 0) * 1000;
      const stale = issuedAtMs > 0 && now() - issuedAtMs > STALE_AFTER_MS;

      return {
        ok: true,
        stale: stale,
        payload: normalized,
        pin: { signingKeyB64: keyB64, islandId: islandId, version: version },
      };
    }

    return { verify: verify };
  }

  /** Shape and bound the document so callers never handle raw server input. */
  function normalizePayload(payload) {
    const entryPoints = [];
    const seenEp = {};
    const rawEp = Array.isArray(payload.entry_points) ? payload.entry_points : [];
    for (let i = 0; i < rawEp.length && entryPoints.length < MAX_ENTRY_POINTS; i++) {
      const e = rawEp[i];
      if (!isPlainObject(e)) continue;
      const apiBase = safeUrl(e.apiBase, ["http:", "https:"]);
      if (!apiBase || seenEp[apiBase]) continue;
      seenEp[apiBase] = true;
      entryPoints.push({
        apiBase: apiBase,
        wsBase: safeUrl(e.wsBase, ["ws:", "wss:"]),
        label: str(e.label).slice(0, 40),
      });
    }

    const relays = [];
    const seenRelay = {};
    const rawRelays = Array.isArray(payload.relays) ? payload.relays : [];
    for (let i = 0; i < rawRelays.length && relays.length < MAX_RELAYS; i++) {
      const r = rawRelays[i];
      if (!isPlainObject(r)) continue;
      const id = str(r.id);
      const url = safeUrl(r.url, ["http:", "https:"]);
      if (!id || !url || seenRelay[id]) continue;
      seenRelay[id] = true;
      relays.push({ id: id, url: url, label: str(r.label).slice(0, 40) });
    }

    const transportKeys = [];
    const rawKeys = Array.isArray(payload.transport_keys) ? payload.transport_keys : [];
    for (let i = 0; i < rawKeys.length && transportKeys.length < MAX_TRANSPORT_KEYS; i++) {
      const k = rawKeys[i];
      if (!isPlainObject(k)) continue;
      const kid = str(k.kid);
      const pub = str(k.public_key_b64);
      if (!kid || !pub) continue;
      transportKeys.push({ kid: kid, publicKeyB64: pub });
    }

    return {
      islandId: str(payload.island_id),
      version: Number(payload.version),
      issuedAt: Number(payload.issued_at || 0),
      entryPoints: entryPoints,
      relays: relays,
      transportKeys: transportKeys,
    };
  }

  const API = {
    SIGN_DOMAIN: SIGN_DOMAIN,
    STALE_AFTER_MS: STALE_AFTER_MS,
    MAX_ENTRY_POINTS: MAX_ENTRY_POINTS,
    MAX_RELAYS: MAX_RELAYS,
    canonicalJson: canonicalJson,
    signingMessage: signingMessage,
    normalizePayload: normalizePayload,
    createIslandListVerifier: createIslandListVerifier,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSIslandList = API;
})(this);
