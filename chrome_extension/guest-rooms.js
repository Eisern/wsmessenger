// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Rooms on another island, taken part in as a guest.
//
// A room lives on one island. Somebody from another island takes part as a
// GUEST of that island: a principal bound to their key, which a moderator there
// created from their contact card. The guest's client talks to the room's
// island directly - its own island is never told - and the two servers never
// speak to each other:
//
//     moderator@R ──POST /rooms/{id}/guests {card}──> R
//     moderator@R ──invite, inside the cross-island DM──> guest@G
//     guest@G ──challenge, signed──> R ──token for the guest principal
//     guest@G ──accept, history, /ws──> R
//
// Three things here must behave identically in both clients, which is why they
// live in a file with no chrome.*, no fetch, no WebCrypto and no React Native -
// everything platform-shaped is injected, as in foreign-dm.js:
//
//   * The session signature. It is checked by the island byte for byte, under a
//     domain of its own so that neither it nor a mailbox claim can be replayed
//     as the other.
//
//   * The invitation. It travels as the plaintext of an ordinary cross-island
//     DM, so it is end-to-end encrypted and signed by the inviter's pinned key
//     like anything else they write. It names a room, not an island: the room
//     is on the INVITER's island, whose address and signing key the guest
//     already holds from the inviter's card. An invite therefore cannot point
//     the guest at a server they were never introduced to.
//
//   * Where things are kept: the key slot and the storage key. A room id means
//     nothing without its island - room 5 exists on every island - so both are
//     scoped by it.
//
// See docs/internal/cross-island-rooms-assessment.md for the design and its
// threat model.

(function (root) {
  "use strict";

  const SESSION_DOMAIN = "ws-guest-session-v1";
  const INVITE_PREFIX = "ROOMINV1::";
  const INVITE_V = 1;
  // Re-sign this long before the access token runs out, so a request in
  // flight does not land on an expired token.
  const SESSION_SLACK_MS = 60 * 1000;

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

  function trimBase(apiBase) {
    return str(apiBase).replace(/\/+$/, "");
  }

  function posInt(v) {
    const n = Number(v);
    return (isFinite(n) && Math.floor(n) === n && n > 0) ? n : 0;
  }

  // What a guest session signs: the island it is addressed to, the key it
  // speaks for, and that island's one-time nonce. The same shape as a mailbox
  // claim under another domain - server/main.py `foreign_guest_session`.
  function sessionSigBytes(islandId, kid, nonceBytes) {
    return concatBytes([
      utf8(SESSION_DOMAIN),
      utf8(str(islandId)),
      utf8(str(kid).toLowerCase()),
      nonceBytes,
    ]);
  }

  /**
   * Sign in to the room's island as the guest bound to `kid`.
   *
   * The island answers 403 to every refusal - no such guest, wrong signature,
   * spent nonce - so a refusal says nothing about which. A challenge from an
   * island other than the one expected is refused here, before anything is
   * signed: an entry point that leads somewhere else must not collect a
   * signature, even one bound to the wrong island.
   *
   * @param {object} deps   { fetchJson(url, opts), sign(bytes), now() }
   * @param {string} apiBase  an entry point of the ROOM's island
   * @param {string} kid      my own kid
   * @param {object} [opts]   { expectIslandId }
   */
  async function openSession(deps, apiBase, kid, opts) {
    const base = trimBase(apiBase);
    const expect = str(opts && opts.expectIslandId).toLowerCase();
    const ch = await deps.fetchJson(base + "/foreign/challenge", { method: "GET" });
    if (!ch.ok) return { ok: false, reason: "challenge failed", status: ch.status };

    const islandId = str(ch.body && ch.body.island_id);
    const nonceB64 = str(ch.body && ch.body.nonce_b64);
    if (!islandId || !nonceB64) return { ok: false, reason: "malformed challenge", status: ch.status };
    if (expect && islandId.toLowerCase() !== expect) {
      return { ok: false, reason: "wrong island", status: ch.status, islandId: islandId };
    }

    // Not being able to sign (a locked panel, a malformed nonce) is our own
    // state, not the island's answer, and must not read as "unreachable".
    let sig;
    try {
      sig = await deps.sign(sessionSigBytes(islandId, kid, unb64(nonceB64)));
    } catch (e) {
      return { ok: false, reason: "cannot sign", status: 0, error: e };
    }
    const res = await deps.fetchJson(base + "/foreign/guest/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ kid: str(kid).toLowerCase(), nonce_b64: nonceB64, sig_b64: b64(sig) }),
    });
    if (!res.ok) return { ok: false, reason: "session refused", status: res.status };

    const body = res.body || {};
    const token = str(body.access_token);
    const username = str(body.username);
    if (!token || !username) return { ok: false, reason: "malformed session", status: res.status };
    const ttl = Number(body.expires_in) > 0 ? Number(body.expires_in) * 1000 : 15 * 60 * 1000;
    const now = deps.now ? deps.now() : Date.now();
    return {
      ok: true,
      islandId: islandId,
      apiBase: base,
      token: token,
      username: username,
      expiresAt: now + ttl,
    };
  }

  /**
   * Sessions with several islands, one per island, opened on demand.
   *
   * There is no refresh token in play: a guest that holds the key signs a new
   * challenge instead, which is what the key is for, and it means nothing that
   * outlives the panel needs storing. A 401 is answered by signing in again
   * once - a token revoked or expired early looks exactly like that.
   *
   * Entry points are tried in order, and only a transport failure moves on to
   * the next: an island that answered has said what it has to say.
   *
   * @param {object} deps { fetchJson, sign, now, myKid: async () => kid }
   */
  function createSessions(deps) {
    const live = new Map();      // islandId(lower) -> session
    const opening = new Map();   // islandId(lower) -> Promise<session>

    function idOf(island) {
      return str(island && island.islandId).toLowerCase();
    }

    function bases(island) {
      const list = (island && Array.isArray(island.entryPoints)) ? island.entryPoints : [];
      return list.map((e) => trimBase(e && e.apiBase)).filter(Boolean);
    }

    async function open(island) {
      const id = idOf(island);
      let kid;
      try {
        kid = await deps.myKid();
      } catch (e) {
        return { ok: false, reason: "locked", status: 0, error: e };
      }
      let last = { ok: false, reason: "no address", status: 0 };
      for (const base of bases(island)) {
        let r;
        try {
          r = await openSession(deps, base, kid, { expectIslandId: id });
        } catch (e) {
          // Only the network throws here: openSession turns everything else
          // into an answer.
          last = { ok: false, reason: "unreachable", status: 0, error: e };
          continue;
        }
        if (r.ok) return r;
        last = r;
        // The island answered and said no, or we could not sign at all.
        // Another door changes neither. Anything else - a 5xx, an entry point
        // that leads to a different island - is worth the next door.
        if (r.status === 403 || r.reason === "cannot sign") break;
      }
      return last;
    }

    /**
     * The session for an island, opened if there is none or it is about to
     * run out. `force` opens a new one - unless `stale` names the token that
     * prompted it and that token has already been replaced, which is what two
     * requests refused together look like: the second must not sign again.
     */
    async function get(island, opts) {
      const id = idOf(island);
      if (!id) return { ok: false, reason: "no island", status: 0 };
      const now = deps.now ? deps.now() : Date.now();
      const have = live.get(id);
      const fresh = !!have && have.expiresAt - SESSION_SLACK_MS > now;
      const stale = opts && opts.stale;
      const force = !!(opts && opts.force) && !(stale && fresh && have.token !== stale);
      if (!force && fresh) return have;
      if (opening.has(id)) return opening.get(id);

      const p = (async () => {
        try {
          const s = await open(island);
          if (s.ok) live.set(id, s);
          else live.delete(id);
          return s;
        } finally {
          opening.delete(id);
        }
      })();
      opening.set(id, p);
      return p;
    }

    /**
     * An authenticated request to `path` on the island, as the guest.
     * Resolves { ok, status, body, session } and never throws for an answer;
     * it throws only when the island could not be reached at all.
     */
    async function request(island, path, opts) {
      const o = opts || {};
      let s = await get(island);
      if (!s.ok) return { ok: false, status: s.status || 0, body: null, reason: s.reason };

      const send = (sess) => {
        const headers = Object.assign({}, o.headers || {}, { Authorization: "Bearer " + sess.token });
        if (o.body != null && !headers["Content-Type"]) headers["Content-Type"] = "application/json";
        return deps.fetchJson(sess.apiBase + path, {
          method: o.method || "GET",
          headers: headers,
          body: o.body == null ? undefined
            : (typeof o.body === "string" ? o.body : JSON.stringify(o.body)),
        });
      };

      let res = await send(s);
      if (res.status === 401) {
        s = await get(island, { force: true, stale: s.token });
        if (!s.ok) return { ok: false, status: s.status || 401, body: null, reason: s.reason };
        res = await send(s);
      }
      return { ok: !!res.ok, status: res.status, body: res.body, session: s };
    }

    function forget(islandId) {
      if (islandId == null) { live.clear(); return; }
      live.delete(str(islandId).toLowerCase());
    }

    function peek(islandId) {
      return live.get(str(islandId).toLowerCase()) || null;
    }

    return { get: get, request: request, forget: forget, peek: peek };
  }

  /**
   * The invitation a moderator sends inside the cross-island DM.
   *
   * `island` is the room's island, and it must be the inviter's own: the
   * receiving client checks it against the card it holds for them and refuses
   * anything else, so the field is a consistency check, never an address.
   */
  function buildInvite(inv) {
    const body = {
      v: INVITE_V,
      island: str(inv.islandId),
      room_id: posInt(inv.roomId),
      room_name: str(inv.roomName).slice(0, 64),
      guest: str(inv.guestName).slice(0, 128),
    };
    if (!body.island || !body.room_id) throw new Error("an invite needs an island and a room");
    return INVITE_PREFIX + b64url(utf8(JSON.stringify(body)));
  }

  /** The invitation in a message, or null when the message is not one. */
  function parseInvite(text) {
    if (typeof text !== "string" || !text.startsWith(INVITE_PREFIX)) return null;
    let body;
    try {
      body = JSON.parse(new TextDecoder().decode(unb64(text.slice(INVITE_PREFIX.length))));
    } catch {
      return null;
    }
    if (!body || typeof body !== "object" || Number(body.v) !== INVITE_V) return null;
    const roomId = posInt(body.room_id);
    const islandId = str(body.island);
    if (!roomId || !islandId) return null;
    return {
      islandId: islandId,
      roomId: roomId,
      roomName: str(body.room_name).slice(0, 64),
      guestName: str(body.guest).slice(0, 128),
    };
  }

  // The client's key slot for a room on another island. Distinct from both a
  // local room id (a number) and a DM slot ("dm:..."), so no key can be read
  // under the wrong one.
  function slot(islandId, roomId) {
    const island = str(islandId).toLowerCase();
    const rid = posInt(roomId);
    if (!island || !rid) return "";
    return "gr:" + island + ":" + rid;
  }

  // Where the list of rooms this account takes part in elsewhere is kept: per
  // home island and per account, like every other per-user slot.
  function listKey(homeIsland, me) {
    return "__guest_rooms:" + str(homeIsland).toLowerCase() + ":" + str(me).toLowerCase();
  }

  function sameRoom(a, b) {
    return !!a && !!b &&
      str(a.islandId).toLowerCase() === str(b.islandId).toLowerCase() &&
      posInt(a.roomId) === posInt(b.roomId);
  }

  // The room socket on the room's island. The address comes from the entry
  // point, never from anything the island said about itself.
  function socketUrl(entry, roomId) {
    const ws = str(entry && entry.wsBase).replace(/\/+$/, "") ||
      trimBase(entry && entry.apiBase).replace(/^http/, "ws");
    return ws + "/ws?room_id=" + encodeURIComponent(String(posInt(roomId)));
  }

  const API = {
    SESSION_DOMAIN: SESSION_DOMAIN,
    INVITE_PREFIX: INVITE_PREFIX,
    sessionSigBytes: sessionSigBytes,
    openSession: openSession,
    createSessions: createSessions,
    buildInvite: buildInvite,
    parseInvite: parseInvite,
    slot: slot,
    listKey: listKey,
    sameRoom: sameRoom,
    socketUrl: socketUrl,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSGuestRooms = API;
})(this);
