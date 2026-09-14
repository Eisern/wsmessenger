# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**WS Messenger** is an end-to-end encrypted messenger with three components in this repository:

- `chrome_extension/` — Chrome browser extension (Manifest V3, side panel). Vanilla JavaScript, no build system, uses only the Web Crypto API.
- `Android/` — React Native 0.84 client (Android only). See `Android/CLAUDE.md` for details.
- `server/` — FastAPI backend (`server/main.py`) and admin panel (`server/admin/`).

## Loading the Extension

Load unpacked via `chrome://extensions/` — point at `chrome_extension/`. No build required. The extension appears as a browser side panel.

## Backend Setup

Requires PostgreSQL 13+ (tested on 17). Runtime dependencies are pinned in [`server/requirements.txt`](server/requirements.txt) — install with `pip install -r server/requirements.txt`. Note that the `passlib[argon2]` extra is used (not `bcrypt`) because the server hashes passwords with Argon2id. The `server/admin/` directory is a FastAPI router (`server/admin/router.py`) with Jinja2 templates and its own HMAC-based CSRF and session management (`server/admin/auth.py`). Audit events are written to an `admin_audit` table.

For a full self-hosting walkthrough (VPS, systemd, nginx + TLS, first admin, updates), see [`docs/self-hosting.md`](docs/self-hosting.md).

Schema lives in [`server/schema.sql`](server/schema.sql) — apply once with `psql -d <db> -f server/schema.sql` before starting the server. The server itself only lazily creates a few archive tables at runtime (`chat_room_key_archive`, `chat_dm_key_archive`, `chat_dm_delete_requests`); base tables must exist before the first request.

Configuration is via environment variables — copy `server/config.example.env` to `server/.env` and fill in values.

Run with: `cd server && uvicorn main:app --reload`.

## Architecture

### Process Boundary

The extension has two execution contexts communicating via `chrome.runtime` ports (port name: `"ws-panel"`):

- **`chrome_extension/background.js`** — MV3 service worker. Owns the WebSocket connection, JWT auth state, and master key storage in memory. Relays API calls from the panel as an HTTP proxy.
- **`chrome_extension/panel.js` + `panel-ui.js` + `panel-crypto.js`** — Side panel UI. Splits across three files: core state/routing (`panel.js`), DOM rendering (`panel-ui.js`), and crypto integration (`panel-crypto.js`).
- **`chrome_extension/login.js`** — Handles password → KEK derivation and hands off keys to background before redirecting to the panel.

### Global Namespace

Both crypto modules self-register on `globalThis.__wsCrypto` using an IIFE with `Object.defineProperty` (non-writable, non-configurable). Access them as:
- `globalThis.__wsCrypto.utils` — raw primitives (`CryptoUtils`)
- `globalThis.__wsCrypto.manager` — frozen facade over `CryptoManager` instance

### Crypto Key Hierarchy

```
Password
  → Argon2id (primary, via WASM) or PBKDF2 (≥600,000 iters, SHA-256/384/512) → KEK
    → AES-GCM-decrypt EPK → X25519 identity private key (non-extractable CryptoKey)
      → ECDH(peer ephemeral) + HKDF-SHA-256 → Unwrap room/DM keys (AES-256-GCM)
```

Key state lives in `CryptoManager` (`chrome_extension/crypto-manager.js`), which holds non-extractable `CryptoKey` objects. `chrome_extension/crypto-utils.js` provides the raw primitives. The private key is cleared from memory on lock/logout.

`background.js` holds two AES-GCM keys in service-worker RAM (not storage), each with a 10-minute idle TTL (`hasMasterKey()` / `hasUnlockKek()`): `_masterKey` is the password-derived KEK (used for `storage_encrypt`/`storage_decrypt` of small at-rest blobs like room passwords) and `_unlockKekKey` is a separate one-shot session AES key generated at unlock time for panel↔background handoff. The interactive unlock auto-lock timer defaults to 5 minutes of inactivity and is user-configurable up to 15 minutes.

Argon2id is loaded from `chrome_extension/argon2id/argon2.js` (Emscripten WASM wrapper) with SIMD variant (`argon2-simd.wasm`) preferred. `chrome_extension/argon2-selftest.js` runs at startup: verifies SHA-256 integrity of both `.wasm` files against pinned hashes, then runs a KDF test vector. If the self-test fails, derivation is blocked (fail-closed — no silent PBKDF2 fallback).

### Message Encryption Format

Wrapped room keys use X25519 ECDH + HKDF-SHA256 (info: `"ws-e2ee-wrap-v2"`, salt: ephemeral pubkey) → AES-256-GCM. Binary format (prefix byte `0x02`): `[version(1)] [ephemeral_pubkey(32)] [IV(12)] [ciphertext+tag]`, base64-encoded. Messages use AES-256-GCM with power-of-2 padding buckets (starting at 64 bytes, 5-byte header) and a `kid` field for key versioning/archival.

### Key Recovery

`crypto-utils.js` includes BIP39 encoding/decoding (`bip39Encode` / `bip39Decode`) that converts the 32-byte raw X25519 private key to a 24-word mnemonic (256-bit entropy + 8-bit checksum). A `deriveRecoveryAuth` helper derives a recovery auth token via HKDF.

### Unlock Flow

On login (`login.js`) and on panel re-unlock (`panel-crypto.js` `interactiveUnlockAndSendKek`):
1. Load EPK from `chrome.storage.local` via `loadLocalIdentity(username)` (key `e2ee_local_identity_v2:<username>`; value is a JSON blob with `v`, `username`, `salt`, `iv`, `data`, `kdf`)
2. `Argon2id` (or PBKDF2 fallback) of password with `epk.salt` → KEK
3. Panel and background perform a **secure handoff** (per-request ephemeral P-256 ECDH + HKDF-SHA-256, `info = "wsapp-unlock-handoff-v1"`, 30 s TTL via `UNLOCK_HANDOFF_TTL_MS`); the master bytes and a fresh session KEK are AES-GCM-encrypted on the wire between contexts. The legacy direct `unlock_kek_set` message is refused server-side in the worker.
4. The panel decrypts the EPK and imports the X25519 identity key as a non-extractable `CryptoKey` into `CryptoManager`, where it stays until lock/logout.

The **panel** holds the identity private key, not the service worker. `crypto-utils.js` and `crypto-manager.js` are loaded only by `panel.html` and `login.html`; `background.js` has no `importScripts` and never sees an X25519 key. What background keeps is the password-derived `_masterKey` (for `storage_encrypt`/`storage_decrypt`), the one-shot `_unlockKekKey` session key, and the ephemeral P-256 key pair used for the handoff in step 3 — each on the 10-minute idle TTL. Room-key wrapping and message decryption therefore happen in the panel; the worker is a transport, not a crypto oracle.

EPK is **never** on the server. `GET /crypto/keys` returns HTTP 410 Gone ([server/main.py:3120](server/main.py#L3120)); any Android/extension code path that still calls it is deprecated and will fail.

### Room Key Delivery

A room key reaches a new member by being wrapped for their public key and uploaded — the server never holds it in the clear. Delivery is **pull-driven backfill**, not a one-shot push:

- `GET /crypto/rooms/key-gaps[?room_id=N]` returns accepted members who have no `chat_room_keys` row, in rooms the caller may serve. The state is derived, not stored — there is no request table.
- `POST /crypto/room/{id}/share` accepts the room **owner or an admin** (`require_room_moderator`). Body field `if_absent: true` makes the write fill a gap only; the server forces it on for every non-owner, so only the owner can ever replace an existing key (which is what `rotateRoomKey` depends on). The response carries `written: bool` — `false` means another provider closed the gap first, which is a success.
- `notify_key_gap` is pushed on `/ws-notify` (per-user, always on) when someone becomes an accepted member. It is a wake-up carrying only `room_id`; recipients re-query the endpoint above.
- The panel's sweep (`sweepRoomKeyGaps` / `scheduleRoomKeySweep` in `panel-crypto.js`) drains the list on startup, unlock, notify, membership change, room open, and a manual **Rooms → Manage → Keys → Send missing keys**. It never prompts for a password: locked means defer, and it backs off on failure.

The old behaviour required the owner to be connected to that specific room's socket at the moment of acceptance; since a client holds one room socket at a time, that failed whenever the owner was offline or simply in another room.

### Cross-Island Direct Messages

Two people on **different islands** reach each other through one-way mailboxes:
each opens a mailbox on their own island for the other's key, and the sender
delivers into it personally. The servers never speak to each other, and a
mailbox is an ordinary DM thread whose only member is its owner, so nothing in
the read path knows the feature exists.

Identity is a key (`kid = sha256(x25519 pub)[:32]`), never a username: a contact
card is handed over out of band, signed by its owner and self-checking, so
neither island has to be trusted for it. Opening a mailbox IS the consent —
there is no way to address a stranger.

- Protocol: `chrome_extension/foreign-dm.js` / `Android/src/services/foreign-dm.js`
  (byte-identical, platform-free — probe, clock and crypto are injected).
- Client wiring: the "Cross-island contacts" section of `panel-crypto.js`, and
  `Android/src/services/ForeignService.js`.
- Server: `POST /foreign/box` (+ `/peer-key`), `GET /foreign/boxes`,
  `DELETE /foreign/box/{tid}`, `GET /foreign/challenge`, `POST /foreign/claim` —
  one 403 for every refusal, nonce spent either way.

A foreign thread must never enter the local DM key path: `ensureDmKeyReady`
reads this island's 404 as "create a key and share it with the peer", for a peer
with no account here. Both clients guard every branch that would ask the local
island about such a peer. Design and threat model:
`docs/internal/cross-island-dm-assessment.md`.

### RPC Transport (`rpc.js`)

`panel-crypto.js` and `panel.js` communicate with the background via a port RPC abstraction in `chrome_extension/rpc.js`. Requests carry a unique `id`; responses are matched by `id`. Reconnects with exponential backoff (1s → 30s + jitter). API relay requests time out after 10 seconds.

### Sealed Sender (DM)

DM messages use a two-layer sealed sender scheme so the server never learns who sent a message:

- **Application layer** (`panel-crypto.js` `encryptDm`): sender identity is embedded inside the encrypted payload as `{ss:1, from: username, body: plaintext}`. Only the recipient can decrypt and learn the sender.
- **Transport layer** (`background.js` `ensureDmDeliverySecret`): a per-thread `delivery_secret_b64` token is fetched once from `GET /dm/{threadId}/delivery-secret` and cached in memory. Messages are sent using this token instead of the user's JWT, so the server cannot associate delivery with a specific account even at the WebSocket level.

### DM WebSocket

DMs use a **separate** WebSocket connection (`/ws-dm?thread_id=...`) managed in `background.js` (`connectDmWs`), distinct from the main room WebSocket. The `dmDeliverySecrets` Map caches delivery tokens per thread for the lifetime of the service worker.

### Storage

| Store | Contents |
|---|---|
| `chrome.storage.local` | EPK (`e2ee_local_identity_v2:<username>` — JSON with `v`/`username`/`salt`/`iv`/`data`/`kdf`), room pinned context, UI preferences |
| `chrome.storage.session` | Active username marker (`e2ee_active_user_v2`) and transient UI hand-off state. **Nothing password-derived.** |
| Server DB | Public keys, wrapped room/DM key blobs, ciphertext, metadata, delivery secrets — **no private key material, no plaintext** |
| Service-worker RAM | Non-extractable `CryptoKey`s (identity, room, DM), `_masterKey`, `_unlockKekKey`, JWT, WebSocket state, `dmDeliverySecrets` Map. Cleared on lock/logout/10-min idle. |

### Backend Hosts

The author's backend hosts are baked into `chrome_extension/manifest.json` `host_permissions`:
- `https://imagine-1-ws.xyz` — primary
- `https://chat-room.work` — secondary

Both support HTTPS and WSS. These are **defaults only** — both clients switch backends at runtime (Login screen → "Connect to another server"), with no manifest edit or rebuild.

The chosen backend lives in `chrome.storage.local` under `server_config`. `login.js` writes it and requests the host permission via `optional_host_permissions`; `background.js` reads it once at service-worker start and re-reads on a `server_config_updated` port message; `panel.js` resolves it at parse time and follows `chrome.storage.onChanged` (`panel-crypto.js` and `panel-ui.js` share that script scope, so key and file operations follow too). A self-hosted backend must be HTTPS: the extension CSP permits only `https:`/`wss:`, and `optional_host_permissions` covers `https://*/*`.

### Entry Points and Failover

One backend with one database is an **island**; it may answer on several
addresses (its own domains today, volunteer TCP-passthrough bridges later).
`server_config` therefore holds an ordered list, schema 2:

```js
{ schema: 2, islandId, endpoints: [{apiBase, wsBase, label}], activeIdx,
  apiBase, wsBase }   // the last two MIRROR endpoints[activeIdx]
```

The mirrored `apiBase`/`wsBase` are what keeps every pre-existing reader working
unchanged — including `panel.js`, which follows `chrome.storage.onChanged` and
so picks up a rotation the worker performed with no new message type. A legacy
`{apiBase, wsBase}` blob is upgraded in place, and in each client exactly one
place persists that upgrade (`background.js` / `NetworkService.loadServerConfig`).

`chrome_extension/endpoints.js` and `Android/src/services/endpoints.js` are the
selector, duplicated **byte-for-byte** (enforced by
`Android/src/services/__tests__/endpoints-parity.test.js`) and free of platform
imports: the probe and the clock are injected. It classifies failures as
`rotate` (transport: `TypeError`/`status 0`, timeout, WS `1006` before `onopen`,
backoff exhausted), `strike` (a short-lived socket, a bare 502/503/504 — rotate
on the second) or `ignore` (the server answered: any 4xx, 5xx with a JSON body,
WS 1008/1009/1013, including a wrong room password). Rotations are single-flight,
generation-guarded and cooled down, so three sockets dying together cause one
rotation, and a full unsuccessful pass backs off without ever logging anyone out.

Two rules carry the whole design:

- **Rotating between entry points of one island clears nothing** — same backend,
  same database, so the JWT, the delivery secrets, the room keys and the open
  room all stay. Only a *disjoint* entry-point list is a different island, and
  only then does the old teardown run (`applyIslandChange` in `background.js`,
  `saveIsland` in `NetworkService.js`). The decision is made by comparing entry
  point **sets** (`classifyConfigChange`), never by a user-visible name.
- **The worker is the only rotation authority** in the extension. Panels report
  a failed request with `{type:"net_fail"}` and follow; they never rotate.

MV3 constraint: `chrome.permissions.request` needs a user gesture, so **Save**
on the login page requests every endpoint's origin in a single call, and
`background.js` checks `chrome.permissions.contains` before selecting an entry
point. Host permissions gate `fetch` but not WebSocket, so skipping that check
yields a client that looks connected and fails every HTTP call.

Full reasoning, threat model and what this deliberately does *not* buy:
[`docs/internal/federation-assessment.md`](docs/internal/federation-assessment.md).

## Key File Roles

| File | Role |
|---|---|
| `chrome_extension/background.js` | Service worker: WS, auth, API relay, master key |
| `chrome_extension/panel.js` | Panel state machine: rooms, DMs, routing |
| `chrome_extension/panel-ui.js` | DOM rendering (large — ~210KB) |
| `chrome_extension/panel-crypto.js` | Crypto state integration with UI |
| `chrome_extension/crypto-utils.js` | Raw crypto primitives (X25519, AES-GCM, PBKDF2, HKDF, BIP39, safety numbers) |
| `chrome_extension/crypto-manager.js` | CryptoKey lifecycle, room key versioning/archival |
| `chrome_extension/rpc.js` | chrome.runtime port transport with reconnect/backoff; exposes `window.{connectPort,safePost,rpcOnMessage,rpcOffMessage,rpcOnConnect,rpcOnDisconnect,rpcDisconnect,rpcGetPort}` |
| `chrome_extension/endpoints.js` | Entry-point list, failure classification and rotation state machine — byte-identical to `Android/src/services/endpoints.js` |
| `chrome_extension/foreign-dm.js` | Cross-island DM protocol (contact cards, mailbox claims, delivery, relay envelopes) — byte-identical to `Android/src/services/foreign-dm.js` |
| `chrome_extension/notifications.js` | Badge management; exposes `window.Notifications` singleton |
| `chrome_extension/login.js` | Login, registration, 2FA, BIP39 recovery form, KEK derivation → background handoff |
| `chrome_extension/argon2-selftest.js` | WASM integrity check (pinned SHA-256) + KDF test vector; blocks unlock on failure |
| `chrome_extension/argon2id/argon2.js` | Emscripten WASM wrapper for Argon2id (SIMD + non-SIMD variants) |
| `chrome_extension/manifest.json` | MV3 config, permissions, CSP |
| `server/main.py` | FastAPI server (~7400 lines): auth, rooms, DMs, WebSocket, public-key storage |
| `server/schema.sql` | Canonical PostgreSQL DDL — apply once before first server start |
| `server/admin/` | Admin panel (FastAPI router + Jinja2 templates): users, rooms, reports, audit log |
| `server/config.example.env` | Example env config — copy to `server/.env` and fill in values |

## Security Invariants

- KDF: Argon2id preferred; PBKDF2 minimum 600,000 iterations with SHA-256/384/512 only — enforced in `crypto-utils.js` and `login.js` to prevent server-driven downgrade.
- Argon2id WASM integrity is pinned at startup (`argon2-selftest.js`); failure blocks derivation (fail-closed).
- Sensitive fields (`token`, `password`, `kek`, `privateKey`, etc.) are redacted from logs via `redactDeep()` in `background.js`.
- `CryptoKey` objects for private/room keys are non-extractable; raw key bytes are wiped from Maps on `clear()` by nulling references to accelerate GC.
- Room passwords are never stored in plaintext in extension storage.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence (optional)

If GitNexus is configured locally as an MCP server, the repo can be indexed as **wsmessenger** and queried for callers, blast radius, and execution flows. None of this is required to work in the repo — the section below describes the workflow when those tools are available. If they are not, ignore this section and use Grep / Glob / Read as usual.

> If a GitNexus tool reports a stale index, re-run `npx gitnexus analyze` (assumes a local GitNexus install).

## Suggested workflow when GitNexus is available

- SHOULD run `gitnexus_impact({target: "symbolName", direction: "upstream"})` before modifying a function/class/method, and surface the blast radius (direct callers, affected processes, risk level) to the user.
- SHOULD run `gitnexus_detect_changes()` before committing to confirm the diff only affects expected symbols and flows.
- SHOULD warn the user when impact analysis returns HIGH or CRITICAL risk before proceeding.
- For exploring unfamiliar code, prefer `gitnexus_query({query: "concept"})` for process-grouped results over plain grep.
- For a 360-degree view of one symbol, use `gitnexus_context({name: "symbolName"})`.

## Avoid

- AVOID find-and-replace renames across files — `gitnexus_rename` understands the call graph and is safer when available.
- AVOID ignoring HIGH or CRITICAL risk warnings from impact analysis without explicitly telling the user.

## Resources (when GitNexus is configured)

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/wsmessenger/context` | Codebase overview, check index freshness |
| `gitnexus://repo/wsmessenger/clusters` | All functional areas |
| `gitnexus://repo/wsmessenger/processes` | All execution flows |
| `gitnexus://repo/wsmessenger/process/{name}` | Step-by-step execution trace |

<!-- gitnexus:end -->
