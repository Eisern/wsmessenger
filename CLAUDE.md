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
4. Background imports the X25519 private key as a non-extractable `CryptoKey` and keeps it until lock/logout (tied to the 10-minute master-key idle TTL).

The panel does **not** hold the private key — it requests crypto operations from the background via port messages.

EPK is **never** on the server. `GET /crypto/keys` returns HTTP 410 Gone ([server/main.py:3120](server/main.py#L3120)); any Android/extension code path that still calls it is deprecated and will fail.

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

Both support HTTPS and WSS. For self-hosting, edit `host_permissions` and reload the unpacked extension. The Android client can switch backends at runtime (Login screen → "Connect to another server") without a manifest edit.

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
