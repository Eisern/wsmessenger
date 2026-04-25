# WS Messenger — Architecture

This document describes the runtime architecture and the end-to-end
cryptography of WS Messenger. It is intended for operators who
self-host the server and for readers who want to audit the security
story before trusting the project.

The canonical source for every claim in this document is the code in
this repository. Where a specific file or line is referenced, it is
given in the form [`file#Lxx`](…) so the reader can jump to it.

---

## Crypto glossary

The codebase uses several similar-sounding terms. Before describing
the flows, here is what each one is and what it is *not*.

### Password

The secret the user types on the login screen. It is never sent to
the server in plaintext and never stored anywhere on disk. The only
thing it is ever fed into is a key derivation function (Argon2id or,
as a fallback, PBKDF2).

### KEK (Key-Encryption Key)

A 32-byte AES-256 key derived from `password + salt` via Argon2id
(preferred) or PBKDF2-SHA-256 with ≥ 600 000 iterations (fallback).

The KEK's only job is to decrypt the **Encrypted Private Key (EPK)**
container on this device. It is not sent to the server and it is not
used to encrypt messages. Derivation lives in
[`crypto-utils.js#L375`](../chrome_extension/crypto-utils.js#L375)
(`deriveKeyFromPassword`).

### EPK (Encrypted Private Key)

A small JSON blob stored in `chrome.storage.local` (Chrome) or
Android Keychain (via the React Native client). Contains:

| Field | Contents |
|---|---|
| `v` | Container version (currently `3`) |
| `username` | Owner username (checked on decrypt) |
| `salt` | KDF salt (base64, 16 bytes) |
| `iv` | AES-GCM IV (base64, 12 bytes) |
| `data` | AES-GCM ciphertext of the PKCS8-encoded X25519 private key |
| `kdf` | KDF parameters (`name`, `iterations`/`time_cost`, …) |

Decryption: `AES-GCM-decrypt(KEK, iv, data)` →
PKCS8 bytes → X25519 private key. See
[`crypto-utils.js#L579`](../chrome_extension/crypto-utils.js#L579)
(`decryptPrivateKey`).

The EPK never leaves the device. The server's `GET /crypto/keys`
endpoint explicitly returns HTTP 410 Gone —
[`server/main.py#L3115`](../server/main.py#L3115).

### Identity key (X25519 private key)

The user's long-term private key. Once the EPK is decrypted, this
key is held as a **non-extractable** `CryptoKey` in memory. It is
used for:

- ECDH with peers to unwrap incoming room / DM keys
- Producing the corresponding **public key** (which *is* published
  to the server, via `POST /keys/me`)

### Room key / DM key

A 32-byte AES-256 key shared by the members of a room (or the two
participants of a DM). Every room-message and DM-message is
encrypted under its room/DM key with AES-256-GCM.

The key itself is **wrapped** (encrypted) for each recipient using
X25519 ECDH + HKDF + AES-GCM, and the wrapped blob is what the
server stores. The server never sees the unwrapped key.

Every room key has a `kid` (key id). Rotating the room key
(e.g. after a kick) produces a new `kid`; old keys are kept in a
local archive so that old messages can still be decrypted. See
[`crypto-manager.js#L84`](../chrome_extension/crypto-manager.js#L84)
(`_archiveCurrentKey`) and
[`crypto-manager.js#L105`](../chrome_extension/crypto-manager.js#L105)
(`_registerInArchive`).

### Ephemeral X25519 keypair

A fresh keypair generated **per wrapping operation**. The sender
does `ECDH(ephemeral_priv, peer_pub)`, then the ephemeral private
key is discarded and the ephemeral public key is included in the
wrapped blob so the recipient can reproduce the shared secret.

### Master key (service worker, Chrome extension only)

The Chrome extension's background service worker holds the
password-derived KEK in memory under the name `_masterKey`
([`background.js#L10`](../chrome_extension/background.js#L10)).
It is *the same 32 bytes* that the KEK is — just named "master
key" in the code that runs inside the service worker. Its second
job, beyond being used for unlock, is to AES-GCM-encrypt small
pieces of state that the panel wants to cache at rest, e.g. room
passwords (see the `storage_encrypt` / `storage_decrypt` handlers
at [`background.js#L1671`](../chrome_extension/background.js#L1671)).

Lifetime: cleared after 10 minutes of inactivity
([`background.js#L39`](../chrome_extension/background.js#L39),
`hasMasterKey(maxAgeMs = 10 * 60 * 1000)`), on lock, and on logout.

### Unlock KEK (handoff / session)

A **separate, random 32-byte AES key** generated at unlock time
(`randomSessionKekBase64()` in
[`login.js#L437`](../chrome_extension/login.js#L437)) and held in
the service worker as `_unlockKekKey`
([`background.js#L7`](../chrome_extension/background.js#L7)).

Despite the confusingly similar name, this is **not** derived from
the password and is **not** the same as the KEK described above.
It is a one-shot session key used by the panel and background to
encrypt messages to each other during the secure unlock handoff.

### Recovery phrase (BIP39)

A 24-word mnemonic that encodes the raw 32 bytes of the X25519
private key (256-bit entropy + 8-bit SHA-256 checksum = 264 bits
= 24 × 11-bit words). See
[`crypto-utils.js#L1177`](../chrome_extension/crypto-utils.js#L1177)
(`bip39Encode`).

The recovery phrase is shown to the user **once** after
registration. The server stores only a hash of a key derived from
it (via HKDF), used to authorise a password reset — not the
phrase itself.

### Delivery secret (DM transport)

A per-thread HMAC secret that the server gives to members of a DM
thread so they can send messages via `POST /ud/dm/send` without an
`Authorization: Bearer <jwt>` header. It is used exclusively for
DM transport — not for content encryption. See
[Sealed sender (DM)](#sealed-sender-dm) below.

---

## Components

```
 ┌──────────────────────────┐        ┌──────────────────────────┐
 │  Chrome MV3 extension    │        │  React Native (Android)  │
 │                          │        │                          │
 │  login.html / panel.html │        │  App.tsx / screens/*     │
 │  ── chrome.runtime port  │        │  ── mitt event bus ──┐   │
 │  background service      │        │  NetworkService      │   │
 │  worker                  │        │  CryptoService       │   │
 └────────────┬─────────────┘        └────────────┬─────────┘   │
              │                                   │             │
              │       HTTPS + WSS (same wire format)            │
              └────────────────┬──────────────────┘             │
                               ▼                                │
                      ┌────────────────────┐                    │
                      │  FastAPI server    │ ←── admin panel ───┘
                      │  server/main.py    │     /admin/*
                      │  PostgreSQL 13+    │
                      └────────────────────┘
```

| Path | What it is |
|---|---|
| [`chrome_extension/`](../chrome_extension/) | Chrome Manifest V3 extension. Side panel UI, service worker, Argon2id WASM. No build step. |
| [`Android/`](../Android/) | React Native 0.84 client (Android only). See [`Android/CLAUDE.md`](../Android/CLAUDE.md). |
| [`server/main.py`](../server/main.py) | FastAPI server. Auth, rooms, DMs, WebSocket, file uploads. |
| [`server/schema.sql`](../server/schema.sql) | Canonical PostgreSQL DDL. |
| [`server/admin/`](../server/admin/) | Admin panel (FastAPI router + Jinja2). Separate HMAC-CSRF + audit log. |

### Process model of the Chrome extension

Two execution contexts talk to each other through a
`chrome.runtime` port named `"ws-panel"`
([`rpc.js#L73`](../chrome_extension/rpc.js#L73),
[`login.js#L478`](../chrome_extension/login.js#L478)):

| Context | Source | Owns |
|---|---|---|
| Service worker | [`background.js`](../chrome_extension/background.js) | WebSockets, JWT, master key, DM delivery secrets |
| Side panel | [`panel.js`](../chrome_extension/panel.js), [`panel-ui.js`](../chrome_extension/panel-ui.js), [`panel-crypto.js`](../chrome_extension/panel-crypto.js) | UI, user input, crypto operations |

Port messages are matched request-to-response by a unique `id`.
The transport layer reconnects with exponential backoff —
`base = min(30_000, 1000 * 2^(attempt-1))` ms plus 0–500 ms of
jitter ([`rpc.js#L42`](../chrome_extension/rpc.js#L42)). Relayed
HTTP requests time out after 10 s.

### Process model of the Android client

Everything runs in the single RN JavaScript thread. The role of the
service worker is split across
[`NetworkService.js`](../Android/src/services/NetworkService.js)
(WebSocket + REST singleton, emits events via `mitt`) and
[`CryptoService.js`](../Android/src/services/CryptoService.js)
(crypto session lifecycle). See
[`Android/CLAUDE.md`](../Android/CLAUDE.md) for the full rationale
and a table of Chrome-API → RN-equivalent substitutions.

---

## Key hierarchy and lifecycle

```
  password (typed by user)
         │
         │   Argon2id (preferred; fallback PBKDF2-SHA-256
         │             ≥ 600 000 iterations)
         │   salt  = epk.salt
         ▼
     KEK  (32 bytes, AES-256)
         │
         │   AES-GCM-decrypt(iv = epk.iv, ad = …) on epk.data
         ▼
   PKCS8 bytes
         │
         │   importKey()
         ▼
  X25519 identity private key  (non-extractable CryptoKey, RAM only)
         │
         │   ECDH(my_priv, ephemeral_pub from wrapped blob)
         │   + HKDF-SHA-256(info = "ws-e2ee-wrap-v2", salt = ephemeral_pub)
         ▼
  Wrapping key (AES-256, one per wrap)
         │
         │   AES-GCM-decrypt
         ▼
  Room key / DM key  (32 bytes, AES-256)
         │
         │   AES-GCM-decrypt(iv = msg.iv, ad = kid) on msg.data
         ▼
  Padded plaintext  →  message text
```

The exact HKDF info string (`"ws-e2ee-wrap-v2"`) and the use of the
ephemeral public key as the HKDF salt are in
[`crypto-utils.js#L835`](../chrome_extension/crypto-utils.js#L835).

**Argon2id integrity.** The Argon2id WASM is loaded from
[`chrome_extension/argon2id/`](../chrome_extension/argon2id/).
Before first use, [`argon2-selftest.js`](../chrome_extension/argon2-selftest.js)
verifies SHA-256 of `argon2.wasm` and `argon2-simd.wasm` against
pinned hashes and runs a KDF test vector. On any failure, key
derivation is **blocked** — there is no silent fallback to PBKDF2
in this path.

**PBKDF2 policy.** When Argon2id is unavailable, PBKDF2 is used
with a hard minimum of 600 000 iterations and the hash restricted to
SHA-256 / SHA-384 / SHA-512
([`crypto-utils.js#L345`](../chrome_extension/crypto-utils.js#L345)).
The current default is 620 000 iterations.

**Memory lifetime.** Long-lived secrets are kept as non-extractable
`CryptoKey` objects; raw bytes used during derivation are zeroed
and nulled as soon as the import completes
([`crypto-manager.js`](../chrome_extension/crypto-manager.js)).
The service worker's `_masterKey` has a 10-minute inactivity TTL
([`background.js#L39`](../chrome_extension/background.js#L39)).
The Chrome panel's configurable idle auto-lock defaults to
5 minutes and can be raised to 15 minutes
([`panel-crypto.js#L336`](../chrome_extension/panel-crypto.js#L336)).

---

## Unlock flow (Chrome extension)

On login and on every re-unlock, the panel and background perform
a **secure handoff** so the derived key bytes never pass through
an unauthenticated `chrome.runtime` message.

1. Panel loads the EPK from `chrome.storage.local` under key
   `e2ee_local_identity_v2:<username>` (prefix at
   [`login.js#L304`](../chrome_extension/login.js#L304); loader
   `loadLocalIdentity` at
   [`login.js#L393`](../chrome_extension/login.js#L393)).
2. Panel derives the KEK from the typed password + `epk.salt`.
3. Panel asks the background for its ephemeral P-256 public key
   (a one-shot, per-request handoff key).
4. Panel generates its own ephemeral P-256 pair, does ECDH, and
   uses HKDF-SHA-256 with `info = "wsapp-unlock-handoff-v1"` to
   derive a transport AES key
   ([`login.js#L259`](../chrome_extension/login.js#L259)).
5. Panel AES-GCM-encrypts `{ master_b64, kek_b64, username,
   req_id, ts, exp = ts + 30 s }` under that transport key and
   sends it through the port.
6. Background decrypts the payload, imports `master_b64` as the
   `_masterKey` and `kek_b64` as the session `_unlockKekKey`.

The handoff token is strictly one-shot with a 30 s expiry
(`UNLOCK_HANDOFF_TTL_MS` at
[`background.js#L17`](../chrome_extension/background.js#L17)).
The legacy transport (`unlock_kek_set`) is disabled server-side in
the worker and refuses any inbound message
([`background.js#L1716`](../chrome_extension/background.js#L1716)).

The decrypted X25519 private key is **never held in the panel** —
the panel calls the background via RPC whenever it needs a crypto
operation.

---

## Message encryption (rooms)

Plaintext → padded plaintext → AES-256-GCM → envelope.

**Padding** ([`crypto-utils.js#L1055`](../chrome_extension/crypto-utils.js#L1055)):

```
 byte 0          : 0x01   (padding version)
 bytes 1..4      : big-endian message length (uint32)
 bytes 5..       : message bytes, then random fill to the next bucket
```

Bucket sizes are powers of two, starting at 64 bytes
(`_PAD_MIN_BUCKET = 64`). Everything past the declared length is
random bytes generated with `getRandomValues()` and is discarded on
decrypt. This hides the exact length of short messages on the wire.

**Envelope.** The padded plaintext is encrypted with AES-256-GCM
under the room key matching the sender's current `kid`. The `kid`
is bound into the GCM additional-data parameter on encrypt and
checked on decrypt; a ciphertext produced under one `kid` cannot be
verified against another
([`crypto-manager.js#L240`](../chrome_extension/crypto-manager.js#L240)).

---

## Room key wrapping format

When a room key is shared with a user (on invite accept, on
rotation, or to oneself at room creation), the key is wrapped
as follows:

```
 shared   = X25519 ECDH( ephemeral_priv, recipient_pub )          (32 bytes)
 wrap_key = HKDF-SHA-256( ikm = shared,
                          salt = ephemeral_pub,
                          info = "ws-e2ee-wrap-v2",
                          len  = 32 )                              (AES-256)
 blob     = 0x02 ‖ ephemeral_pub (32) ‖ iv (12)
            ‖ AES-GCM-encrypt(wrap_key, iv, room_key_bytes)        (base64)
```

Layout constants are in
[`crypto-utils.js#L234`](../chrome_extension/crypto-utils.js#L234)
(`_WRAP_VERSION = 0x02`, `_WRAP_EPHEM_LEN = 32`, `_WRAP_IV_LEN = 12`,
`_WRAP_HEADER = 45`). The ephemeral keypair is regenerated on every
wrap, so repeat wraps of the same key to the same recipient produce
different blobs.

The server stores these blobs (and the corresponding `kid`) in the
`chat_room_keys` / `chat_dm_keys` tables. It cannot read them.

---

## Sealed sender (DM)

DMs are designed so that the server does not learn who sent a DM,
even at the transport layer. This is done in two independent layers.

### Application layer

The DM ciphertext body is not `AES-GCM(key, plaintext)`. It is
`AES-GCM(key, canonical_json({ ss: 1, from, body }))` — the
sender's username is embedded **inside** the encrypted payload. The
server sees only the opaque ciphertext; only the recipient, after
unwrapping the DM key with their identity key, learns who sent the
message. See
[`panel-crypto.js#L1710`](../chrome_extension/panel-crypto.js#L1710)
(`encryptDm`), with the sealed envelope `{ ss: 1, from, body }`
assembled at
[`panel-crypto.js#L1733`](../chrome_extension/panel-crypto.js#L1733).

### Transport layer

Messages are delivered via `POST /ud/dm/send`
([`server/main.py#L7104`](../server/main.py#L7104)) with **no
`Authorization` header**. Requests are instead authenticated with
an HMAC-SHA-256 tag over a per-thread `delivery_secret`. The
server records `user_id = NULL` for the row, so even the write
path in the database does not associate the send with a user
account.

The delivery secret is fetched once per thread via
`GET /dm/{thread_id}/delivery-secret`
([`server/main.py#L7219`](../server/main.py#L7219)) — this call
*does* require the user's JWT (it verifies membership) — and then
cached. Cache lives in `dmDeliverySecrets` on Chrome
([`background.js#L569`](../chrome_extension/background.js#L569))
and in `CryptoService._deliverySecretCache` on Android. Secrets
have a TTL (24 h, persisted in `chat_dm_delivery.expires_at`); on
expiry the server returns 401 and the client re-fetches with the
Bearer token, which re-verifies membership.

Send-over-WebSocket is deliberately disabled: the DM WebSocket
endpoint (`/ws-dm`) rejects every non-ping client message and tells
the client to use `POST /ud/dm/send` instead
([`server/main.py#L5893`](../server/main.py#L5893)).

### Scope: DM only, not rooms

Sealed sender is intentionally a property of DMs, not rooms. The
room model relies on server-side enforcement of per-user roles
(owner / admin / member, mutes, bans, kicks, posting rights), which
requires the server to know the identity of the sender on every
write. Hiding the sender from the server in rooms would make that
enforcement impossible, so the architecture does not attempt it.

---

## WebSockets

| Endpoint | Scope | What flows over it | Authentication |
|---|---|---|---|
| [`/ws`](../server/main.py#L3527) | One room per connection | Ciphertext for messages in that room, presence, member-change events | JWT |
| [`/ws-dm`](../server/main.py#L5687) | One DM thread per connection | DM ciphertext to the connected client; no sending | JWT + membership check |
| [`/ws-notify`](../server/main.py#L5920) | Per user, all rooms/DMs | Lightweight metadata notifications (room/DM ids, timestamp, sender for rooms) — **no ciphertext** | JWT |

For DMs, `/ws-notify` payloads preserve sealed sender (no sender
username) — see
[`server/main.py#L6105`](../server/main.py#L6105).

---

## Storage

| Location | Contents | Lifetime |
|---|---|---|
| `chrome.storage.local` | EPK (under `e2ee_local_identity_v2:<username>`), room pinned context, UI preferences | Until user clears |
| `chrome.storage.session` | Active username marker; nothing password-derived | Until browser restart |
| RN `AsyncStorage` (Android) | Rooms, pinned context, UI prefs, server config, *encrypted* message history | Until user clears |
| `react-native-keychain` (Android) | Auth tokens, raw identity key for silent re-unlock, history-encryption keys, TOFU fingerprints | Android Keystore |
| Server PostgreSQL | Public keys, wrapped room/DM keys, ciphertext, metadata, delivery secrets | Persistent |
| Service worker RAM | `_masterKey`, `_unlockKekKey`, identity `CryptoKey`, room key `CryptoKey`s, JWT, DM delivery secrets | Until lock / logout / 10 min idle |

The server database contains **no identity private key material**
and **no message plaintext**. Wrapped room/DM keys are not
decryptable by the server because unwrapping requires the
recipient's X25519 private key, which the server does not have.

---

## Key recovery

A user who loses their password but still has their recovery phrase
can reset. The flow:

1. Client calls `POST /auth/recover-start` with the username and
   receives a single-use nonce.
2. Client decodes the phrase to the raw 32 bytes via `bip39Decode`,
   derives a `recovery_auth_b64` via HKDF, and submits it with the
   new password to `POST /auth/recover`.
3. Server verifies `recovery_auth_b64` against the stored
   `recovery_key_hash` and updates the password hash.
4. Client re-encrypts the EPK locally under the new password and
   saves it as `v: 3` in `chrome.storage.local` /
   `react-native-keychain`.

See [`login.js#L895`](../chrome_extension/login.js#L895) for the
client side. The server never sees the raw phrase or the raw
32-byte key — only the HKDF-derived auth token.

---

## What the server sees and does not see

Sees:

- Usernames, account metadata, TOTP secrets (hashed), room
  metadata, pinned context (plaintext by design — room pins are
  not E2EE), room membership, DM thread membership.
- Public keys (X25519 and Ed25519).
- Wrapped room / DM keys (opaque blobs).
- Ciphertext blobs, message timestamps, message ids.
- IP and user-agent on connect, for rate limiting and ban checks.
- Which JWT sent which room message. **For DMs, with sealed sender
  enabled, only the thread id and timestamp — not the sender.**

Does not see:

- Passwords, KEKs, derived keys.
- Identity private keys (`GET /crypto/keys` returns 410 Gone).
- Room / DM key plaintext.
- Message plaintext.
- DM senders, at either the application or transport layer.
- Recovery phrases (only an HKDF-derived hash).
