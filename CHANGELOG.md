# Changelog

What changed between releases, and what it means for somebody running this.

Versions are shared by the whole project from 0.4.0 on: the tag, the extension's
`manifest.json` and the Android `versionName` say the same thing. Before that
they drifted apart (the extension was at 0.3.0 while the last tag was v0.1.0).

## 0.4.0 — 2026-09-14

Six months of work that had never been released. Two of the fixes below are the
reason this release exists rather than waiting for the next feature.

### Fixed — security

- **A self-hoster's WebSockets went to the author's server.** React Native ships
  a URL polyfill whose `origin` answers `""` for anything that is not http(s),
  so a stored `ws://` address was silently dropped and the client fell back to
  the bundled default. REST went to the configured island, every socket did not.
  It only bit from the second launch, which is why nothing caught it. Both
  clients now parse a ws base without `URL.origin`.
- **The check that a peer's public key has not been swapped did nothing on
  Android.** The guard returned early when the client did not know its own
  username, which — because the login answer carried no name and the empty value
  was written over the stored one — was always. Every room key and DM key was
  wrapped for whatever public key the server offered, unpinned, unannounced. It
  is now fail-closed, as it always was in the extension.
  - A second hole in the same guard: detecting a key change advanced the stored
    fingerprint, so the next attempt saw "same key" and went through. One
    refusal, then the door opened. The pin now moves only when the user confirms
    the new key.
- **Android signed nothing it sent.** The Ed25519 seed was derived only by the
  BIP39 import path, so after a password sign-in or a Keychain auto-unlock it
  was null: `encryptDm` quietly skipped the signature and the public half was
  never published. To the recipient that reads as "unverified" — and, once they
  have seen a signed message from the same person, as **forged**.
- The login answer now carries the username, which is what fixes the three
  above at the source. Session restore across restarts and token refresh on
  Android depended on the same field and start working as a consequence.

### Added — what a message and a key can prove

Both of these are **readers only** in this release. The writers are behind flags
(`ROOM_SIG_WRITE_ENABLED`, `KEY_WRAP_SIG_WRITE_ENABLED`, and the older
`CHAIN_WRITE_ENABLED`), off in both clients: a client that has not learned the
new shape would show it as gibberish or, for a key, fail to open a room at all.
They are turned on in a later release, once readers are out.

- **Room messages can be signed.** A room key proves membership and nothing
  else, so until now the author was whatever the server wrote in the row. The
  envelope `{rs:1, from, body, sig}` makes the claim checkable, and readers
  report both a failed signature and a name that does not match the row.
- **A wrapped key can say who wrapped it.** The old wrap derives from an
  ephemeral key, so it proves only that somebody knew your public key — which
  the server does. Version `0x03` carries the sharer's name and signature inside
  the blob, bound to the room, the recipient and the key version. A signed wrap
  that does not verify is **refused**, not flagged; unsigned ones still work.

### Added — writing to somebody on another server

- **Cross-island direct messages on Android.** The protocol shipped earlier;
  this is the client around it — contact cards, mailboxes, delivery, the queue
  for what a foreign island would not take, and per-contact relaying. The
  extension gained the same in this cycle.
- **Entry-point failover.** One island may answer on several addresses; the
  client rotates between them without touching the session, and only a
  completely different set of addresses counts as a different server.
- **A signed island list** so a contact's addresses can be refreshed without
  trusting whoever answered, and a **relay** that carries a message to another
  island without being able to read it or learn who sent it.
- **Safety numbers for a cross-island pair** (v2): keys ordered by their
  fingerprint, no usernames in them at all, because a name means nothing across
  the border.

### Fixed — other

- Key derivation refuses weakened parameters instead of quietly raising them to
  the minimum (Android used to accept and fix up what the extension rejected).
- The worker's key TTL is enforced; it was documented but never applied.
- Reading a conversation could rate-limit itself by asking the worker to decrypt
  the same archive once per message.
- A cross-island thread no longer enters the local key path, where a 404 was
  read as "create a key and share it with the peer".
- `makeInitials` was defined twice in the extension with different behaviour.
- A `ReferenceError` in the Android room-settings screen whenever a room had no
  name.

### Changed — the project itself

- CI runs the offline test suite (280 tests) and both clients' linters. It ran
  neither: the extension's linter had been failing for months, and the Android
  test project existed only on the author's machine.
- Documentation follows the code again — `CLAUDE.md` in the root and under
  `Android/` describe cross-island DMs, the message and key formats, and the
  rule that a foreign thread must never enter the local key path.

## 0.1.0 — 2026-04-25

First tagged release.
