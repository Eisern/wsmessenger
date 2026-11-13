# Changelog

What changed between releases, and what it means for somebody running this.

Versions are shared by the whole project from 0.4.0 on: the tag, the extension's
`manifest.json` and the Android `versionName` say the same thing. Before that
they drifted apart (the extension was at 0.3.0 while the last tag was v0.1.0).

## Unreleased

### Read this first, if you run a server

- **The server takes only encrypted files, so update the clients with it.** A
  client from before this version still uploads a file as it is, and now gets
  a 400 telling its user to update; reading and sending messages is unaffected.
  Files uploaded earlier stay downloadable until they expire (`FILE_TTL_DAYS`,
  7 by default) and stay in whatever backups already hold them - in the clear,
  with their names.
- **Guests from other islands are accepted as soon as `ISLAND_ID` is set** —
  also on a server that had the island identity before this version, with
  nothing to opt in to. `ISLAND_ACCEPT_GUESTS=0` in `.env` refuses them.
- No schema change and no new required setting. The guest table is created on
  first use, as the archive tables are: the database user must be allowed to
  create tables (the database owner is, as in `docs/self-hosting.md`).

### Added — rooms across islands, server side

Somebody from another island can now take part in a room here as a **guest**:
a principal bound to their key, not an account they registered. The clients do
not offer it yet; this is the half they will talk to.

- `POST /rooms/{id}/guests` — a room moderator invites a person by their
  signed contact card. The island checks the card on its own (the kid is the
  hash of the X25519 key, the payload is signed by the Ed25519 key it carries —
  verified against a card built by the real `foreign-dm.js`, non-ASCII name and
  all), then finds or creates the guest by key and invites them exactly as a
  local member, without the friends-only check a guest could never pass.
- `POST /foreign/guest/session` — a guest signs in by signing a nonce from
  `/foreign/challenge` under its own domain (`ws-guest-session-v1`), bound to
  this island. Same 403 for every refusal; no password ever works.
- A guest reaches the rooms it was invited to and nothing else. Enforced by an
  allow-list on every HTTP request and an explicit refusal on `/ws-dm`, and
  decided by the database, not by the token — `/auth/refresh` issues a plain
  token, and a claim it dropped would have turned a guest into a full account.
- Guests are on wherever `ISLAND_ID` is set; `ISLAND_ACCEPT_GUESTS=0` turns
  them off, and the server says which at startup.

### Added — rooms across islands, in the extension

The extension uses the server half above, both as the inviting side and as the
guest. Android does the same since the section below.

- **Inviting.** Rooms → Manage → *Invite someone from another server* lists
  your cross-island contacts. The island creates the guest from their card and
  names them; the extension pins that name to the keys on the card before
  anything else uses it, and refuses if the name is already pinned to other
  keys. The invitation then goes to them inside your conversation. Somebody you
  cannot write to yet is not created on the island at all.
- **Being invited.** The invitation shows in the conversation with a *Join*
  button. It is followed only to the inviter's island as their card names it:
  the extension signs a challenge from that island with your key (a session per
  island, held in memory, signed again when it runs out), accepts, and lists the
  room under *Rooms on other servers*. The inviter's keys are pinned from their
  card under their name there, so the room key they wrap for you is checked
  against what they signed, not against what that island serves.
- **Reading and writing.** The room key is accepted under exactly the rules
  used at home (signed by a member, under a pinned key; an unsigned wrap cannot
  introduce a key), with that island's names. Messages are signed as your guest
  name there; other members' signatures are checked against keys pinned on that
  island, kept apart from names at home. The panel holds the room's socket
  itself; nothing goes through your own server, which is not told.
- **Not yet:** files in guest rooms, older history than the last 100 messages,
  unread markers for a guest room that is not open, and moderation by guests.

### Added — rooms across islands, on Android

- The same, with the same rules: *Invite someone from another server* in a
  room's member list (owners and admins), a *Join* button on an invitation in a
  cross-island conversation, *Rooms on other servers* in the room list, and a
  guest room screen. Signatures and keys are checked by the same code as at
  home (`CryptoService.acceptWrappedKeyIn` / `openRoomEnvelopeIn`, with that
  island's names); pins go to the Keychain under that island.
- What a guest room shows, and in what order, is one module both clients share
  (`guest-room-feed.js`): the extension moved onto it from its own copy.
- Not yet on Android either: files in guest rooms, older history than the last
  100 messages, unread markers for guest rooms.

### Added — Android hands out missing room keys

Until now Android shared a room key only from the room screen of an owner who
had that room open at the moment somebody accepted. Everybody else - a member
who accepted while the owner was away, an admin's rooms, a guest from another
island - waited for somebody's browser extension.

- Android now sweeps like the extension: an owner's or admin's app asks the
  island who in their rooms holds no key (`/crypto/rooms/key-gaps`) and
  wraps it for them - signed, filling the gap only - on unlock, on the notify
  socket's `notify_key_gap`, on a membership change, when they open the room,
  when a peer is verified, and from **Send missing keys** in the member list.
  A member whose key changed since it was pinned gets nothing until verified,
  and the room says so.
- The rules - when, how often, what each failure costs - are one module both
  clients share (`key-sweep.js`); the extension's sweep moved onto it. On the
  way: two runs asked for at the same moment could both start, because the
  "already running" flag was set only after the first await. It is claimed
  first now.
- Android's key-share trust refusals carry the extension's codes
  (`TRUST_CHANGED` / `TRUST_UNVERIFIED` / `TRUST_UNVERIFIABLE`), and
  `shareRoomKeyToUser` takes `ifAbsent` and says whether it wrote.

### Changed

- A cross-island contact now keeps the card exactly as they signed it, because
  inviting them hands it to an island that checks the signature. Contacts added
  before this have no card; the extension says so and asks for the card again.
- **CI is green again; it had been red since April.** The Android job ran Node
  20, below the `>= 22.11.0` that `Android/package.json` declares, and on 20
  five extension-crypto suites fail (44 tests): its WebCrypto refuses typed
  arrays made inside the Jest sandbox. Both Node jobs now run 22, and with
  `test:unit` passing, `test:screens` and the Android lint run in CI for the
  first time. The server lint (`ruff`, 438 findings in code older than the
  lint) now checks for bugs, not style: `try/except/pass` as best-effort
  cleanup, `contextlib.suppress`, collapsed `if`/`with` and `raise ... from`
  are off, as are mid-file imports in `main.py`; what was left is fixed —
  unused and repeated imports, whitespace, `timezone.utc` → `UTC`, and the
  findings below.

### Fixed

- **A contact card from a second domain named the wrong island.** Without a
  signed island list the card carried the host the client happened to use,
  not the island's name - so nobody could join that user's rooms as a guest
  (the sign-in is checked against the name on the card). Both clients now ask
  the island what it calls itself.
- **"Send missing keys" said "everyone already has the key" when it could not
  get the list.** A run now reports `incomplete`, and both buttons say so.
- **A guest room's key was not looked for again after a passing server
  error** - only after "not there yet" or "no answer". Two invitations of the
  same new guest at once could also end in a 500 for one of them; the second
  now finds the first's guest.
- **A room key wrapped for somebody with a capital in their name did not open
  on Android.** A signed wrap (0.5.0) binds the recipient's name, and each side
  wrote that name on its own: the sharer as the member list spells it
  ("Alice"), the Android reader lower-cased. The signature never matched, so
  the key was refused as forged. Signer and recipient are now signed
  lower-cased by both clients, as the server compares names. A wrap made before
  this for a name with capitals no longer verifies on the extension either, and
  the key sweep will not notice - the row exists, it only fills gaps - so the
  room owner re-shares it (Rooms → Manage → Members → *Re-share key*). Guests
  from other islands are the common case: their name is built from the display
  name on their card.
- **`scripts/bootstrap.sh` did not work on a fresh server.** Its virtualenv
  step ran as `sudo -iu wsapp -- bash -c "<several lines>"`; with `-i`, sudo
  escapes newlines into line continuations, so the script ran as one line
  (`set -e python3 -m venv ...`), created nothing and succeeded. The install
  stopped two steps later (`.venv/bin/python: No such file or directory`),
  after the database and `.env` were made. One command per sudo now, and the
  script checks the venv exists. Verified by installing on Ubuntu 24.04.
  With `WSAPP_SKIP_CERTBOT=1` it also writes `http://` entry points into the
  island list, which a contact card then carries; it now says what to change
  once TLS is in place.
- **A new member got no room key if they accepted within a minute of the
  owner's last key sweep** (both clients). That is the usual case - create a
  room, invite someone, they accept - and the wake-up for it landed inside the
  sweep's 60-second interval and was thrown away; the key came only when the
  owner happened to do something that asks again. It now runs when the
  interval ends. Found on a live server.
- **Every invitation ended in "Invite OK, but key share failed"**
  (extension). The panel handed the key to the invitee at once, which the
  island refuses until they accept. The key goes over when they accept.
- **Friend requests stopped arriving about four minutes after signing in**
  (extension). A background poll asked for the three friends lists every
  10-15 s; they share one island limit of 60 per user per 10 minutes, so
  every panel ran into 429 and stayed there. They are asked about once a
  minute now; the DM list and room invitations keep the short cycle.
- **A room on another server showed nothing in the extension.**
  `guest-room-feed.js` handed the browser's `setTimeout` around as a method of
  a plain object; Chrome refuses that ("Illegal invocation"), Node does not,
  so every test passed while in the browser the wait for the room's socket
  failed and no history was drawn. Messages sent afterwards still arrived.
  Found by driving the extension in Chromium against two islands. Android
  should not have been affected - React Native's timers are plain functions
  that do not care how they are called - but that was not tried on a device.
- **After unlocking, the open room stayed empty, or short of what arrived
  while locked** (extension). A message that comes in while locked cannot be
  decrypted and is dropped, and a history that comes back meanwhile clears the
  chat without drawing it. Unlocking was meant to read the room again, but
  called a function that never existed - since the first commit - inside a
  `try/catch` that hid it, and only from the overlay's **Unlock** button.
  Every unlock now reads the open room or conversation again, including one
  asked for by an action (*My card*, an invitation).
- **A server socket being closed for a revoked session or a ban swallowed
  its own cancellation.** Ten `return`s inside `finally` turned anything
  `ws.close()` raised - `asyncio.CancelledError` too, which is how a shutdown
  stops a handler - into an ordinary return. They now ignore ordinary errors
  only. The check behind *Turn off 2FA* was spelled out again (same rule: the
  code, or else the password) and the closure that hands an owner's rooms on
  when they delete their account binds its room and heir; both are now tested.

### Fixed — security

- **Attachments were not encrypted.** Neither client encrypted a file: the
  server received its bytes, its name and its type, kept all three, and every
  backup of the upload directory carried them - while this README said the
  server held no plaintext content. In a room the extension also announced the
  file with a message sent in the clear. Now a file is encrypted on the device
  under a key made for it alone (AES-256-GCM in 1 MiB chunks, each bound to its
  place, padded to a size class), the server is handed one opaque blob called
  `blob`, and the key, the name, the type and the size travel only inside the
  encrypted message that announces the file (`FILE3`). The server refuses
  anything else, stores no name and no type, and no longer repeats the ones it
  kept for older files. A reader saves nothing unless the whole blob verified,
  so a file the server altered, cut short or swapped is an error, not a
  download. Format: `file-crypt.js`, one file shared by both clients.
- **An expired file was deleted only if somebody tried to download it.** One
  nobody asked for again stayed on disk for good. Expired files are now purged
  on every upload.
- **A file could follow the user into another conversation.** The extension
  read where to send the file after the upload finished; it is now settled
  when the file is picked.
- **A guest's sign-in handed out a refresh token.** Valid for a week, it was a
  way in as the guest that needed no key - the one thing a guest session is
  meant to require - and it put a row in `refresh_tokens`, which nothing ever
  prunes, at every sign-in: every ten minutes while a guest room is open.
  `/foreign/guest/session` now answers with an access token only; the client
  signs a new challenge when it runs out, as it already did. `/auth/refresh`
  is off a guest's allow-list.
- **A room on another island showed a message its server wrote in the clear
  as a member's.** At home an unencrypted message is history from before
  encryption; in a guest room it is something that island wrote under a
  member's name. Both clients now show it as unverified.
- **`/foreign/claim` did not spend its nonce on a refusal**, contrary to its
  own comment: the nonce was deleted inside the transaction every refusal
  rolled back. It is now spent in a transaction of its own, before anything is
  decided.

### Added — tests

- Attachments: `fileCrypt.test.js` (the shared format, both copies: known
  blobs, padding, every way to drop, repeat, reorder or cut a chunk, the
  marker and what a name may contain), `extensionFileTransfer.test.js` (the
  real send and fetch code from `panel.js` against an island that keeps
  everything it is handed - none of the file, its name or its key is in it),
  `fileTransferService.test.js` (Android, through a file system in memory) and
  `server/tests/test_files.py` (the real server: plain uploads refused, no
  name or type kept, the largest allowed file fits, expired files purged).
  20 protections, each removed in turn, fail a test; three that did not at
  first got the tests they lacked. Driven by hand in a browser as well: files
  in a room and in a conversation come back byte for byte, and a blob edited
  on the server's disk is refused.
- `server/tests` — the first tests of the server: the real `uvicorn main:app`
  against a real PostgreSQL (`TEST_DATABASE_URL`, or `pgserver` locally), 35 of
  them for guests, the claim nonce and the invitation flow they share with
  local members. CI runs them against a `postgres:17` service. Each protection
  was checked by removing it: the allow-list, the `/ws-dm` refusal, the nonce
  spend and both signature checks each fail their own tests.
- `keySweep.test.js`: a trigger inside the interval runs when it ends - on
  one timer, at the end, not a timer that fires at once and sets another;
  a locked client waits for the unlock. `extensionInviteKey.test.js` and
  `extensionPollBudget.test.js` run the real code from `panel.js`; the poll
  test reads the island's limit from `server/main.py`, so a change on either
  side is checked against the other. Each fails without its fix.
- `extensionUnlockHistory.test.js` runs the real unlock path from `panel.js`
  (the retry and the `ws_crypto_unlocked` listener): the room is read again,
  only if it is still the one on screen, and not into a conversation or a
  guest room. `guestRoomFeed.test.js` gained a run under timers that refuse to
  be called as methods, as a browser's do. Each of the 7 guards, removed in
  turn, fails a test; the timer test failed before the fix.
- `server/tests/test_account.py` — turning 2FA off (either factor, never
  neither); a revoked session turned away by all three sockets when it
  connects and, on `/ws-dm`, mid-session by the socket's own check; and an
  owner's account deletion leaving each room to its own member, renamed when
  the heir already owns a room of that name. Of 10 deliberate breakages, 9 fail
  a test; the tenth - dropping only the revocation check at connect - is
  covered by the forced check that runs right after it, and dropping both is
  caught.
- Guest rooms in the extension, offline: `guestRooms.test.js` (the protocol,
  against an island that checks the session signature with its own byte layout
  and its own Ed25519), `extensionGuestRooms.test.js` (the real
  `panel-crypto.js`, both the moderator and the guest, against an adversarial
  island) and `extensionGuestRoomView.test.js` (the real view code from
  `panel-ui.js`, stepped through by hand: nothing lost between history and
  socket, nothing drawn twice or out of order, nothing drawn into a closed
  view). 36 deliberate breakages of the code - each protection removed in turn -
  are each caught; three that were not at first got the tests they lacked.
- Android: `guestRoomService.test.js` and `guestRoomModerator.test.js` (the
  real CryptoService, StorageService and ForeignService against an adversarial
  island), `guestRoomFeed.test.js`, and `GuestRoomScreen.test.js` - a screen
  rendered with react-test-renderer, run by the new `npm run test:screens`,
  which CI now runs too. Each of 24 service, 9 feed and 7 screen protections,
  removed in turn, fails a test.
- Key sweep: `keySweep.test.js` (the shared rules, with the clock in the
  test's hands), `keySweepService.test.js` (Android over the real CryptoService
  and StorageService: what goes over the wire, the trust stop, the triggers),
  `extensionKeySweep.test.js` (the extension's wiring) and
  `MembersModal.test.js` (the member list's controls). 37 protections, each
  removed in turn, fail a test.
- End to end on two real islands: `guestRoomTwoIslands.test.js` (the extension
  on both sides) and `guestRoomAndroid.test.js` (an Android guest, an extension
  moderator) - card, invitation, signed sign-in, key sweep, messages both ways
  over real room sockets, each verified on the other side.
- `scripts/integration_stand.py` brings up everything the integration suites
  need - two islands and a relay - from a checkout and one PostgreSQL; all 12
  suites (116 tests) pass against it. The suites' failover ports can be moved
  (`WSAPP_IT_*`), because Windows with Hyper-V reserves them; the integration
  project gained the clipboard stub the first suite to load CryptoService
  needed. Two waits in the unit suites counted event-loop turns where real
  WebCrypto had to finish, and failed now and then under a full parallel run;
  they wait for the condition instead.

## 0.5.0 — 2026-11-08

### Read this first: what stops working

0.4.0 shipped the **readers** for three things; this release switches on the
**writers**, in both clients, and starts refusing keys it cannot vouch for.
Nothing changes for the server, and nothing has to be migrated, but two kinds of
old things stop working.

**Clients older than 0.4.0.** Anybody still on one — extension or APK — should
update before the people they talk to do:

| What is now written | What a client older than 0.4.0 does with it |
|---|---|
| Signed room messages (`ROOM_SIG_WRITE_ENABLED`) | shows the envelope's JSON as the message text |
| Signed key wraps, format v3 (`KEY_WRAP_SIG_WRITE_ENABLED`) | **cannot open the room or DM key at all** |
| Chained DM signatures, v2 (`CHAIN_WRITE_ENABLED`) | rejects the signature: an honest message reads as forged |

**Keys handed out before 0.5.0.** They are all unsigned, so they now open only
on a device that already held them. In the extension that is any device that had
opened the room or DM before (its key archive is persisted). On Android it covers
rooms but **not DMs**: Android does not keep DM keys between sessions, so a DM
whose key predates 0.5.0 no longer opens there. A room recovers when its owner
rotates the key; a DM does not — there is no DM re-key. The project has no
users yet, so this costs test data only.

### Changed — what a message and a key prove

The writers being on is half of it. Following what the readers checked the new
signatures against showed that, against a dishonest island — the one adversary
they exist for — they proved far less than they claimed. This release closes
that too.

- **A room message says who wrote it, checkably.** The room key proves only
  membership; the signature is what stops a server from moving one member's
  words under another member's name.
- **Signatures are checked against a key the island cannot swap.** Every
  signature — DM, room message, key wrap — used to be verified with whatever
  Ed25519 key `/keys/{name}` returned, unpinned, so the island could serve a key
  of its own and sign anything as anyone. Peers' signing keys are now pinned on
  first sight, next to the X25519 pin; a different key later is parked, not
  used, and only the user verifying the peer moves the pin.
- **A key says who handed it to you, and only an entitled person may.** Every
  room and DM key this client wraps carries the wrapper's name and signature,
  bound to the room, the recipient and the key version. A signed key must verify
  under the signer's pinned key and come from the DM peer or a member of the
  room — the island can still mint an account, but it then has to show it in the
  member list. Anything that fails is refused, not flagged.
- **An unsigned key can no longer bring anything new.** It only hands back a key
  the device already held. Writers refuse to produce an unsigned wrap instead of
  quietly skipping the signature, and a new room's key — which must go up
  unsigned, before the room has an id to sign against — is re-signed as soon as
  the island answers with the id. Cross-island keys stay unsigned (v2): there is
  no local name to bind them to, and they never enter this path.
- **Deleting or reordering stored DMs is detectable.** Each message signs its
  position in the sender's run, so a gap or a re-filed message shows up on the
  reader's side. Cross-island threads are not chained yet.
- **What this still does not do.** First contact is trust-on-first-use, as it
  was for X25519 keys: safety numbers cover the X25519 key only, so comparing
  them does not yet catch a signing key swapped at first contact. Room
  membership is the island's word. And the island can still serve an *older*
  key the device already holds as the current one.

### Fixed — security

- **No signed current key could be opened.** The island sends no `key_id` with
  a current room or DM key, and the readers checked a wrap's signature against
  that missing id — so with the writer on, every room and every DM refused its
  own key. Readers now open the wrap first and check the signature against the
  id of the key inside; whatever `key_id` the island attaches is never trusted,
  which also means a genuine key cannot be re-filed as another version. Found by
  running the integration suites against a real island; the offline tests had
  served a `key_id` the server never sends, and now pin that it does not.
- **Android loaded an archived key with no key id as the room's current key**,
  which let the island roll a room back to a key a departed member still held.
  Archived keys now always go to the archive, under the id of the key itself.
- **Cross-island contact names sat on the island in the clear.** The clients
  sent the name from a contact card as the mailbox label. They no longer do;
  the server drops the field and erases what it had stored.

### Added — tests

- The flags' tests used to pin "nothing signed goes out yet" on purpose; they
  now pin the new state, and close the loop the flags open: what each writer
  produces is fed back to the matching reader — a room message must verify, and
  a key this client wraps and uploads must open the room again when the server
  hands it back.
- `extensionKeyTrust.test.js` runs the extension's real `panel-crypto.js`
  headless against a stubbed island — the first offline tests of the
  extension's key handling — and holds it to the same rules as Android.
- Each rule was checked by breaking it: accepting unsigned keys, skipping the
  signer check, and trusting the served signing key each fail exactly the tests
  written for them, in both clients.
- The integration suites ran against two real islands: `panelLocal`,
  `recovery`, `crossIsland` and `panelCrossIsland` pass, apart from the one
  case that needs a running relay. `panelLocal` now reads room messages the way
  the panel shows them, so it checks room signatures end to end as well.

### Added — self-hosting

- **A server installed by the guide can now talk to other servers.** Direct
  messages between islands shipped in 0.4.0, but they need `ISLAND_ID`, and
  nothing on the install path set it: no line in `config.example.env`, no step
  in the guide, nothing in `bootstrap.sh`. Every `/foreign/*` endpoint answered
  404 and the server said nothing. Now `bootstrap.sh` generates the island
  identity — id, Ed25519 signing key, signed list of entry points built from
  the domains it certifies — on a fresh install and on an existing one that
  lacks it (safe: without `ISLAND_ID` nobody could have pinned anything).
  Values already in `.env` are never replaced. `WSAPP_SKIP_ISLAND=1` opts out.
- The server logs at startup whether cross-island messages are on, and if not,
  which setting is missing.
- `docs/self-hosting.md` §8.3 explains the feature, the manual setup, and the
  three rules that keep contacts on other servers working: never change the id
  or the key, raise `ISLAND_LIST_VERSION` with every list change, list every
  address.

### Fixed — self-hosting

- **The shipped systemd unit ran two workers, and two workers split the
  server.** Room sockets, DM sockets, notifications and rate limits live in the
  process's memory, so two people in one room or one DM who landed on different
  workers stopped seeing each other's messages live (they appeared only after a
  reload), a room owner could miss the wake-up that a new member needs the key,
  and every rate limit was effectively doubled. Nothing logged an error. Both
  `scripts/bootstrap.sh` and `docs/self-hosting.md` now use `--workers 1`;
  re-running the bootstrap script fixes an existing install.
- **A login froze every socket on the server for a few hundred milliseconds.**
  Argon2id ran inline in async handlers — login, registration, password change,
  recovery, account deletion, room passwords — and blocked the event loop for
  the whole hash. It now runs in a thread, at most `ARGON2_MAX_CONCURRENCY`
  (default 2) at once, so a burst of logins cannot hold dozens of 64 MiB
  buffers on a small VPS.

### Changed — documentation

- The README no longer says the server does not know who you talk to in direct
  messages. It does: thread membership and message timing are stored in plain.
  Sealed sender hides which of the two wrote a given message, and nothing more;
  `docs/architecture.md` now says so next to the mechanism.
- `docs/architecture.md` describes islands — several addresses for one server,
  the signed island list, direct messages between servers, relays — and what
  each server learns about a cross-island conversation. It had not mentioned
  any of it.
- `relay/README.md` no longer says no client speaks the relay protocol; both
  do. It now walks through connecting a relay to an island end to end,
  including the two steps that were missing: publishing the relay in the
  island's signed list (clients learn relays from nowhere else), and keying the
  relay's config by the island's exact `ISLAND_ID`.
- The README says what the two goals it announced have become.

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
