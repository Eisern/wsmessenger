# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**WS Messenger Android** — a React Native (Android-only) port of the WS Messenger Chrome extension (`../`). Preserves the full E2EE architecture (X25519 + AES-256-GCM) while replacing all browser/extension APIs with React Native equivalents. No build step for JS — Metro bundler handles this at runtime.

## Build Commands

All commands run from the `Android/` directory.

```bash
npm run android          # Build debug APK + install on connected device/emulator (requires Metro)
npm start                # Start Metro bundler (required for run-android)
npm run android:release  # Release APK → android/app/build/outputs/apk/release/
npm run android:bundle   # AAB for Play Store → android/app/build/outputs/bundle/release/
npm test                 # All Jest tests
npm run test:crypto      # Crypto-only tests (Node env, verbose)
```

**Building APK directly via Gradle** (from `Android/android/`):
```bash
./gradlew assembleDebug    # → app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleRelease  # Requires keystore.properties
./gradlew clean assembleDebug  # Force full rebuild (clears Gradle cache)
```

Release signing: copy `android/keystore.properties.example` → `android/keystore.properties` and fill credentials. Run `npm run keygen` to generate keystore first.

**Prerequisites**: JDK 17, Android SDK 36, NDK 27.1.12297006, Gradle 8.x (Gradle 9 incompatible with RN 0.84).

## Architecture

### Process Model

Unlike the Chrome Extension (two contexts via `chrome.runtime` ports), the Android app runs in a single JS thread. The role of `background.js` is split across services:

| Chrome Extension | Android |
|---|---|
| `background.js` (service worker) | `NetworkService.js` (singleton) |
| `chrome.runtime` port | `mitt` event emitter |
| `chrome.storage.local` | `AsyncStorage` (StorageService) |
| `chrome.storage.session` | in-memory state |
| `SecureStore` (ext) | `react-native-keychain` |

### Key Files

| File | Role |
|---|---|
| `index.js` | Entry point: installs `react-native-quick-crypto` polyfill first, before any other import |
| `App.tsx` | Root navigator: `AuthStack` (login/register) ↔ `AppTabs` (rooms/DM/invites/profile) |
| `src/contexts/AppContext.js` | Central state via `useReducer`; all UI state lives here |
| `src/services/NetworkService.js` | WebSocket + REST singleton; emits `message`, `dm_message`, `wsOnline`, `sessionExpired` etc. |
| `src/services/CryptoService.js` | Crypto session lifecycle: unlock, auto-lock (20 min idle), DM key management |
| `src/services/StorageService.js` | AsyncStorage (rooms, pinned context) + react-native-keychain (auth tokens) |
| `src/crypto/CryptoUtils.js` | Raw crypto primitives — adapted from `../crypto-utils.js` |
| `src/crypto/CryptoManager.js` | Room key lifecycle, archival — adapted from `../crypto-manager.js` |
| `src/components/PasswordModal.js` | Promise-based password prompt (legacy — no longer used in Chat/DM screens) |

### Keyboard Handling

**`react-native-keyboard-controller`** — universal keyboard handling for edge-to-edge displays (required since `targetSdkVersion = 36` enforces Android 15 edge-to-edge mode, where `adjustResize` no longer reliably resizes the window).

**Setup:**
- `AndroidManifest.xml`: `windowSoftInputMode="adjustNothing"` — disables OS-level resize; insets are handled in JS.
- `App.tsx`: root wrapped in `<KeyboardProvider>` (from `react-native-keyboard-controller`).
- `ChatScreen.js` / `DMChatScreen.js`: root element is `<KeyboardAvoidingView style={styles.root} behavior="padding">` (imported from `react-native-keyboard-controller`, not `react-native`).

**Why `react-native-keyboard-controller`:**
- Uses `WindowInsetsAnimationCompat` natively — correctly tracks keyboard animation on all manufacturers including Samsung One UI.
- React Native's built-in `KeyboardAvoidingView` with `adjustResize` or `adjustPan` causes double-adjustment, gaps, or no effect at all on edge-to-edge devices.
- Login/register/import screens use `ScrollView` inside a plain `View` — no KAV needed there (forms scroll naturally).

**Do NOT revert to `adjustResize`** — it silently fails on Samsung Galaxy S23 Ultra and other Android 15 devices, causing the keyboard to cover the input field and bottom navigation.

### Crypto Unlock Flow

Password is entered **once** — either on LoginScreen (fresh login) or UnlockScreen (app restart with saved auth). After that, crypto stays unlocked transparently:

```
Login/Import → unlockWithPassword(pwd) or unlockWithRawKey(raw)
                → caches raw privkey to Keychain (react-native-keychain)
                → _emit('unlocked')

App restart  → StorageService.getAuth() → auto-login
             → CryptoService.ensureReady({ interactive: false })
                → tries: KEK → cached password → Keychain auto-unlock
                → if all fail → UnlockScreen (one-time password entry)

Idle (20 min) → timer fires → _tryAutoUnlockFromKeychain()
                → if Keychain works: silently re-unlock, reset timer (no user action)
                → if Keychain fails: lockSession() (rare — device lock/wipe)

Any encrypt/decrypt call → if !isReady(), auto-calls ensureReady({ interactive: false })
                          → transparent Keychain re-unlock on every crypto operation
```

**Key invariants:**
- No interactive password prompts in ChatScreen or DMChatScreen — removed PasswordModal from both.
- `CryptoManager.initializeUserKeyFromRaw()` **copies** the `privRaw` buffer (`new Uint8Array(privRaw)`) — callers may `.fill(0)` the original safely.
- `unlockWithRawKey()` **awaits** `_cachePrivKeyToKeychain()` before returning — ensures Keychain is written before caller wipes key material.

### Event Listener Pattern (Ref-Based Stable Handlers)

ChatScreen and DMChatScreen use **ref-based stable handlers** to prevent listener accumulation in `mitt` when navigating between tabs:

```js
_handleIncomingMsgRef.current = handleIncomingMsg; // update ref on every render
useEffect(() => {
  const stableHandler = (msg) => _handleIncomingMsgRef.current?.(msg);
  NetworkService.on('message', stableHandler);
  return () => NetworkService.off('message', stableHandler);
}, []); // empty deps — register once on mount, remove once on unmount
```

This pattern solves the message duplication bug where visiting N chats produced N copies of sent messages. The root cause was `mitt`'s `off()` silently failing when the function reference didn't match (React re-creates closures on each render, but `useEffect` cleanup captured a stale reference when deps like `[roomId, cryptoReady]` triggered re-runs during tab navigation).

The same pattern is applied to:
- `handleIncomingMsg` (ChatScreen — room messages)
- `handleMembersChanged` (ChatScreen — member change events)
- `handleIncoming` (DMChatScreen — DM messages)

Additionally, `APPEND_ROOM_MESSAGE` reducer now deduplicates by content (ciphertext body + decrypted text + timestamp ±2s window), not just by `id`.

### WS Message Queue (Race Condition Prevention)

Both ChatScreen and DMChatScreen use a **key-readiness gate** to prevent messages arriving via WebSocket before the room/DM key is loaded:

- `_roomKeyReadyRef` / `_dmKeyReadyRef` — ref set to `true` after `ensureRoomKeyReady()` / `ensureDmKeyReady()` completes in the init effect.
- `_pendingIncomingRef` — array queuing WS messages that arrive before the key is ready.
- After key loads + history fetch, queued messages are flushed with proper decryption.
- The `'unlocked'` event handler also loads the key and flushes the queue (for cases where crypto wasn't ready during init).

### Global DM Handler vs Screen Handler

`NetworkService._post()` emits events in order: `'message'` first, then `msg.type` (e.g. `'dm_message'`). Two handlers process DMs:

1. **App.tsx `globalDmHandler`** — listens on `'message'` event, handles DMs when DMChatScreen is NOT mounted (background dispatch + notifications).
2. **DMChatScreen `handleIncoming`** — listens on `'dm_message'` event, handles DMs for the active thread.

To prevent double-processing (which causes ciphertext duplicates):
- `activeScreenThreadIds` — a **synchronous module-level `Set`** exported from DMChatScreen, updated in `useFocusEffect`. No React state lag.
- The global handler checks `activeDmScreens.has(threadId)` before processing — skips if the screen handler is active.

### Notification Handler (App.tsx)

The `notifHandler` in App.tsx uses `stateRef` (not direct `state`) for all checks, allowing it to be registered once (`deps: [state.isLoggedIn]`) instead of re-registering on every `currentRoomId`/`currentDmThreadId` change. This prevents listener churn and unnecessary re-registrations in `mitt`.

### WS Connection & Notifications

Room WS connects to **one room**, DM WS connects to **one thread**. Notifications only arrive for connected channels.

- **Auto-connect on login**: if no saved `lastConn`/`lastDm`, App.tsx fetches the room list and DM threads from REST API and connects to the first of each.
- **WS stays alive on back-navigation**: ChatScreen and DMChatScreen do NOT disconnect WS when the user presses back. WS is replaced only when entering a different room/DM.
- **Notification channel created early**: `NotificationService.setup()` runs with `await` in the init effect, before auth restore and WS connect — ensures `_channelId` is ready before messages arrive.
- **Limitation**: for notifications across ALL rooms/DMs simultaneously, FCM push is required (server-side). Currently one room + one DM thread at a time.

### Crypto Constraints (react-native-quick-crypto)

`react-native-quick-crypto` is the Web Crypto polyfill but has gaps — use these alternatives:

| Operation | Do NOT use | Use instead |
|---|---|---|
| X25519 key generation / ECDH | `crypto.subtle.generateKey` / `deriveBits` | `@noble/curves/ed25519` (`x25519`) |
| HKDF key derivation | `crypto.subtle.deriveKey` | `@noble/hashes/hkdf` |
| HMAC sign/verify | `crypto.subtle.importKey + sign` | `@noble/hashes/hmac` |
| SHA-256 hash | works via `crypto.subtle.digest('SHA-256', ...)` | or `@noble/hashes/sha2` |
| AES-GCM encrypt/decrypt | works normally | — |
| PBKDF2 deriveBits | works normally | — |
| Argon2id | N/A (no native impl) | `@noble/hashes/argon2` (pure JS) |

**Critical**: All files that use `crypto.subtle` must use a lazy proxy — the polyfill is installed **after** module evaluation:
```js
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};
```

### DM Send Architecture (Sealed Sender)

DMs use **UD (Unsealed Delivery)** — `POST /ud/dm/send` with no `Authorization` header, authenticated via HMAC-SHA256 over a per-thread `delivery_secret`. The server stores `user_id = NULL`, preserving sender anonymity.

- Delivery secret: fetched via `GET /dm/{threadId}/delivery-secret` (requires JWT)
- HMAC input: `utf8(threadId) | utf8(ts) | nonce | sha256(ciphertext_bytes)`
- `ciphertext_b64` field: `base64url(utf8(encryptedJSON))` — Chrome Extension decodes this before passing to `decryptDm()`
- WS (`/ws-dm`) is **receive-only** — server rejects all send attempts except `ping`
- **Delivery secret TTL**: `expires_at` column (24h) added to `chat_dm_delivery`. Server returns `401` on expired secret; client invalidates cache and re-fetches with Bearer token (re-checks membership). `GET /dm/{threadId}/delivery-secret` returns `expires_at` in ISO format. Client cache (`_deliverySecretCache`) stores `{ secret, expiresAt }` and pre-emptively re-fetches with >60s margin.

### Tests

Two Jest environments configured in `jest.config.js`:

- **`crypto` project** (Node env) — `src/crypto/__tests__/` — runs against native Node Web Crypto; 30 tests covering X25519, AES-GCM, PBKDF2, Argon2id, safety numbers
- **`react-native` project** (RN env) — `__tests__/` and non-crypto `src/` tests

```bash
npm run test:crypto   # Run crypto tests only (fastest feedback loop)
npm test              # All tests
```

### Build Configuration

- **`debuggableVariants = []`** in `android/app/build.gradle` — JS bundle is always included in debug APK (standalone installs without Metro dev server).
- **`unstable_enablePackageExports: true`** in `metro.config.js` — required for `@react-native-documents/picker` (v12) which uses `exports` field in package.json. Causes warnings for `@noble/*` packages but they fall back to file-based resolution safely.

### Camera & File Attachment

The `+` button in DMChatScreen shows a two-option menu (via `Alert.alert`):

- **File from device** — `@react-native-documents/picker` (`pickDocument`), any file type
- **Take photo** — `react-native-image-picker` (`launchCamera`), camera only

**Camera security model:**
- Uses Android `ACTION_IMAGE_CAPTURE` intent — the OS camera app handles capture; this app has no direct hardware access while the camera is active
- `saveToPhotos: false` — photo lives only in the app's temp cache until upload completes, never saved to gallery
- Photo is E2EE-encrypted (DM key) before upload — same path as any file attachment
- `CAMERA` permission is a runtime "dangerous" permission — Android shows an explicit OS dialog on first use
- `<uses-feature android:required="false">` in manifest — app is installable on devices without a camera (camera option shows "No camera available" alert)
- Max resolution 1920×1920, quality 0.85 — prevents sending unnecessarily large files

### Image Preview

`ImageCard.js` — renders inline thumbnails for image attachments (jpg/jpeg/png/webp/gif).

- **Detection**: `isImageFile(filename)` in `fileMarker.js` — extension check, same sanitization path as all filenames
- **Fetch**: downloads via `RNFS.downloadFile` with `Authorization: Bearer` — same auth as all file downloads
- **Cache**: stored in `RNFS.CachesDirectoryPath/ws_img_{token}` — app-private, not accessible by other apps. Token is pre-validated to `[A-Za-z0-9_-]` by `parseFileMarker` — no path traversal possible
- **Corrupt cache**: on non-200 response the partial file is deleted immediately (`RNFS.unlink`) — prevents stale cache causing repeated failed loads
- **Fallback**: any download or render error falls back to the regular `FileCard` (no silent failure)
- **Fullscreen**: tap thumbnail → `Modal` with `resizeMode="contain"`, tap to close. `onRequestClose` handles Android back button

### File Picker

File attachment uses `@react-native-documents/picker` (v12, renamed from `react-native-document-picker`):

```js
import { pick as pickDocument, types as pickerTypes } from '@react-native-documents/picker';
const [res] = await pickDocument({ type: [pickerTypes.allFiles] });
```

- **API change from v9**: `pick()` returns array (no `pickSingle`), cancel error code is `OPERATION_CANCELED` (not `DOCUMENT_PICKER_CANCELED`).
- Import must be **top-level** (not lazy `require()`) — Metro needs to resolve at bundle time.

### Username Comparison

All `isMe` checks **must** use case-insensitive comparison (matching the Chrome Extension):

```js
const meLower = (myUsername || '').toLowerCase();
const isMe = (msg.author || '').toLowerCase() === meLower || (msg.username || '').toLowerCase() === meLower;
```

Server may return usernames in different case than stored in `state.username`. Strict `===` will break message alignment (own messages appearing on the left).

### Visual Style

UI styles are ported from the Chrome Extension's `panel.css`. Key design tokens live in `src/theme.js`. Main visual patterns:

- **Messages**: left-border style (2px `border-left` for others, `border-right` for self) — not card bubbles
- **List items** (rooms, DMs, invites): card-style with `borderRadius: 10`, margin, and border — not flat rows
- **Modals**: bottom-sheet with `borderRadius: 14`, `elevation: 8`
- **Headers**: `elevation: 4`, `borderSubtle` divider
- **Search bar**: glass-morphism (`rgba(0,0,0,0.22)` background)
- **Badges**: cyan `#2aabee` (rooms), purple `#8b5cf6` (DMs)

### Room Management

Room management features ported from the Chrome Extension:

**Room Creation with E2EE key**:
- `POST /rooms` requires `encrypted_room_key` — the room key encrypted for the owner.
- `CryptoService.generateRoomKeyForCreation()` generates AES-256 room key, encrypts with owner's X25519 public key, returns `{ encrypted_room_key, rawB64 }`.
- After creation, `CryptoService.loadRoomKey(roomId, rawB64)` stores the key locally.
- CreateRoomModal (RoomsListScreen) handles the full flow: ensure crypto → generate key → create room → load key locally.

**Invite flow (deferred key sharing)**:
- `NetworkService.inviteToRoom(roomId, username)` creates a `pending` membership on the server.
- Room key **cannot** be shared at invite time — server's `/crypto/room/{rid}/share` requires `status = 'accepted'`.
- Key sharing happens automatically when the invitee accepts: ChatScreen listens for WS `members_changed` with `action: invite_accepted` and calls `CryptoService.shareRoomKeyToUser()` if the current user is the room owner.
- `CryptoService.shareRoomKeyToUser(roomId, username)` — exports current room key, fetches peer's X25519 public key, validates 32-byte length, TOFU check, encrypts and shares via API.

**Key rotation after kick**:
- After `NetworkService.kickFromRoom()`, ChatScreen fetches remaining members, retrieves each member's public key via `NetworkService.fetchPeerKey()`, then calls `CryptoService.rotateRoomKey(roomId, members)`.
- `rotateRoomKey` generates a new room key, encrypts for each member with TOFU verification, and distributes via API. Kicked user cannot decrypt new messages.

**Room Settings (owner only)**:
- RoomSettingsModal in ChatScreen: edit description (`NetworkService.setRoomMeta`), change password (`PUT /rooms/{id}/password`), delete room (`NetworkService.deleteRoom`).
- Gear icon (⚙) in header visible to owners only.

**Pinned Context**:
- `NetworkService.fetchRoomPin(roomId)` / `putRoomPin(roomId, { url, text })` — `GET`/`PUT /rooms/{id}/pin`.
- Collapsible bar in ChatScreen with URL (clickable) and text preview (180 chars).
- Long-press (owner) opens edit modal with URL + text fields → `putRoomPin()`.

**Leave Room**:
- MembersModal (ChatScreen): "Leave Room" button at the bottom. Owner → alert "Cannot leave — delete from settings". Non-owner → confirm → `NetworkService.leaveRoom(roomId)` → `navigation.goBack()`.
- RoomsListScreen: "Leave" button on each room in "My Rooms". Same owner guard. After leave → refresh list.
- Matches Chrome Extension behavior: owner cannot leave, only delete.

**User Reporting**:
- `NetworkService.reportUser(targetUsername, reason, comment)` → `POST /reports` with `{ target_type: 'user', target_username, reason, comment }`.
- ChatScreen MembersModal: ⚑ button per member (except self) → report modal with 5 reasons (spam, harassment, illegal content, impersonation, other) + optional comment.
- DMChatScreen header: ⚑ button → same report modal for the peer.

### Friends Management

- Friends list displayed as a section in InvitesScreen (tab "Invites"), loaded via `NetworkService.getFriends()` → `GET /friends/list`.
- Each friend row: "Message" button (opens DM via `openDmThread`) + "Remove" button (with confirm → `NetworkService.removeFriend()`).
- "+ Add Friend" button in header → modal with username input → `NetworkService.sendFriendRequest()`.
- Incoming friend requests shown as a separate section with Accept/Decline buttons.
- Screen title: "Friends & Invites".

### Privacy Settings

ProfileScreen privacy toggles use server-compatible keys:
- `allow_group_invites_from_non_friends` — allow strangers to invite you to group chats
- `allow_dm_from_non_friends` — allow non-friends to DM you
- Labels: "Allow group invites from non-friends" / "Allow DMs from non-friends"
- Hint: "Privacy settings are visible only to you."

### Recovery Phrase (BIP39)

Registration generates a 24-word BIP39 mnemonic and computes `recovery_key_hash` (HKDF → SHA-256). The mnemonic is shown in a modal after registration — user must acknowledge before proceeding. `recovery_key_hash` is sent to the server for future recovery via `ImportKeyScreen`.

ProfileScreen has a "Show Recovery Phrase" button (in Encryption Identity section) that requires password re-entry to decrypt EPK and display the 24 words.

### Key Change Alerts (TOFU)

`CryptoService.checkAndAlertKeyChange(peerUsername)` checks the peer's public key fingerprint against the stored value. If changed, shows `Alert.alert` and emits `'key_changed'` event. Session-level dedup (`_kcAlerted` Set) prevents re-alerting for the same peer.

- **ChatScreen**: batch-checks all room members on entry (`checkRoomPeersKeyChanges`), per-message check on incoming messages.
- **DMChatScreen**: checks DM peer on thread entry, per-message check on incoming DMs.
- `resetKeyChangeAlerts()` called on room/thread navigation change.

### Message Copy

Long-press on any message bubble (rooms and DMs) copies decrypted text to clipboard via `@react-native-clipboard/clipboard`.

### Crypto Auto-Lock Timeout

Configurable via ProfileScreen (Encryption Identity → Auto-Lock Timeout). Options: 5/10/20/30/60 minutes. Persisted to AsyncStorage (`crypto_idle_lock_ms`), restored on app startup via `CryptoService.restoreIdleLockSetting()`.

### Room Logo Upload

RoomSettingsModal (owner only) has "Upload Logo" button. Uses `@react-native-documents/picker` for image selection, uploads via `NetworkService.uploadRoomLogo()`, then sets `logo_token` via `setRoomMeta()`.

### Room Password Prompt

RoomsListScreen detects 403 "Bad room password" from `joinPublicRoom()` and shows a password modal. User enters password → retry join with password in request body.

### Safety Number Verification UI

DMChatScreen safety number modal includes: verification status display, "I verified this" button (marks key as trusted via `CryptoService.verifyPeerKey()`), key change warning banner (red, shown when peer's key has changed), "Copy number" button. Session-level dedup via `_kcAlerted` Set prevents repeated alerts for the same peer.

### WS Reconnect on Foreground

`NetworkService._onForeground()` handles room, DM, and notification WebSocket reconnection. For apparently-open connections, sends a ping to detect stale TCP; if ping fails, triggers reconnect. For closed connections, reconnects immediately with reset backoff.

### Notification WebSocket (`/ws-notify`)

A single per-user WebSocket that receives lightweight notifications for **all** rooms and DMs the user belongs to, regardless of which room/DM is currently open.

**Architecture:**
- `NetworkService.connectNotify()` connects to `wss://server/ws-notify` on login, stays connected for the session lifetime.
- Server-side `NotifyManager` maps `user_id → set[WebSocket]`. On each room or DM message broadcast, a lightweight notification is fan-out to all members via their `/ws-notify` connection.
- The notification WS is **read-only** (client only sends `auth` + `ping`).

**Payloads (no ciphertext — metadata only):**
- Room: `{type: "notify_room_msg", room_id, room_name, from, ts}` — sender username included (not sealed).
- DM: `{type: "notify_dm_msg", thread_id, ts}` — **no sender** (sealed sender preserved).

**Client-side deduplication (App.tsx):**
- `NetworkService.isConnectedToRoom(roomId)` / `isConnectedToDm(threadId)` — if the user is already connected to this room/thread via the primary WS, the notification event is skipped (the primary WS already delivered it).
- Unread badge counters (`INCREMENT_UNREAD_ROOM` / `INCREMENT_UNREAD_DM`) are incremented from notify events.

**Security:**
- JWT auth required, origin check, rate limit on connect, ban check every 30s.
- No message ciphertext in payloads — only metadata for notification display.
- DM notifications preserve sealed sender (no sender username).
- Inbound message size capped at 512 bytes.

**Lifecycle:** `connectNotify()` on login, `disconnectNotify()` on logout/session expired, auto-reconnect with exponential backoff, foreground reconnect via `_onForeground()`.

### Server Config (Self-Host Support)

Users can point the Android app at any self-hosted server at runtime.

**Storage:** `AsyncStorage` key `com.wsmessenger.server_config` → `{ apiBase, wsBase }`. Loaded once at startup in `App.tsx` before auth restore (`NetworkService.loadServerConfig()`).

**Module-level state:** `let _apiBase/_wsBase` at the top of `NetworkService.js`. All `_fetch()` / `fetch()` calls inside the class access them via closure — no `this.` needed on every reference.

**NetworkService methods:**

| Method | Description |
|---|---|
| `setServerConfig(apiBase, wsBase)` | Apply in-memory only (no persist) |
| `async saveServerConfig(apiBase, wsBase)` | Apply + persist to AsyncStorage; clears delivery secret cache |
| `async loadServerConfig()` | Read AsyncStorage and apply; call once at startup |
| `async clearServerConfig()` | Reset to defaults + remove from AsyncStorage; clears delivery secret cache |
| `getServerConfig()` | Returns `{ apiBase, wsBase, isDefault }` |

**LoginScreen UI:** collapsible "Connect to another server" section at the bottom of the login form.
- Two inputs: API base URL + WS base (auto-derived if empty)
- **Test** button: `fetch(api + '/health')` with 5 s `AbortController` timeout; independent `setupTestLoading` state
- **Save** button: validates URL (HTTPS only; `http://localhost` allowed), strips to origin, calls `NetworkService.saveServerConfig()`; independent `setupSaveLoading` state
- **Reset** button (shown when non-default): calls `NetworkService.clearServerConfig()`
- Both buttons disable while either is loading (prevents concurrent Test + Save)

**URL validation rules (both clients):**
- Scheme must be `https:` (or `http:` for `localhost`/`127.0.0.1` only)
- Path/query stripped — only `parsed.origin` is stored
- WS base: `https://` → `wss://`, `http://` → `ws://`

**Delivery secret cache:** `saveServerConfig` and `clearServerConfig` both call `this._deliverySecretCache.clear()` + `this._deliverySecretPending.clear()` — prevents secrets from one server being used against another.

### Server Broadcast Notice (MOTD)

`NetworkService.fetchNotice()` calls `GET /api/notice` (no auth required). On app startup (init effect in App.tsx), if server returns `{active: true, message, type}`, displays an `Alert.alert()` with type-appropriate title (Server Notice / Warning / Maintenance).

### Security Hardening

Applied security measures:
1. `network_security_config.xml` — cleartext blocked; certificate pinning (pins valid until 2027-01-01)
2. Rate limiting — login/register/verify2fa (5/60s), crypto unlock (5/60s)
3. KDF minimum — 600k iterations, only SHA-256/384/512
4. `FLAG_SECURE` — screenshot blocking on main Activity window AND all Dialog/Modal windows via `SecureWindowManager` Kotlin delegate in `MainActivity.kt`
5. ProGuard enabled for release builds
6. Clipboard cleared after crypto unlock and 60s after message copy
7. File upload size validation — 50MB max for files, 5MB max for room logos
8. Delivery secret TTL (24h) — limits compromise window; forced re-auth with membership check on expiry
9. Notification lock screen privacy — `AndroidVisibility.PRIVATE` on all channels; sensitive content hidden on lock screen
10. Password change revokes all sessions — `POST /auth/change-password` calls `revoke_all_user_refresh_tokens` server-side; all refresh tokens on all devices invalidated atomically with hash update

### Known Issues / TODO

- **Recovery phrase "Incorrect password"**: FIXED. `getRecoveryPhrase()` now delegates entirely to `CryptoUtils.decryptPrivateKey()` (the same path as login) and reads raw key bytes from the returned `_x25519.priv` field. Previous "fix" reimplemented the KDF+decrypt inline with subtle divergences; delegating to the shared path eliminates any possibility of mismatch.
- **Password change**: FIXED. `CryptoService.changePassword(oldPass, newPass)` — verifies old password via `CryptoUtils.decryptPrivateKey`, re-encrypts EPK with new password (Argon2id-preferred KDF), calls `POST /auth/change-password` (server verifies old pass + revokes all refresh tokens), saves new EPK to Keychain. UI in ProfileScreen Security section; "OK" button triggers `NetworkService.logout()` after showing success message (logout deferred to avoid setState-on-unmounted-component).
- **Online presence panel**: No dedicated panel showing who's online in a room with filter/search. Extension has a full presence panel with role badges, kick/role buttons, and collapsible state. Android shows online dots in MembersModal but no standalone presence UI.
- **Unread messages on login (offline gap)**: When a user logs in after being offline, there is no server poll for missed messages. `/ws-notify` only delivers real-time events — anything sent while the user was offline is lost from a notification standpoint. Need a REST endpoint (e.g. `GET /unread/summary`) that returns per-room and per-thread unread counts + last message timestamps, called once on login to populate badge counters and optionally show catch-up notifications.

### Security TODO

Issues found in the Android client security audit. Listed by severity.

**HIGH**

- **Plaintext key material in JS heap**: FIXED. `CryptoManager.clear()` calls `priv.fill(0)` before nulling. `CryptoUtils._deriveWrappingKey` now awaits `importKey` and wipes the HKDF output (`rawKey.fill(0)`). `encryptRoomKeyForUser` wipes `ephPrivRaw` and `sharedRaw` after use. `decryptRoomKeyForUser` wipes `sharedRaw` after use.

- **`atob` not available in all Hermes versions**: Not applicable — all `atob` calls in `tryDecrypt` and `globalDmHandler` are already inside `try/catch` blocks that swallow `ReferenceError`. On RN 0.84 / Hermes, `atob` is available (shipped since RN 0.71).

- **File download path traversal**: `ImageCard.js` validates the file token against `[A-Za-z0-9_-]` (via `parseFileMarker`), but the cached file path is built as `RNFS.CachesDirectoryPath + '/ws_img_' + token`. If a future code path ever skips token validation, a crafted token could escape the cache directory. Confirm `parseFileMarker` is always on the critical path.

- **Delivery secret cached without expiry check on send**: Already implemented. `getDeliverySecret()` checks `cached.expiresAt > Date.now() + 60_000` on every call — including the call immediately before each send in `DMChatScreen`.

**MEDIUM**

- **TOFU check bypassed if peer key unavailable**: AUDITED + FIXED. All callers of `_assertPeerKeyTrustedForSharing` abort on failure (throw propagates). In ChatScreen, when auto-key-share is blocked by a TOFU re-verification error, an `Alert.alert` is shown to the owner instead of silently swallowing the error.

- **Ed25519 signature not required for DM receive**: FIXED. `sigValid === null` with a known sender (from ≠ null, from ≠ self) now sets `_sealedSenderUnverified: true` on the message. DMChatScreen renders `(unverified)` in muted italic style below the message, distinct from the yellow `⚠ Signature verification failed` for `sigValid === false`.

- **Certificate pinning expiry (2027-01-01)**: `network_security_config.xml` pins expire on 2027-01-01. Set a calendar reminder well before that date to rotate pins; expired pins cause all HTTPS to fail silently on Android 9+.

- **`FLAG_SECURE` not applied to `Modal` overlays**: FIXED. `MainActivity.kt` overrides `getSystemService(WINDOW_SERVICE)` to return a `SecureWindowManager` Kotlin delegate that ORs `FLAG_SECURE` into every `WindowManager.addView()` call — including the separate Dialog window created by RN's `Modal`. All overlays (safety number, recovery phrase, change password) are now protected.

- **No jailbreak/root detection**: On rooted devices, `react-native-keychain` Android Keystore-backed storage can be bypassed. Consider adding SafetyNet/Play Integrity attestation check on startup (or at minimum warn the user if Keystore is software-backed).

- **`AsyncStorage` stores message history in plaintext**: ALREADY FIXED (TODO was stale). `StorageService.setRoomHistory`/`getRoomHistory` use `_encryptHistory`/`_decryptHistory` — AES-256-GCM with a per-kid key stored in Keychain (`history_keyring`). Encryption is fail-closed: if it fails, storage is refused (never falls back to plaintext). TOFU fingerprints also stored in Keychain, not AsyncStorage.

**LOW**

- **No replay protection on DM delivery HMAC**: The HMAC input includes `ts` and `nonce`, but the server's replay window tolerance is not documented. If the server allows a large `ts` drift, a captured delivery secret + HMAC could be replayed. Confirm server enforces strict `ts` window (e.g., ±60s).

- **`Clipboard.setString('')` clears clipboard after unlock but not after message copy**: FIXED. `ChatScreen` and `DMChatScreen` use `_copyMessage()` helper that sets a 60s `setTimeout` to clear the clipboard. Multiple rapid copies cancel the previous timer (module-level `_clipClearTimer`).

- **Log verbosity in production**: FIXED (crypto-sensitive lines). `[_loadDmKey] ERROR`, `[decryptDm]` family, `DM Ed25519 signature INVALID`, `Ed25519 verify error`, `sealed sender envelope` logs are now guarded with `if (__DEV__)` in `CryptoService.js`.

- **`react-native-fs` download without MIME validation**: FIXED. `ImageCard.js` reads the first 12 bytes of the downloaded file and checks JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), GIF (`47 49 46`), and WEBP (`RIFF....WEBP`) magic numbers before setting `localUri`. Non-matching files are deleted from cache and fall back to `FileCard`.

### Backend

Same backend as Chrome Extension — see `../CLAUDE.md` for host URLs and API structure.

- `delivery_secret` is created server-side in `POST /dm/open` (one per thread, not per user)
- `POST /dm/open` is idempotent — safe to call for existing threads; will create delivery secret if missing
