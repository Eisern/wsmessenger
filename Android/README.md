# WS Messenger — Android client

React Native 0.84 port of the WS Messenger Chrome extension. **Android
only** — there is no iOS target.

The full E2EE crypto layer (X25519 + AES-256-GCM + Argon2id) from the
extension is preserved; browser/extension APIs are replaced with React
Native equivalents (Keychain instead of `chrome.storage`,
`react-native-quick-crypto` polyfill, etc.).

## Prerequisites

- Node.js 22+
- JDK 17
- Android SDK Build-Tools 36, NDK 27.1.12297006
- Android emulator or physical device (API 24+ / Android 7.0+)

## Quick start

```sh
npm install
npm start                 # Metro bundler (in one terminal)
npm run android           # build debug APK and install (in another terminal)
```

## Build commands

```sh
npm run android           # debug APK + install on connected device
npm run android:release   # release APK → android/app/build/outputs/apk/release/
npm run android:bundle    # release AAB → android/app/build/outputs/bundle/release/
npm test                  # all Jest tests
npm run test:crypto       # crypto-only tests (faster feedback)
```

For release-signing setup (keystore, `keystore.properties`),
FCM/Firebase setup, and full troubleshooting, see [BUILDING.md](BUILDING.md).

## Architecture and code layout

See [CLAUDE.md](CLAUDE.md) for:
- the service-vs-screen split and event/listener patterns
- crypto unlock flow, sealed-sender DM transport, key-rotation rules
- keyboard handling on Android 15 edge-to-edge displays
- security hardening notes (FLAG_SECURE, certificate pinning,
  rate limits, KDF minimums)

## License

Same as the parent project — AGPL-3.0-or-later. See `../LICENSE`.
