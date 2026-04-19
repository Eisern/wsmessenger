# Building WS Messenger Android APK

## Prerequisites

- **Node.js** 22+ (`node --version`)
- **JDK 17** (`java -version`)
- **Android Studio** (latest stable) with:
  - Android SDK Build-Tools 36
  - Android NDK 27.1.12297006
  - Emulator or physical device (API 24+ / Android 7.0+)

## First-time setup

```bash
# 1. Install dependencies
cd Android
npm install

# 2. Link native modules (autolinking handles most, but run this to verify)
npx react-native doctor
```

---

## Debug APK (development)

```bash
# Start Metro bundler (keep this running)
npm start

# In a second terminal — build + install on connected device/emulator
npm run android
```

---

## Release APK

### Step 1 — Generate a release keystore (one time only)

```bash
npm run keygen
# Follow the prompts (CN, O, OU, etc.)
# This creates: android/app/release.keystore
```

### Step 2 — Create keystore.properties

Copy the example file and fill in your credentials:

```bash
# Windows (PowerShell)
copy android\keystore.properties.example android\keystore.properties

# Linux / macOS
cp android/keystore.properties.example android/keystore.properties
```

Edit `android/keystore.properties`:
```properties
storeFile=release.keystore
storePassword=YOUR_STORE_PASSWORD
keyAlias=wsapp
keyPassword=YOUR_KEY_PASSWORD
```

> ⚠️ **Never commit `keystore.properties` or `release.keystore` to git.**

### Step 3 — Build release APK

```bash
npm run android:release
```

Output: `android/app/build/outputs/apk/release/app-release.apk`

### Step 4 — Build release AAB (for Google Play)

```bash
npm run android:bundle
```

Output: `android/app/build/outputs/bundle/release/app-release.aab`

---

## Push notifications (optional)

Local in-app notifications work without Firebase. For **FCM push notifications** (messages when app is closed):

1. Create a Firebase project at [console.firebase.google.com](https://console.firebase.google.com)
2. Add an Android app with package `com.wsmessenger`
3. Download `google-services.json` → place in `android/app/`
4. Install Firebase packages:
   ```bash
   npm install @react-native-firebase/app @react-native-firebase/messaging
   ```
5. Follow the [React Native Firebase setup guide](https://rnfirebase.io/)
6. In `android/build.gradle`, add to `dependencies`:
   ```groovy
   classpath 'com.google.gms:google-services:4.4.2'
   ```
7. In `android/app/build.gradle`, add at the bottom:
   ```groovy
   apply plugin: 'com.google.gms.google-services'
   ```

The backend needs to send FCM payloads to registered tokens. The app automatically registers the token via `NetworkService.registerFcmToken()` on login.

---

## Open in Android Studio

1. Open Android Studio
2. **File → Open** → select the `Android/` folder (not the parent)
3. Wait for Gradle sync to complete
4. Click the green **Run** button (or `Shift+F10`)

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `SDK location not found` | Open Android Studio → SDK Manager → note the SDK path → create `android/local.properties` with `sdk.dir=/path/to/sdk` |
| `JAVA_HOME not set` | Set `JAVA_HOME` to JDK 17 installation path |
| Metro bundler port conflict | `npm start -- --port 8082` |
| `IBM_SEMERU` / Gradle 9 error | RN 0.84 не поддерживает Gradle 9. В `android/gradle/wrapper/gradle-wrapper.properties` установить `gradle-8.14-bin.zip` |
| `react-native-quick-crypto` build fail | Ensure NDK version matches `ndkVersion = "27.1.12297006"` in `android/build.gradle` |
| Hermes crash on device | Device must be API 24+ (Android 7). Lower API devices not supported |
