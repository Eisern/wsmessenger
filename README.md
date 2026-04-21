# WS Messenger

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

От автора: это полностью навайбкоденный проект, который родился из желания государства контролировать общение своих граждан и логичного желания "автора" иметь анонимный, с защищенной от посторонних глаз перепиской, мессенджер.

Он не требует от вас личных данных во время регистрации, он не управляет камерой вашего смартфона.
Он шифрует вашу переписку в личках и группах и не хранит ваши приватные ключи шифрования на сервере и, при должной схеме развертывания, даже не знает с кем вы общаетесь в личке.
Он сделан для того, чтобы каждый, кому хочется иметь чуть больше приватности (и самостоятельно контролировать её!), мог скачать проект, развернуть его на простеньком VPS и получить канал связи, который будет надежно защищен в наше неспокойное время.

Прямо сейчас, скачав файлы клиента-расширения (из папки \chrome_extension) или готовый apk (Android\android\app\build\outputs\apk\debug\app-debug.apk), и запустив их, вы автоматически подключитесь к уже работающему тестовому серверу, и сможете пощупать проект руками и даже попробовать пообщаться на нем со своими друзьями.

Или вы можете взять файл бэкенда (\server\main.py), схему базы данных (\server\schema.sql) почитать файл \docs\self-hosting.md и запустить свой такой же сервер и, указав его в клиенте, общаться в вашем небольшом (или большом!) кругу.

А я пойду пилить его дальше-из ближайших целей-максимально возможно упростить self-hosting проекта и попробовать внедрить федеративный протокол для общения между такими самостоятельными серверами.



## End-to-end encrypted, WebSocket-based messenger.
WS Messenger consists of three components in this repository:

- **Browser extension** — Chrome MV3 side panel, plain ES modules, no
  build step. Source in [`chrome_extension/`](chrome_extension/).
- **Android client** — React Native 0.84. Source in [`Android/`](Android/).
- **Backend** — FastAPI + admin panel. Source in [`server/`](server/).

All three speak the same WebSocket protocol and share the same E2EE
scheme. The server never holds plaintext message content, room keys, or
identity private key material.

## Cryptography at a glance

| Layer | Primitive |
|-------|-----------|
| Password → KEK | Argon2id (preferred, WASM, integrity-pinned at startup) or PBKDF2-SHA-256 ≥ 600 000 iterations (fallback) |
| Identity keys | X25519 |
| Symmetric | AES-256-GCM |
| Wrap (DM / room key) | X25519 ECDH + HKDF-SHA-256 → AES-256-GCM |
| DM transport | sealed sender (per-thread `delivery_secret`, sender identity inside the encrypted payload) |
| Recovery | BIP39 24-word phrase (256-bit entropy + 8-bit checksum), derived from the identity key |
| Peer trust (Android) | TOFU fingerprints in Keychain |

The Argon2id WASM is integrity-pinned (SHA-256) and self-tested at
startup; failure blocks key derivation (fail-closed, no silent PBKDF2
fallback).

## Repository layout

| Path | Contents |
|------|----------|
| `chrome_extension/` | Chrome MV3 extension: service worker, side panel, crypto layer, Argon2id WASM, manifest |
| `server/main.py` | FastAPI server |
| `server/admin/` | Admin panel (FastAPI router + Jinja2 templates + audit log) |
| `server/config.example.env` | Example backend configuration — copy to `server/.env` |
| `Android/` | React Native 0.84 client (see `Android/CLAUDE.md`) |

## Loading the extension

Open `chrome://extensions/`, enable Developer Mode, click
**Load unpacked**, and point at the [`chrome_extension/`](chrome_extension/)
directory. No build step.

## Self-hosting

The Chrome extension ships with the original author's backend hosts
(`chat-room.work`, `imagine-1-ws.xyz`) baked into
[`chrome_extension/manifest.json`](chrome_extension/manifest.json) under
`host_permissions`. To point the extension at your own server, edit
that field:

```json
"host_permissions": [
  "https://your-server.example.com/*"
]
```

then reload the unpacked extension. The Android client can switch
backends at runtime (Login screen → "Connect to another server"); no
manifest edit is needed.

## Running the backend

Requires Python 3.11+ and PostgreSQL 13+ (tested on 17). Quick start for
local development:

```sh
# 1. Install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r server/requirements.txt

# 2. Create database and apply schema
createdb chatdb
psql -d chatdb -f server/schema.sql

# 3. Configure
cp server/config.example.env server/.env       # then fill in values
#    set DATABASE_URL=postgresql+asyncpg://USER:PASSWORD@localhost:5432/chatdb
#    set JWT_SECRET to a long random string

# 4. Run
cd server && uvicorn main:app --reload
```

The schema in [`server/schema.sql`](server/schema.sql) is the canonical
DDL. The server itself only lazily creates a few archive tables at runtime
(`chat_room_key_archive`, `chat_dm_key_archive`, `chat_dm_delete_requests`);
all base tables must exist before the first request.

For a full production deployment — VPS setup, systemd unit, nginx + TLS,
creating the first admin, updates, and troubleshooting — see
[`docs/self-hosting.md`](docs/self-hosting.md).

## Building the Android APK

```sh
cd Android/android
JAVA_HOME=".../jdk-17" GRADLE_USER_HOME="C:/GH" ./gradlew assembleDebug
# APK: android/app/build/outputs/apk/debug/app-debug.apk
```

See [`Android/CLAUDE.md`](Android/CLAUDE.md) for build-environment notes
(Gradle home path, crypto substitutions, keyboard handling).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under
the project license (AGPL-3.0-or-later) and require a per-commit
`Signed-off-by` line (DCO 1.1). There is no separate CLA.

## Security

If you find a security issue, please email
<y.kropochev87@gmail.com> with the subject prefix `[security]`.
Do not open a public issue until a fix is released.

## License

WS Messenger is licensed under the
**GNU Affero General Public License, version 3 or any later version**
(`AGPL-3.0-or-later`). The full license text is in [LICENSE](LICENSE).

If you run a modified version of this software on a network server,
**AGPL section 13** requires you to offer the source code of the running
version to its users. The canonical source is at:
**<https://github.com/Eisern/wsmessenger>**.

Third-party components are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

```
WS Messenger — end-to-end encrypted messenger
Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
