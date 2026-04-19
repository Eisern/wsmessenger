# Third-Party Notices

WS Messenger as a whole is licensed under
**GNU AGPL-3.0-or-later** (see `LICENSE`).

It bundles, links to, or otherwise depends on the third-party components
listed below. Each component remains under its own license. The licenses
here are all compatible with AGPL-3.0-or-later when the combined work is
distributed under AGPL-3.0-or-later.

If you add or upgrade a dependency, please update this file.

---

## Browser extension (`chrome_extension/`)

| Component | Version | License | Source |
|-----------|---------|---------|--------|
| argon2-browser / Argon2 reference WASM | bundled in `chrome_extension/argon2id/` | Apache-2.0 OR CC0-1.0 (Argon2 reference); MIT (argon2-browser wrapper) | https://github.com/antelle/argon2-browser, https://github.com/P-H-C/phc-winner-argon2 |

The extension has no other runtime JavaScript dependencies — it uses
only the browser-provided Web Crypto API.

## Backend (`server/`)

Inferred from imports in `server/main.py` and `server/admin/`. There is no
`requirements.txt`; the table below is informational.

| Package | License (SPDX) | Project URL |
|---------|----------------|-------------|
| FastAPI | MIT | https://github.com/tiangolo/fastapi |
| Starlette | BSD-3-Clause | https://github.com/encode/starlette |
| Uvicorn | BSD-3-Clause | https://github.com/encode/uvicorn |
| SQLAlchemy | MIT | https://github.com/sqlalchemy/sqlalchemy |
| Pydantic | MIT | https://github.com/pydantic/pydantic |
| passlib (with bcrypt) | BSD-2-Clause (passlib), Apache-2.0 (bcrypt) | https://passlib.readthedocs.io/ |
| python-jose | MIT | https://github.com/mpdavis/python-jose |
| pyotp | MIT | https://github.com/pyauth/pyotp |
| qrcode | BSD-3-Clause | https://github.com/lincolnloop/python-qrcode |
| Jinja2 | BSD-3-Clause | https://github.com/pallets/jinja |

## Android client (`Android/`)

Selected runtime dependencies (see `Android/package.json` for the
authoritative list and exact versions).

| Package | License (SPDX) | Notes |
|---------|----------------|-------|
| react-native | MIT | https://github.com/facebook/react-native |
| react | MIT | https://github.com/facebook/react |
| react-native-quick-crypto | MIT | https://github.com/margelo/react-native-quick-crypto |
| @noble/curves | MIT | https://github.com/paulmillr/noble-curves |
| @noble/hashes | MIT | https://github.com/paulmillr/noble-hashes |
| react-native-keychain | MIT | https://github.com/oblador/react-native-keychain |
| react-native-keyboard-controller | MIT | https://github.com/kirillzyusko/react-native-keyboard-controller |
| @react-native-async-storage/async-storage | MIT | https://github.com/react-native-async-storage/async-storage |
| @react-navigation/* | MIT | https://github.com/react-navigation/react-navigation |
| react-native-screens | MIT | https://github.com/software-mansion/react-native-screens |
| react-native-gesture-handler | MIT | https://github.com/software-mansion/react-native-gesture-handler |
| react-native-svg | MIT | https://github.com/software-mansion/react-native-svg |
| react-native-vector-icons | MIT | https://github.com/oblador/react-native-vector-icons |
| react-native-fs | MIT | https://github.com/itinance/react-native-fs |
| react-native-image-picker | MIT | https://github.com/react-native-image-picker/react-native-image-picker |
| @notifee/react-native | Apache-2.0 | https://github.com/invertase/notifee |
| mitt | MIT | https://github.com/developit/mitt |

Build-time-only dependencies (Babel, Metro, Jest, ESLint, etc.) are
permissively licensed (MIT/BSD/Apache-2.0) and are not redistributed in
the final APK.

---

## Notes

- All licenses listed above are compatible with combination under
  AGPL-3.0-or-later for the purpose of distribution.
- For exact license texts, see each project's repository or the
  `LICENSE` files inside `Android/node_modules/<package>/` after
  installation.
- If you find an inaccuracy in this file, please open an issue or PR.
