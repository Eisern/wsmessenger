# Contributing to WS Messenger

Thanks for your interest in contributing. This document describes how to
submit changes and what you agree to when you do so.

## License of contributions

WS Messenger is licensed under the **GNU Affero General Public License,
version 3 or (at your option) any later version** (`AGPL-3.0-or-later`).
By submitting a contribution, you agree that your work is licensed under
the same terms.

There is no separate Contributor License Agreement (CLA). We use the
**Developer Certificate of Origin (DCO) 1.1** instead — a lightweight,
per-commit attestation. The full text is at <https://developercertificate.org/>.

In short, you certify that:

1. The contribution was created in whole or in part by you, and you have
   the right to submit it under the project's license, **or**
2. The contribution is based on a previous work that, to the best of your
   knowledge, is licensed under an appropriate open-source license that
   allows you to submit that work modified or unmodified under the same
   license, **or**
3. The contribution was provided directly to you by some other person who
   certified (1), (2), or (3) and you have not modified it.

You sign off on a commit by adding a line like this to its message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Set up `git` to do this automatically:

```sh
git config --global user.name  "Your Name"
git config --global user.email "your.email@example.com"
git commit -s -m "your commit message"
```

PRs without a `Signed-off-by` line on every commit will be asked to
amend their history before merge.

## Reporting issues

- **Security issues:** please email <y.kropochev87@gmail.com> with the
  subject prefix `[security]`. Do **not** open a public issue for
  security-sensitive reports until a fix is released.
- **Bugs and feature requests:** open an issue on the repository tracker.
  Include reproduction steps, environment (extension version, Android
  version, browser), and relevant logs (with secrets redacted).

## Coding guidelines

- The Chrome extension is plain ES modules — no build step. Keep it that
  way unless there is a strong reason.
- The Android client is React Native; respect the existing structure and
  the `Android/CLAUDE.md` notes on crypto, keyboard handling, and event
  listener patterns.
- The backend is FastAPI; keep the audit-logging pattern in
  `server/admin/` intact when touching admin routes.
- Do not weaken cryptographic invariants documented in the root
  `CLAUDE.md` (KDF strength, key non-extractability, fail-closed
  Argon2 self-test, redaction of sensitive fields in logs).

## Tests

The Android client has a Jest suite:

```sh
cd Android && npm test
```

If you change cryptographic code, please also exercise the affected
path manually (login, unlock, send/receive room and DM messages, peer
key change, recovery from BIP39 phrase) before opening the PR.

## Adding files

New source files should carry an SPDX header:

```
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) <year> <Your Name> <your.email@example.com>
```

For HTML use `<!-- ... -->`, for Python use `# ...`.

## Adding third-party code

Only add third-party code that is compatible with `AGPL-3.0-or-later`
(MIT, BSD, Apache-2.0, ISC, MPL-2.0, LGPL, GPL-3.0+, AGPL-3.0+ are fine;
GPL-2.0-only is **not**).

When you add a dependency, append an entry to `THIRD_PARTY_NOTICES.md`
with the package name, version, license SPDX identifier, and project URL.
