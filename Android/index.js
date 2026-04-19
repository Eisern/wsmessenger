// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * @format
 *
 * react-native-quick-crypto provides Web Crypto for Hermes.
 * We import it and explicitly set globalThis.crypto from its named exports,
 * because the JSI side-effect alone may not populate globalThis.crypto reliably.
 */

// 1. Load native JSI bindings (side-effect)
import 'react-native-quick-crypto';

// 2. Import named exports and explicitly install on globalThis.crypto
import QuickCrypto from 'react-native-quick-crypto';

if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = QuickCrypto;
}

import { AppRegistry } from 'react-native';
import App from './App';
import { name as appName } from './app.json';

AppRegistry.registerComponent(appName, () => App);
