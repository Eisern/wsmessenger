// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * src/crypto/index.js
 *
 * Точка входа крипто-слоя.
 * Создаёт синглтон CryptoManager и экспортирует оба объекта.
 *
 * Использование:
 *   import { CryptoUtils, cryptoManager } from '../crypto';
 *
 * Требования:
 *   В index.js приложения ДОЛЖЕН быть подключён polyfill ПЕРВЫМ:
 *   import { install } from 'react-native-quick-crypto';
 *   install();
 */

import CryptoUtils from './CryptoUtils';
import CryptoManager from './CryptoManager';

// Единственный экземпляр на всё приложение
const cryptoManager = new CryptoManager();

export { CryptoUtils, CryptoManager, cryptoManager };

export default { utils: CryptoUtils, manager: cryptoManager };
