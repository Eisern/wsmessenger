// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// CryptoService clears the clipboard after handing out a recovery phrase.
// Under node there is none; the call still has to go somewhere.
const Clipboard = {
  setString() {},
  async getString() { return ''; },
};

module.exports = Clipboard;
module.exports.default = Clipboard;
