// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// NetworkService calls `new WebSocket(url, null, { headers: { Origin } })` —
// the React Native three-argument form. Node's built-in WebSocket ignores the
// third argument and sends no Origin at all, which the server rejects before
// accept() as CSWSH protection. Swapping in `ws` keeps the client code
// untouched and lets the real Origin check be exercised.
const WS = require('ws');

class RNCompatWebSocket extends WS {
  constructor(url, protocols, options) {
    super(url, protocols || undefined, options || undefined);
  }
}
RNCompatWebSocket.CONNECTING = 0;
RNCompatWebSocket.OPEN = 1;
RNCompatWebSocket.CLOSING = 2;
RNCompatWebSocket.CLOSED = 3;

global.WebSocket = RNCompatWebSocket;
