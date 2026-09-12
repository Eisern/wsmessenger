// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * A controllable entry point in front of a real backend.
 *
 * Both entry points forward to the SAME upstream, which is the whole point:
 * an island is one backend with one database reached through several doors.
 * The mode switch is the failure injector — it reproduces, deterministically,
 * what a blocked domain, a dead edge or a hostile middlebox looks like to the
 * client, without touching the client or the server.
 *
 * Modes:
 *   'ok'         proxy everything
 *   'refuse'     destroy the connection (connection refused / reset)
 *   '503'        answer 503 with an empty body (edge up, backend unreachable)
 *   'hang'       accept and never answer (client-side timeout)
 *   'drop-ws'    HTTP works, WebSocket upgrades are destroyed
 *   'ws-flap'    WebSocket upgrades succeed, then die after flapAfterMs
 *   'foreign'    /health answers, everything authenticated answers 401 —
 *                what a mistyped address leading to somebody else's instance
 *                looks like: the server is up, our token means nothing there
 */

const http = require('http');
const net = require('net');

function createEntryPoint({ port, upstreamHost = '127.0.0.1', upstreamPort = 8000, flapAfterMs = 800 } = {}) {
  let mode = 'ok';
  const live = new Set();

  const server = http.createServer((req, res) => {
    if (mode === 'refuse') { req.socket.destroy(); return; }
    if (mode === '503') { res.writeHead(503, { 'content-type': 'text/plain' }); res.end(''); return; }
    if (mode === 'hang') { return; }
    if (mode === 'foreign' && !String(req.url || '').startsWith('/health')) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ detail: 'Not authenticated' }));
      return;
    }

    // The Host header is passed through untouched on purpose: it proves the
    // server accepts a request that arrived under a name it does not know.
    const up = http.request(
      { host: upstreamHost, port: upstreamPort, method: req.method, path: req.url, headers: req.headers },
      (upRes) => {
        res.writeHead(upRes.statusCode, upRes.headers);
        upRes.pipe(res);
      },
    );
    up.on('error', () => { try { res.writeHead(502); res.end(); } catch { /* client gone */ } });
    req.pipe(up);
  });

  server.on('upgrade', (req, socket, head) => {
    if (mode === 'refuse' || mode === 'drop-ws') { socket.destroy(); return; }
    if (mode === '503') { socket.end('HTTP/1.1 503 Service Unavailable\r\n\r\n'); return; }
    if (mode === 'foreign') { socket.end('HTTP/1.1 401 Unauthorized\r\n\r\n'); return; }
    if (mode === 'hang') { return; }

    const up = net.connect(upstreamPort, upstreamHost, () => {
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
      }
      up.write(lines.join('\r\n') + '\r\n\r\n');
      if (head && head.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);

      if (mode === 'ws-flap') {
        setTimeout(() => { try { socket.destroy(); } catch { /* already gone */ } }, flapAfterMs);
      }
    });
    up.on('error', () => socket.destroy());
    live.add(socket);
    socket.on('close', () => live.delete(socket));
  });

  server.on('connection', (s) => { live.add(s); s.on('close', () => live.delete(s)); });

  return {
    port,
    apiBase: `http://127.0.0.1:${port}`,
    wsBase: `ws://127.0.0.1:${port}`,
    setMode(m) { mode = m; },
    getMode() { return mode; },
    /** Cut every live connection — what a blocked route does to open sockets. */
    cut() {
      for (const s of live) { try { s.destroy(); } catch { /* already gone */ } }
      live.clear();
    },
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, '127.0.0.1', resolve);
      });
    },
    close() {
      return new Promise((resolve) => {
        this.cut();
        server.close(() => resolve());
      });
    },
  };
}

module.exports = { createEntryPoint };
