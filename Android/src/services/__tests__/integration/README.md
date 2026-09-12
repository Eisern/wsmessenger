# Failover integration tests

These run the **real** `NetworkService` against a **real** backend. Only the
React Native surface is stubbed (AsyncStorage, Keychain, AppState); `fetch` and
`WebSocket` are genuine, and two controllable proxies stand in for two entry
points of one island. Failures are injected at the proxy, so neither the client
nor the server knows a test is running.

They are excluded from `npm test` because they need a server.

## 1. A backend on 127.0.0.1:8000

Any instance will do. In the Debian container used for this repo:

```sh
docker start wsapp-test
docker exec wsapp-test bash -lc 'service postgresql start'
docker exec -d wsapp-test bash -lc \
  'cd /opt/src/server && set -a && . ./.env && set +a && \
   exec /opt/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/uvicorn.log 2>&1'
curl -s http://127.0.0.1:8000/health
```

Relax the rate limits in `server/.env`, or the suite will trip them - it logs in
once per test and reconnects sockets repeatedly from a single IP:

```
RL_LOGIN_IP_PER_MIN=2000
RL_LOGIN_USER_PER_MIN=2000
RL_WS_CONNECT_IP_PER_MIN=2000
RL_WSDM_CONNECT_IP_PER_MIN=2000
RL_WSNOTIFY_CONNECT_IP_PER_MIN=2000
RL_REGISTER_IP_PER_5MIN=500
```

## 2. Run

```sh
npm run test:failover
```

The suite creates two accounts (`failover_a_fo1`, `failover_b_fo1`) on first run
and reuses them afterwards; a duplicate registration is expected and ignored. It
also grants both accounts "allow DMs from non-friends", otherwise `/dm/open`
answers 403 and the DM rows cannot run.

Ports 18101 and 18102 are the two entry points. Both forward to 8000 - that is
the whole point: one island, one database, several doors.

## What each mode reproduces

| Proxy mode | Real-world equivalent |
|---|---|
| `refuse` | blocked IP, connection reset |
| `503` | edge is up, backend behind it is not |
| `hang` | black-holed route (client-side timeout) |
| `drop-ws` | middlebox that allows HTTP and kills WebSocket upgrades |
| `ws-flap` | edge that accepts a socket and drops it seconds later |
| `foreign` | a mistyped address leading to somebody else's instance: `/health` answers, everything authenticated returns 401 |

## Two bugs these tests found

Worth knowing, because both produced a working-looking client:

1. The rollback off a foreign entry point was blocked by the rotation cooldown,
   so the client stayed on a server that would never accept its session.
   Verdicts that re-trying cannot change now pass `{ force: true }`.
2. `_doRefresh` called `_handleSessionExpired()` on a 401 **before** the
   foreign-island guard in `_fetch` could run - so a typo in the address logged
   the user out after all. The guard now also sits in the refresh path, and it
   is generation-guarded, because one 401 reaches it twice (once from the
   request, once from the refresh) and the second call would otherwise
   blacklist the healthy entry point it had just rotated to.

---

# Relay prototype tests

`relay.test.js` sends a direct message through a real relay process to the real
island and asserts, among other things, that the relay is handed nothing it
could correlate on. Run with `npm run test:relay`.

## Extra setup

**1. Island: enable relay ingress.** Generate a transport keypair and a shared
key per relay (see `relay/README.md`), then in the container's `server/.env`:

```
RELAY_TRANSPORT_KEY_B64=<base64 x25519 private key>
RELAY_PEERS='{"relay-alpha":"<base64 32-byte shared key>"}'
```

Single quotes matter: the file is sourced by a shell, which strips the double
quotes and leaves invalid JSON. Restart uvicorn, then check:

```sh
curl -s http://127.0.0.1:8000/relay/key
```

**2. Relay: run one.** From `relay/`, with a config naming the island as
`island-test` at `http://127.0.0.1:8000`:

```sh
RELAY_CONFIG=/path/to/relay.config.json python -m uvicorn relay:app \
  --host 127.0.0.1 --port 18800
```

Override the endpoints with `RELAY_TEST_ISLAND` / `RELAY_TEST_RELAY` if you run
them elsewhere.

## A design bug these tests found

The first version sealed only the *delivery* answer and returned errors in the
clear. That let a relay tell "duplicate" from "delivered" by the status code —
and, worse, forge a 409 so the client would stop retrying elsewhere. Every
outcome after the envelope is opened is now sealed, and the outer HTTP status is
always 200.
