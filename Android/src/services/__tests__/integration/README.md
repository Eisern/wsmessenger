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

---

# Signed island list tests

`islandList.test.js` fetches `/.well-known/wsapp-island` and verifies the real
signature with **both** client crypto stacks. Run with `npm run test:island-list`.

This is the test that holds the canonical form together: the island
canonicalizes the payload in Python and signs it; the clients canonicalize the
same payload in JavaScript to check the signature. A one-byte disagreement —
a float rendered `1.0` instead of `1`, a non-ASCII label escaped on one side
only, keys sorted differently — makes the signature fail. Nothing else needs to
assert the canonical form.

## Setup

Generate an Ed25519 signing key and describe the island in `server/.env`:

```
ISLAND_SIGNING_KEY_B64=<base64 ed25519 private key, 32 raw bytes>
ISLAND_ID=island-test
ISLAND_LIST_VERSION=3
ISLAND_ENTRY_POINTS='[{"apiBase":"http://127.0.0.1:18101","wsBase":"ws://127.0.0.1:18101","label":"основной"},{"apiBase":"http://127.0.0.1:18102","wsBase":"ws://127.0.0.1:18102","label":"mirror"}]'
ISLAND_RELAYS='[{"id":"relay-alpha","url":"http://127.0.0.1:18800"}]'
```

Single quotes again, and keep a **non-ASCII label** in there: one of the tests
asserts it is present, because without it the canonical-form check would pass
for the wrong reason.

```sh
python - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
k = Ed25519PrivateKey.generate()
print(base64.b64encode(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
PY
```

The list also republishes the relay transport key, and a test asserts it matches
what `/relay/key` serves — the development endpoint and the signed document must
not drift apart, because only the signed one may be trusted.

---

# Two independent islands

`twoIslands.test.js` runs against **two** islands in two containers: two
processes, two databases, two JWT secrets, two island signing keys, two relay
transport keys. Run with `npm run test:two-islands`.

That distinction is the point. The foreign-island guard - the highest-risk item
in the entry-point work - was previously exercised against a proxy that returned
401 on command, which proves the client copes with a 401, not that it copes with
a different server.

Cross-island direct messaging is designed but not implemented, so nothing here
sends a message between users of the two islands.

## Bringing up the second island

Clone the working container rather than building one: it already has the venv.

```sh
docker commit wsapp-test wsapp-island-b:latest
docker run -d --name wsapp-island-b -p 8001:8000 wsapp-island-b:latest sleep infinity
docker exec wsapp-island-b bash -lc 'service postgresql start'
```

It is a clone, so it holds island A's accounts. An independent island must not:
recreate the database empty.

```sh
docker exec wsapp-island-b bash -lc '
  su postgres -c "psql -c \"DROP DATABASE IF EXISTS wsapp;\"" &&
  su postgres -c "psql -c \"CREATE DATABASE wsapp OWNER wsapp;\"" &&
  su postgres -c "psql -d wsapp -f /opt/src/server/schema.sql"'
```

Then give it its own secrets in `server/.env` - a **different** `JWT_SECRET`
above all, or a token from A would still be accepted and the foreign-island test
would pass for the wrong reason - plus `ISLAND_ID=island-b`, its own
`ISLAND_SIGNING_KEY_B64`, its own `RELAY_TRANSPORT_KEY_B64` and its own
`RELAY_PEERS` key. Start uvicorn the same way as on island A.

Point the relay at both by listing them in `relay.config.json`, each with the
key that island expects. The relay reads its config once at import, so restart
it after editing - and kill it by port, since it is easy to leave the old
process holding the socket with the old config.

---

# Tampering with stored messages

`chainTamper.test.js` builds messages with the real client crypto, sends them
down the real send path into a real database, and then alters that database
directly with psql - which is what an island's operator can do and what no
amount of transport security prevents. Run it with the island up; it needs
`docker exec` against the island's container (`ISLAND_A_CONTAINER`, default
`wsapp-test`).

It demonstrates the difference between the two guarantees:

| The operator does | What happens |
|---|---|
| edits a message | the signature fails immediately, and the message never enters the chain |
| deletes a message | every survivor still verifies, and a GAP appears where the message was |
| re-files a genuine message at another position | its own signature is valid; only the chain notices |

Note the third row. That is the case nothing before the chain could catch: the
message is real, signed by the real sender, and unmodified - it is simply in
the wrong place, next to a different question.

Deleting is detected, not prevented. Nobody can stop the holder of a database
from dropping a row; the chain only stops them from doing it quietly.

---

# Cross-island direct messages

Two suites, and the split between them is the point.

`crossIsland.test.js` proves the **protocol**: it calls `foreign-dm.js` and does
the crypto itself, so it answers "do two independent islands agree". Run it with
`npx jest --selectProjects integration --runInBand --forceExit crossIsland`.

`panelCrossIsland.test.js` proves the **client**: it loads
`chrome_extension/panel-crypto.js` into a sandbox and calls the functions the
buttons call. It answers a different question - "does the extension do the
protocol" - and on its first run it caught `sendForeignMessage` emitting
ciphertext the extension's own decrypt path throws away. The protocol test could
not have caught that, because it never asked the client to read what the client
wrote.

Only the browser's side is stubbed: storage, permissions, the DOM, and a
stand-in for `CryptoManager` whose `encryptMessage` matches the real one byte
for byte. Unlocking the real one needs an encrypted identity blob and the
Argon2 WASM self-test, which is a different thing to test.

## What the islands need

Both must have `ISLAND_ID` set - the claim signature binds it, so the endpoints
answer 404 without it.

Island A's entry-point list carries addresses that answer nothing (18101/18102,
the failover proxies). That is deliberate: the claim has to walk past an
unreachable entry point to reach a live one, and one test asserts it does.

## TLS, and why the extension needs it

The extension's CSP allows `https:`/`wss:` only, so a panel in a browser cannot
reach a container that speaks http - not for cross-island delivery and not for
anything else. Node is not bound by that, so the test suites run against the
plain http ports and need none of this.

To drive the extension by hand, put a TLS front in front of both islands:

```sh
# Caddyfile: named sites, because a browser talking to a raw IP sends no SNI
# and there is then no certificate to select.
#   localhost:8443 { tls internal
#                    reverse_proxy host.docker.internal:8000 }
#   localhost:8444 { tls internal
#                    reverse_proxy host.docker.internal:8001 }
docker run -d --name wsapp-tls -p 8443:8443 -p 8444:8444 \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  --add-host host.docker.internal:host-gateway caddy:2-alpine
curl -sk https://localhost:8443/health
```

Then add the https address to each island's `ISLAND_ENTRY_POINTS` **first** in
the list, so a contact card carries an address a browser can use. Chrome will
not trust Caddy's local CA: open both URLs once per profile and accept the
warning, after which the extension's own requests to that origin go through.
Nothing has to be installed in the OS trust store.

## One-time fix on a cloned island

A database recreated from `schema.sql` as `postgres` leaves every table owned by
`postgres`, and the server's own role cannot read them - every authenticated
call answers 500. Island B was built that way and nothing noticed for weeks,
because the suite that touched it asserted only that a login there does *not*
succeed.

```sh
docker exec wsapp-island-b bash -lc 'su postgres -c "psql -d wsapp -c \"
  GRANT ALL ON ALL TABLES IN SCHEMA public TO wsapp;
  GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO wsapp;
  ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO wsapp;\""'
```

---

# The panel, headless

`helpers/panelHarness.js` loads `chrome_extension/panel-crypto.js` into a vm
sandbox and supplies only what a browser would: storage, permissions, a DOM
that answers nothing, and the handful of globals `panel.js` defines. The server
is a real island, because the point is to run the real request paths.

It unlocks the **real** `CryptoManager`. The shipped unlock derives its key with
Argon2id behind a WASM self-test that fails closed, so the harness builds the
same v3 identity container with PBKDF2 and hands it to the same entry point.
That detail is not cosmetic: the first version of this harness had a stand-in
manager with the same method names, and its `createRoomKey` did not archive the
key it replaced - so "old messages still decrypt after a rotation" failed
against the stub while the shipped code was right. A stand-in proves nothing
about the thing it stands in for.

`panelLocal.test.js` uses it for the paths with no other coverage: a local DM
between two accounts, the sealed envelope and its signature, a room key created
before the room exists, a rotation that must leave yesterday readable, and a
fresh client recovering both keys from the island.

## If the signing key will not publish

`setUp` fails loudly when `/crypto/ed25519-key` is refused, because the
alternative is a suite that passes while every signature verifies as "unknown".
A 429 there means the per-IP limit: raise `RL_ED25519_KEY_IP_PER_10MIN` and
`RL_ED25519_KEY_USER_PER_10MIN` in the island's `.env`. Every client
republishes that key on each unlock, so one address running a test suite - or
an office behind one NAT - reaches the default quickly.

## Restarting an island without leaving two of them

A shell loop that kills processes by matching their command line will match
its own wrapper first, whose command line contains the pattern it was given -
so it kills itself, the real server survives, and the next start leaves a
second process that never binds. The symptom is an `.env` change that appears
to do nothing. Build the pattern at run time so the literal never appears in
the wrapper:

```sh
docker exec <island> bash -lc 'P=$(printf "%s%s" "uvi" "corn")
  for d in /proc/[0-9]*; do cl=$(tr " " " " < $d/cmdline 2>/dev/null)
    case "$cl" in *"$P"*) case "$cl" in *python3*) kill -9 ${d#/proc/};; esac;; esac
  done'
```

## Rate limits the suites need relaxed

Recovery is deliberately strict in production - five attempts per hour per
address, three per account - and a suite that exercises it reaches that in one
run. Set `RL_RECOVER_IP_PER_HOUR` and `RL_RECOVER_USER_PER_HOUR` high in the
island's `.env`, along with the others listed above. A 429 here shows up as a
missing nonce and then as a 422 from the endpoint that needed it, which reads
like a client bug and is not one.
