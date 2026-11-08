# WS Messenger message relay

**Status: experimental.** It works end to end and both clients use it, but every
relay is wired to every island by hand.

A relay carries **cross-island direct messages** to an island and **cannot read
them**. It holds no database, no user data, no message history and no island
certificate.

## Why it exists

When you write to somebody on another server, your client delivers the message
into their mailbox on *their* island (see `docs/self-hosting.md` §8.3). Sent
directly, that island learns your IP address and the moment you typed — a
server you have no account with and no reason to trust. A relay sits in between:
the island sees the relay, the relay sees you, and neither sees both.

## What a relay sees, and what it does not

| Sees | Does not see |
|---|---|
| size of an envelope (already padded into power-of-two buckets) | message content |
| when it passed through | who sent it, who receives it |
| which island it was bound for | the thread it belongs to |
| the sender's IP address | |

It also cannot **forge** a message (it has no thread delivery secret), cannot
**replay** one (the island de-duplicates), cannot **fake a delivery receipt**
(the island's answer is sealed to the client), and cannot be pointed at a host
its operator has not listed (`next` is a name from your config, not an address).

What it *can* do is stay silent. A relay that drops traffic is a denial of
service, not a disclosure; the client tries the island's next relay, which is
safe by construction because a message that did arrive comes back as a
duplicate.

## How the clients use it

- **Per contact, and only when asked.** In both clients: the contact's actions
  → **Send through a relay**. The contact then shows "via relay".
- **The transport key comes only from the island's signed list**
  (`/.well-known/wsapp-island`), never from `GET /relay/key`, which is a
  development convenience. Whoever substitutes that key reads the metadata of
  every envelope sealed to it.
- **No silent fallback.** If no relay carries the message it is queued, not sent
  directly — falling back would hand over exactly the address the user asked to
  withhold. A contact whose island lists no relay cannot be switched to relaying.

## Connecting a relay to an island

Three parties are involved, and it helps to keep them apart: the **island
operator** (runs the server whose users receive the messages), the **relay
operator** (runs this), and the **senders** (users on other islands, who need
nothing but the switch above).

### 1. Island operator: accept relayed traffic

Generate a transport keypair once, and one shared key per relay:

```sh
~/wsmessenger/.venv/bin/python - <<'PY'
import base64, json, secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
k = X25519PrivateKey.generate()
print("RELAY_TRANSPORT_KEY_B64=" + base64.b64encode(
    k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print("RELAY_PEERS='" + json.dumps({"relay-yourname": base64.b64encode(secrets.token_bytes(32)).decode()}) + "'")
PY
```

Put both lines in `server/.env`. Note the **single quotes** around `RELAY_PEERS`:
the value is JSON, and systemd and the shell both strip double quotes.

Then **publish the relay in the island's signed list**, or no client will ever
use it — clients learn relays and the transport key from that list and from
nowhere else:

```env
ISLAND_RELAYS='[{"id":"relay-yourname","url":"https://relay.example.net"}]'
ISLAND_LIST_VERSION=2        # raise by one: the list changed
```

`sudo systemctl restart wsapp`, then check that the list now carries the relay
and a transport key:

```sh
curl -s https://messenger.example.com/.well-known/wsapp-island
```

Give the relay operator two things: the **shared key** from `RELAY_PEERS`, and
your island's **`ISLAND_ID`** exactly as it appears in `.env`.

Relay ingress stays off unless both `RELAY_TRANSPORT_KEY_B64` and `RELAY_PEERS`
are set, so an island that does not take relayed traffic carries no extra
surface at all. `RELAY_QUOTA_PER_10S` (default 600) caps how much one relay may
push. Behind a relay there is no usable client IP, so this quota and the
per-thread limit are what replace per-IP rate limiting — do not raise it
casually.

### 2. Relay operator: run one

```sh
cp relay.config.example.json relay.config.json
```

Fill in your `relay_id` (the name the island operator used in `RELAY_PEERS`)
and, under `islands`, one entry per island you serve. **The entry's name must be
that island's `ISLAND_ID`, character for character**: clients address a relay by
island id, and the relay looks it up in this map.

```json
{
  "relay_id": "relay-yourname",
  "islands": {
    "messenger.example.com": {
      "url": "https://messenger.example.com",
      "key_b64": "<the shared key the island operator gave you>"
    }
  }
}
```

```sh
docker build -t wsapp-relay .
docker run -d --name wsapp-relay -p 8800:8800 \
  -v "$PWD/relay.config.json:/app/relay.config.json:ro" \
  wsapp-relay
curl -s http://127.0.0.1:8800/health
```

Without Docker:

```sh
pip install -r requirements.txt
RELAY_CONFIG=relay.config.json uvicorn relay:app --host 0.0.0.0 --port 8800
```

Put it behind TLS the same way you would any other service — the URL in the
island's `ISLAND_RELAYS` must be `https://` for the browser extension. The relay
terminates TLS for its own name; it never needs the island's certificate, which
is what makes it easier to host than the TCP-passthrough bridges in
`docs/self-hosting.md` §8.2. It reads its config once at start: restart it after
every edit.

## What it does not do yet

- **Discovery.** Every relay–island pair is set up by hand, as above. There is no
  directory of relays and no way for a relay to offer itself to an island.
- **Relays for local traffic.** It carries cross-island direct messages only.
  Your own island's users talk to it directly; hiding their IPs from it is what
  `TRUST_PROXY_HEADERS=0` and the bridges in `docs/self-hosting.md` are about.
- **Files.** Cross-island messages cannot carry attachments yet, relayed or not.
