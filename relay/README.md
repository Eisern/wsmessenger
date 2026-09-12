# WS Messenger message relay

**Status: prototype.** The transport works end to end and is covered by tests, but
no shipped client speaks it yet — see `docs/internal/message-relay-assessment.md`
for the design, the threat model and the honest list of what it does not buy.

A relay carries direct messages to an island and **cannot read them**. It holds no
database, no user data, no message history and no island certificate.

## What a relay sees, and what it does not

| Sees | Does not see |
|---|---|
| size of an envelope (already padded into power-of-two buckets) | message content |
| when it passed through | who sent it, who receives it |
| which island it was bound for | the thread it belongs to |

It also cannot **forge** a message (it has no thread delivery secret), cannot
**replay** one (the island de-duplicates), cannot **fake a delivery receipt**
(the island's answer is sealed to the client), and cannot be pointed at a host
its operator has not listed (`next` is a name from your config, not an address).

What it *can* do is stay silent. A relay that drops traffic is a denial of
service, not a disclosure; clients answer that by retrying through another relay,
which is safe by construction because a message that did arrive comes back as a
duplicate.

## Running one

You need two things from the island operator: the island's **id** (a short name)
and a **shared key** that identifies your relay to that island.

```sh
cp relay.config.example.json relay.config.json
# fill in relay_id, the island's URL and the key you were given
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

Put it behind TLS the same way you would any other service. The relay terminates
TLS for its own name; it never needs the island's certificate, which is what
makes it easier to host than the TCP-passthrough bridges in
`docs/self-hosting.md` §8.2.

## For the island operator

Generate a transport keypair and one shared key per relay, then set in `server/.env`:

```sh
python - <<'PY'
import base64, json, secrets
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
k = X25519PrivateKey.generate()
print("RELAY_TRANSPORT_KEY_B64=" + base64.b64encode(
    k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
print("RELAY_PEERS='" + json.dumps({"relay-yourname": base64.b64encode(secrets.token_bytes(32)).decode()}) + "'")
PY
```

Note the **single quotes** around `RELAY_PEERS`: the value is JSON and the file is
sourced by a shell, which would otherwise eat the double quotes.

Relay ingress stays disabled unless both variables are set, so an island that
does not accept relayed traffic carries no extra surface at all.

`RELAY_QUOTA_PER_10S` (default 600) caps how much one relay may push. Behind a
relay there is no usable client IP, so this quota and the per-thread limit are
what replace per-IP rate limiting — do not raise it casually.

## Two things this prototype does not do yet

- **The island's transport key is served over plain HTTPS** at `GET /relay/key`,
  for development. In production a client must take that key from the signed
  entry-point list and pin it: whoever substitutes the key reads every
  envelope's metadata. That list does not exist yet.
- **No client speaks this.** The envelope is implemented once, in the test
  helpers. Shipping it means writing it twice (WebCrypto in the extension,
  @noble on Android), and that must not happen before there are cross-client
  pinned test vectors — the repository has already had two hand-written crypto
  implementations drift apart unnoticed.
