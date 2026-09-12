# Self-hosting WS Messenger

This guide walks through running the WS Messenger backend on your own
server. The typical target is a small Linux VPS (1 vCPU / 1–2 GB RAM
is enough for a handful of users) behind nginx with a free Let's Encrypt
certificate.

> **Prefer a one-shot install?** There is a bootstrap script at
> [`scripts/bootstrap.sh`](../scripts/bootstrap.sh) that performs the
> sections below (install packages, create DB, render `.env`, install
> the systemd unit, configure nginx, obtain a TLS cert) in one go on a
> fresh Debian 12 or Ubuntu 22.04/24.04 host. Read the rest of this
> file to understand what it does and to deploy manually if you prefer.

> **What the server does, and what it does not.** The backend stores
> user accounts, public keys, encrypted message ciphertext, and media
> blobs; it relays messages over WebSocket. It **never** sees plaintext
> messages, room keys, or private identity keys. The encrypted private
> key (EPK) is held on the client only — `GET /crypto/keys` returns
> `410 Gone`. With sealed-sender DMs enabled by the clients, the server
> also cannot attribute DMs to a specific sender account at the WS
> level. You are hosting transport and storage, not plaintext.

---

## 1. Requirements

| | |
|---|---|
| **OS** | Any modern Linux (examples use Ubuntu 22.04 / 24.04 or Debian 12). Windows and macOS work for local development but are not covered here. |
| **Python** | 3.11 or newer. 3.12 is tested. |
| **PostgreSQL** | 13+ (tested on 17). |
| **Reverse proxy** | nginx (or Caddy / Traefik). Must terminate TLS and proxy both HTTP and WebSocket. |
| **Domain** | A DNS A/AAAA record pointing at the VPS, used for the TLS cert and for clients to connect. |
| **Resources** | ~300 MB RAM idle, more under load (Argon2id password hashing is memory-hard — defaults use 64 MiB per login). 1 GB disk plus whatever you allocate for uploaded media. |

Open ports: **443/tcp** to the world (the backend itself should bind
only to `127.0.0.1` — nginx talks to it locally), **22/tcp** for SSH.
Nothing else.

---

## 2. Install system packages

Example for Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip \
    postgresql postgresql-contrib \
    nginx certbot python3-certbot-nginx \
    build-essential libpq-dev git
```

`build-essential` and `libpq-dev` are only needed if a wheel is missing
for `asyncpg` on your platform (rare on Debian/Ubuntu x86_64).

---

## 3. Get the source

```sh
sudo useradd --system --create-home --shell /bin/bash wsapp
sudo -iu wsapp
git clone https://github.com/Eisern/wsmessenger.git
cd wsmessenger
```

The rest of this guide assumes the repo is at `~/wsmessenger` under the
`wsapp` user.

---

## 4. Python virtualenv and dependencies

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r server/requirements.txt
```

`server/requirements.txt` pins the runtime dependencies. Notable choices:

- `passlib[argon2]` — user passwords are hashed with **Argon2id**
  server-side (the `[bcrypt]` extra is not used).
- `python-jose[cryptography]` — JWT signing with the `cryptography`
  backend.
- `python-multipart` — required by FastAPI to parse multipart form
  bodies (admin login, uploads).
- `uvicorn[standard]` — pulls in `websockets`, `httptools`, and
  `uvloop` on Linux.

---

## 5. Create the database

From a shell with PostgreSQL superuser access:

```sh
sudo -u postgres psql <<'SQL'
CREATE USER wsapp WITH PASSWORD 'choose-a-long-random-password';
CREATE DATABASE wsapp OWNER wsapp;
SQL
```

Apply the canonical schema:

```sh
# As the wsapp user, from the repo root:
PGPASSWORD='choose-a-long-random-password' \
  psql -h 127.0.0.1 -U wsapp -d wsapp -f server/schema.sql
```

The server itself only lazily creates a few archive tables
(`chat_room_key_archive`, `chat_dm_key_archive`,
`chat_dm_delete_requests`) — every other table must exist before the
first request, so do not skip this step.

### Backups

Take at least daily `pg_dump` backups:

```sh
pg_dump -h 127.0.0.1 -U wsapp wsapp | gzip > ~/backups/wsapp-$(date +%F).sql.gz
```

Put the uploads directory (see `UPLOAD_DIR` below) in the same backup
set — media blobs live on disk, not in Postgres.

---

## 6. Configure `.env`

Copy the example and fill in values:

```sh
cp server/config.example.env server/.env
```

Minimum required edits:

```env
DATABASE_URL=postgresql+asyncpg://wsapp:choose-a-long-random-password@127.0.0.1:5432/wsapp
JWT_SECRET=<paste output of: python3 -c "import secrets; print(secrets.token_urlsafe(64))">
APP_BASE_URL=https://messenger.example.com
APP_NAME=WS Messenger
CORS_ORIGINS=https://messenger.example.com
ENV=prod
```

Key notes:

- **`JWT_SECRET`** must be long and random. Never commit it, never
  reuse it across deployments. For key rotation, switch to
  `JWT_SECRETS=v1:<old>,v2:<new>` + `JWT_CURRENT_KID=v2`.
- **`APP_BASE_URL`** is the public URL clients will hit. It is used
  in room-logo URLs and in the admin panel's CSP header — get it
  right or the admin UI will break.
- **`CORS_ORIGINS`** only matters if you serve a web client from a
  different origin. `chrome-extension://` is always allowed, so leave
  empty if you use only the browser extension and the Android client.
- **`ENV=prod`** enables the HSTS header and disables `/docs`,
  `/redoc`, `/openapi.json`.
- **`UPLOAD_DIR`** (optional) — absolute path for stored media. Default
  is `./uploads` under the process's working directory. Pick an
  explicit path on your data volume, e.g.
  `UPLOAD_DIR=/var/lib/wsapp/uploads`.
- **`TRUST_PROXY_HEADERS`** — controls whether the server trusts
  `X-Forwarded-For` / `X-Real-IP` as the client IP.
  - `=1` (recommended for standard self-host): set this when the
    backend runs behind nginx on the same host, so the server sees
    real client IPs for rate limiting and audit logs. The uvicorn
    flags `--proxy-headers --forwarded-allow-ips="127.0.0.1"` in the
    systemd unit below complement this on the ASGI layer.
  - `=0` (for privacy-focused deployments): set this if you
    intentionally put the server behind one or more relays to hide
    client IPs. The server records only the TCP peer — for a typical
    nginx-on-localhost setup that means `127.0.0.1`, and real end-user
    IPs never reach the server or its logs. In this mode, **also drop
    `--proxy-headers` from the uvicorn ExecStart** (section 7 below),
    otherwise uvicorn rewrites `request.client.host` from
    `X-Forwarded-For` regardless of the app-level flag and the
    real IPs leak back in. Per-IP rate limits collapse to a single
    bucket in this mode — rely on the per-user limits instead.
- **SMTP_*** / `FEEDBACK_TO` — only needed if you want the in-app
  feedback form to email you. Skip for a personal deployment.

The remaining rate-limit and Argon2id knobs have safe defaults — leave
them alone unless you have a reason.

---

## 7. Run the server

### Smoke test (foreground)

```sh
cd ~/wsmessenger/server
source ../.venv/bin/activate
# Load .env variables for this shell:
set -a; source .env; set +a
uvicorn main:app --host 127.0.0.1 --port 8000
```

Visit `http://127.0.0.1:8000/health` via SSH tunnel or `curl` — it
should respond without error.

### systemd unit (production)

Create `/etc/systemd/system/wsapp.service`:

```ini
[Unit]
Description=WS Messenger backend
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=wsapp
Group=wsapp
WorkingDirectory=/home/wsapp/wsmessenger/server
EnvironmentFile=/home/wsapp/wsmessenger/server/.env
ExecStart=/home/wsapp/wsmessenger/.venv/bin/uvicorn main:app \
    --host 127.0.0.1 --port 8000 --workers 2 --proxy-headers \
    --forwarded-allow-ips="127.0.0.1"
Restart=on-failure
RestartSec=5s

# Hardening.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/wsapp/wsmessenger /var/lib/wsapp
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now wsapp
sudo journalctl -u wsapp -f
```

Worker count: 1–2 workers is plenty for most self-hosted loads. Each
worker holds its own in-memory WebSocket state, so do **not** scale to
many workers unless you understand that rooms can be split across them.

---

## 8. nginx reverse proxy + TLS

Create `/etc/nginx/sites-available/wsapp.conf`:

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name messenger.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name messenger.example.com;

    # certbot will fill these in.
    ssl_certificate     /etc/letsencrypt/live/messenger.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/messenger.example.com/privkey.pem;

    # Tune for media uploads.
    # Backend caps uploads at MAX_UPLOAD_BYTES = 100 MiB (server/main.py);
    # give nginx ~10 MiB of headroom.
    client_max_body_size 110m;

    # HTTP API + admin panel.
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    # All three WebSocket endpoints: /ws (rooms), /ws-dm (sealed-sender DMs),
    # /ws-notify (per-user notifications and unread badges). Miss any one of
    # them and it silently falls through to `location /` above, which has no
    # Upgrade headers -- the handshake then fails with a 404 and the feature
    # dies with no server-side error.
    location ~ ^/(ws|ws-dm|ws-notify)(/|$) {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

Enable and issue a cert:

```sh
sudo ln -s /etc/nginx/sites-available/wsapp.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
sudo certbot --nginx -d messenger.example.com
```

Certbot will modify the config to point at the issued cert and install
a renewal timer.

### 8.1. Several domains for one server

Both clients keep an **ordered list of entry points** for your server and move
to the next one when the current one stops answering — without dropping the
session, because every entry point reaches the same backend and the same
database. Several names for one server is therefore the cheapest protection
against a domain-level block, and it costs one certificate.

Put every name on the same `server_name` line and issue one multi-SAN cert:

```nginx
server_name messenger.example.com mirror.example.net;
```

```sh
sudo certbot --nginx -d messenger.example.com -d mirror.example.net
```

`scripts/bootstrap.sh` does this for you with `WSAPP_EXTRA_DOMAINS`:

```sh
sudo WSAPP_DOMAIN=messenger.example.com \
     WSAPP_EXTRA_DOMAINS=mirror.example.net \
     WSAPP_LETSENCRYPT_EMAIL=admin@example.com \
     bash scripts/bootstrap.sh
```

Two things to keep straight:

- **`APP_BASE_URL` stays single and canonical.** It feeds the CSP of the pages
  the server renders itself (the admin panel) and the absolute room-logo URL.
- **`CORS_ORIGINS` must list every name** (`https://a,https://b`). The two
  shipped clients pass the origin check by prefix (`chrome-extension://`,
  `react-native://`) and do not need it, but the admin panel and any
  browser-based client do.

The WebSocket location block is regex-matched on the path, so it covers all
names automatically — but re-read the warning above about `/ws`, `/ws-dm` and
`/ws-notify`: with several names it is even easier to ship a half-copied config.

### 8.2. Volunteer bridges (planned, not implemented yet)

The next step beyond your own domains is an entry point held by someone else:
a small VPS that forwards raw TCP to your server. Nothing in the clients needs
to change for it — a bridge is just another address in the list — but the
deployment has two traps worth writing down before anyone tries it.

**The bridge must not terminate TLS.** If it does, it sees the plaintext of
every request, including `Authorization: Bearer …`. That is not a metadata
leak, it is account takeover; message *contents* stay safe (they are E2EE) and
nothing else does. A bridge does TCP passthrough (`nginx stream`, or socat) and
never holds a private key. The certificate for the bridge's own name is issued
by **your** server, with the volunteer delegating
`_acme-challenge.bridge.volunteer.net` by CNAME to your ACME account.

**Real client IPs need PROXY protocol v2.** Under passthrough your nginx sees
the bridge's IP as `$remote_addr` for every user coming through it, and the
rate limiter is keyed by IP (`ws:connect:ip:…`, `uddm:msg:ip:…`, in-process, in
`server/main.py`). Without PROXY protocol every user of one bridge shares one
bucket, so a single busy user rate-limits all the others — and one ban by IP
hits everyone on that bridge.

On the bridge:

```nginx
# /etc/nginx/nginx.conf — `stream` is a top-level block, a sibling of `http`,
# so it cannot live in sites-available/.
stream {
    server {
        listen 443;
        proxy_pass island.example.com:8443;
        proxy_protocol on;
    }
}
```

On your server:

```nginx
server {
    listen 8443 ssl proxy_protocol;      # bridged traffic only
    set_real_ip_from 203.0.113.7;        # the bridge, and nothing else
    real_ip_header proxy_protocol;
    # …the rest identical to the 443 block…
}
```

**The trap:** `proxy_protocol` on a listener makes the PROXY header
*mandatory* there, so direct browser connections to that port break. Keep `443`
plain for direct clients and give bridged traffic its own port, as above. And
`set_real_ip_from` must name the bridges explicitly — a wildcard there lets
anyone spoof any client IP.

The trade-off is deliberate: with PROXY protocol your server learns the real
client IP (the bridge is not an anonymizer), and in exchange rate limits and
bans keep working per user. Without it the bridge hides client IPs from you and
becomes a lever for denial of service against its own users.

---

## 9. Create the first admin

There is no env-based bootstrap — you promote an existing account by
inserting a row into `admin_users`.

1. Register a normal user through the Chrome extension or Android
   client (see [Section 10](#10-point-clients-at-your-server)).
2. Find the user's id:

   ```sh
   psql -h 127.0.0.1 -U wsapp -d wsapp \
       -c "SELECT id, username FROM users WHERE username='your-username';"
   ```

3. Grant superadmin:

   ```sh
   psql -h 127.0.0.1 -U wsapp -d wsapp \
       -c "INSERT INTO admin_users(user_id, role) VALUES (<id>, 'superadmin');"
   ```

4. Log in at `https://messenger.example.com/admin/` with the same
   credentials. Roles are `admin` (moderation) and `superadmin` (full
   access, including promoting other admins).

> **The admin panel requires HTTPS.** The session cookie is issued with
> `Secure`, so over plain `http://` the browser accepts the login and then
> drops the cookie -- every page afterwards returns 401. If you see that,
> you are on HTTP, not misconfigured.

> **Restrict who can reach `/admin/`.** Nothing in the application limits
> admin access by network -- the guard is a session cookie only, and the
> nginx config above serves `/admin/` to the whole internet. Put it behind
> your VPN or an IP allowlist:
>
> ```nginx
> location /admin/ {
>     allow 10.8.0.0/24;   # your VPN subnet
>     deny  all;
>     proxy_pass http://127.0.0.1:8000;
>     proxy_set_header Host              $host;
>     proxy_set_header X-Real-IP         $remote_addr;
>     proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
>     proxy_set_header X-Forwarded-Proto $scheme;
> }
> ```

---

## 10. Point clients at your server

### Chrome extension

No edit and no reload required. On the login screen open **"Connect to
another server"**, enter your API base (`https://messenger.example.com`),
press **Add**, then **Save**. The extension asks Chrome for permission to talk
to that origin, stores the choice in `chrome.storage.local` under
`server_config`, and every later request follows it. **Test all** checks
`/health` on each address before you commit to them.

If your server has several addresses (§8.1), add them all — the list is
ordered, the first one is preferred, and the extension moves down it when one
stops answering. A failover between addresses of the same server keeps you
logged in and keeps the open room and DM working; only pointing the client at a
genuinely different server (no address in common with the previous list) tears
the session down.

**Add every address in one go.** Chrome only grants host permissions in
response to a click, so the permission dialog you get when pressing **Save**
covers exactly the addresses in the list at that moment. An address added later
cannot be granted in the background, and the extension will skip it and show a
banner asking you to press **Save** again.

Your backend must be reachable over **HTTPS**. The extension's content
security policy permits only `https:` and `wss:`, and its
`optional_host_permissions` cover `https://*/*` - so a plain-HTTP
backend cannot be granted, not even on localhost.

The author's hosts (`chat-room.work`, `imagine-1-ws.xyz`) stay in
`manifest.json` and in the JS files as **defaults**, used until you save
a server of your own. Editing them out is optional; if you distribute a
fork and want your host to be the default, change all four places, since
each context resolves its own base:

| File | Constants |
|---|---|
| `chrome_extension/manifest.json` | `host_permissions` |
| `chrome_extension/background.js` | `API_BASE`, `WS_BASE` |
| `chrome_extension/login.js` | `DEFAULT_API_BASE`, `DEFAULT_WS_BASE` |
| `chrome_extension/panel.js` | `API_BASE` (shared with `panel-crypto.js`, `panel-ui.js`) |

```sh
cd chrome_extension
grep -rn "imagine-1-ws.xyz\|chat-room.work" background.js login.js panel.js manifest.json
```

### Android

No rebuild required. On the Login screen tap **"Connect to another
server"**, enter `https://messenger.example.com`, tap **+**, then **Save**.
The list is saved per-device and is also reachable later from
**Profile → Server**.

As in the extension, the list is ordered and the app fails over down it without
losing the session; **Test all** probes every address. There are no certificate
pins, so any address with a certificate from a public CA works — including one
added after the APK was built.

---

## 11. Updating

```sh
sudo -iu wsapp
cd ~/wsmessenger
git pull
source .venv/bin/activate
pip install -r server/requirements.txt
# If schema.sql changed between versions, review the diff and apply
# migrations manually — there is no migration tool yet.
exit
sudo systemctl restart wsapp
```

Watch `journalctl -u wsapp -f` on first start after an update.

---

## 12. Troubleshooting

**`GET /crypto/keys` returns 410 Gone.**
This is by design. The encrypted private key (EPK) lives on the client
only. Old extension builds that still try this endpoint will fail —
update them.

**CORS errors in the browser console.**
`CORS_ORIGINS` must include the exact origin of the web client
(protocol + host + port). `chrome-extension://` is always allowed and
does not need to be listed.

**WebSocket connects, then drops after a minute.**
Increase `proxy_read_timeout` / `proxy_send_timeout` in nginx. The
example config uses 1 hour.

**`IP: -` in logs, rate limits behaving oddly.**
Set `TRUST_PROXY_HEADERS=1` in `.env` and make sure nginx forwards
`X-Forwarded-For`. Also pass `--proxy-headers
--forwarded-allow-ips="127.0.0.1"` to uvicorn (the systemd unit above
already does). If you are running in privacy mode
(`TRUST_PROXY_HEADERS=0`) this behaviour is intentional — client IPs
are being intentionally hidden from the server and only per-user rate
limits are effective.

**Argon2id login is very slow under load.**
Login is CPU- and memory-bound by design. Lower `ARGON2_MEMORY_COST`
cautiously if your VPS is memory-constrained, but never below 32 MiB.

**Admin panel 403s after login.**
Your account has no `admin_users` row. Revisit
[Section 9](#9-create-the-first-admin).

---

## 13. A word on AGPL

If you run a modified version of this software on a network server,
**AGPL §13** requires you to offer the corresponding source to users
of that server. Keep a fork of your modifications accessible (e.g. a
public git repo) and advertise its URL — a link in the admin panel
footer or a `/source` route is fine. The canonical upstream is
<https://github.com/Eisern/wsmessenger>.
