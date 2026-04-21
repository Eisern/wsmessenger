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
- **`TRUST_PROXY_HEADERS=1`** — set this when you run behind nginx so
  the server honours `X-Forwarded-For` for rate limiting and logs.
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

    # Room WebSocket.
    location /ws {
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

    # DM WebSocket (sealed sender).
    location /ws-dm {
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

---

## 10. Point clients at your server

### Chrome extension

The author's hosts (`chat-room.work`, `imagine-1-ws.xyz`) are baked
into `chrome_extension/manifest.json` under `host_permissions`. Edit it
in your checkout:

```json
"host_permissions": [
  "https://messenger.example.com/*"
]
```

Also edit the default backend URL in `chrome_extension/background.js`
(search for the existing host strings and replace them). Then reload
the unpacked extension at `chrome://extensions/`.

### Android

No rebuild required. On the Login screen tap **"Connect to another
server"** and enter `https://messenger.example.com`. The URL is saved
per-device.

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
already does).

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
