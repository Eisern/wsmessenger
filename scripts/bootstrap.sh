#!/usr/bin/env bash
# ============================================================================
# WS Messenger — bare-server bootstrap.
#
# Installs PostgreSQL, Python, the backend, nginx, and a Let's Encrypt cert,
# then leaves a running systemd unit behind https://<your-domain>.
#
# Target: fresh Debian 12 / Ubuntu 22.04 / Ubuntu 24.04, run as root.
#
# Interactive:
#     sudo bash scripts/bootstrap.sh
#
# Non-interactive:
#     sudo WSAPP_DOMAIN=messenger.example.com \
#          WSAPP_LETSENCRYPT_EMAIL=admin@example.com \
#          bash scripts/bootstrap.sh
#
# Other env vars (all optional):
#     WSAPP_EXTRA_DOMAINS     more domains for THIS backend, comma-separated.
#                             Clients keep an ordered list of entry points and
#                             fail over between them without losing the session;
#                             all names go on one multi-SAN certificate.
#                             (e.g. "mirror.example.com,alt.example.net")
#     WSAPP_USER              service account name       (default: wsapp)
#     WSAPP_INSTALL_DIR       source checkout path       (default: /home/wsapp/wsmessenger)
#     WSAPP_UPLOAD_DIR        media storage path         (default: /var/lib/wsapp/uploads)
#     WSAPP_DB_NAME           postgres database name     (default: wsapp)
#     WSAPP_DB_USER           postgres role name         (default: wsapp)
#     WSAPP_REPO_URL          git remote                 (default: canonical upstream)
#     WSAPP_REPO_REF          branch/tag to check out    (default: main)
#     WSAPP_SKIP_CERTBOT=1    skip TLS issuance (prototype/no domain)
#     WSAPP_SKIP_ISLAND=1     do not set up an island identity, so users here
#                             cannot exchange direct messages with users of
#                             other servers (see docs/self-hosting.md §8.3)
#
# Re-running: safe. If server/.env already exists, credentials and the
# database are left untouched; only code, dependencies, systemd unit, and
# nginx config are refreshed. The one thing added to an existing .env is a
# missing island identity — generated once, never replaced afterwards.
#
# CAVEAT: HTTPS is effectively mandatory. The Chrome extension only talks
# to https:// hosts, and sealed-sender DMs rely on a WSS upgrade. Plain
# HTTP deployments are only useful for local experimentation.
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "error: run as root: sudo bash $0" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null; then
    echo "error: this script supports Debian/Ubuntu (apt-based) only." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WSAPP_USER="${WSAPP_USER:-wsapp}"
WSAPP_INSTALL_DIR="${WSAPP_INSTALL_DIR:-/home/${WSAPP_USER}/wsmessenger}"
WSAPP_UPLOAD_DIR="${WSAPP_UPLOAD_DIR:-/var/lib/wsapp/uploads}"
WSAPP_DB_NAME="${WSAPP_DB_NAME:-wsapp}"
WSAPP_DB_USER="${WSAPP_DB_USER:-wsapp}"
WSAPP_REPO_URL="${WSAPP_REPO_URL:-https://github.com/Eisern/wsmessenger.git}"
WSAPP_REPO_REF="${WSAPP_REPO_REF:-main}"
WSAPP_SKIP_CERTBOT="${WSAPP_SKIP_CERTBOT:-0}"
WSAPP_SKIP_ISLAND="${WSAPP_SKIP_ISLAND:-0}"

if [[ -z "${WSAPP_DOMAIN:-}" ]]; then
    read -rp "Public domain for this server (e.g. messenger.example.com): " WSAPP_DOMAIN
fi
if [[ -z "${WSAPP_DOMAIN}" ]]; then
    echo "error: WSAPP_DOMAIN is required." >&2
    exit 1
fi

# Additional domains pointing at this same backend (comma-separated, optional).
# Clients keep an ordered list of entry points and fail over between them
# without losing the session, so several names for one island are the cheapest
# defence against a domain-level block. All names end up on ONE certificate.
WSAPP_EXTRA_DOMAINS="${WSAPP_EXTRA_DOMAINS:-}"
WSAPP_ALL_DOMAINS="${WSAPP_DOMAIN}"
if [[ -n "${WSAPP_EXTRA_DOMAINS}" ]]; then
    WSAPP_ALL_DOMAINS="${WSAPP_DOMAIN},${WSAPP_EXTRA_DOMAINS}"
fi
# Four forms of the same list: nginx server_name (space-separated),
# CORS_ORIGINS (comma-separated origins), certbot flags, and bare lowercase
# host names for the island's signed list of entry points.
WSAPP_SERVER_NAMES=""
WSAPP_CORS_ORIGINS=""
WSAPP_CERTBOT_DOMAINS=()
WSAPP_HOSTS=()
IFS=',' read -ra _wsapp_domain_list <<< "${WSAPP_ALL_DOMAINS}"
for _d in "${_wsapp_domain_list[@]}"; do
    _d="$(echo -n "${_d}" | tr -d '[:space:]')"
    [[ -z "${_d}" ]] && continue
    WSAPP_SERVER_NAMES+="${WSAPP_SERVER_NAMES:+ }${_d}"
    WSAPP_CORS_ORIGINS+="${WSAPP_CORS_ORIGINS:+,}https://${_d}"
    WSAPP_CERTBOT_DOMAINS+=(-d "${_d}")
    WSAPP_HOSTS+=("${_d,,}")
done
unset _d _wsapp_domain_list

if [[ "${WSAPP_SKIP_CERTBOT}" != "1" && -z "${WSAPP_LETSENCRYPT_EMAIL:-}" ]]; then
    read -rp "Email for Let's Encrypt notices: " WSAPP_LETSENCRYPT_EMAIL
    if [[ -z "${WSAPP_LETSENCRYPT_EMAIL}" ]]; then
        echo "error: WSAPP_LETSENCRYPT_EMAIL is required (or set WSAPP_SKIP_CERTBOT=1)." >&2
        exit 1
    fi
fi

VENV_DIR="${WSAPP_INSTALL_DIR}/.venv"
ENV_FILE="${WSAPP_INSTALL_DIR}/server/.env"
SCHEMA_MARKER="${WSAPP_INSTALL_DIR}/.schema-applied"

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*" >&2; }

# Replace (or append) a KEY=VALUE line in .env. Value may contain any character
# except NUL; we escape sed metacharacters for the replacement side.
set_env_var() {
    local key="$1" value="$2"
    local esc
    esc=$(printf '%s' "$value" | sed -e 's/[\\|&]/\\&/g')
    if grep -qE "^${key}=" "${ENV_FILE}"; then
        sed -i -E "s|^${key}=.*|${key}=${esc}|" "${ENV_FILE}"
    else
        printf '%s=%s\n' "$key" "$value" >> "${ENV_FILE}"
    fi
}

# The raw value of KEY in .env (quotes included), or "" if it is not set.
get_env_var() {
    sed -n -E "s/^$1=//p" "${ENV_FILE}" | tail -n 1
}

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
log "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y \
    python3 python3-venv python3-pip \
    postgresql postgresql-contrib \
    nginx \
    git curl ca-certificates \
    build-essential libpq-dev

if [[ "${WSAPP_SKIP_CERTBOT}" != "1" ]]; then
    apt-get install -y certbot python3-certbot-nginx
fi

# ---------------------------------------------------------------------------
# 2. Service user
# ---------------------------------------------------------------------------
if ! id -u "${WSAPP_USER}" >/dev/null 2>&1; then
    log "Creating service user '${WSAPP_USER}'"
    useradd --system --create-home --shell /bin/bash "${WSAPP_USER}"
fi

# ---------------------------------------------------------------------------
# 3. Source checkout
# ---------------------------------------------------------------------------
if [[ -d "${WSAPP_INSTALL_DIR}/.git" ]]; then
    log "Updating source in ${WSAPP_INSTALL_DIR}"
    sudo -iu "${WSAPP_USER}" -- git -C "${WSAPP_INSTALL_DIR}" fetch --all --prune
    sudo -iu "${WSAPP_USER}" -- git -C "${WSAPP_INSTALL_DIR}" checkout "${WSAPP_REPO_REF}"
    sudo -iu "${WSAPP_USER}" -- git -C "${WSAPP_INSTALL_DIR}" pull --ff-only || \
        warn "git pull --ff-only refused; leaving working tree as-is"
else
    log "Cloning source to ${WSAPP_INSTALL_DIR}"
    install -d -o "${WSAPP_USER}" -g "${WSAPP_USER}" "$(dirname "${WSAPP_INSTALL_DIR}")"
    sudo -iu "${WSAPP_USER}" -- git clone --branch "${WSAPP_REPO_REF}" \
        "${WSAPP_REPO_URL}" "${WSAPP_INSTALL_DIR}"
fi

# ---------------------------------------------------------------------------
# 4. Python virtualenv + dependencies
# ---------------------------------------------------------------------------
log "Setting up Python virtualenv"
# One command per sudo, and no `sudo -i ... bash -c "<several lines>"`: with
# -i, sudo escapes every newline in the arguments into a line continuation, so
# such a script runs as the single line `set -e python3 -m venv ...` - which
# sets positional parameters, succeeds, and creates nothing.
sudo -u "${WSAPP_USER}" -H python3 -m venv "${VENV_DIR}"
sudo -u "${WSAPP_USER}" -H "${VENV_DIR}/bin/pip" install --upgrade pip
sudo -u "${WSAPP_USER}" -H "${VENV_DIR}/bin/pip" install -r "${WSAPP_INSTALL_DIR}/server/requirements.txt"
if [[ ! -x "${VENV_DIR}/bin/python" || ! -x "${VENV_DIR}/bin/uvicorn" ]]; then
    echo "error: the virtualenv in ${VENV_DIR} was not created" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 5. PostgreSQL + schema + .env
#
# If .env already exists we preserve it and do NOT rotate the DB password
# or the JWT_SECRET — otherwise existing sessions/users would break.
# ---------------------------------------------------------------------------
install -d -o "${WSAPP_USER}" -g "${WSAPP_USER}" "${WSAPP_UPLOAD_DIR}"

if [[ -f "${ENV_FILE}" ]]; then
    log "Existing ${ENV_FILE} found — preserving DB credentials and JWT_SECRET"
    # Quick sanity check that the DB role exists; we don't touch the password.
    if ! sudo -u postgres psql -tAc \
            "SELECT 1 FROM pg_roles WHERE rolname='${WSAPP_DB_USER}'" | grep -q 1; then
        warn "role '${WSAPP_DB_USER}' is missing but .env exists — review manually"
    fi
else
    log "Generating secrets, creating DB role and database"
    DB_PASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')

    if sudo -u postgres psql -tAc \
            "SELECT 1 FROM pg_roles WHERE rolname='${WSAPP_DB_USER}'" | grep -q 1; then
        # Role exists from a previous botched run — rotate its password to
        # match the new .env.
        sudo -u postgres psql -c \
            "ALTER USER ${WSAPP_DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null
    else
        sudo -u postgres psql -c \
            "CREATE USER ${WSAPP_DB_USER} WITH PASSWORD '${DB_PASS}';" >/dev/null
    fi

    if ! sudo -u postgres psql -tAc \
            "SELECT 1 FROM pg_database WHERE datname='${WSAPP_DB_NAME}'" | grep -q 1; then
        sudo -u postgres createdb -O "${WSAPP_DB_USER}" "${WSAPP_DB_NAME}"
    fi

    log "Rendering ${ENV_FILE} from config.example.env"
    cp "${WSAPP_INSTALL_DIR}/server/config.example.env" "${ENV_FILE}"

    set_env_var DATABASE_URL \
        "postgresql+asyncpg://${WSAPP_DB_USER}:${DB_PASS}@127.0.0.1:5432/${WSAPP_DB_NAME}"
    set_env_var JWT_SECRET          "${JWT_SECRET}"
    set_env_var APP_BASE_URL        "https://${WSAPP_DOMAIN}"
    # APP_BASE_URL stays single and canonical: it feeds the CSP of the pages the
    # server renders itself (the admin panel) and the absolute room-logo URL.
    # CORS_ORIGINS must list every entry point, for browser-based clients.
    set_env_var CORS_ORIGINS        "${WSAPP_CORS_ORIGINS}"
    set_env_var ENV                 "prod"
    set_env_var UPLOAD_DIR          "${WSAPP_UPLOAD_DIR}"
    set_env_var TRUST_PROXY_HEADERS "1"

    chown "${WSAPP_USER}:${WSAPP_USER}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"

    log "Applying schema.sql"
    PGPASSWORD="${DB_PASS}" psql \
        -h 127.0.0.1 -U "${WSAPP_DB_USER}" -d "${WSAPP_DB_NAME}" \
        -v ON_ERROR_STOP=1 \
        -f "${WSAPP_INSTALL_DIR}/server/schema.sql" >/dev/null
    sudo -u "${WSAPP_USER}" touch "${SCHEMA_MARKER}"

    unset DB_PASS JWT_SECRET
fi

# ---------------------------------------------------------------------------
# 5b. Island identity
#
# One backend with one database is an island. Its id and its signing key let
# users here exchange direct messages with users of other islands, and let a
# contact on another island find this one again after an address changes.
# Without ISLAND_ID every /foreign/* endpoint answers 404.
#
# Both are pinned by every client that has ever added a contact from here.
# Replace either and those clients reject every later address list from this
# island as forged ("bad signature" / "different island"), so a contact can no
# longer follow it to a new address. They are therefore generated ONCE, only
# when missing, and never touched again. That is also why enabling this on an
# existing install is safe: with no ISLAND_ID nobody could have added a contact
# from here, so there is no pin to break.
# ---------------------------------------------------------------------------
WSAPP_ISLAND_ID=""
if [[ "${WSAPP_SKIP_ISLAND}" == "1" ]]; then
    warn "WSAPP_SKIP_ISLAND=1 — no island identity; cross-server direct messages stay off."
else
    _island_scheme=https
    [[ "${WSAPP_SKIP_CERTBOT}" == "1" ]] && _island_scheme=http

    if [[ ${#WSAPP_HOSTS[@]} -gt 8 ]]; then
        warn "clients read at most 8 entry points from the island list; only the first 8 domains will be used by them"
    fi

    if [[ -z "$(get_env_var ISLAND_SIGNING_KEY_B64)" ]]; then
        log "Generating the island signing key (Ed25519)"
        set_env_var ISLAND_SIGNING_KEY_B64 "$("${VENV_DIR}/bin/python" - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
k = Ed25519PrivateKey.generate()
print(base64.b64encode(k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode())
PY
)"
    fi

    if [[ -z "$(get_env_var ISLAND_ID)" ]]; then
        # The primary domain, as the clients themselves name an island by the
        # host of its first entry point. It is an identifier from here on, not
        # an address: if the domain is ever lost, the id stays.
        set_env_var ISLAND_ID "${WSAPP_HOSTS[0]}"
    fi

    # Entry points: every domain this script puts on the certificate, in order.
    # Single quotes, because the value is JSON and both systemd and a shell
    # `source` would otherwise strip its double quotes.
    _island_eps="$("${VENV_DIR}/bin/python" - "${_island_scheme}" "${WSAPP_HOSTS[@]}" <<'PY'
import json, sys
scheme, hosts = sys.argv[1], sys.argv[2:]
ws = "wss" if scheme == "https" else "ws"
print(json.dumps(
    [{"apiBase": f"{scheme}://{h}", "wsBase": f"{ws}://{h}", "label": ""} for h in hosts],
    separators=(",", ":"),
))
PY
)"
    _current_eps="$(get_env_var ISLAND_ENTRY_POINTS)"
    if [[ -z "${_current_eps}" ]]; then
        set_env_var ISLAND_ENTRY_POINTS "'${_island_eps}'"
        if [[ -z "$(get_env_var ISLAND_LIST_VERSION)" ]]; then
            set_env_var ISLAND_LIST_VERSION 1
        fi
    elif ! "${VENV_DIR}/bin/python" - "${_current_eps}" "${WSAPP_HOSTS[@]}" <<'PY'
import json, sys
from urllib.parse import urlsplit
raw = sys.argv[1].strip()
if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
    raw = raw[1:-1]
try:
    have = {urlsplit(e["apiBase"]).hostname for e in json.loads(raw)}
except Exception:
    sys.exit(1)
sys.exit(0 if have == set(sys.argv[2:]) else 1)
PY
    then
        # Hand-edited lists are left alone: an entry point is something clients
        # will dial, and this script cannot tell a typo from a bridge somebody
        # added on purpose.
        warn "ISLAND_ENTRY_POINTS in ${ENV_FILE} does not name the same domains as this run (${WSAPP_SERVER_NAMES}). Left as is. If the domains changed, set:"
        warn "  ISLAND_ENTRY_POINTS='${_island_eps}'"
        warn "  CORS_ORIGINS=${WSAPP_CORS_ORIGINS}"
        warn "and raise ISLAND_LIST_VERSION by one, then: systemctl restart wsapp"
    fi

    WSAPP_ISLAND_ID="$(get_env_var ISLAND_ID)"
    chown "${WSAPP_USER}:${WSAPP_USER}" "${ENV_FILE}"
    chmod 600 "${ENV_FILE}"
    unset _island_scheme _island_eps _current_eps
fi

chown -R "${WSAPP_USER}:${WSAPP_USER}" "${WSAPP_UPLOAD_DIR}"

# ---------------------------------------------------------------------------
# 6. systemd unit
# ---------------------------------------------------------------------------
log "Installing systemd unit /etc/systemd/system/wsapp.service"
# Exactly ONE worker. Room sockets, DM sockets, notifications and rate limits
# all live in the process's memory, so a second worker splits them: two people
# in one room who land on different workers stop seeing each other's messages
# live. Earlier versions of this script set --workers 2; re-running it fixes
# such an install.
cat > /etc/systemd/system/wsapp.service <<EOF
[Unit]
Description=WS Messenger backend
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=${WSAPP_USER}
Group=${WSAPP_USER}
WorkingDirectory=${WSAPP_INSTALL_DIR}/server
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV_DIR}/bin/uvicorn main:app \\
    --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers \\
    --forwarded-allow-ips=127.0.0.1
Restart=on-failure
RestartSec=5s

# Hardening.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${WSAPP_INSTALL_DIR} ${WSAPP_UPLOAD_DIR}
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now wsapp
systemctl restart wsapp

# ---------------------------------------------------------------------------
# 7. nginx reverse proxy
# ---------------------------------------------------------------------------
log "Writing /etc/nginx/sites-available/wsapp.conf"
NGINX_CONF=/etc/nginx/sites-available/wsapp.conf
cat > "${NGINX_CONF}" <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name ${WSAPP_SERVER_NAMES};

    # Uploads: backend caps at 100 MiB; give nginx some headroom.
    client_max_body_size 110m;

    # HTTP API + admin panel.
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 60s;
    }

    # WebSocket endpoints (room + DM + per-user notifications).
    location ~ ^/(ws|ws-dm|ws-notify)(/|\$) {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/wsapp.conf
if [[ -L /etc/nginx/sites-enabled/default ]]; then
    rm /etc/nginx/sites-enabled/default
fi

nginx -t
systemctl reload nginx

# ---------------------------------------------------------------------------
# 8. TLS via Let's Encrypt
# ---------------------------------------------------------------------------
if [[ "${WSAPP_SKIP_CERTBOT}" != "1" ]]; then
    log "Issuing Let's Encrypt certificate for ${WSAPP_SERVER_NAMES}"
    # One multi-SAN certificate covering every entry point of this island.
    certbot --nginx --non-interactive --agree-tos \
        --email "${WSAPP_LETSENCRYPT_EMAIL}" \
        "${WSAPP_CERTBOT_DOMAINS[@]}" \
        --redirect
else
    warn "WSAPP_SKIP_CERTBOT=1 — nginx is serving plain HTTP only. Clients require HTTPS."
fi

# ---------------------------------------------------------------------------
# 9. Smoke test
# ---------------------------------------------------------------------------
log "Running smoke test"
sleep 2
if curl -fsS --max-time 5 http://127.0.0.1:8000/health >/dev/null; then
    echo "   backend /health responded OK"
else
    warn "backend did not respond on /health — check: journalctl -u wsapp -e"
fi
if [[ -n "${WSAPP_ISLAND_ID}" ]]; then
    # The list is the one thing that proves the island identity is live: the
    # server mounts it only when the key parses and ISLAND_ENTRY_POINTS is
    # valid JSON, and says why in the journal when it does not.
    if curl -fsS --max-time 5 http://127.0.0.1:8000/.well-known/wsapp-island >/dev/null; then
        echo "   island list /.well-known/wsapp-island responded OK"
    else
        warn "island list did not respond — check ISLAND_* in ${ENV_FILE} and: journalctl -u wsapp -e"
    fi
fi

# ---------------------------------------------------------------------------
# 10. Summary
# ---------------------------------------------------------------------------
PROTO=https
[[ "${WSAPP_SKIP_CERTBOT}" == "1" ]] && PROTO=http

cat <<EOF

============================================================
 WS Messenger backend bootstrapped.

   Public URL:  ${PROTO}://${WSAPP_DOMAIN}
   Entry points: ${WSAPP_SERVER_NAMES}
   Admin panel: ${PROTO}://${WSAPP_DOMAIN}/admin/
   Island id:   ${WSAPP_ISLAND_ID:-(none — cross-server messages off)}
   Config:      ${ENV_FILE}     (mode 600, owner ${WSAPP_USER})
   Uploads:     ${WSAPP_UPLOAD_DIR}
   Service:     systemctl status wsapp
   Logs:        journalctl -u wsapp -f

 NEXT STEPS

 1. Register a regular user via the Chrome extension or Android
    client (point it at ${PROTO}://${WSAPP_DOMAIN}).

 2. Promote that account to superadmin:

      sudo -u postgres psql -d ${WSAPP_DB_NAME} \\
          -c "INSERT INTO admin_users(user_id, role)
               SELECT id, 'superadmin' FROM users
                WHERE username='YOUR_USERNAME';"

 3. Sign in at ${PROTO}://${WSAPP_DOMAIN}/admin/

 BACK UP ${ENV_FILE} — it holds the database password and the
 JWT signing secret. Losing JWT_SECRET invalidates all issued
 tokens (users must re-login; no data is destroyed).

 It also holds ISLAND_SIGNING_KEY_B64. That one cannot be
 replaced: users on other servers pin it. With a new key their
 clients reject every later address list from here as forged,
 so their contacts work only at the addresses they already know
 — until those change.
============================================================
EOF
