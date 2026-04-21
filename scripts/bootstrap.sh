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
#     WSAPP_USER              service account name       (default: wsapp)
#     WSAPP_INSTALL_DIR       source checkout path       (default: /home/wsapp/wsmessenger)
#     WSAPP_UPLOAD_DIR        media storage path         (default: /var/lib/wsapp/uploads)
#     WSAPP_DB_NAME           postgres database name     (default: wsapp)
#     WSAPP_DB_USER           postgres role name         (default: wsapp)
#     WSAPP_REPO_URL          git remote                 (default: canonical upstream)
#     WSAPP_REPO_REF          branch/tag to check out    (default: main)
#     WSAPP_SKIP_CERTBOT=1    skip TLS issuance (prototype/no domain)
#
# Re-running: safe. If server/.env already exists, credentials and the
# database are left untouched; only code, dependencies, systemd unit, and
# nginx config are refreshed.
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

if [[ -z "${WSAPP_DOMAIN:-}" ]]; then
    read -rp "Public domain for this server (e.g. messenger.example.com): " WSAPP_DOMAIN
fi
if [[ -z "${WSAPP_DOMAIN}" ]]; then
    echo "error: WSAPP_DOMAIN is required." >&2
    exit 1
fi

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
sudo -iu "${WSAPP_USER}" -- bash -c "
    set -e
    python3 -m venv '${VENV_DIR}'
    '${VENV_DIR}/bin/pip' install --upgrade pip
    '${VENV_DIR}/bin/pip' install -r '${WSAPP_INSTALL_DIR}/server/requirements.txt'
"

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

    # Replace (or append) a KEY=VALUE line. Value may contain any character
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

    set_env_var DATABASE_URL \
        "postgresql+asyncpg://${WSAPP_DB_USER}:${DB_PASS}@127.0.0.1:5432/${WSAPP_DB_NAME}"
    set_env_var JWT_SECRET          "${JWT_SECRET}"
    set_env_var APP_BASE_URL        "https://${WSAPP_DOMAIN}"
    set_env_var CORS_ORIGINS        "https://${WSAPP_DOMAIN}"
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

chown -R "${WSAPP_USER}:${WSAPP_USER}" "${WSAPP_UPLOAD_DIR}"

# ---------------------------------------------------------------------------
# 6. systemd unit
# ---------------------------------------------------------------------------
log "Installing systemd unit /etc/systemd/system/wsapp.service"
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
    --host 127.0.0.1 --port 8000 --workers 2 --proxy-headers \\
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
    server_name ${WSAPP_DOMAIN};

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

    # WebSocket endpoints (room + DM).
    location ~ ^/(ws|ws-dm)(/|\$) {
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
    log "Issuing Let's Encrypt certificate for ${WSAPP_DOMAIN}"
    certbot --nginx --non-interactive --agree-tos \
        --email "${WSAPP_LETSENCRYPT_EMAIL}" \
        -d "${WSAPP_DOMAIN}" \
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

# ---------------------------------------------------------------------------
# 10. Summary
# ---------------------------------------------------------------------------
PROTO=https
[[ "${WSAPP_SKIP_CERTBOT}" == "1" ]] && PROTO=http

cat <<EOF

============================================================
 WS Messenger backend bootstrapped.

   Public URL:  ${PROTO}://${WSAPP_DOMAIN}
   Admin panel: ${PROTO}://${WSAPP_DOMAIN}/admin/
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
============================================================
EOF
