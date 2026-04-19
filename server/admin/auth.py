# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from collections import defaultdict
import secrets
import time
import hmac
from fastapi import Request, Response, HTTPException

SESSION_COOKIE = "admin_session"
SESSION_TTL = timedelta(hours=8)

# MVP: in-memory. Лучше потом Redis/DB.
_sessions: dict[str, dict] = {}

# ── rate limiter (пункт 1) ────────────────────────────────
RATE_LIMIT_WINDOW = 60          # секунд
RATE_LIMIT_MAX_ATTEMPTS = 5     # попыток за окно

# {key: [timestamp, timestamp, ...]}
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _rate_limit_key(request: Request, username: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{ip}:{username}"


def check_rate_limit(request: Request, username: str) -> bool:
    """Возвращает True если лимит превышен."""
    key = _rate_limit_key(request, username)
    now = time.monotonic()
    bucket = _rate_buckets[key]
    # убираем старые записи за пределами окна
    _rate_buckets[key] = bucket = [t for t in bucket if now - t < RATE_LIMIT_WINDOW]
    if len(bucket) >= RATE_LIMIT_MAX_ATTEMPTS:
        return True
    bucket.append(now)
    return False


@dataclass
class AdminPrincipal:
    user_id: int
    username: str
    role: str  # admin | superadmin

def create_session(user_id: int, username: str, role: str) -> str:
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.now(timezone.utc) + SESSION_TTL,
        "csrf_token": secrets.token_urlsafe(32),
    }
    return sid

def destroy_session(sid: str):
    _sessions.pop(sid, None)

def get_principal(request: Request) -> AdminPrincipal | None:
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return None
    s = _sessions.get(sid)
    if not s:
        return None
    if s["exp"] < datetime.now(timezone.utc):
        destroy_session(sid)
        return None
    return AdminPrincipal(user_id=s["user_id"], username=s["username"], role=s["role"])

def require_admin(request: Request) -> AdminPrincipal:
    p = get_principal(request)
    if not p:
        raise HTTPException(status_code=401, detail="Admin auth required")
    return p

def require_superadmin(request: Request) -> AdminPrincipal:
    p = require_admin(request)
    if p.role != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin required")
    return p

def set_session_cookie(resp: Response, sid: str):
    resp.set_cookie(
        SESSION_COOKIE,
        sid,
        httponly=True,
        secure=True,          # обязательно под https
        samesite="strict",
        max_age=int(SESSION_TTL.total_seconds()),
        path="/admin",
    )


# ── CSRF protection ──────────────────────────────────────
def get_csrf_token(request: Request) -> str:
    """Return the CSRF token for the current admin session, or empty string."""
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        return ""
    s = _sessions.get(sid)
    if not s:
        return ""
    return s.get("csrf_token", "")


async def verify_csrf(request: Request) -> None:
    """
    Verify CSRF token from form data against session-stored token.
    Must be called on every state-changing (POST) admin endpoint.
    Raises HTTPException(403) on mismatch.
    """
    sid = request.cookies.get(SESSION_COOKIE)
    if not sid:
        raise HTTPException(status_code=403, detail="CSRF: no session")

    s = _sessions.get(sid)
    if not s:
        raise HTTPException(status_code=403, detail="CSRF: invalid session")

    expected = s.get("csrf_token", "")
    if not expected:
        raise HTTPException(status_code=403, detail="CSRF: no token in session")

    # Read form data (cached by FastAPI, safe to call multiple times)
    form = await request.form()
    submitted = str(form.get("_csrf", ""))

    if not submitted or not hmac.compare_digest(submitted, expected):
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
