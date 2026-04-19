# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

import os
import json
import time
import secrets
import string
import shutil
import asyncio
from contextlib import asynccontextmanager
import mimetypes
import base64
import hashlib
import uuid
import pyotp
import io
import hmac
import smtplib
import re
from email.message import EmailMessage
import logging
logger = logging.getLogger("wsapp.feedback")

try:
    import qrcode
    import qrcode.image.svg
    _HAS_QRCODE = True
except ImportError:
    _HAS_QRCODE = False
from fastapi import Response
from fastapi import Header
from sqlalchemy.exc import IntegrityError

from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from pydantic import BaseModel
from jose import jwt, JWTError
from passlib.context import CryptContext
from jose.utils import base64url_decode
from jose.constants import Algorithms

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy import text
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi import status

from fastapi import UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
from fastapi import Query
from fastapi import HTTPException
from pydantic import Field

from sqlalchemy import bindparam, Integer

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from fastapi.staticfiles import StaticFiles
from admin.router import router as admin_router

import base64, hmac, hashlib, time
from pydantic import BaseModel

class UdDmSendIn(BaseModel):
    thread_id: int
    ts: int                      # unix ms
    nonce_b64: str               # base64
    ciphertext_b64: str          # base64
    tag_b64: str                 # base64(HMAC-SHA256)

ALLOWED_ORIGIN_PREFIXES = (
    "chrome-extension://",
    "react-native://",
)

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return default

def b64_to_bytes(s: str) -> bytes:
    s = (s or "").strip().replace("-", "+").replace("_", "/")
    s += "=" * ((4 - (len(s) % 4)) % 4)
    return base64.b64decode(s.encode("utf-8"))

def safe_b64_bytes_len(s: str, max_len: int) -> bytes:
    b = b64_to_bytes(s)
    if len(b) > max_len:
        raise HTTPException(status_code=400, detail="payload too large")
    return b

def hmac_tag(delivery_secret: bytes, thread_id: int, ts: int, nonce: bytes, ciphertext: bytes) -> bytes:
    # tag = HMAC(secret, thread_id || ts || nonce || sha256(ciphertext))
    h = hashlib.sha256(ciphertext).digest()
    msg = (
        str(thread_id).encode("utf-8") + b"|" +
        str(ts).encode("utf-8") + b"|" +
        nonce + b"|" + h
    )
    return hmac.new(delivery_secret, msg, hashlib.sha256).digest()

def is_allowed_origin(origin: str | None) -> bool:
    if not origin:
        return False
    if origin in ALLOWED_ORIGINS:
        return True
    return any(origin.startswith(p) for p in ALLOWED_ORIGIN_PREFIXES)

async def _save_feedback_to_db(
    session,
    *,
    user_id: int,
    username: str,
    ip: str | None,
    ua: str,
    meta: dict,
    message: str,
):
    # --- hard bounds (defense in depth; DB CHECKs should exist too) ---
    username = (username or "")[:80]
    ua = (ua or "")[:400]
    message = (message or "")[:1200]

    # --- normalize IP for inet column (optional but recommended) ---
    ip_norm = (ip or "").strip() or None
    if ip_norm and "," in ip_norm:
        ip_norm = ip_norm.split(",", 1)[0].strip()
    if ip_norm and ip_norm.lower() == "unknown":
        ip_norm = None

    # --- meta must be JSON-serializable and bounded ---
    try:
        meta_json_str = json.dumps(meta or {}, ensure_ascii=False)
        if len(meta_json_str) > 2000:
            meta_json_str = json.dumps(
                {"_truncated": True, "raw": meta_json_str[:2000]},
                ensure_ascii=False,
            )
    except Exception:
        meta_json_str = json.dumps({"_error": "meta not serializable"}, ensure_ascii=False)

    await session.execute(
        text("""
            INSERT INTO public.chat_feedback (user_id, username, ip, ua, meta_json, message)
            VALUES (:user_id, :username, :ip, :ua, CAST(:meta_json AS jsonb), :message)
        """),
        {
            "user_id": int(user_id),
            "username": username,
            "ip": ip_norm,   # строка "1.2.3.4" -> inet, None -> NULL
            "ua": ua,
            "meta_json": meta_json_str,
            "message": message,
        },
    )

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# --- SQL helpers: enforce Integer bindparams for int-like placeholders ---
_INTLIKE_PARAMS = {
    "id","rid","uid","tid","oid","me","other","low","high","lim","limit","by",
    "room_id","user_id","thread_id","owner_user_id","invited_by","requester_id","addressee_id",
}
def sql_i(sql: str, *names: str):
    """Return sqlalchemy.text(sql) with Integer-typed bindparams for given names."""
    q = text(sql)
    if names:
        q = q.bindparams(*(bindparam(n, type_=Integer) for n in names))
    return q

# Ref-counted per-room logo locks. Entry is [asyncio.Lock, refcount];
# the entry is removed from the dict when the last user releases, preventing
# unbounded growth as rooms are created/deleted over time.
_ROOM_LOGO_LOCKS: dict[int, list] = {}

@asynccontextmanager
async def _room_logo_lock(room_id: int):
    entry = _ROOM_LOGO_LOCKS.get(room_id)
    if entry is None:
        entry = [asyncio.Lock(), 0]
        _ROOM_LOGO_LOCKS[room_id] = entry
    entry[1] += 1
    try:
        async with entry[0]:
            yield
    finally:
        entry[1] -= 1
        if entry[1] <= 0:
            # Last user — drop the entry to keep the map bounded.
            # Safe in single-threaded asyncio: no other coroutine could have
            # incremented the refcount between the decrement above and here.
            _ROOM_LOGO_LOCKS.pop(room_id, None)

def forbid_room():
    
    raise HTTPException(status_code=404, detail="Not found")
        
def forbid_dm():
    raise HTTPException(status_code=404, detail="Not found")
    
def _sniff_image_ext(first_bytes: bytes) -> str | None:
    # PNG
    if first_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    # JPEG
    if first_bytes.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    # WEBP: RIFF....WEBP
    if len(first_bytes) >= 12 and first_bytes[0:4] == b"RIFF" and first_bytes[8:12] == b"WEBP":
        return ".webp"
    return None

ENV = os.getenv("ENV", "dev").lower()
DISABLE_DOCS = os.getenv("DISABLE_DOCS", "0").lower() in ("1","true","yes","on")

app = FastAPI(
    docs_url=None if (ENV == "prod" or DISABLE_DOCS) else "/docs",
    redoc_url=None if (ENV == "prod" or DISABLE_DOCS) else "/redoc",
    openapi_url=None if (ENV == "prod" or DISABLE_DOCS) else "/openapi.json",
)

# ===== Admin panel =====
app.include_router(admin_router)

BASE_DIR = Path(__file__).resolve().parent
ADMIN_STATIC_DIR = BASE_DIR / "admin" / "static"
if ADMIN_STATIC_DIR.is_dir():
    app.mount("/admin/static", StaticFiles(directory=str(ADMIN_STATIC_DIR)), name="admin-static")

DEBUG = (os.getenv("DEBUG", "0").strip().lower() in ("1", "true", "yes", "on"))

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100MB
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads")).resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

FILE_TTL_DAYS = int(os.getenv("FILE_TTL_DAYS", "7"))

RL_WS_DM_CONNECT_IP_PER_MIN = 120
RL_WS_DM_MSG_PER_10S = 25
RL_WS_DM_MSG_IP_PER_10S = 60
RL_FEEDBACK_IP_PER_10M = 5
RL_FEEDBACK_USER_PER_10M = 3
RL_ROOMS_INVITE_IP_PER_10MIN   = _env_int("RL_ROOMS_INVITE_IP_PER_10MIN", 60)
RL_ROOMS_INVITE_USER_PER_10MIN = _env_int("RL_ROOMS_INVITE_USER_PER_10MIN", 20)

RL_ROOMS_KICK_USER_PER_10MIN   = _env_int("RL_ROOMS_KICK_USER_PER_10MIN", 20)
RL_ROOMS_SETROLE_USER_PER_10MIN= _env_int("RL_ROOMS_SETROLE_USER_PER_10MIN", 30)
RL_ROOMS_SETROLE_IP_PER_10MIN = _env_int("RL_ROOMS_SETROLE_IP_PER_10MIN", 120)
RL_ROOMS_KICK_IP_PER_10MIN = _env_int("RL_ROOMS_KICK_IP_PER_10MIN", 60)

RL_ROOMS_JOINADM_IP_PER_10MIN = _env_int("RL_ROOMS_JOINADM_IP_PER_10MIN", 120)
RL_ROOMS_JOINADM_USER_PER_10MIN = _env_int("RL_ROOMS_JOINADM_USER_PER_10MIN", 60)

RL_ROOMS_APPROVE_USER_PER_10MIN= _env_int("RL_ROOMS_APPROVE_USER_PER_10MIN", 60)
MAX_DM_MSG_BYTES = 32 * 1024  # 32KB

from collections import deque
from fastapi import Request

TRUST_PROXY_HEADERS = (os.getenv("TRUST_PROXY_HEADERS") or "0").strip().lower() in (
    "1", "true", "yes", "y", "on"
)

ALLOW_LEGACY_JWT_NO_KID = (os.getenv("ALLOW_LEGACY_JWT_NO_KID") or "0").strip().lower() in (
    "1", "true", "yes", "y", "on"
)
ALLOW_LEGACY_ACCESS_NO_PURPOSE = (os.getenv("ALLOW_LEGACY_ACCESS_NO_PURPOSE") or "0").strip().lower() in (
    "1", "true", "yes", "y", "on"
)

def _client_ip_from_headers(headers, fallback: str = "unknown") -> str:
    if TRUST_PROXY_HEADERS:
        xff = headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        xri = headers.get("x-real-ip")
        if xri:
            return xri.strip()
    return fallback

def get_client_ip_request(request: Request) -> str:
    fallback = request.client.host if request.client else "unknown"
    return _client_ip_from_headers(request.headers, fallback=fallback)

def get_client_ip_ws(ws: WebSocket) -> str:
    fallback = ws.client.host if ws.client else "unknown"
    return _client_ip_from_headers(ws.headers, fallback=fallback)

class MemoryRateLimiter:
    """Sliding-window limiter.
    check(key, limit, window_sec) -> retry_after (sec) or None if allowed.
    """
    def __init__(self):
        self._buckets: dict[str, deque[float]] = {}
        self._lock = asyncio.Lock()
        self._last_gc = 0.0

    async def check(self, key: str, limit: int, window_sec: int) -> int | None:
        if limit <= 0 or window_sec <= 0:
            return None
        now = time.time()
        cutoff = now - window_sec

        async with self._lock:
            q = self._buckets.get(key)
            if q is None:
                q = deque()
                self._buckets[key] = q

            while q and q[0] <= cutoff:
                q.popleft()

            if len(q) >= limit:
                retry = int(window_sec - (now - q[0])) + 1
                return max(1, retry)

            q.append(now)

            if now - self._last_gc > 60:
                self._last_gc = now
                dead = [k for k, dq in self._buckets.items() if not dq or dq[-1] <= cutoff]
                for k in dead[:2000]:
                    self._buckets.pop(k, None)

        return None

rate_limiter = MemoryRateLimiter()

RL_LOGIN_IP_PER_MIN      = _env_int("RL_LOGIN_IP_PER_MIN", 20)
RL_LOGIN_USER_PER_MIN    = _env_int("RL_LOGIN_USER_PER_MIN", 10)
RL_REGISTER_IP_PER_5MIN  = _env_int("RL_REGISTER_IP_PER_5MIN", 8)

RL_WS_CONNECT_IP_PER_MIN = _env_int("RL_WS_CONNECT_IP_PER_MIN", 60)

RL_RECOVER_IP_PER_HOUR   = _env_int("RL_RECOVER_IP_PER_HOUR",   5)
RL_RECOVER_USER_PER_HOUR = _env_int("RL_RECOVER_USER_PER_HOUR", 3)
RL_WS_MSG_PER_10S        = _env_int("RL_WS_MSG_PER_10S", 30)
RL_WS_ROOM_TRY_PER_MIN   = _env_int("RL_WS_ROOM_TRY_PER_MIN", 30)
RL_WS_BADPW_PER_MIN      = _env_int("RL_WS_BADPW_PER_MIN", 6)
RL_ROOMS_RESOLVE_IP_PER_MIN        = _env_int("RL_ROOMS_RESOLVE_IP_PER_MIN", 120)
RL_ROOMS_JOINREQ_IP_PER_10MIN      = _env_int("RL_ROOMS_JOINREQ_IP_PER_10MIN", 20)
RL_ROOMS_JOINREQ_USER_PER_10MIN    = _env_int("RL_ROOMS_JOINREQ_USER_PER_10MIN", 10)
RL_ROOMS_INVITE_USER_PER_10MIN     = _env_int("RL_ROOMS_INVITE_USER_PER_10MIN", 20)
RL_ROOMS_INVITE_IP_PER_10MIN       = _env_int("RL_ROOMS_INVITE_IP_PER_10MIN", 60)
RL_KEYS_PUBLISH_IP_PER_10MIN       = _env_int("RL_KEYS_PUBLISH_IP_PER_10MIN", 120)
RL_KEYS_PUBLISH_USER_PER_10MIN     = _env_int("RL_KEYS_PUBLISH_USER_PER_10MIN", 60)
RL_CRYPTO_KEYWRITE_IP_PER_10MIN    = _env_int("RL_CRYPTO_KEYWRITE_IP_PER_10MIN", 180)
RL_CRYPTO_KEYWRITE_USER_PER_10MIN  = _env_int("RL_CRYPTO_KEYWRITE_USER_PER_10MIN", 120)
RL_ROOMS_CREATE_IP_PER_10MIN       = _env_int("RL_ROOMS_CREATE_IP_PER_10MIN", 30)
RL_ROOMS_CREATE_USER_PER_10MIN     = _env_int("RL_ROOMS_CREATE_USER_PER_10MIN", 20)
RL_ROOMS_DELETE_IP_PER_10MIN       = _env_int("RL_ROOMS_DELETE_IP_PER_10MIN", 30)
RL_ROOMS_DELETE_USER_PER_10MIN     = _env_int("RL_ROOMS_DELETE_USER_PER_10MIN", 20)
RL_ROOMS_RENAME_IP_PER_10MIN       = _env_int("RL_ROOMS_RENAME_IP_PER_10MIN", 60)
RL_ROOMS_RENAME_USER_PER_10MIN     = _env_int("RL_ROOMS_RENAME_USER_PER_10MIN", 30)
RL_ROOMS_META_IP_PER_10MIN         = _env_int("RL_ROOMS_META_IP_PER_10MIN", 120)
RL_ROOMS_META_USER_PER_10MIN       = _env_int("RL_ROOMS_META_USER_PER_10MIN", 60)
RL_ROOMS_PASSWORD_IP_PER_10MIN     = _env_int("RL_ROOMS_PASSWORD_IP_PER_10MIN", 60)
RL_ROOMS_PASSWORD_USER_PER_10MIN   = _env_int("RL_ROOMS_PASSWORD_USER_PER_10MIN", 30)
RL_ROOMS_PIN_IP_PER_10MIN          = _env_int("RL_ROOMS_PIN_IP_PER_10MIN", 120)
RL_ROOMS_PIN_USER_PER_10MIN        = _env_int("RL_ROOMS_PIN_USER_PER_10MIN", 60)
RL_ROOMS_LOGO_IP_PER_10MIN         = _env_int("RL_ROOMS_LOGO_IP_PER_10MIN", 30)
RL_ROOMS_LOGO_USER_PER_10MIN       = _env_int("RL_ROOMS_LOGO_USER_PER_10MIN", 20)
RL_UPLOAD_IP_PER_10MIN             = _env_int("RL_UPLOAD_IP_PER_10MIN", 60)
RL_UPLOAD_USER_PER_10MIN           = _env_int("RL_UPLOAD_USER_PER_10MIN", 40)
RL_DM_OPEN_IP_PER_10MIN            = _env_int("RL_DM_OPEN_IP_PER_10MIN", 120)
RL_DM_OPEN_USER_PER_10MIN          = _env_int("RL_DM_OPEN_USER_PER_10MIN", 60)
RL_DM_DELETE_IP_PER_10MIN          = _env_int("RL_DM_DELETE_IP_PER_10MIN", 60)
RL_DM_DELETE_USER_PER_10MIN        = _env_int("RL_DM_DELETE_USER_PER_10MIN", 30)
RL_DM_DELIVERY_SECRET_IP_PER_MIN   = _env_int("RL_DM_DELIVERY_SECRET_IP_PER_MIN", 60)
RL_DM_DELIVERY_SECRET_USER_PER_MIN = _env_int("RL_DM_DELIVERY_SECRET_USER_PER_MIN", 30)
RL_DELETE_ACCOUNT_IP_PER_HOUR      = _env_int("RL_DELETE_ACCOUNT_IP_PER_HOUR", 10)
RL_DELETE_ACCOUNT_USER_PER_HOUR    = _env_int("RL_DELETE_ACCOUNT_USER_PER_HOUR", 3)
RL_FRIENDS_REQ_IP_PER_10MIN        = _env_int("RL_FRIENDS_REQ_IP_PER_10MIN", 60)
RL_FRIENDS_REQ_USER_PER_10MIN      = _env_int("RL_FRIENDS_REQ_USER_PER_10MIN", 20)
RL_FRIENDS_ACTION_IP_PER_10MIN     = _env_int("RL_FRIENDS_ACTION_IP_PER_10MIN", 60)
RL_FRIENDS_ACTION_USER_PER_10MIN   = _env_int("RL_FRIENDS_ACTION_USER_PER_10MIN", 30)
RL_FRIENDS_LIST_IP_PER_10MIN       = _env_int("RL_FRIENDS_LIST_IP_PER_10MIN", 120)
RL_FRIENDS_LIST_USER_PER_10MIN     = _env_int("RL_FRIENDS_LIST_USER_PER_10MIN", 60)
RL_PROFILE_IP_PER_10MIN            = _env_int("RL_PROFILE_IP_PER_10MIN", 120)
RL_PROFILE_USER_PER_10MIN          = _env_int("RL_PROFILE_USER_PER_10MIN", 60)
RL_PROFILE_UPDATE_IP_PER_10MIN     = _env_int("RL_PROFILE_UPDATE_IP_PER_10MIN", 30)
RL_PROFILE_UPDATE_USER_PER_10MIN   = _env_int("RL_PROFILE_UPDATE_USER_PER_10MIN", 15)
FRIENDS_DECLINE_COOLDOWN_SEC       = _env_int("FRIENDS_DECLINE_COOLDOWN_SEC", 86400)  # 24h

MAX_WS_MSG_BYTES = _env_int("MAX_WS_MSG_BYTES", 32 * 1024)  # 32KB
MAX_ENCRYPTED_KEY_B64_LEN = _env_int("MAX_ENCRYPTED_KEY_B64_LEN", 16384)
MAX_PIN_URL_LEN = _env_int("MAX_PIN_URL_LEN", 2048)
MAX_PIN_TEXT_LEN = _env_int("MAX_PIN_TEXT_LEN", 4000)

for _name, _value in (
    ("MAX_ENCRYPTED_KEY_B64_LEN", MAX_ENCRYPTED_KEY_B64_LEN),
    ("MAX_PIN_URL_LEN", MAX_PIN_URL_LEN),
    ("MAX_PIN_TEXT_LEN", MAX_PIN_TEXT_LEN),
):
    if _value < 1:
        raise RuntimeError(f"{_name} must be >= 1")

async def enforce_http_rate_limit(key: str, limit: int, window_sec: int, detail: str = "Too Many Requests"):
    retry = await rate_limiter.check(key, limit=limit, window_sec=window_sec)
    if retry is not None:
        raise HTTPException(
            status_code=429,
            detail=detail,
            headers={"Retry-After": str(retry)},
        )

def _parse_cors_origins() -> list[str]:
    raw = (os.getenv("CORS_ORIGINS") or "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return []

CORS_ORIGINS = _parse_cors_origins()
# Origins allowed for WebSocket connections (same set, minus wildcard, plus chrome-extension prefix handled separately)
ALLOWED_ORIGINS: set[str] = {o for o in CORS_ORIGINS if o != "*"}
CORS_ALLOW_CREDENTIALS = (os.getenv("CORS_ALLOW_CREDENTIALS") or "0").strip().lower() in (
    "1", "true", "yes", "y", "on"
)

if CORS_ALLOW_CREDENTIALS and "*" in CORS_ORIGINS:
    raise RuntimeError("CORS misconfig: allow_credentials=true cannot be used with allow_origins=['*']")

if not CORS_ORIGINS:
    logging.getLogger(__name__).warning(
        "CORS_ORIGINS is not set — no web origins are allowed. "
        "Set CORS_ORIGINS in your environment (comma-separated URLs). "
        "Example: CORS_ORIGINS=https://your-domain.example"
    )

from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """ÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â·ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¹Ã¢â‚¬Â ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ Pydantic ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â² ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¹ ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡"""
    errors = exc.errors()
    if errors:
        
        first_error = errors[0]
        field = first_error.get("loc", ["", ""])[-1]
        msg = first_error.get("msg", "Invalid value")
        detail = f"{field}: {msg}" if field else msg
    else:
        detail = "Validation error"
    
    return JSONResponse(
        status_code=422,
        content={"detail": detail}
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["authorization", "content-type", "x-csrf-token"],
)

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_async_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
app.state.SessionLocal = SessionLocal
app.state.broadcast_notice = None  # {"message": str, "type": str, "updated_by": str} | None

APP_NAME     = os.getenv("APP_NAME", "WS Messenger")
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")

ARGON2_TYPE = (os.getenv("ARGON2_TYPE") or "ID").upper()
if ARGON2_TYPE not in {"ID", "I", "D"}:
    raise RuntimeError("ARGON2_TYPE must be one of: ID, I, D")

ARGON2_MEMORY_COST = _env_int("ARGON2_MEMORY_COST", 65536)  # 64 MiB
ARGON2_TIME_COST = _env_int("ARGON2_TIME_COST", 3)
ARGON2_PARALLELISM = _env_int("ARGON2_PARALLELISM", 2)
ARGON2_SALT_SIZE = _env_int("ARGON2_SALT_SIZE", 16)
ARGON2_HASH_LEN = _env_int("ARGON2_HASH_LEN", 32)

for _name, _value in (
    ("ARGON2_MEMORY_COST", ARGON2_MEMORY_COST),
    ("ARGON2_TIME_COST", ARGON2_TIME_COST),
    ("ARGON2_PARALLELISM", ARGON2_PARALLELISM),
    ("ARGON2_SALT_SIZE", ARGON2_SALT_SIZE),
    ("ARGON2_HASH_LEN", ARGON2_HASH_LEN),
):
    if _value < 1:
        raise RuntimeError(f"{_name} must be >= 1")

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__type=ARGON2_TYPE,
    argon2__memory_cost=ARGON2_MEMORY_COST,
    argon2__time_cost=ARGON2_TIME_COST,
    argon2__parallelism=ARGON2_PARALLELISM,
    argon2__salt_size=ARGON2_SALT_SIZE,
    argon2__hash_len=ARGON2_HASH_LEN,
)

JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "1440"))

# JWT rotation: short-lived access + long-lived refresh
ACCESS_TOKEN_EXPIRES_MIN = int(os.getenv("ACCESS_TOKEN_EXPIRES_MIN", "10"))
REFRESH_TOKEN_EXPIRES_MIN = int(os.getenv("REFRESH_TOKEN_EXPIRES_MIN", "10080"))  # 7 days

JWT_SECRETS_RAW = (os.getenv("JWT_SECRETS") or "").strip()
JWT_SECRET = (os.getenv("JWT_SECRET") or "").strip()
JWT_CURRENT_KID = (os.getenv("JWT_CURRENT_KID") or "").strip()


import sys

# --- Early CLI commands (must run before app/static mount) ---
if __name__ == "__main__" and len(sys.argv) >= 2:
    cmd = sys.argv[1]

    if cmd == "cleanup_ud_nonces":
        import asyncio
        from sqlalchemy import text

        days = int(sys.argv[2]) if len(sys.argv) >= 3 else 7

        async def _run():
            async with SessionLocal() as session:
                async with session.begin():
                    await session.execute(text("""
                        DELETE FROM chat_dm_ud_nonces
                        WHERE created_at < now() - (:days * interval '1 day')
                    """), {"days": days})

        asyncio.run(_run())
        raise SystemExit(0)
# ------------------------------------------------------------

if not JWT_SECRETS_RAW and not JWT_SECRET:
    raise RuntimeError("JWT_SECRET or JWT_SECRETS must be set")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password_and_rehash(password: str, password_hash: str) -> tuple[bool, str | None]:
    try:
        ok, replacement_hash = pwd_context.verify_and_update(password, password_hash)
        return bool(ok), replacement_hash
    except Exception:
        # Fail closed for malformed/legacy markers (e.g. system "deleted account").
        return False, None

def verify_password(password: str, password_hash: str) -> bool:
    ok, _ = verify_password_and_rehash(password, password_hash)
    return ok
    
async def verify_password_async(password: str, password_hash: str) -> bool:
    return verify_password(password, password_hash)

app.state.verify_password = verify_password_async
app.state.admin_dummy_hash = hash_password(secrets.token_urlsafe(32))

def get_password_kdf_runtime_config() -> dict:
    argon2_name = {
        "ID": "argon2id",
        "I": "argon2i",
        "D": "argon2d",
    }.get(ARGON2_TYPE, "argon2id")
    return {
        "scheme": "argon2",
        "variant": argon2_name,
        "memory_cost": ARGON2_MEMORY_COST,
        "time_cost": ARGON2_TIME_COST,
        "parallelism": ARGON2_PARALLELISM,
        "salt_size": ARGON2_SALT_SIZE,
        "hash_len": ARGON2_HASH_LEN,
        "rehash_on_login": True,
    }


def _parse_jwt_keyring(raw: str) -> dict[str, str]:
    ring: dict[str, str] = {}
    for part in [p.strip() for p in raw.split(",") if p.strip()]:
        if ":" not in part:
            continue
        kid, sec = part.split(":", 1)
        kid, sec = kid.strip(), sec.strip()
        if kid and sec:
            ring[kid] = sec
    return ring

JWT_KEYRING = _parse_jwt_keyring(JWT_SECRETS_RAW)

def _require_strong_secret(s: str) -> None:
    
    if not s or len(s) < 32:
        raise RuntimeError("JWT secret is too short. Set JWT_SECRETS or JWT_SECRET >= 32 chars.")

if JWT_KEYRING:
    if not JWT_CURRENT_KID:
        
        JWT_CURRENT_KID = next(iter(JWT_KEYRING.keys()))
    if JWT_CURRENT_KID not in JWT_KEYRING:
        raise RuntimeError("JWT_CURRENT_KID not found in JWT_SECRETS keyring.")
    
    for _kid, _sec in JWT_KEYRING.items():
        _require_strong_secret(_sec)
else:
    _require_strong_secret(JWT_SECRET)

def _jwt_signing_key_and_headers() -> tuple[str, dict]:
    if JWT_KEYRING:
        return JWT_KEYRING[JWT_CURRENT_KID], {"kid": JWT_CURRENT_KID}
    return JWT_SECRET, {}

def create_access_token(user_id: int, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "purpose": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_TOKEN_EXPIRES_MIN)).timestamp()),
    }
    key, headers = _jwt_signing_key_and_headers()
    return jwt.encode(payload, key, algorithm=JWT_ALG, headers=headers)


def create_refresh_token(user_id: int, username: str, family_id: str | None = None) -> tuple[str, str, str]:
    """Create a refresh token. Returns (token_str, jti, family_id)."""
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    fid = family_id or str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "username": username,
        "purpose": "refresh",
        "jti": jti,
        "fid": fid,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=REFRESH_TOKEN_EXPIRES_MIN)).timestamp()),
    }
    key, headers = _jwt_signing_key_and_headers()
    token = jwt.encode(payload, key, algorithm=JWT_ALG, headers=headers)
    return token, jti, fid


async def store_refresh_token(jti: str, user_id: int, family_id: str, expires_at: datetime):
    async with SessionLocal() as db:
        await db.execute(text("""
            INSERT INTO refresh_tokens (jti, user_id, family_id, expires_at)
            VALUES (:jti, :uid, :fid, :exp)
        """), {"jti": jti, "uid": user_id, "fid": family_id, "exp": expires_at})
        await db.commit()


async def revoke_refresh_token(jti: str, replaced_by: str | None = None):
    async with SessionLocal() as db:
        await db.execute(text("""
            UPDATE refresh_tokens
            SET revoked_at = now(), replaced_by = :rep
            WHERE jti = :jti AND revoked_at IS NULL
        """), {"jti": jti, "rep": replaced_by})
        await db.commit()


async def revoke_refresh_family(family_id: str):
    """Revoke ALL tokens in a rotation family â€” used on theft detection."""
    async with SessionLocal() as db:
        await db.execute(text("""
            UPDATE refresh_tokens
            SET revoked_at = now()
            WHERE family_id = :fid AND revoked_at IS NULL
        """), {"fid": family_id})
        await db.commit()


async def revoke_all_user_refresh_tokens(user_id: int):
    """Revoke ALL active refresh tokens for a user (logout-all)."""
    async with SessionLocal() as db:
        await db.execute(text("""
            UPDATE refresh_tokens
            SET revoked_at = now()
            WHERE user_id = :uid AND revoked_at IS NULL
        """), {"uid": user_id})
        await db.commit()

def decode_token(token: str) -> dict:
    try:
        hdr = jwt.get_unverified_header(token) or {}
    except Exception:
        hdr = {}

    # 1) keyring mode (rotation)
    if JWT_KEYRING:
        kid = (hdr.get("kid") or "").strip()
        
        if kid:
            key = JWT_KEYRING.get(kid)
            if not key:
                raise HTTPException(status_code=401, detail="Invalid token (unknown kid)")
            try:
                return jwt.decode(token, key, algorithms=[JWT_ALG])
            except JWTError:
                raise HTTPException(status_code=401, detail="Invalid token")
        
        if ALLOW_LEGACY_JWT_NO_KID and JWT_SECRET:
            try:
                return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            except JWTError:
                raise HTTPException(status_code=401, detail="Invalid token")

        raise HTTPException(status_code=401, detail="Invalid token (missing kid)")

    # 2) legacy mode
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_user_from_token(token: str) -> dict:
    payload = decode_token(token)

    # Reject non-access tokens (refresh, 2fa temp, etc.).
    # Legacy purpose-less tokens are disabled by default.
    purpose = payload.get("purpose")
    if purpose != "access":
        if not (purpose is None and ALLOW_LEGACY_ACCESS_NO_PURPOSE):
            raise HTTPException(status_code=401, detail="Invalid token (wrong purpose)")

    sub = payload.get("sub")
    if sub is None:
        raise HTTPException(status_code=401, detail="Invalid token (no sub)")

    try:
        user_id = int(sub)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token (bad sub)")

    username = (payload.get("username") or "").strip()
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token (no username)")

    return {
        "user_id": user_id,  # int
        "username": username,
    }

# ====================== TOTP 2FA ======================

TOTP_TEMP_TOKEN_EXPIRE_SEC = 300  # 5 min to enter TOTP code

def create_temp_token(user_id: int, username: str) -> str:
    """Short-lived JWT that proves password-OK but still needs 2FA."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "purpose": "2fa",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=TOTP_TEMP_TOKEN_EXPIRE_SEC)).timestamp()),
    }
    key, headers = _jwt_signing_key_and_headers()
    return jwt.encode(payload, key, algorithm=JWT_ALG, headers=headers)

def decode_temp_token(token: str) -> dict:
    """Decode temp_token; raises HTTPException if invalid or wrong purpose."""
    payload = decode_token(token)
    if payload.get("purpose") != "2fa":
        raise HTTPException(status_code=401, detail="Invalid temp token")
    return payload

def generate_totp_secret() -> str:
    return pyotp.random_base32(32)

def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # Ãƒâ€šÃ‚Â±30 sec

def generate_otpauth_uri(secret: str, username: str, issuer: str | None = None) -> str:
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer or APP_NAME)

def generate_qr_svg(data: str) -> str:
    """Generate QR code as inline SVG string. Returns empty string if qrcode lib not installed."""
    if not _HAS_QRCODE:
        return ""
    try:
        factory = qrcode.image.svg.SvgPathImage
        img = qrcode.make(data, image_factory=factory, box_size=8, border=2)
        buf = io.BytesIO()
        img.save(buf)
        svg = buf.getvalue().decode("utf-8")
        # Strip XML declaration if present
        if svg.startswith("<?xml"):
            svg = svg[svg.index("?>") + 2:].strip()
        return svg
    except Exception:
        return ""

def generate_backup_codes(count: int = 8) -> list[str]:
    """Generate one-time backup codes."""
    return [secrets.token_hex(4).upper() for _ in range(count)]

# Rate limits for TOTP
RL_TOTP_VERIFY_PER_MIN = _env_int("RL_TOTP_VERIFY_PER_MIN", 10)
RL_TOTP_SETUP_PER_10MIN = _env_int("RL_TOTP_SETUP_PER_10MIN", 5)

# Pydantic models for TOTP endpoints
class TotpVerifyLoginIn(BaseModel):
    temp_token: str
    code: str = Field(..., min_length=6, max_length=8)

class TotpSetupVerifyIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)

class TotpDisableIn(BaseModel):
    code: str = Field(default="", max_length=8)
    password: str = Field(default="", max_length=128)

ALIAS_ALPHABET = string.ascii_uppercase + string.digits

def generate_alias(length: int = 6) -> str:
    return "".join(secrets.choice(ALIAS_ALPHABET) for _ in range(length))

async def get_or_create_user_id(username: str) -> int:
    
    async with SessionLocal() as session:
        res = await session.execute(
            text("""
                INSERT INTO chat_users (username)
                VALUES (:u)
                ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
                RETURNING id
            """),
            {"u": username},
        )
        await session.commit()
        return int(res.scalar_one())

from sqlalchemy.exc import IntegrityError

async def create_room(
    owner_user_id: int,
    name: str,
    room_password: str | None,
    is_public: bool = False,
    is_readonly: bool = False,
) -> dict:
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Room name required")

    ph = hash_password(room_password) if (room_password and room_password.strip()) else None
    
    join_policy = "approval" if bool(is_public) else "invite_only"


    async with SessionLocal() as session:
        
        res = await session.execute(
            sql_i("""
                SELECT id, owner_user_id, name, alias, password_hash, is_public, is_readonly, join_policy, created_at
                FROM chat_rooms
                WHERE owner_user_id = :oid AND name = :name
            """, "oid"),
            {"oid": owner_user_id, "name": name},
        )
        existing = res.mappings().first()
        if existing:
            raise HTTPException(status_code=409, detail="Room with this name already exists for this user")
        
        for _ in range(20):
            alias = generate_alias(6)
            try:
                res = await session.execute(
                    sql_i("""
                        INSERT INTO chat_rooms (owner_user_id, name, alias, password_hash, is_public, is_readonly, join_policy)
                        VALUES (:oid, :name, :alias, :ph, :is_public, :is_readonly, :join_policy)
                        RETURNING id, owner_user_id, name, alias, password_hash, is_public, is_readonly, join_policy, created_at
                    """, "oid"),
                    {
                        "oid": owner_user_id,
                        "name": name,
                        "alias": alias,
                        "ph": ph,
                        "is_public": bool(is_public),
                        "is_readonly": bool(is_readonly),
                        "join_policy": join_policy,
                    },
                )

                room = dict(res.mappings().one())

                await session.execute(
                    sql_i("""
                        INSERT INTO chat_room_members (room_id, user_id, role, invited_by, status)
                        VALUES (:rid, :uid, 'owner', :uid, 'accepted')
                        ON CONFLICT (room_id, user_id) DO NOTHING
                    """, "rid", "uid"),
                    {"rid": room["id"], "uid": owner_user_id},
                )

                await session.commit()
                return room

            except IntegrityError as e:
                await session.rollback()
                
                diag = getattr(getattr(e, "orig", None), "diag", None)
                c = getattr(diag, "constraint_name", None)

                if c == "chat_rooms_alias_uq":
                    continue  # alias collision, retry

                if c == "chat_rooms_owner_name_uq":
                    raise HTTPException(status_code=409, detail="Room with this name already exists for this user")

                raise HTTPException(status_code=500, detail=f"Failed to create room: {c or 'integrity error'}")

        raise HTTPException(status_code=500, detail="Failed to create room (alias collisions)")

async def save_message_v3(room_id: int, user_id: int, text_msg: str):
    async with SessionLocal() as session:
        await session.execute(
            sql_i("""
                INSERT INTO chat_messages (room_id, user_id, text)
                VALUES (:room_id, :user_id, :text)
            """, "room_id", "user_id"),
            {"room_id": room_id, "user_id": user_id, "text": text_msg},
        )
        await session.commit()

class CsrfMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.method in SAFE_METHODS:
            return await call_next(request)

        origin = request.headers.get("origin")
        cookie = request.headers.get("cookie") or ""

        has_csrf_cookie = "csrf_token=" in cookie  
        
        if has_csrf_cookie:
            if origin and origin not in CORS_ORIGINS:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF blocked (bad origin)"},
                )

            csrf_h = (request.headers.get("x-csrf-token") or "").strip()
            csrf_c = request.cookies.get("csrf_token") or ""
            if not csrf_h or csrf_h != csrf_c:
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF blocked"},
                )

        return await call_next(request)


app.add_middleware(CsrfMiddleware)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ security headers ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼"""
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
                
        response.headers["X-Frame-Options"] = "DENY"
                
        response.headers["X-Content-Type-Options"] = "nosniff"
                
        response.headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions policy
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        # Content Security Policy
        _csp_ws = ""
        if APP_BASE_URL:
            _app_wss = APP_BASE_URL.replace("https://", "wss://").replace("http://", "ws://")
            _csp_ws = f" {_app_wss}"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            f"connect-src 'self'{_csp_ws}; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        
        if ENV == "prod":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        return response

app.add_middleware(SecurityHeadersMiddleware)

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)
    password: str = Field(..., min_length=1, max_length=128)

class LoginResponse(BaseModel):
    token: str

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32, pattern=r'^[a-zA-Z][a-zA-Z0-9_]*$')
    password: str = Field(..., min_length=8, max_length=128)
    public_key: str | None = None
    recovery_key_hash: str | None = None        # hex SHA-256(HKDF recovery_auth bytes)

class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str
    
class RoomCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    password: str | None = Field(None, max_length=128)
    encrypted_room_key: str | None = Field(None, max_length=MAX_ENCRYPTED_KEY_B64_LEN)
    is_public: bool = False
    is_readonly: bool = False

class RoomJoinRequestIn(BaseModel):
    password: str | None = None

class RoomJoinResolveOut(BaseModel):
    id: int
    alias: str
    name: str
    owner_user_id: int
    has_password: bool
    is_public: bool = False
    is_readonly: bool = False

class RoomPinIn(BaseModel):
    url: str | None = Field(None, max_length=MAX_PIN_URL_LEN)
    text: str | None = Field(None, max_length=MAX_PIN_TEXT_LEN)
    
class RoomInviteIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)

class RoomKickIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)

class FriendRequestIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)

class FriendRequestActionIn(BaseModel):
    username: str
    
class RoomKeyIn(BaseModel):
    room_id: int
    encrypted_room_key: str = Field(..., max_length=MAX_ENCRYPTED_KEY_B64_LEN)
    key_id: str | None = None

class RoomKeyShareIn(BaseModel):
    encrypted_room_key: str = Field(..., max_length=MAX_ENCRYPTED_KEY_B64_LEN)
    key_id: str | None = None

class DmOpenIn(BaseModel):
    username: str

class DmDeleteIn(BaseModel):
    scope: str = Field("self", pattern=r"^(self|both)$")

class DmKeyIn(BaseModel):
    thread_id: int
    encrypted_thread_key: str = Field(..., max_length=MAX_ENCRYPTED_KEY_B64_LEN)
    key_id: str | None = None

class DmKeyShareIn(BaseModel):
    username: str
    encrypted_thread_key: str = Field(..., max_length=MAX_ENCRYPTED_KEY_B64_LEN)
    key_id: str | None = None

class Ed25519KeyIn(BaseModel):
    public_key: str = Field(..., max_length=64)  # base64-encoded 32-byte Ed25519 pubkey
    
class RoomMetaOut(BaseModel):
    room_id: int
    description: str = ""
    has_logo: bool = False
    logo_url: str | None = None
    is_readonly: bool = False
    updated_at: str | None = None  # isoformat

class RoomMetaIn(BaseModel):
    description: str = Field("", max_length=2000)

from typing import Any, Dict

class PrivacySettings(BaseModel):
    allow_group_invites_from_non_friends: bool = False
    allow_dm_from_non_friends: bool = False

class ProfilePublic(BaseModel):
    username: str
    about: str = ""

class ProfileMe(ProfilePublic):
    privacy: PrivacySettings

class ProfileUpdate(BaseModel):
    about: str = Field("", max_length=360)
    privacy: PrivacySettings | None = None

DEFAULT_PRIVACY = {
    "allow_group_invites_from_non_friends": False,
    "allow_dm_from_non_friends": False,
}

# ====================== Recovery nonce store (DB-backed, single-use) ======================
# Stored in users.recovery_nonce + users.recovery_nonce_expires (DOUBLE PRECISION).
# Migration: ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_nonce TEXT;
#            ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_nonce_expires DOUBLE PRECISION;
# TTL = 5 minutes. Works correctly with multiple uvicorn workers.

RECOVER_NONCE_TTL = 300  # seconds

async def _recovery_nonce_set(username: str) -> str:
    nonce = secrets.token_hex(32)
    expires_at = time.time() + RECOVER_NONCE_TTL
    async with SessionLocal() as db:
        res = await db.execute(
            text("""
                UPDATE users
                SET recovery_nonce = :nonce, recovery_nonce_expires = :exp
                WHERE LOWER(username) = LOWER(:u)
            """),
            {"nonce": nonce, "exp": expires_at, "u": username},
        )
        await db.commit()
        rows_updated = res.rowcount
    _rlog = logging.getLogger("uvicorn.error")
    _rlog.info("[recovery] nonce_set username=%r rows_updated=%d", username, rows_updated)
    if rows_updated == 0:
        _rlog.warning("[recovery] nonce_set UPDATE matched 0 rows for username=%r", username)
    return nonce

async def _recovery_nonce_consume(username: str, nonce: str) -> bool:
    """Fetch, verify, and delete nonce atomically. Returns True if valid."""
    _rlog = logging.getLogger("uvicorn.error")
    async with SessionLocal() as db:
        # FOR UPDATE prevents a concurrent request from reading the same
        # nonce before we clear it — guarantees single-use.
        res = await db.execute(
            text("""
                SELECT recovery_nonce, recovery_nonce_expires
                FROM users
                WHERE LOWER(username) = LOWER(:u)
                LIMIT 1
                FOR UPDATE
            """),
            {"u": username},
        )
        row = res.mappings().first()
        _rlog.info(
            "[recovery] nonce_consume username=%r row_found=%s stored_nonce_present=%s",
            username,
            row is not None,
            bool(row and row["recovery_nonce"]) if row else False,
        )
        if not row or not row["recovery_nonce"]:
            return False

        stored_nonce = row["recovery_nonce"]
        expires_at   = row["recovery_nonce_expires"] or 0.0

        # Always clear the nonce (consumed or expired) to prevent reuse
        await db.execute(
            text("""
                UPDATE users
                SET recovery_nonce = NULL, recovery_nonce_expires = NULL
                WHERE LOWER(username) = LOWER(:u)
            """),
            {"u": username},
        )
        await db.commit()

    now = time.time()
    _rlog.info("[recovery] nonce_consume expires_at=%s now=%s expired=%s match=%s",
               expires_at, now, now > expires_at,
               hmac.compare_digest(stored_nonce, nonce))
    if now > expires_at:
        return False
    return hmac.compare_digest(stored_nonce, nonce)


class RecoverStartIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)

class RecoverIn(BaseModel):
    username: str = Field(..., min_length=1, max_length=32)
    nonce: str
    recovery_auth_b64: str
    new_password: str = Field(..., min_length=8, max_length=128)


_KEY_ARCHIVE_TABLES_READY = False
_KEY_ARCHIVE_TABLES_LOCK = asyncio.Lock()
_CHAT_FILES_DM_READY = False
_CHAT_FILES_DM_LOCK = asyncio.Lock()
_DM_DELETE_REQ_READY = False
_DM_DELETE_REQ_LOCK = asyncio.Lock()
_ED25519_SUPPORT_READY = False
_ED25519_SUPPORT_LOCK = asyncio.Lock()

def _normalize_key_id(key_id: str | None) -> str | None:
    if key_id is None:
        return None
    kid = str(key_id).strip().lower()
    if not kid:
        return None
    if len(kid) > 64:
        raise HTTPException(status_code=400, detail="key_id too long")
    if not all(c in "0123456789abcdef" for c in kid):
        raise HTTPException(status_code=400, detail="key_id must be lowercase hex")
    return kid

async def _ensure_key_archive_tables(session: AsyncSession) -> None:
    global _KEY_ARCHIVE_TABLES_READY
    if _KEY_ARCHIVE_TABLES_READY:
        return
    async with _KEY_ARCHIVE_TABLES_LOCK:
        if _KEY_ARCHIVE_TABLES_READY:
            return
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS chat_room_key_archive (
                room_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                key_id VARCHAR(64) NOT NULL,
                encrypted_room_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (room_id, user_id, key_id)
            )
        """))
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS chat_dm_key_archive (
                thread_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                key_id VARCHAR(64) NOT NULL,
                encrypted_thread_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (thread_id, user_id, key_id)
            )
        """))
        await session.commit()
        _KEY_ARCHIVE_TABLES_READY = True

async def _ensure_ed25519_support(session: AsyncSession) -> None:
    """Migrate chat_user_keys to allow alg='ed25519' alongside 'x25519'."""
    global _ED25519_SUPPORT_READY
    if _ED25519_SUPPORT_READY:
        return
    async with _ED25519_SUPPORT_LOCK:
        if _ED25519_SUPPORT_READY:
            return
        # Check current constraint definition; only migrate if 'ed25519' is absent.
        res = await session.execute(text("""
            SELECT pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            WHERE t.relname = 'chat_user_keys' AND c.conname = 'chat_user_keys_alg_chk'
        """))
        row = res.first()
        if row and 'ed25519' not in row[0]:
            await session.execute(text(
                "ALTER TABLE chat_user_keys DROP CONSTRAINT chat_user_keys_alg_chk"
            ))
            await session.execute(text(
                "ALTER TABLE chat_user_keys ADD CONSTRAINT chat_user_keys_alg_chk "
                "CHECK (alg IN ('x25519', 'ed25519'))"
            ))
            await session.commit()
        _ED25519_SUPPORT_READY = True

async def _ensure_chat_files_dm_support(session: AsyncSession) -> None:
    global _CHAT_FILES_DM_READY
    if _CHAT_FILES_DM_READY:
        return
    async with _CHAT_FILES_DM_LOCK:
        if _CHAT_FILES_DM_READY:
            return
        await session.execute(text("""
            ALTER TABLE chat_files
            ADD COLUMN IF NOT EXISTS thread_id BIGINT NULL
        """))
        await session.execute(text("""
            ALTER TABLE chat_files
            ADD COLUMN IF NOT EXISTS room_id BIGINT NULL
        """))
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_chat_files_thread_id ON chat_files(thread_id)
        """))
        await session.execute(text("""
            ALTER TABLE chat_files
            ALTER COLUMN room_id DROP NOT NULL
        """))
        await session.commit()
        _CHAT_FILES_DM_READY = True

async def _ensure_dm_delete_requests_table(session: AsyncSession) -> None:
    global _DM_DELETE_REQ_READY
    if _DM_DELETE_REQ_READY:
        return
    async with _DM_DELETE_REQ_LOCK:
        if _DM_DELETE_REQ_READY:
            return
        await session.execute(text("""
            CREATE TABLE IF NOT EXISTS chat_dm_delete_requests (
                thread_id BIGINT NOT NULL,
                requester_id BIGINT NOT NULL,
                scope VARCHAR(16) NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (thread_id, requester_id)
            )
        """))
        await session.execute(text("""
            CREATE INDEX IF NOT EXISTS idx_dm_delete_requests_exp
            ON chat_dm_delete_requests(expires_at)
        """))
        await session.commit()
        _DM_DELETE_REQ_READY = True

async def _purge_orphan_dm_thread_files(session: AsyncSession) -> int:
    """
    Remove files bound to DM threads that no longer have members.
    Returns number of deleted file rows.
    """
    await _ensure_chat_files_dm_support(session)
    res = await session.execute(text("""
        DELETE FROM chat_files f
        WHERE f.thread_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM chat_dm_members m
              WHERE m.thread_id = f.thread_id
          )
        RETURNING f.storage_path
    """))
    rows = res.mappings().all()
    deleted = 0
    for row in rows:
        deleted += 1
        path = (row.get("storage_path") or "").strip()
        if not path:
            continue
        try:
            p = Path(path).resolve()
            _assert_within_dir(p, UPLOAD_DIR)
            if p.exists():
                p.unlink()
        except Exception:
            pass
    return deleted

async def _delete_dm_files_for_thread(session: AsyncSession, thread_id: int) -> int:
    await _ensure_chat_files_dm_support(session)
    res = await session.execute(text("""
        DELETE FROM chat_files
        WHERE thread_id = :tid
        RETURNING storage_path
    """), {"tid": int(thread_id)})
    rows = res.mappings().all()
    deleted = 0
    for row in rows:
        deleted += 1
        path = (row.get("storage_path") or "").strip()
        if not path:
            continue
        try:
            p = Path(path).resolve()
            _assert_within_dir(p, UPLOAD_DIR)
            if p.exists():
                p.unlink()
        except Exception:
            pass
    return deleted


async def _rotate_dm_delivery_secret(session: AsyncSession, thread_id: int) -> None:
    await session.execute(text("""
        INSERT INTO chat_dm_delivery(thread_id, delivery_secret, expires_at)
        VALUES (:tid, :secret, NOW() + INTERVAL '24 hours')
        ON CONFLICT (thread_id)
        DO UPDATE SET delivery_secret = EXCLUDED.delivery_secret,
                      expires_at = EXCLUDED.expires_at
    """), {"tid": int(thread_id), "secret": secrets.token_bytes(32)})


class ConnectionManager:
    def __init__(self):
        self.rooms = {}   # room -> set[ws]
        self.users = {}   # ws -> username
        self.online = {}  # room -> set[username]

    def connect(self, room, ws, username):
        room = str(room)
        self.rooms.setdefault(room, set()).add(ws)
        self.users[ws] = username
        self.online.setdefault(room, set()).add(username)

    def disconnect(self, room, ws):
        room = str(room)
                
        if room in self.rooms:
            self.rooms[room].discard(ws)
            if not self.rooms[room]:
                del self.rooms[room]
        
        username = self.users.pop(ws, None)
        if username:
            still_here = any(
                (w in self.rooms.get(room, set()) and self.users.get(w) == username)
                for w in self.rooms.get(room, set())
            )
            if not still_here:
                s = self.online.get(room)
                if s:
                    s.discard(username)
                    if not s:
                        del self.online[room]

    def get_online(self, room):
        return sorted(self.online.get(str(room), set()))

    async def broadcast(self, room, message):
        room = str(room)
        for ws in list(self.rooms.get(room, set())):
            try:
                await ws.send_json(message)
            except Exception:
                
                self.disconnect(room, ws)

    async def kick_user(self, room, username: str, code: int = 1008, reason: str = "kicked"):
        room = str(room)
        uname = str(username or "").strip().lower()
        targets = [
            ws
            for ws in list(self.rooms.get(room, set()))
            if str(self.users.get(ws) or "").strip().lower() == uname
        ]

        for ws in targets:
            try:
                await ws.close(code=code, reason=reason)
            except Exception:
                pass
            finally:
                self.disconnect(room, ws)

    async def kick_user_everywhere(self, username: str, code: int = 1008, reason: str = "kicked"):
        uname = str(username or "").strip()
        if not uname:
            return
        for room in list(self.rooms.keys()):
            await self.kick_user(room, uname, code=code, reason=reason)

from pydantic import BaseModel
from typing import Any, Dict

from pydantic import BaseModel, Field

class KeyPublishIn(BaseModel):
    kid: str
    public_key: str
    alg: str = "x25519"

def _normalize_privacy(v) -> dict:
    if not v:
        return dict(DEFAULT_PRIVACY)
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except Exception:
            return dict(DEFAULT_PRIVACY)
    if not isinstance(v, dict):
        return dict(DEFAULT_PRIVACY)

    out = dict(DEFAULT_PRIVACY)
    for k in out.keys():
        if k in v:
            out[k] = bool(v[k])
    return out

async def get_profile_row(session: AsyncSession, user_id: int) -> dict:
    res = await session.execute(sql_i("""
        SELECT user_id, about, privacy
        FROM chat_user_profiles
        WHERE user_id = :uid
    """, "uid"), {"uid": int(user_id)})
    row = res.mappings().first()
    if row:
        return {
            "user_id": int(row["user_id"]),
            "about": row.get("about") or "",
            "privacy": _normalize_privacy(row.get("privacy")),
        }
    
    await session.execute(sql_i("""
        INSERT INTO chat_user_profiles(user_id, about, privacy)
        VALUES (:uid, '', CAST(:privacy AS jsonb))
        ON CONFLICT (user_id) DO NOTHING
    """, "uid"), {"uid": int(user_id), "privacy": json.dumps(DEFAULT_PRIVACY)})
    
    res2 = await session.execute(sql_i("""
        SELECT user_id, about, privacy
        FROM chat_user_profiles
        WHERE user_id = :uid
    """, "uid"), {"uid": int(user_id)})
    row2 = res2.mappings().first()
    if row2:
        return {
            "user_id": int(row2["user_id"]),
            "about": row2.get("about") or "",
            "privacy": _normalize_privacy(row2.get("privacy")),
        }
    
    return {"user_id": int(user_id), "about": "", "privacy": dict(DEFAULT_PRIVACY)}

async def are_friends(session: AsyncSession, a: int, b: int) -> bool:
    res = await session.execute(text("""
        SELECT 1
        FROM chat_friendships f
        WHERE (
          (f.requester_id=:a AND f.addressee_id=:b)
          OR
          (f.requester_id=:b AND f.addressee_id=:a)
        ) AND f.status='accepted'
        LIMIT 1
    """), {"a": int(a), "b": int(b)})
    return res.scalar_one_or_none() is not None

MAX_ROOM_LOGO_BYTES = 5 * 1024 * 1024
ROOM_LOGO_DIR = (UPLOAD_DIR / "room_logos").resolve()
ROOM_LOGO_DIR.mkdir(parents=True, exist_ok=True)


async def _purge_room_storage_files(session: AsyncSession, room_id: int) -> None:
    """
    Delete on-disk artefacts (chat_files contents + room logos) for a room.
    Callers remain responsible for the DB row deletions.
    """
    try:
        res = await session.execute(
            sql_i("SELECT storage_path FROM chat_files WHERE room_id = :rid", "rid"),
            {"rid": int(room_id)},
        )
        paths = [str(p) for p in res.scalars().all() if p]
    except Exception:
        paths = []

    for p in paths:
        try:
            path = Path(p).resolve()
            path.relative_to(UPLOAD_DIR.resolve())
        except Exception:
            continue
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass

    for ext in (".png", ".jpg", ".webp"):
        logo_path = ROOM_LOGO_DIR / f"room_{int(room_id)}{ext}"
        try:
            if logo_path.exists():
                logo_path.unlink()
        except Exception:
            pass

def _assert_within_dir(path: Path, base_dir: Path) -> None:
    
    try:
        path.resolve().relative_to(base_dir.resolve())
    except Exception:
        raise HTTPException(status_code=400, detail="Bad path")

def _sniff_image_ext(first_bytes: bytes) -> str | None:
    # PNG
    if first_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    # JPEG
    if first_bytes.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    # WEBP: RIFF....WEBP
    if len(first_bytes) >= 12 and first_bytes[0:4] == b"RIFF" and first_bytes[8:12] == b"WEBP":
        return ".webp"
    return None

def _logo_ext_from_content_type(ct: str | None) -> str:
    ct = (ct or "").lower()
    if ct == "image/png": return ".png"
    if ct in ("image/jpeg", "image/jpg"): return ".jpg"
    if ct == "image/webp": return ".webp"
    
    return ""

manager = ConnectionManager()


# ---------------------------------------------------------------------------
# NotifyManager — per-user WebSocket fan-out for /ws-notify
# ---------------------------------------------------------------------------
class NotifyManager:
    """Maps user_id → set[WebSocket] for the notification channel."""

    def __init__(self):
        self.connections: dict[int, set] = {}          # user_id -> set[ws]
        self.user_ids: dict[object, int] = {}          # ws -> user_id

    def connect(self, user_id: int, ws):
        self.connections.setdefault(user_id, set()).add(ws)
        self.user_ids[ws] = user_id

    def disconnect(self, ws):
        uid = self.user_ids.pop(ws, None)
        if uid is not None:
            s = self.connections.get(uid)
            if s:
                s.discard(ws)
                if not s:
                    del self.connections[uid]

    async def notify(self, user_id: int, payload: dict):
        for ws in list(self.connections.get(user_id, [])):
            try:
                await ws.send_json(payload)
            except Exception:
                self.disconnect(ws)

    async def notify_many(self, user_ids, payload: dict):
        for uid in user_ids:
            await self.notify(uid, payload)

    async def kick_user(self, user_id: int, code: int = 1008, reason: str = "session revoked"):
        """Close all /ws-notify sockets for the given user_id."""
        try:
            uid = int(user_id)
        except Exception:
            return
        for ws in list(self.connections.get(uid, [])):
            try:
                await ws.close(code=code, reason=reason)
            except Exception:
                pass
            finally:
                self.disconnect(ws)


notify_manager = NotifyManager()


def validate_token(token: str) -> str:
    try:
        user = get_user_from_token(token)
        return user["username"] or f"user_{user['user_id']}"
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def require_user_from_bearer(authorization: str | None) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    try:
        u = get_user_from_token(token)
        return {"user_id": int(u["user_id"]), "username": u["username"]}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.middleware("http")
async def ban_guard_middleware(request: Request, call_next):
    """
    Block banned users for any HTTP endpoint accessed with a valid Bearer token.
    Invalid/missing tokens are left to endpoint-level auth checks.
    """
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1].strip()
        if token:
            try:
                u = get_user_from_token(token)
            except Exception:
                u = None
            if u:
                async with SessionLocal() as session:
                    banned, reason = await _fetch_user_ban_state(session, int(u["user_id"]))
                if banned:
                    detail = "User is banned" + (f": {reason}" if reason else "")
                    return JSONResponse(
                        status_code=403,
                        content={
                            "detail": detail,
                            "reason": "banned",
                            "ban_reason": reason or "",
                            "message": detail,
                        },
                    )
    return await call_next(request)



class UserBannedError(HTTPException):
    def __init__(self, reason: str | None = None):
        detail = "User is banned"
        if reason:
            detail = f"User is banned: {reason}"
        super().__init__(status_code=403, detail=detail)

# --- Ban state cache (in-memory, per worker) ---
# Cuts DB load significantly even without Redis.
BAN_CACHE_TTL = float(os.getenv("BAN_CACHE_TTL", "15"))  # seconds
# user_id -> (expires_at_epoch, banned_bool, reason_or_none)
_BAN_STATE_CACHE: dict[int, tuple[float, bool, str | None]] = {}

def _ban_cache_get(user_id: int) -> tuple[bool, str | None] | None:
    item = _BAN_STATE_CACHE.get(int(user_id))
    if not item:
        return None
    exp, banned, reason = item
    if exp <= time.time():
        _BAN_STATE_CACHE.pop(int(user_id), None)
        return None
    return banned, reason

def _ban_cache_set(user_id: int, banned: bool, reason: str | None) -> None:
    _BAN_STATE_CACHE[int(user_id)] = (time.time() + BAN_CACHE_TTL, bool(banned), reason)

def ban_cache_invalidate(user_id: int | None = None) -> None:
    """Invalidate ban cache for one user (or all users if None)."""
    if user_id is None:
        _BAN_STATE_CACHE.clear()
    else:
        _BAN_STATE_CACHE.pop(int(user_id), None)

async def _fetch_user_ban_state_db(session, user_id: int) -> tuple[bool, str | None]:
    r = await session.execute(
        sql_i("SELECT is_banned, banned_reason FROM users WHERE id=:uid LIMIT 1", "uid"),
        {"uid": int(user_id)},
    )
    row = r.mappings().first()
    if not row:
        # Treat deleted/missing user as invalid for any bearer-authenticated flow.
        return True, "account deleted"
    return bool(row.get("is_banned") or False), (row.get("banned_reason") or None)

async def _fetch_user_ban_state(session, user_id: int) -> tuple[bool, str | None]:
    cached = _ban_cache_get(int(user_id))
    if cached is not None:
        return cached
    banned, reason = await _fetch_user_ban_state_db(session, int(user_id))
    _ban_cache_set(int(user_id), banned, reason)
    return banned, reason

# --- WS ban checker helper (shared for /ws and /ws-dm) ---

def _make_ws_ban_checker(ws: WebSocket, user_id: int, interval: float = 10.0):
    """
    Returns async function check(force=False)->bool.
    Uses in-memory interval throttling per connection + existing ban cache (_fetch_user_ban_state).
    """
    _last_ban_check = 0.0

    async def _check_ban_maybe(force: bool = False) -> bool:
        nonlocal _last_ban_check
        now = time.time()
        if (not force) and (now - _last_ban_check) < float(interval):
            return True
        _last_ban_check = now

        async with SessionLocal() as _s:
            banned, reason = await _fetch_user_ban_state(_s, int(user_id))

        if not banned:
            return True

        # best-effort notify + close (same semantics as your current closure)
        try:
            await ws.send_json({
                "type": "auth_state",
                "loggedIn": False,
                "reason": "banned",
                "ban_reason": reason or "",
                "message": ("User is banned" + (f": {reason}" if reason else "")),
            })
            try:
                await ws.send_json({
                    "type": "banned",
                    "ban_reason": reason or "",
                    "message": ("User is banned" + (f": {reason}" if reason else "")),
                })
            except Exception:
                pass
        except Exception:
            pass

        try:
            close_reason = ("banned" + (f": {reason}" if reason else ""))[:120]
            await ws.close(code=1008, reason=close_reason)
        finally:
            return False

    return _check_ban_maybe

async def ensure_not_banned(session, user_id: int) -> None:
    banned, reason = await _fetch_user_ban_state(session, int(user_id))
    if banned:
        raise UserBannedError(reason)


# --- Access-token revocation via per-user "tokens_valid_after" watermark -----
# JWT access tokens are stateless: once issued, they remain valid until `exp`.
# logout-all / account deletion only revokes refresh tokens, so WS sessions
# bound to an already-issued access token could keep receiving broadcasts.
# We store a monotonic `tokens_valid_after` epoch on the user row; any access
# token with `iat < tokens_valid_after` is treated as revoked.
_TOKENS_VALID_AFTER_CACHE: dict[int, tuple[float, float]] = {}
TOKENS_VALID_AFTER_CACHE_TTL = 10.0  # seconds
_TVA_MIGRATION_READY = False
_TVA_MIGRATION_LOCK = asyncio.Lock()


async def _ensure_tokens_valid_after_column(session: AsyncSession) -> None:
    global _TVA_MIGRATION_READY
    if _TVA_MIGRATION_READY:
        return
    async with _TVA_MIGRATION_LOCK:
        if _TVA_MIGRATION_READY:
            return
        try:
            await session.execute(text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS tokens_valid_after DOUBLE PRECISION"
            ))
            await session.commit()
        except Exception:
            pass
        _TVA_MIGRATION_READY = True


def _tva_cache_get(user_id: int) -> float | None:
    item = _TOKENS_VALID_AFTER_CACHE.get(int(user_id))
    if not item:
        return None
    exp, val = item
    if exp <= time.time():
        _TOKENS_VALID_AFTER_CACHE.pop(int(user_id), None)
        return None
    return val


def _tva_cache_set(user_id: int, val: float) -> None:
    _TOKENS_VALID_AFTER_CACHE[int(user_id)] = (
        time.time() + TOKENS_VALID_AFTER_CACHE_TTL,
        float(val or 0.0),
    )


def tokens_valid_after_invalidate(user_id: int | None = None) -> None:
    if user_id is None:
        _TOKENS_VALID_AFTER_CACHE.clear()
    else:
        _TOKENS_VALID_AFTER_CACHE.pop(int(user_id), None)


async def _fetch_tokens_valid_after(session, user_id: int) -> float:
    cached = _tva_cache_get(int(user_id))
    if cached is not None:
        return cached
    await _ensure_tokens_valid_after_column(session)
    r = await session.execute(
        sql_i("SELECT tokens_valid_after FROM users WHERE id=:uid LIMIT 1", "uid"),
        {"uid": int(user_id)},
    )
    row = r.mappings().first()
    val = float((row and row.get("tokens_valid_after")) or 0.0)
    _tva_cache_set(int(user_id), val)
    return val


async def bump_tokens_valid_after(user_id: int) -> float:
    """Mark all access tokens for this user (iat < now) as revoked."""
    now_ts = time.time()
    async with SessionLocal() as s:
        await _ensure_tokens_valid_after_column(s)
        await s.execute(
            sql_i(
                "UPDATE users SET tokens_valid_after = :t WHERE id = :uid",
                "uid",
            ),
            {"uid": int(user_id), "t": now_ts},
        )
        await s.commit()
    _tva_cache_set(int(user_id), now_ts)
    return now_ts


def _token_iat(payload: dict) -> float:
    try:
        return float(payload.get("iat") or 0.0)
    except Exception:
        return 0.0


async def _is_token_revoked(user_id: int, iat: float) -> bool:
    async with SessionLocal() as s:
        valid_after = await _fetch_tokens_valid_after(s, int(user_id))
    return float(iat or 0.0) < valid_after

ROLE_OWNER = "owner"
ROLE_ADMIN = "admin"
ROLE_MEMBER = "member"
VALID_ROLES = {ROLE_OWNER, ROLE_ADMIN, ROLE_MEMBER}
LEGACY_ROOM_ROLE_ALIASES = {
    "moderator": ROLE_MEMBER,
}

def _normalize_room_role_value(value: str | None) -> str | None:
    role = str(value or ROLE_MEMBER).strip().lower()
    role = LEGACY_ROOM_ROLE_ALIASES.get(role, role)
    if role not in VALID_ROLES:
        return None
    return role

async def get_room_role(session, room_id: int, user_id: int) -> str | None:
    # Canonical owner fallback from rooms table (protects from member-role drift).
    own = await session.execute(
        sql_i("""
            SELECT 1
            FROM chat_rooms
            WHERE id = :rid AND owner_user_id = :uid
            LIMIT 1
        """, "rid", "uid"),
        {"rid": int(room_id), "uid": int(user_id)},
    )
    if own.scalar_one_or_none():
        return ROLE_OWNER

    r = await session.execute(
        sql_i("""
            SELECT role
            FROM chat_room_members
            WHERE room_id=:rid
              AND user_id=:uid
              AND status='accepted'
            LIMIT 1
        """, "rid", "uid"),
        {"rid": int(room_id), "uid": int(user_id)},
    )
    row = r.mappings().first()
    if not row:
        return None

    role = _normalize_room_role_value(row.get("role"))
    if role is None:
        return None

    return role

async def require_room_role(
    session,
    room_id: int,
    user_id: int,
    allowed: tuple[str, ...],
    *,
    require_accepted: bool = True,
) -> str:
    q = """
        SELECT role
        FROM chat_room_members
        WHERE room_id=:rid AND user_id=:uid
    """
    if require_accepted:
        q += " AND status='accepted'"
    q += " LIMIT 1"

    r = await session.execute(sql_i(q, "rid", "uid"), {"rid": int(room_id), "uid": int(user_id)})
    row = r.mappings().first()
    if not row:
        raise HTTPException(status_code=403, detail="Not a room member")

    role = _normalize_room_role_value(row.get("role"))
    if role is None:
        raise HTTPException(status_code=403, detail="Invalid member role")
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient role")
    return role

async def is_owner(session, room_id: int, user_id: int) -> bool:
    r = await session.execute(
        sql_i("""
            SELECT 1
            FROM chat_room_members
            WHERE room_id=:rid
              AND user_id=:uid
              AND status='accepted'
              AND role='owner'
            LIMIT 1
        """, "rid", "uid"),
        {"rid": int(room_id), "uid": int(user_id)},
    )
    return r.scalar_one_or_none() is not None

async def require_room_moderator(session, room_id: int, user_id: int) -> str:
    role = await get_room_role(session, room_id, user_id)
    if role not in (ROLE_OWNER, ROLE_ADMIN):
        raise HTTPException(status_code=403, detail="Moderator access required")
    return role


async def require_room_owner_only(session, room_id: int, user_id: int) -> None:
    # Prefer canonical owner source first.
    own = await session.execute(
        sql_i("""
            SELECT 1
            FROM chat_rooms
            WHERE id=:rid AND owner_user_id=:uid
            LIMIT 1
        """, "rid", "uid"),
        {"rid": int(room_id), "uid": int(user_id)},
    )
    if own.scalar_one_or_none():
        return

    role = await get_room_role(session, room_id, user_id)
    if role is None:
        
        r = await session.execute(
            sql_i("SELECT 1 FROM chat_rooms WHERE id=:rid", "rid"),
            {"rid": int(room_id)},
        )
        exists = r.scalar_one_or_none()
        if not exists:
            raise HTTPException(status_code=404, detail="Room not found")
        raise HTTPException(status_code=403, detail="Owner access required")

    if role != ROLE_OWNER:
        raise HTTPException(status_code=403, detail="Owner access required")


async def require_room_access(session: AsyncSession, room_id: int, user_id: int) -> None:
    room_id = int(room_id)
    user_id = int(user_id)

    res = await session.execute(sql_i("""
        SELECT 1
        FROM (
          SELECT 1
          FROM chat_rooms r
          WHERE r.id = :rid AND r.owner_user_id = :uid

          UNION

          SELECT 1
          FROM chat_room_members m
          WHERE m.room_id = :rid
            AND m.user_id = :uid
            AND m.status = 'accepted'
        ) x
        LIMIT 1
    """, "rid", "uid"), {"rid": room_id, "uid": user_id})

    if not res.scalar_one_or_none():
        
        raise HTTPException(status_code=404, detail="Not found")

async def require_room_owner(session: AsyncSession, room_id: int, user_id: int) -> None:
    room_id = int(room_id)
    user_id = int(user_id)

    res = await session.execute(sql_i("""
        SELECT 1
        FROM chat_rooms r
        WHERE r.id = :rid AND r.owner_user_id = :uid
        LIMIT 1
    """, "rid", "uid"), {"rid": room_id, "uid": user_id})

    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Not found")

async def require_dm_access(session: AsyncSession, thread_id: int, user_id: int) -> None:
    res = await session.execute(sql_i("""
        SELECT 1
        FROM chat_dm_members
        WHERE thread_id = :tid AND user_id = :uid
        LIMIT 1
    """, "tid", "uid"), {"tid": thread_id, "uid": user_id})

    if not res.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Not found")

async def get_user_id_by_username(username: str) -> int | None:
    username = (username or "").strip()
    if not username:
        return None
    async with SessionLocal() as session:
        res = await session.execute(
            text("SELECT id FROM users WHERE LOWER(username) = LOWER(:u)"),
            {"u": username},
        )
        v = res.scalar_one_or_none()
        return int(v) if v is not None else None


MAX_HISTORY = 100

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/auth/password-kdf")
async def auth_password_kdf(authorization: str | None = Header(default=None)):
    require_user_from_bearer(authorization)
    return get_password_kdf_runtime_config()


@app.get("/api/notice")
def get_notice(request: Request):
    """Public endpoint — returns the current broadcast notice for the login page."""
    n = getattr(request.app.state, "broadcast_notice", None)
    if n:
        return {"active": True, "message": n["message"], "type": n["type"]}
    return {"active": False, "message": None, "type": None}


async def _issue_token_pair(user_id: int, username: str) -> dict:
    """Issue access + refresh token pair, store refresh in DB."""
    access = create_access_token(user_id, username)
    refresh, jti, fid = create_refresh_token(user_id, username)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRES_MIN)
    await store_refresh_token(jti, user_id, fid, expires_at)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRES_MIN * 60,
    }


@app.post("/auth/login")
async def login(payload: LoginRequest, request: Request):
    username = payload.username.strip()
    password = payload.password

    ip = get_client_ip_request(request)
    uname = username.lower()

    await enforce_http_rate_limit(
        f"login:ip:{ip}",
        RL_LOGIN_IP_PER_MIN,
        60,
        detail="Too many login attempts",
    )
    if uname:
        await enforce_http_rate_limit(
            f"login:user:{uname}",
            RL_LOGIN_USER_PER_MIN,
            60,
            detail="Too many login attempts",
        )

    async with SessionLocal() as db:
        q = text("""
            SELECT id, username, password_hash, totp_secret,
                   COALESCE(is_banned, false) AS is_banned,
                   banned_reason
            FROM users
            WHERE LOWER(username) = LOWER(:u)
        """)
        res = await db.execute(q, {"u": username})
        row = res.mappings().first()

        if not row:
            # Constant-time dummy check: prevent username enumeration via timing side-channel.
            verify_password_and_rehash(password, app.state.admin_dummy_hash)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if bool(row.get("is_banned")):
            raise UserBannedError(row.get("banned_reason"))

        password_ok, replacement_hash = verify_password_and_rehash(password, row["password_hash"])
        if not password_ok:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if replacement_hash:
            try:
                await db.execute(
                    text("""
                        UPDATE users
                        SET password_hash = :new_hash
                        WHERE id = :uid AND password_hash = :old_hash
                    """),
                    {
                        "new_hash": replacement_hash,
                        "uid": row["id"],
                        "old_hash": row["password_hash"],
                    },
                )
                await db.commit()
            except Exception:
                await db.rollback()
                logger.exception("login: password rehash update failed user_id=%s", row["id"])

        # Check if 2FA is enabled
        totp_secret = row.get("totp_secret") or None
        if totp_secret:
            temp_token = create_temp_token(row["id"], row["username"])
            return {"requires_2fa": True, "temp_token": temp_token}

        return await _issue_token_pair(row["id"], row["username"])


# ====================== TOTP 2FA Endpoints ======================

@app.post("/auth/totp/verify")
async def totp_verify_login(payload: TotpVerifyLoginIn, request: Request):
    """Step 2 of 2FA login: verify TOTP code with temp_token ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ get real access_token."""
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"totp:verify:ip:{ip}", RL_TOTP_VERIFY_PER_MIN, 60,
        detail="Too many TOTP attempts",
    )

    try:
        claims = decode_temp_token(payload.temp_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired temp token")

    user_id = int(claims["sub"])
    username = claims["username"]
    code = payload.code.strip()

    await enforce_http_rate_limit(
        f"totp:verify:user:{user_id}", RL_TOTP_VERIFY_PER_MIN, 60,
        detail="Too many TOTP attempts",
    )

    async with SessionLocal() as db:
        q = text("SELECT totp_secret, totp_backup_codes FROM users WHERE id = :uid")
        res = await db.execute(q, {"uid": user_id})
        row = res.mappings().first()
        if not row or not row.get("totp_secret"):
            raise HTTPException(status_code=400, detail="2FA not enabled")

        totp_secret = row["totp_secret"]

        # Try TOTP code first (time-based — stateless, no lock needed)
        if verify_totp_code(totp_secret, code):
            return await _issue_token_pair(user_id, username)

        # Try backup code — re-fetch with row lock to prevent double-spend race.
        # Without FOR UPDATE, two parallel requests could both read the same code
        # as valid and both consume it, issuing two tokens for one backup code.
        res2 = await db.execute(
            text("SELECT totp_backup_codes FROM users WHERE id = :uid FOR UPDATE"),
            {"uid": user_id},
        )
        row2 = res2.mappings().first()
        backup_codes_raw = (row2.get("totp_backup_codes") if row2 else None) or "[]"
        try:
            backup_codes = json.loads(backup_codes_raw) if isinstance(backup_codes_raw, str) else (backup_codes_raw or [])
        except Exception:
            backup_codes = []

        code_upper = code.upper()
        if code_upper in backup_codes:
            backup_codes.remove(code_upper)
            await db.execute(
                text("UPDATE users SET totp_backup_codes = :codes WHERE id = :uid"),
                {"codes": json.dumps(backup_codes), "uid": user_id},
            )
            await db.commit()
            return await _issue_token_pair(user_id, username)

        raise HTTPException(status_code=401, detail="Invalid TOTP code")


@app.get("/auth/totp/status")
async def totp_status(authorization: str | None = Header(default=None)):
    """Check if current user has 2FA enabled."""
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as db:
        q = text("SELECT totp_secret FROM users WHERE id = :uid")
        res = await db.execute(q, {"uid": u["user_id"]})
        row = res.mappings().first()

    enabled = bool(row and row.get("totp_secret"))
    return {"enabled": enabled}


@app.post("/auth/totp/setup")
async def totp_setup(authorization: str | None = Header(default=None), request: Request = None):
    """Generate TOTP secret for setup (not yet confirmed)."""
    u = require_user_from_bearer(authorization)

    if request:
        ip = get_client_ip_request(request)
        await enforce_http_rate_limit(
            f"totp:setup:ip:{ip}", RL_TOTP_SETUP_PER_10MIN, 600,
            detail="Too many setup attempts",
        )

    secret = generate_totp_secret()
    otpauth_uri = generate_otpauth_uri(secret, u["username"])
    qr_svg = generate_qr_svg(otpauth_uri)

    # Store pending secret (not yet active) use a separate column
    async with SessionLocal() as db:
        await db.execute(
            text("UPDATE users SET totp_pending_secret = :sec WHERE id = :uid"),
            {"sec": secret, "uid": u["user_id"]},
        )
        await db.commit()

    return {
        "secret": secret,
        "otpauth_uri": otpauth_uri,
        "qr_svg": qr_svg,
    }


@app.post("/auth/totp/verify-setup")
async def totp_verify_setup(payload: TotpSetupVerifyIn, authorization: str | None = Header(default=None), request: Request = None):
    """Verify first TOTP code to confirm setup. Activates 2FA."""
    u = require_user_from_bearer(authorization)
    code = payload.code.strip()

    if request:
        ip = get_client_ip_request(request)
        await enforce_http_rate_limit(
            f"totp:verify-setup:ip:{ip}", RL_TOTP_VERIFY_PER_MIN, 60,
            detail="Too many attempts",
        )

    async with SessionLocal() as db:
        q = text("SELECT totp_pending_secret, totp_secret FROM users WHERE id = :uid")
        res = await db.execute(q, {"uid": u["user_id"]})
        row = res.mappings().first()

        if not row or not row.get("totp_pending_secret"):
            raise HTTPException(status_code=400, detail="No pending TOTP setup. Call /auth/totp/setup first.")

        if row.get("totp_secret"):
            raise HTTPException(status_code=400, detail="2FA is already enabled")

        pending_secret = row["totp_pending_secret"]
        if not verify_totp_code(pending_secret, code):
            raise HTTPException(status_code=400, detail="Invalid code. Please try again.")

        # Activate 2FA
        backup_codes = generate_backup_codes()
        await db.execute(
            text("""
                UPDATE users
                SET totp_secret = :secret,
                    totp_pending_secret = NULL,
                    totp_backup_codes = :backup
                WHERE id = :uid
            """),
            {"secret": pending_secret, "backup": json.dumps(backup_codes), "uid": u["user_id"]},
        )
        await db.commit()

    return {"ok": True, "backup_codes": backup_codes}


@app.post("/auth/totp/disable")
async def totp_disable(payload: TotpDisableIn, authorization: str | None = Header(default=None), request: Request = None):
    """Disable 2FA. Requires a valid TOTP code or account password."""
    u = require_user_from_bearer(authorization)
    code = (payload.code or "").strip()
    password = (payload.password or "").strip()

    if not code and not password:
        raise HTTPException(status_code=400, detail="Provide TOTP code or password")

    if request:
        ip = get_client_ip_request(request)
        await enforce_http_rate_limit(
            f"totp:disable:ip:{ip}", RL_TOTP_VERIFY_PER_MIN, 60,
            detail="Too many attempts",
        )

    async with SessionLocal() as db:
        q = text("SELECT totp_secret, password_hash FROM users WHERE id = :uid")
        res = await db.execute(q, {"uid": u["user_id"]})
        row = res.mappings().first()
        if not row or not row.get("totp_secret"):
            raise HTTPException(status_code=400, detail="2FA is not enabled")

        # Verify by TOTP code
        if code and verify_totp_code(row["totp_secret"], code):
            pass  # OK
        elif password and verify_password(password, row["password_hash"]):
            pass  # OK
        else:
            raise HTTPException(status_code=401, detail="Invalid code or password")

        await db.execute(
            text("""
                UPDATE users
                SET totp_secret = NULL,
                    totp_pending_secret = NULL,
                    totp_backup_codes = NULL
                WHERE id = :uid
            """),
            {"uid": u["user_id"]},
        )
        await db.commit()

    return {"ok": True}

@app.get("/profile/me", response_model=ProfileMe)
async def profile_me(request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"profile:ip:{ip}", RL_PROFILE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"profile:user:{int(u['user_id'])}", RL_PROFILE_USER_PER_10MIN, 600)

    async with SessionLocal() as session:
        p = await get_profile_row(session, u["user_id"])
        await session.commit()

    return {
        "username": u["username"],
        "about": p["about"],
        "privacy": p["privacy"],
    }

@app.put("/profile/me", response_model=ProfileMe)
async def profile_update_me(payload: ProfileUpdate, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"profile:update:ip:{ip}", RL_PROFILE_UPDATE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"profile:update:user:{int(u['user_id'])}", RL_PROFILE_UPDATE_USER_PER_10MIN, 600)

    about = (payload.about or "").strip()
    
    if len(about) > 360:
        about = about[:360]

    async with SessionLocal() as session:
        current = await get_profile_row(session, u["user_id"])

        new_priv = current["privacy"]
        if payload.privacy is not None:
            new_priv = _normalize_privacy(payload.privacy.model_dump())

        await session.execute(sql_i("""
            UPDATE chat_user_profiles
            SET about = :about,
                privacy = CAST(:privacy AS jsonb),
                updated_at = now()
            WHERE user_id = :uid
        """, "uid"), {
            "uid": int(u["user_id"]),
            "about": about,
            "privacy": json.dumps(new_priv),
        })

        await session.commit()

    return {
        "username": u["username"],
        "about": about,
        "privacy": new_priv,
    }

@app.get("/profile/{username}", response_model=ProfilePublic)
async def profile_public(username: str, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"profile:ip:{ip}", RL_PROFILE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"profile:user:{int(u['user_id'])}", RL_PROFILE_USER_PER_10MIN, 600)

    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    async with SessionLocal() as session:
        r = await session.execute(text("SELECT id, username FROM users WHERE LOWER(username)=LOWER(:u)"), {"u": username})
        row = r.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        p = await get_profile_row(session, int(row["id"]))
        await session.commit()

    return {"username": row["username"], "about": p["about"]}

@app.post("/auth/register", status_code=201)
async def register(payload: RegisterRequest, request: Request):
    username = payload.username.strip().lower()
    password = payload.password
    
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"register:ip:{ip}",
        RL_REGISTER_IP_PER_5MIN,
        300,
        detail="Too many registrations",
    )

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username/password required")

    async with SessionLocal() as db:
       
        q = text("SELECT id FROM users WHERE LOWER(username) = LOWER(:u)")
        res = await db.execute(q, {"u": username})
        exists = res.scalar_one_or_none()
        if exists:
            raise HTTPException(status_code=409, detail="User already exists")

        ph = hash_password(password)

        public_key = (payload.public_key or "").strip()
        if not public_key:
            raise HTTPException(status_code=400, detail="public_key required")
        try:
            raw_pk = base64.b64decode(public_key, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="public_key must be valid base64")
        if len(raw_pk) != 32:
            raise HTTPException(status_code=400, detail="public_key must be 32-byte X25519 key")
        # Validate recovery_key_hash format if provided (must be hex SHA-256)
        rkh = None
        if payload.recovery_key_hash:
            rkh = payload.recovery_key_hash.strip().lower()
            if len(rkh) != 64 or not all(c in "0123456789abcdef" for c in rkh):
                raise HTTPException(status_code=400, detail="Invalid recovery_key_hash format")

        # INSERT user + RETURNING id
        # The pre-check above (SELECT id WHERE LOWER(username)=…) is racy: two
        # concurrent registrations with the same username can both pass it, then
        # collide on the UNIQUE(username) constraint at INSERT time. Catch the
        # IntegrityError and convert to 409 — the alternative is an opaque 500.
        q = text("""
            INSERT INTO users (
                username,
                password_hash,
                public_key,
                recovery_key_hash
            )
            VALUES (:u, :ph, :pk, :rkh)
            RETURNING id
        """)
        try:
            res = await db.execute(q, {
                "u": username,
                "ph": ph,
                "pk": public_key,
                "rkh": rkh,
            })
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=409, detail="User already exists")

        user_id = int(res.scalar_one())

        kid = hashlib.sha256(raw_pk).hexdigest()[:32]
        await db.execute(sql_i("""
            INSERT INTO chat_user_keys(user_id, alg, kid, public_key, is_active, revoked_at)
            VALUES (:uid, 'x25519', :kid, :pk, true, NULL)
            ON CONFLICT (user_id, alg, kid)
            DO UPDATE SET
              public_key = EXCLUDED.public_key,
              is_active = true,
              revoked_at = NULL,
              created_at = now()
        """, "uid"), {
            "uid": user_id,
            "kid": kid,
            "pk": public_key,
        })
        
        await db.execute(sql_i("""
            INSERT INTO chat_user_profiles(user_id, about, privacy)
            VALUES (:uid, '', CAST(:privacy AS jsonb))
            ON CONFLICT (user_id) DO NOTHING
        """, "uid"), {
            "uid": user_id,
            "privacy": json.dumps(DEFAULT_PRIVACY)
        })

        await db.commit()
        return {"id": user_id, "username": username}


# ====================== JWT Refresh & Logout ======================

class RefreshRequest(BaseModel):
    refresh_token: str

RL_REFRESH_PER_MIN = _env_int("RL_REFRESH_PER_MIN", 30)

@app.post("/auth/refresh")
async def refresh_tokens(payload: RefreshRequest, request: Request):
    """Exchange a valid refresh token for a new access + refresh pair (rotation)."""
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"refresh:ip:{ip}", RL_REFRESH_PER_MIN, 60,
        detail="Too many refresh attempts",
    )

    # 1. Decode refresh token
    try:
        claims = decode_token(payload.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # 2. Validate purpose
    if claims.get("purpose") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    jti = claims.get("jti")
    family_id = claims.get("fid")
    user_id_raw = claims.get("sub")
    username = (claims.get("username") or "").strip()

    if not jti or not family_id or not user_id_raw or not username:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    user_id = int(user_id_raw)

    # 3. Validate + rotate in ONE transaction to avoid race conditions
    async with SessionLocal() as db:
        res = await db.execute(text("""
            SELECT rt.revoked_at, rt.family_id, rt.replaced_by,
                   COALESCE(u.is_banned, false) AS is_banned,
                   u.banned_reason
            FROM refresh_tokens rt
            JOIN users u ON u.id = rt.user_id
            WHERE rt.jti = :jti AND rt.user_id = :uid
            FOR UPDATE
        """), {"jti": jti, "uid": user_id})
        row = res.mappings().first()

        if not row:
            raise HTTPException(status_code=401, detail="Unknown refresh token")

        if bool(row.get("is_banned")):
            raise UserBannedError(row.get("banned_reason"))

        db_family_id = str(row.get("family_id") or "")
        if not db_family_id or db_family_id != str(family_id):
            raise HTTPException(status_code=401, detail="Malformed refresh token")

        # THEFT DETECTION: token already revoked = reuse attack
        if row["revoked_at"] is not None:
            await db.execute(text("""
                UPDATE refresh_tokens
                SET revoked_at = now()
                WHERE family_id = :fid AND revoked_at IS NULL
            """), {"fid": db_family_id})
            await db.commit()
            raise HTTPException(
                status_code=401,
                detail="Refresh token reuse detected. All sessions revoked.",
            )

        # Rotate: revoke old, issue new pair atomically
        new_access = create_access_token(user_id, username)
        new_refresh, new_jti, _ = create_refresh_token(user_id, username, family_id=db_family_id)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRES_MIN)

        upd = await db.execute(text("""
            UPDATE refresh_tokens
            SET revoked_at = now(), replaced_by = :rep
            WHERE jti = :jti AND user_id = :uid AND revoked_at IS NULL
        """), {"rep": new_jti, "jti": jti, "uid": user_id})
        if (upd.rowcount or 0) != 1:
            raise HTTPException(status_code=401, detail="Refresh token already used")

        await db.execute(text("""
            INSERT INTO refresh_tokens (jti, user_id, family_id, expires_at)
            VALUES (:jti, :uid, :fid, :exp)
        """), {"jti": new_jti, "uid": user_id, "fid": db_family_id, "exp": expires_at})
        await db.commit()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRES_MIN * 60,
    }

@app.post("/auth/logout")
async def logout(authorization: str | None = Header(default=None)):
    """Revoke all active refresh tokens for the current user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization[7:]
    try:
        user = get_user_from_token(token)
    except Exception:
        # Best-effort: even with expired access token, try to extract user_id
        # from the still-signed JWT (verify signature but skip exp)
        try:
            hdr = jwt.get_unverified_header(token) or {}
            kid = (hdr.get("kid") or "").strip()
            key = JWT_KEYRING.get(kid, JWT_SECRET) if JWT_KEYRING else JWT_SECRET
            payload = jwt.decode(token, key, algorithms=[JWT_ALG], options={"verify_exp": False})
            purpose = payload.get("purpose")
            if purpose is not None and purpose != "access":
                raise HTTPException(status_code=401, detail="Invalid token (wrong purpose)")
            uid = payload.get("sub")
            if uid:
                await revoke_all_user_refresh_tokens(int(uid))
                return {"ok": True}
        except HTTPException:
            raise
        except Exception:
            pass
        raise HTTPException(status_code=401, detail="Invalid token")

    await revoke_all_user_refresh_tokens(user["user_id"])
    return {"ok": True}


@app.post("/auth/logout-all")
async def logout_all(authorization: str | None = Header(default=None)):
    """Revoke ALL refresh tokens and active access tokens for this user."""
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"])
    username = (u.get("username") or "").strip()

    await revoke_all_user_refresh_tokens(user_id)
    await bump_tokens_valid_after(user_id)

    # Best-effort: drop active WS sessions so in-flight access tokens stop
    # receiving broadcasts before the periodic token-freshness check fires.
    try:
        if username:
            await manager.kick_user_everywhere(username, code=1008, reason="session revoked")
    except Exception:
        pass
    try:
        if username:
            await dm_manager.kick_user_everywhere(username, code=1008, reason="session revoked")
    except Exception:
        pass
    try:
        await notify_manager.kick_user(user_id, code=1008, reason="session revoked")
    except Exception:
        pass

    return {"ok": True}


class ChangePasswordIn(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)


@app.post("/auth/change-password")
async def change_password(
    payload: ChangePasswordIn,
    authorization: str | None = Header(default=None),
    request: Request = None,
):
    """Change password for an authenticated user. Verifies old password before updating."""
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"])
    ip = get_client_ip_request(request)

    await enforce_http_rate_limit(f"change-pwd:ip:{ip}", 5, 300)
    await enforce_http_rate_limit(f"change-pwd:user:{user_id}", 3, 300)

    async with SessionLocal() as db:
        res = await db.execute(
            text("SELECT password_hash FROM users WHERE id = :uid"),
            {"uid": user_id},
        )
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    ok, _ = verify_password_and_rehash(payload.old_password, row["password_hash"])
    if not ok:
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    new_hash = hash_password(payload.new_password)
    async with SessionLocal() as db:
        await db.execute(
            text("UPDATE users SET password_hash = :h WHERE id = :uid"),
            {"h": new_hash, "uid": user_id},
        )
        await db.commit()

    # Revoke all refresh tokens AND active access tokens so other
    # devices/sessions must re-login with the new password.
    await revoke_all_user_refresh_tokens(user_id)
    try:
        await bump_tokens_valid_after(user_id)
    except Exception:
        pass

    return {"ok": True}


# ====================== BIP39 Account Recovery ======================

@app.post("/auth/recover-start")
async def recover_start(payload: RecoverStartIn, request: Request):
    """
    Issue a single-use nonce for the recovery challenge.
    Always returns a nonce (fake for unknown users — prevents username enumeration).
    """
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"recover-start:ip:{ip}", RL_RECOVER_IP_PER_HOUR, 3600,
        detail="Too many recovery attempts",
    )

    username = (payload.username or "").strip().lower()

    async with SessionLocal() as db:
        res = await db.execute(
            text("SELECT 1 FROM users WHERE LOWER(username) = LOWER(:u) LIMIT 1"),
            {"u": username},
        )
        exists = res.scalar_one_or_none() is not None

    if not exists:
        # Return fake nonce — same shape, no timing difference
        return {"nonce": secrets.token_hex(32)}

    nonce = await _recovery_nonce_set(username)
    return {"nonce": nonce}


@app.post("/auth/recover")
async def recover(payload: RecoverIn, request: Request):
    """
    Verify recovery_auth against stored hash, then reset password.
    """
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"recover:ip:{ip}", RL_RECOVER_IP_PER_HOUR, 3600,
        detail="Too many recovery attempts",
    )

    username = (payload.username or "").strip().lower()

    await enforce_http_rate_limit(
        f"recover:user:{username}", RL_RECOVER_USER_PER_HOUR, 3600,
        detail="Too many recovery attempts",
    )

    # 1. Consume nonce (single-use, 5-min TTL)
    if not await _recovery_nonce_consume(username, payload.nonce):
        raise HTTPException(status_code=400, detail="Invalid or expired recovery nonce")

    # 2. Fetch user + recovery_key_hash
    async with SessionLocal() as db:
        res = await db.execute(
            text("SELECT id, recovery_key_hash FROM users WHERE LOWER(username) = LOWER(:u) LIMIT 1"),
            {"u": username},
        )
        row = res.mappings().first()

    if not row or not row["recovery_key_hash"]:
        raise HTTPException(status_code=401, detail="Recovery not available for this account")

    user_id = int(row["id"])

    # 3. Verify recovery_auth: SHA-256(decoded bytes) == stored hash
    try:
        recovery_auth_bytes = base64.b64decode(payload.recovery_auth_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid recovery_auth_b64 encoding")

    actual_hash = hashlib.sha256(recovery_auth_bytes).hexdigest()
    if not hmac.compare_digest(actual_hash, row["recovery_key_hash"]):
        raise HTTPException(status_code=401, detail="Recovery phrase is incorrect")

    # 4. Update password (recovery_key_hash stays — it's derived from the key, not the password)
    new_password_hash = hash_password(payload.new_password)
    async with SessionLocal() as db:
        await db.execute(
            sql_i("""
                UPDATE users
                SET password_hash = :ph
                WHERE id = :uid
            """, "uid"),
            {"ph": new_password_hash, "uid": user_id},
        )
        await db.commit()

    # 5. Invalidate all active sessions (refresh tokens + access tokens).
    await revoke_all_user_refresh_tokens(user_id)
    try:
        await bump_tokens_valid_after(user_id)
    except Exception:
        pass

    return {"ok": True, "message": "Password reset successfully"}


from sqlalchemy import text
import json
from fastapi import Header, Request, HTTPException

def _normalize_alg(v: str | None) -> str:
    alg = (v or "x25519").strip().lower()
    if alg != "x25519":
        raise HTTPException(status_code=400, detail="unsupported alg")
    return alg

def _validate_x25519_public_key_b64(public_key: str | None) -> str:
    pk = (public_key or "").strip()
    if not pk:
        raise HTTPException(status_code=400, detail="public_key required")
    try:
        raw = base64.b64decode(pk, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="public_key must be 32-byte X25519 key")
    return pk

async def _get_user_id_by_username(session: AsyncSession, username: str) -> int | None:
    res = await session.execute(text("""
        SELECT id
        FROM users
        WHERE LOWER(username) = LOWER(:u)
        LIMIT 1
    """), {"u": username})
    row = res.mappings().first()
    return int(row["id"]) if row else None

async def _get_active_x25519_key_row(session: AsyncSession, username: str):
    res = await session.execute(text("""
        SELECT k.kid, k.public_key, k.alg
        FROM users u
        JOIN chat_user_keys k
          ON k.user_id = u.id
        WHERE LOWER(u.username) = LOWER(:u)
          AND k.alg = 'x25519'
          AND k.is_active = true
        LIMIT 1
    """), {"u": username})
    return res.mappings().first()

@app.post("/keys/me")
async def publish_my_key(
    payload: KeyPublishIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"])
    _ = _normalize_alg(payload.alg)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"keys:publish:ip:{ip}", RL_KEYS_PUBLISH_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"keys:publish:user:{user_id}", RL_KEYS_PUBLISH_USER_PER_10MIN, 600)

    kid = (payload.kid or "").strip().lower()
    if not kid or len(kid) > 64:
        raise HTTPException(status_code=400, detail="bad kid")
    if not all(c in "0123456789abcdef" for c in kid):
        raise HTTPException(status_code=400, detail="kid must be lowercase hex")

    public_key = _validate_x25519_public_key_b64(payload.public_key)

    expected_kid = hashlib.sha256(base64.b64decode(public_key)).hexdigest()[:32]
    if kid != expected_kid:
        raise HTTPException(status_code=400, detail="kid does not match SHA-256 of public_key")

    async with SessionLocal() as session:
        async with session.begin():  #one transaction

            #serialize publishes per user to avoid ux_chat_user_keys_one_active races
            await session.execute(text("""
                SELECT 1
                FROM users
                WHERE id = :uid
                FOR UPDATE
            """), {"uid": user_id})

            res = await session.execute(text("""
                SELECT kid
                FROM chat_user_keys
                WHERE user_id = :uid AND alg = 'x25519' AND is_active = true
                LIMIT 1
            """), {"uid": user_id})
            row_active = res.mappings().first()
            active_kid = row_active["kid"] if row_active else None

            if active_kid == kid:
                await session.execute(sql_i("""
                    INSERT INTO chat_user_keys(user_id, alg, kid, public_key, is_active, revoked_at)
                    VALUES (:uid, 'x25519', :kid, :pk, true, NULL)
                    ON CONFLICT (user_id, alg, kid)
                    DO UPDATE SET
                      public_key = EXCLUDED.public_key,
                      is_active = true,
                      revoked_at = NULL,
                      created_at = now()
                """), {"uid": user_id, "kid": kid, "pk": public_key})

                return {"ok": True, "kid": kid, "alg": "x25519", "rotated": False}

            # forbid re-activating revoked kid
            res = await session.execute(text("""
                SELECT revoked_at
                FROM chat_user_keys
                WHERE user_id = :uid AND alg = 'x25519' AND kid = :kid
                LIMIT 1
            """), {"uid": user_id, "kid": kid})
            r = res.mappings().first()
            if r and r["revoked_at"] is not None:
                raise HTTPException(status_code=400, detail="kid revoked; rotate required")

            # deactivate previous active key (if any)
            await session.execute(sql_i("""
                UPDATE chat_user_keys
                SET is_active = false,
                    revoked_at = COALESCE(revoked_at, now())
                WHERE user_id = :uid AND alg = 'x25519' AND is_active = true
            """), {"uid": user_id})

            # upsert new key as active
            await session.execute(sql_i("""
                INSERT INTO chat_user_keys(user_id, alg, kid, public_key, is_active, revoked_at)
                VALUES (:uid, 'x25519', :kid, :pk, true, NULL)
                ON CONFLICT (user_id, alg, kid)
                DO UPDATE SET
                  public_key = EXCLUDED.public_key,
                  is_active = true,
                  revoked_at = NULL,
                  created_at = now()
            """), {"uid": user_id, "kid": kid, "pk": public_key})

            return {"ok": True, "kid": kid, "alg": "x25519", "rotated": True}

@app.get("/keys/{username}")
async def get_user_key(username: str, authorization: str | None = Header(default=None)):
    _ = require_user_from_bearer(authorization)

    username = (username or "").strip().lower()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    async with SessionLocal() as session:
        row = await _get_active_x25519_key_row(session, username)
        # Also fetch Ed25519 signing key if the user has registered one.
        ed_res = await session.execute(text("""
            SELECT k.public_key
            FROM chat_user_keys k
            JOIN users u ON u.id = k.user_id
            WHERE lower(u.username) = :uname AND k.alg = 'ed25519' AND k.is_active = true
            LIMIT 1
        """), {"uname": username})
        ed_row = ed_res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="No active public key for this user")

    pk = _validate_x25519_public_key_b64(row["public_key"])
    result = {"kid": row["kid"], "alg": row["alg"], "public_key": pk}
    if ed_row:
        result["ed25519_public_key"] = ed_row["public_key"]
    return result

@app.get("/keys/{username}/{kid}")
async def get_user_key_by_kid(username: str, kid: str, authorization: str | None = Header(default=None)):
    _ = require_user_from_bearer(authorization)

    username = (username or "").strip().lower()
    kid = (kid or "").strip().lower()
    if not username or not kid:
        raise HTTPException(status_code=400, detail="username and kid required")

    async with SessionLocal() as session:
        uid = await _get_user_id_by_username(session, username)
        if not uid:
            raise HTTPException(status_code=404, detail="No public key for this user/kid")
        res = await session.execute(text("""
            SELECT kid, alg, public_key, is_active, revoked_at
            FROM chat_user_keys
            WHERE user_id = :uid AND alg = 'x25519' AND kid = :kid
            LIMIT 1
        """), {"uid": uid, "kid": kid})
        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="No public key for this user/kid")

    out = dict(row)
    out["public_key"] = _validate_x25519_public_key_b64(out.get("public_key"))
    return out

@app.get("/crypto/keys")
async def get_user_crypto_keys(authorization: str | None = Header(default=None)):
    _ = require_user_from_bearer(authorization)
    raise HTTPException(
        status_code=410,
        detail="Deprecated: private keys are device-only and are never returned by server",
    )

@app.post("/crypto/room-key", status_code=201)
async def save_room_key(
    payload: RoomKeyIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Save encrypted room key for user"""
    u = require_user_from_bearer(authorization)
    key_id = _normalize_key_id(payload.key_id)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"crypto:keywrite:ip:{ip}", RL_CRYPTO_KEYWRITE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"crypto:keywrite:user:{int(u['user_id'])}", RL_CRYPTO_KEYWRITE_USER_PER_10MIN, 600)
    
    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)
        # Check room access
        await require_room_access(session, payload.room_id, u["user_id"])
        
        # Upsert encrypted room key
        await session.execute(sql_i("""
            INSERT INTO chat_room_keys (room_id, user_id, encrypted_room_key)
            VALUES (:rid, :uid, :erk)
            ON CONFLICT (room_id, user_id) 
            DO UPDATE SET encrypted_room_key = EXCLUDED.encrypted_room_key
        """, "rid", "uid"), {
            "rid": payload.room_id,
            "uid": u["user_id"],
            "erk": payload.encrypted_room_key
        })
        if key_id:
            await session.execute(sql_i("""
                INSERT INTO chat_room_key_archive (room_id, user_id, key_id, encrypted_room_key)
                VALUES (:rid, :uid, :kid, :erk)
                ON CONFLICT (room_id, user_id, key_id)
                DO NOTHING
            """, "rid", "uid"), {
                "rid": payload.room_id,
                "uid": u["user_id"],
                "kid": key_id,
                "erk": payload.encrypted_room_key,
            })
        await session.commit()
    
    return {"ok": True, "room_id": payload.room_id}

@app.post("/crypto/room/{room_id}/share")
async def share_room_key(
    room_id: int,
    payload: RoomKeyShareIn,
    request: Request,
    target_username: str = Query(...),
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    owner_user_id = int(u["user_id"])
    key_id = _normalize_key_id(payload.key_id)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"crypto:keywrite:ip:{ip}", RL_CRYPTO_KEYWRITE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"crypto:keywrite:user:{owner_user_id}", RL_CRYPTO_KEYWRITE_USER_PER_10MIN, 600)

    target_username = (target_username or "").strip()
    if not target_username:
        raise HTTPException(status_code=400, detail="target_username required")

    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)
        
        res = await session.execute(sql_i("""
            SELECT owner_user_id
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": room_id})
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Room not found")

        if int(row["owner_user_id"]) != owner_user_id:
            raise HTTPException(status_code=403, detail="Only room owner can share room key")

        res2 = await session.execute(text("""
            SELECT id
            FROM users
            WHERE LOWER(username) = LOWER(:u)
        """), {"u": target_username})
        trow = res2.mappings().first()
        if not trow:
            raise HTTPException(status_code=404, detail="Target user not found")
        target_user_id = int(trow["id"])
        
        res3 = await session.execute(sql_i("""
            SELECT 1
            FROM chat_room_members
            WHERE room_id = :rid AND user_id = :uid AND status = 'accepted'
        """, "rid", "uid"), {"rid": room_id, "uid": target_user_id})
        if not res3.first():
            raise HTTPException(status_code=403, detail="Target user is not a member of this room")
        
        await session.execute(sql_i("""
            INSERT INTO chat_room_keys (room_id, user_id, encrypted_room_key)
            VALUES (:rid, :uid, :erk)
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET encrypted_room_key = EXCLUDED.encrypted_room_key
        """, "rid", "uid"), {"rid": room_id, "uid": target_user_id, "erk": payload.encrypted_room_key})
        if key_id:
            await session.execute(sql_i("""
                INSERT INTO chat_room_key_archive (room_id, user_id, key_id, encrypted_room_key)
                VALUES (:rid, :uid, :kid, :erk)
                ON CONFLICT (room_id, user_id, key_id)
                DO NOTHING
            """, "rid", "uid"), {
                "rid": room_id,
                "uid": target_user_id,
                "kid": key_id,
                "erk": payload.encrypted_room_key,
            })

        await session.commit()

    return {"ok": True}

@app.get("/crypto/room-key/{room_id}")
async def get_room_key(room_id: int, authorization: str | None = Header(default=None)):
    """Get encrypted room key for user"""
    u = require_user_from_bearer(authorization)
    
    async with SessionLocal() as session:
        # Check room access
        await require_room_access(session, room_id, u["user_id"])
        
        # Get encrypted room key
        res = await session.execute(sql_i("""
            SELECT encrypted_room_key
            FROM chat_room_keys
            WHERE room_id = :rid AND user_id = :uid
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        row = res.mappings().first()
        
        if not row or not row["encrypted_room_key"]:
            raise HTTPException(status_code=404, detail="Room key not found")
        
        return {
            "room_id": room_id,
            "encrypted_room_key": row["encrypted_room_key"]
        }

@app.get("/crypto/room/{room_id}/key")
async def get_room_key_new(
    room_id: int,
    authorization: str | None = Header(default=None)
):
    return await get_room_key(room_id, authorization)

@app.get("/crypto/room-key/{room_id}/archive")
async def get_room_key_archive(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)
        await require_room_access(session, room_id, u["user_id"])
        res = await session.execute(sql_i("""
            SELECT key_id, encrypted_room_key, created_at
            FROM chat_room_key_archive
            WHERE room_id = :rid AND user_id = :uid
            ORDER BY created_at DESC
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        rows = res.mappings().all()

    return {
        "room_id": room_id,
        "keys": [
            {
                "key_id": r["key_id"],
                "encrypted_room_key": r["encrypted_room_key"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ],
    }

@app.post("/rooms", status_code=201)
async def rooms_create(
    payload: RoomCreateIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:create:ip:{ip}", RL_ROOMS_CREATE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:create:user:{int(u['user_id'])}", RL_ROOMS_CREATE_USER_PER_10MIN, 600)
    
    if not payload.encrypted_room_key:
        raise HTTPException(status_code=400, detail="encrypted_room_key is required")

    row = await create_room(
        u["user_id"],
        payload.name,
        payload.password,
        bool(payload.is_public),
        bool(payload.is_readonly),
    )

    async with SessionLocal() as session:
                
        await session.execute(sql_i("""
            INSERT INTO chat_room_members (room_id, user_id, role, invited_by, status)
            VALUES (:rid, :uid, 'owner', NULL, 'accepted')
            ON CONFLICT (room_id, user_id) DO UPDATE
            SET role='owner',
                status='accepted',
                invited_by=NULL
        """, "rid", "uid"), {"rid": row["id"], "uid": u["user_id"]})
        
        await session.execute(sql_i("""
            INSERT INTO chat_room_keys (room_id, user_id, encrypted_room_key)
            VALUES (:rid, :uid, :erk)
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET encrypted_room_key = EXCLUDED.encrypted_room_key
        """, "rid", "uid"), {
            "rid": row["id"],
            "uid": u["user_id"],
            "erk": payload.encrypted_room_key
        })

        await session.commit()


    return {
        "id": row["id"],
        "alias": row["alias"],
        "name": row["name"],
        "has_password": bool(row["password_hash"]),
        "is_public": bool(row.get("is_public")),
        "is_readonly": bool(row.get("is_readonly")),
        "join_policy": row.get("join_policy") or ("approval" if bool(row.get("is_public")) else "invite_only"),
        "created_at": row["created_at"],
    }

@app.get("/rooms/resolve", response_model=RoomJoinResolveOut)
async def rooms_resolve(alias: str, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    uid = int(u["user_id"])

    alias = (alias or "").strip().upper()
    if not alias or len(alias) > 32:
        raise HTTPException(status_code=400, detail="Bad alias")

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT id, owner_user_id, name, alias, password_hash, is_public, is_readonly
            FROM chat_rooms
            WHERE alias = :a
            LIMIT 1
        """, "a"), {"a": alias})
        row = res.mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Room not found")

        room_id = int(row["id"])
        is_public = bool(row["is_public"])
        has_password = bool(row["password_hash"])

        # Public rooms: return full info (как было)
        if is_public:
            return {
                "id": room_id,
                "alias": row["alias"],
                "name": row["name"],
                "owner_user_id": int(row["owner_user_id"]),
                "has_password": has_password,
                "is_public": True,
                "is_readonly": bool(row.get("is_readonly")),
            }

        # Private rooms: full info only to owner or accepted member
        acc = await session.execute(sql_i("""
            SELECT 1
            FROM (
              SELECT 1
              FROM chat_rooms r
              WHERE r.id = :rid AND r.owner_user_id = :uid
              UNION
              SELECT 1
              FROM chat_room_members m
              WHERE m.room_id = :rid AND m.user_id = :uid AND m.status = 'accepted'
            ) x
            LIMIT 1
        """, "rid", "uid"), {"rid": room_id, "uid": uid})
        can_see = bool(acc.scalar_one_or_none())

        if can_see:
            return {
                "id": room_id,
                "alias": row["alias"],
                "name": row["name"],
                "owner_user_id": int(row["owner_user_id"]),
                "has_password": has_password,
                "is_public": False,
                "is_readonly": bool(row.get("is_readonly")),
            }

        # Outsider -> schema-safe minimal response (без утечки метаданных)
        return {
            "id": room_id,
            "alias": row["alias"],
            "name": "Private room",
            "owner_user_id": 0,
            "has_password": False,
            "is_public": False,
            "is_readonly": False,
        }

@app.get("/rooms/{room_id}/history")
async def get_history(
    room_id: int,
    limit: int = 50,
    before_id: int | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    limit = max(1, min(int(limit), 200))
    before = int(before_id) if (before_id is not None and int(before_id) > 0) else None
    lim_plus = limit + 1

    async with SessionLocal() as session:
        await require_room_access(session, room_id, u["user_id"])

        if before:
            res = await session.execute(
                sql_i("""
                    SELECT m.id, COALESCE(u.username, 'Deleted account') as username, m.text, m.ts
                    FROM chat_messages m
                    LEFT JOIN users u ON u.id = m.user_id
                    WHERE m.room_id = :room_id
                      AND m.id < :before_id
                    ORDER BY m.id DESC
                    LIMIT :limit
                """, "limit", "room_id", "before_id"),
                {"room_id": int(room_id), "before_id": int(before), "limit": int(lim_plus)},
            )
        else:
            res = await session.execute(
                sql_i("""
                    SELECT m.id, COALESCE(u.username, 'Deleted account') as username, m.text, m.ts
                    FROM chat_messages m
                    LEFT JOIN users u ON u.id = m.user_id
                    WHERE m.room_id = :room_id
                    ORDER BY m.id DESC
                    LIMIT :limit
                """, "limit", "room_id"),
                {"room_id": int(room_id), "limit": int(lim_plus)},
            )
        rows = res.mappings().all()

    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]
    msgs = list(reversed(rows))
    oldest_id = int(msgs[0]["id"]) if msgs else None
    return {
        "room_id": int(room_id),
        "messages": msgs,
        "has_more": bool(has_more),
        "oldest_id": oldest_id,
    }

@app.get("/rooms/mine")
async def rooms_mine(authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    user_id = u["user_id"]
    
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT 
                r.id, r.name, r.alias, r.password_hash, r.created_at,
                r.description, r.logo_path, r.is_public, r.is_readonly,
                (SELECT MAX(m.ts) 
                 FROM chat_messages m 
                 WHERE m.room_id = r.id) as last_message_at,
                (SELECT rs.seen_at 
                 FROM room_seen rs 
                 WHERE rs.room_id = r.id AND rs.user_id = :uid) as last_seen_at
            FROM chat_rooms r
            WHERE r.owner_user_id = :oid
            ORDER BY r.created_at DESC
        """, "oid", "uid"), {"oid": user_id, "uid": user_id})
        rows = res.mappings().all()
        
    return [{
        "id": int(r["id"]),
        "name": r["name"],
        "alias": r["alias"],
        "has_password": bool(r["password_hash"]),
        "created_at": r["created_at"],
        "description": r.get("description"),
        "logo_url": f"/rooms/{r['id']}/logo" if r.get("logo_path") else None,
        "logo_token": None,
        "is_public": bool(r.get("is_public")),
        "is_readonly": bool(r.get("is_readonly")),
        "is_owner": True,
        "last_message_at": r["last_message_at"].isoformat() if r.get("last_message_at") else None,
        "last_seen_at": r["last_seen_at"].isoformat() if r.get("last_seen_at") else None,
    } for r in rows]

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    # Origin check before accept (CSWSH protection)
    origin = ws.headers.get("origin")
    if not is_allowed_origin(origin):
        try:
            await ws.close(code=1008, reason="forbidden")
        except Exception:
            pass
        return

    await ws.accept()

    async def ws_forbid():
        
        await ws.close(code=1008, reason="forbidden")

    async def ws_try_later():
        
        await ws.close(code=1013, reason="try later")

    # [OK] connect rate-limit 
    ip = get_client_ip_ws(ws)
    retry = await rate_limiter.check(f"ws:connect:ip:{ip}", RL_WS_CONNECT_IP_PER_MIN, 60)
    if retry is not None:
        await ws_try_later()
        return
    
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5)
    except Exception:
        await ws_forbid()
        return

    if not isinstance(first, dict) or first.get("type") != "auth" or not first.get("token"):
        await ws_forbid()
        return

    token = first["token"]

    try:
        user = get_user_from_token(token)
        token_payload = decode_token(token)
    except Exception:
        await ws_forbid()
        return

    user_id = int(user["user_id"])
    token_iat = _token_iat(token_payload)

    if await _is_token_revoked(user_id, token_iat):
        try:
            await ws.send_json({
                "type": "auth_state",
                "loggedIn": False,
                "reason": "session_revoked",
                "message": "Session revoked. Sign in again.",
            })
        except Exception:
            pass
        try:
            await ws.close(code=1008, reason="session revoked")
        finally:
            return

    BAN_CHECK_INTERVAL = 10.0
    _last_ban_check = 0.0

    async def _check_ban_maybe(force: bool = False):
        nonlocal _last_ban_check
        now = time.time()
        if (not force) and (now - _last_ban_check) < BAN_CHECK_INTERVAL:
            return True
        _last_ban_check = now
        async with SessionLocal() as _s:
            banned, reason = await _fetch_user_ban_state(_s, user_id)
            valid_after = await _fetch_tokens_valid_after(_s, user_id)
        if token_iat < valid_after:
            try:
                await ws.send_json({
                    "type": "auth_state",
                    "loggedIn": False,
                    "reason": "session_revoked",
                    "message": "Session revoked. Sign in again.",
                })
            except Exception:
                pass
            try:
                await ws.close(code=1008, reason="session revoked")
            finally:
                return False
        if banned:
            try:
                await ws.send_json({
                    "type": "auth_state",
                    "loggedIn": False,
                    "reason": "banned",
                    "ban_reason": reason or "",
                    "message": ("User is banned" + (f": {reason}" if reason else "")),
                })
                # also send explicit event for UIs that don't inspect auth_state.reason
                try:
                    await ws.send_json({
                        "type": "banned",
                        "ban_reason": reason or "",
                        "message": ("User is banned" + (f": {reason}" if reason else "")),
                    })
                except Exception:
                    pass
            except Exception:
                pass
            try:
                # include close reason so clients can display it even if they miss the last JSON frame
                close_reason = ("banned" + (f": {reason}" if reason else ""))[:120]
                await ws.close(code=1008, reason=close_reason)
            finally:
                return False
        return True

    if not await _check_ban_maybe(force=True):
        return
    username = (user.get("username") or "").strip() or f"user_{user_id}"
    
    room_id_raw = ws.query_params.get("room_id")
    alias = ws.query_params.get("alias")

    room_id: int | None = None

    if room_id_raw:
        try:
            room_id = int(room_id_raw)
        except ValueError:
            await ws_forbid()
            return
    elif alias:
        alias = alias.strip().upper()
        if not alias:
            await ws_forbid()
            return
        async with SessionLocal() as session:
            res = await session.execute(text("""
                SELECT id
                FROM chat_rooms
                WHERE alias = :a
            """), {"a": alias})
            row = res.mappings().first()
        if not row:
            await ws_forbid()
            return
        room_id = int(row["id"])
    else:
        await ws_forbid()
        return

    async with SessionLocal() as session:
        try:
            await require_room_access(session, room_id, user_id)
        except HTTPException:
            await ws_forbid()
            return

        res = await session.execute(sql_i("""
            SELECT name, is_readonly
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": room_id})
        room = res.mappings().first()
        if not room:
            
            await ws_forbid()
            return

    room_key = str(room_id)
    room_name = room["name"]

    manager.connect(room_key, ws, username)

    # presence
    await manager.broadcast(room_key, {
        "type": "presence",
        "ts": int(time.time()),
        "room_id": room_id,
        "room_name": room_name,
        "online": manager.get_online(room_key),
    })

    try:
        while True:
            if not await _check_ban_maybe():
                return
            text_msg = (await ws.receive_text()).strip()
            if not text_msg:
                continue
            
            if len(text_msg.encode("utf-8")) > MAX_WS_MSG_BYTES:
                await ws.close(code=1009, reason="message too big")
                return
            
            retry = await rate_limiter.check(f"ws:msg:{room_id}:{user_id}", RL_WS_MSG_PER_10S, 10)
            if retry is not None:
                
                await ws.send_text(json.dumps({"type": "error", "message": "rate limited", "retry_after": retry}))
                continue

            t = text_msg
            
            if t in ("ping", "pong"):
                if t == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
                continue

# ping/pong (json)
            if t.startswith("{") and t.endswith("}"):
                try:
                    obj = json.loads(t)
                    if isinstance(obj, dict):
                        msg_type = obj.get("type")
                        
                        # ping/pong
                        if msg_type in ("ping", "pong"):
                            if msg_type == "ping":
                                await ws.send_text(json.dumps({"type": "pong"}))
                            continue
                        
                        # rooms_meta_get
                        if msg_type == "rooms_meta_get":
                            room_id_meta = obj.get("roomId")
                            try:
                                rid_meta = int(room_id_meta)
                                if rid_meta <= 0:
                                    raise ValueError("bad room id")
                                async with SessionLocal() as session:
                                    await require_room_access(session, rid_meta, user_id)
                                    res = await session.execute(sql_i("""
                                        SELECT description, logo_path
                                        FROM chat_rooms
                                        WHERE id = :rid
                                    """, "rid"), {"rid": rid_meta})
                                    row = res.mappings().first()
                                    
                                    if row:
                                        has_logo = bool(row.get("logo_path"))
                                        await ws.send_text(json.dumps({
                                            "type": "rooms_meta_get",
                                            "ok": True,
                                            "roomId": rid_meta,
                                            "meta": {
                                                "description": row.get("description"),
                                                "logo_url": f"/rooms/{rid_meta}/logo" if has_logo else None,
                                                "logo_token": None,
                                            }
                                        }))
                                    else:
                                        await ws.send_text(json.dumps({
                                            "type": "rooms_meta_get",
                                            "ok": False,
                                            "roomId": rid_meta,
                                            "message": "Room not found"
                                        }))
                            except HTTPException:
                                await ws.send_text(json.dumps({
                                    "type": "rooms_meta_get",
                                    "ok": False,
                                    "roomId": room_id_meta,
                                    "message": "Room not found"
                                }))
                            except Exception as e:
                                await ws.send_text(json.dumps({
                                    "type": "rooms_meta_get",
                                    "ok": False,
                                    "roomId": room_id_meta,
                                    "message": "Failed to get room metadata"
                                }))
                            continue
                        
                        # rooms_meta_set / rooms_change_password are HTTP-only now.
                        # Use PUT /rooms/{id}/meta and PUT /rooms/{id}/password — those
                        # have dedicated rate limits and the canonical validation.
                        if msg_type in ("rooms_meta_set", "rooms_change_password"):
                            await ws.send_text(json.dumps({
                                "type": msg_type,
                                "ok": False,
                                "roomId": obj.get("roomId"),
                                "message": "Not supported over websocket; use HTTP endpoint",
                            }))
                            continue

                except Exception:
                    pass
            
            async with SessionLocal() as session:
                try:
                    await require_room_access(session, room_id, user_id)
                except HTTPException:
                    await ws_forbid()
                    return
                rs = await session.execute(sql_i("""
                    SELECT is_readonly
                    FROM chat_rooms
                    WHERE id = :rid
                    LIMIT 1
                """, "rid"), {"rid": int(room_id)})
                room_live = rs.mappings().first()
                if not room_live:
                    await ws_forbid()
                    return

                if bool(room_live.get("is_readonly")):
                    role = await get_room_role(session, room_id, user_id)
                    if role not in (ROLE_OWNER, ROLE_ADMIN):
                        await ws.send_text(json.dumps({
                            "type": "error",
                            "message": "Room is read-only: only owner/admin can post",
                        }))
                        continue

                try:
                    await session.execute(
                        sql_i("""
                            INSERT INTO chat_messages (room_id, user_id, text)
                            VALUES (:room_id, :user_id, :text)
                        """, "room_id", "user_id"),
                        {"room_id": int(room_id), "user_id": int(user_id), "text": text_msg},
                    )
                    await session.commit()
                except Exception:
                    try:
                        await session.rollback()
                    except Exception:
                        pass
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "message": "Failed to save message",
                    }))
                    continue

            await manager.broadcast(room_key, {
                "type": "message",
                "ts": int(time.time()),
                "room_id": room_id,
                "room_name": room_name,
                "from": username,
                "text": text_msg,
            })

            # Fan out lightweight notification to /ws-notify (no ciphertext)
            try:
                await _notify_room_members(room_id, room_name, username, exclude_user_ids={user_id})
            except Exception:
                pass

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(room_key, ws)
        # presence update
        await manager.broadcast(room_key, {
            "type": "presence",
            "ts": int(time.time()),
            "room_id": room_id,
            "room_name": room_name,
            "online": manager.get_online(room_key),
        })

from fastapi import Response

@app.delete("/rooms/{room_id}", status_code=204)
async def rooms_delete(room_id: int, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:delete:ip:{ip}", RL_ROOMS_DELETE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:delete:user:{int(u['user_id'])}", RL_ROOMS_DELETE_USER_PER_10MIN, 600)

    async with SessionLocal() as session:

        await require_room_owner_only(session, room_id, u["user_id"])

        await _purge_room_storage_files(session, int(room_id))

        await session.execute(
            sql_i("DELETE FROM chat_files WHERE room_id = :rid", "rid"),
            {"rid": int(room_id)},
        )
        await session.execute(
            sql_i("DELETE FROM chat_rooms WHERE id = :rid", "rid"),
            {"rid": int(room_id)},
        )

        await session.commit()

    return Response(status_code=204)


@app.post("/rooms/{room_id}/invite", status_code=201)
async def rooms_invite(room_id: int, payload: RoomInviteIn, request: Request, authorization: str | None = Header(default=None)):

    u = require_user_from_bearer(authorization)
    target_username = (payload.username or "").strip() 

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:invite:ip:{ip}", RL_ROOMS_INVITE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:invite:user:{int(u['user_id'])}", RL_ROOMS_INVITE_USER_PER_10MIN, 600)

    if not target_username:
        raise HTTPException(status_code=400, detail="username required")
    
    if len(target_username) > 32:
        raise HTTPException(status_code=400, detail="username too long")

    target_user_id = await get_user_id_by_username(target_username)
    if not target_user_id:
        raise HTTPException(status_code=404, detail="User not found")
    
    if int(target_user_id) == int(u["user_id"]):
        raise HTTPException(status_code=400, detail="can't invite yourself")
        
    async with SessionLocal() as session:
        
        res = await session.execute(sql_i("""
            SELECT id, name, alias
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": room_id})
        room = res.mappings().first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        
        await require_room_moderator(session, room_id, u["user_id"])
        
        invitee_profile = await get_profile_row(session, int(target_user_id))
        allow_from_non_friends = bool((invitee_profile.get("privacy") or {}).get(
            "allow_group_invites_from_non_friends", False
        ))

        if not allow_from_non_friends:
            if not await are_friends(session, int(u["user_id"]), int(target_user_id)):
                raise HTTPException(status_code=403, detail="User doesn't accept group invites from non-friends")

        # 3) invitee state: accepted/pending/none/declined
        cur = await session.execute(sql_i("""
            SELECT status
            FROM chat_room_members
            WHERE room_id = :rid AND user_id = :uid
            LIMIT 1
        """, "rid", "uid"), {"rid": room_id, "uid": target_user_id})
        st = cur.scalar_one_or_none()  # 'accepted' | 'pending' | 'declined' | None | ...

        # already accepted -> no-op
        if st == "accepted":
            return {
                "ok": True,
                "room_id": room_id,
                "invited_username": target_username,
                "status": "already_member",
            }
        
        if st == "pending":
            await session.execute(sql_i("""
                UPDATE chat_room_members
                SET invited_by = :by
                WHERE room_id = :rid AND user_id = :uid AND status = 'pending'
            """, "by", "rid", "uid"), {"rid": room_id, "uid": target_user_id, "by": u["user_id"]})

            await session.commit()

            return {
                "ok": True,
                "room_id": room_id,
                "invited_username": target_username,
                "status": "already_invited",
            }
        
        if st == "requested":
            # User already requested to join — convert to pending invite
            await session.execute(sql_i("""
                UPDATE chat_room_members
                SET role = 'member',
                    invited_by = :by,
                    status = 'pending'
                WHERE room_id = :rid
                  AND user_id = :uid
                  AND status = 'requested'
            """, "by", "rid", "uid"), {"rid": room_id, "uid": target_user_id, "by": u["user_id"]})

            await session.commit()

            return {
                "ok": True,
                "room_id": room_id,
                "invited_username": target_username,
                "status": "invited",
            }

        if st in ("declined", "rejected", "kicked"):
            # Only room owner can re-invite kicked users
            if st == "kicked":
                res_owner = await session.execute(sql_i("""
                    SELECT 1 FROM chat_rooms
                    WHERE id = :rid AND owner_user_id = :uid
                    LIMIT 1
                """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
                if not res_owner.scalar_one_or_none():
                    raise HTTPException(status_code=403, detail="Only room owner can re-invite kicked users")

            await session.execute(sql_i("""
                UPDATE chat_room_members
                SET role = 'member',
                    invited_by = :by,
                    status = 'pending'
                WHERE room_id = :rid
                  AND user_id = :uid
                  AND status IN ('declined', 'rejected', 'kicked')
            """, "by", "rid", "uid"), {"rid": room_id, "uid": target_user_id, "by": u["user_id"]})

            await session.commit()

            return {
                "ok": True,
                "room_id": room_id,
                "invited_username": target_username,
                "status": "reinvited",
            }
       
        if st is None:
            await session.execute(sql_i("""
                INSERT INTO chat_room_members (room_id, user_id, role, invited_by, status)
                VALUES (:rid, :uid, 'member', :by, 'pending')
                ON CONFLICT (room_id, user_id)
                DO UPDATE SET
                    role = 'member',
                    invited_by = EXCLUDED.invited_by,
                    status = CASE
                        WHEN chat_room_members.status = 'accepted' THEN 'accepted'
                        ELSE 'pending'
                    END
            """, "by", "rid", "uid"), {"rid": room_id, "uid": target_user_id, "by": u["user_id"]})

            await session.commit()

            return {
                "ok": True,
                "room_id": room_id,
                "invited_username": target_username,
                "status": "invited",
            }

        # unknown state -> stop
        raise HTTPException(status_code=400, detail="Invalid member state")

@app.post("/rooms/{room_id}/kick", status_code=200)
async def rooms_kick(room_id: int, payload: RoomKickIn, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:kick:ip:{ip}", RL_ROOMS_KICK_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:kick:user:{int(u['user_id'])}", RL_ROOMS_KICK_USER_PER_10MIN, 600)

    target_username = (payload.username or "").strip()
    if not target_username:
        raise HTTPException(status_code=400, detail="username required")

    target_user_id = await get_user_id_by_username(target_username)
    if not target_user_id:
        raise HTTPException(status_code=404, detail="User not found")
    
    if int(target_user_id) == int(u["user_id"]):
        raise HTTPException(status_code=400, detail="Cannot kick yourself")

    removed = False

    async with SessionLocal() as session:
       
        res = await session.execute(
            sql_i("""
                SELECT id
                FROM chat_rooms
                WHERE id = :rid
            """, "rid"),
            {"rid": int(room_id)},
        )
        room = res.mappings().first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")
        
        actor_role = await require_room_moderator(session, int(room_id), int(u["user_id"]))
        
        target_role = await get_room_role(session, int(room_id), int(target_user_id))
        if not target_role:
            
            removed = False
        else:
            
            if target_role == ROLE_OWNER:
                raise HTTPException(status_code=400, detail="Cannot kick room owner")
            
            if actor_role == ROLE_ADMIN and target_role == ROLE_ADMIN:
                raise HTTPException(status_code=403, detail="Admin cannot kick another admin")
            
            r1 = await session.execute(
                sql_i("""
                    UPDATE chat_room_members
                    SET status = 'kicked'
                    WHERE room_id = :rid AND user_id = :uid AND status = 'accepted'
                """, "rid", "uid"),
                {"rid": int(room_id), "uid": int(target_user_id)},
            )
            removed = bool((r1.rowcount or 0) > 0)
            
            await session.execute(
                sql_i("""
                    DELETE FROM chat_room_keys
                    WHERE room_id = :rid AND user_id = :uid
                """, "rid", "uid"),
                {"rid": int(room_id), "uid": int(target_user_id)},
            )

            await session.commit()
    
    if removed:
        await manager.kick_user(str(room_id), target_username, code=1008, reason="kicked")
        
        await manager.broadcast(str(room_id), {
            "type": "members_changed",
            "ts": int(time.time()),
            "room_id": int(room_id),
            "action": "kick",
            "username": target_username,
        })
        
        await manager.broadcast(str(room_id), {
            "type": "presence",
            "ts": int(time.time()),
            "room_id": int(room_id),
            "online": manager.get_online(str(room_id)),
        })

    return {
        "ok": True,
        "room_id": int(room_id),
        "kicked_username": target_username,
        "removed": removed
    }


@app.get("/rooms/{room_id}/members")
async def rooms_members(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
       
        res = await session.execute(sql_i("""
            SELECT 1
            FROM chat_rooms r
            WHERE r.id = :rid AND (
              r.owner_user_id = :uid
              OR EXISTS (
                SELECT 1 FROM chat_room_members m
                WHERE m.room_id = r.id AND m.user_id = :uid
                  AND m.status = 'accepted'
              )
            )
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        if not res.first():
            raise HTTPException(status_code=403, detail="No access")

        rows = (await session.execute(sql_i("""
            SELECT
              u.username,
              COALESCE(m.role, 'owner') AS role,
              (r.owner_user_id = u.id) AS is_owner
            FROM chat_rooms r
            JOIN users u ON (u.id = r.owner_user_id)
            LEFT JOIN chat_room_members m ON (m.room_id = r.id AND m.user_id = u.id)
            WHERE r.id = :rid

            UNION ALL

            SELECT
              u.username,
              m.role,
              false AS is_owner
            FROM chat_room_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.room_id = :rid
              AND m.status = 'accepted'
              AND m.user_id <> (
                SELECT owner_user_id FROM chat_rooms WHERE id = :rid
              )
            ORDER BY username
        """, "rid"), {"rid": room_id})).mappings().all()

    return [
        {
            "username": r["username"],
            "role": (_normalize_room_role_value(r["role"]) or ROLE_MEMBER),
            "is_owner": bool(r["is_owner"]),
        }
        for r in rows
    ]


class SetRoleRequest(BaseModel):
    role: str = Field(..., description="New role: admin or member")


@app.post("/rooms/{room_id}/members/{target_username}/role")
async def rooms_set_member_role(
    room_id: int,
    target_username: str,
    body: SetRoleRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """
    Change a member's role in a room.
    Only owner can change roles.
    Cannot change owner's role (use transfer ownership instead).
    Cannot change own role.
    Valid roles: admin, member
    """
    u = require_user_from_bearer(authorization)
    actor_id = int(u["user_id"])
    actor_username = u["username"]

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:setrole:ip:{ip}", RL_ROOMS_SETROLE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:setrole:user:{actor_id}", RL_ROOMS_SETROLE_USER_PER_10MIN, 600)
    
    new_role = body.role.strip().lower()

    # Validate new role
    if new_role not in (ROLE_ADMIN, ROLE_MEMBER):
        raise HTTPException(status_code=400, detail="Invalid role. Must be 'admin' or 'member'")

    # Cannot change own role
    if target_username.lower() == actor_username.lower():
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    async with SessionLocal() as session:
        # 1) Room must exist
        room_res = await session.execute(
            sql_i("SELECT id, owner_user_id FROM chat_rooms WHERE id = :rid", "rid"),
            {"rid": room_id},
        )
        room = room_res.mappings().first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")

        # 2) Only owner can change roles
        await require_room_owner_only(session, room_id, actor_id)

        # 3) Get target user id
        target_res = await session.execute(
            text("SELECT id FROM users WHERE LOWER(username) = LOWER(:uname)"),
            {"uname": target_username},
        )
        target_user = target_res.mappings().first()
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        target_user_id = int(target_user["id"])

        # 4) Cannot change owner's role
        if target_user_id == int(room["owner_user_id"]):
            raise HTTPException(status_code=400, detail="Cannot change owner's role. Use transfer ownership instead.")

        # 5) Target must be an accepted member
        target_role = await get_room_role(session, room_id, target_user_id)
        if not target_role:
            raise HTTPException(status_code=400, detail="User is not an accepted member of this room")

        # 6) Update role (accepted-only)
        r = await session.execute(
            sql_i("""
                UPDATE chat_room_members
                SET role = :new_role
                WHERE room_id = :rid
                  AND user_id = :uid
                  AND status = 'accepted'
            """, "rid", "uid"),
            {"rid": room_id, "uid": target_user_id, "new_role": new_role},
        )
        if (r.rowcount or 0) == 0:
            raise HTTPException(status_code=400, detail="User is not an accepted member of this room")

        await session.commit()

    # 7) Notify all clients about role change
    await manager.broadcast(str(room_id), {
        "type": "members_changed",
        "ts": int(time.time()),
        "room_id": room_id,
        "action": "role_changed",
        "username": target_username,
        "new_role": new_role,
    })

    return {
        "ok": True,
        "room_id": room_id,
        "username": target_username,
        "new_role": new_role,
    }


@app.get("/rooms/list")
async def rooms_list(authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    user_id = u["user_id"]

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT
              r.id, r.name, r.alias, r.password_hash, r.is_public, r.is_readonly, r.created_at,
              r.logo_path,
              (r.owner_user_id = :uid) AS is_owner,
              COALESCE(m.role, CASE WHEN r.owner_user_id = :uid THEN 'owner' ELSE 'member' END) AS role,
              (SELECT MAX(msg.ts)
               FROM chat_messages msg
               WHERE msg.room_id = r.id) as last_message_at,
              (SELECT rs.seen_at
               FROM room_seen rs
               WHERE rs.room_id = r.id AND rs.user_id = :uid) as last_seen_at
            FROM chat_rooms r
            LEFT JOIN chat_room_members m ON m.room_id = r.id AND m.user_id = :uid AND m.status = 'accepted'
            WHERE r.owner_user_id = :uid
               OR EXISTS (
                   SELECT 1
                   FROM chat_room_members mem
                   WHERE mem.room_id = r.id AND mem.user_id = :uid
                   AND mem.status = 'accepted'
               )
            ORDER BY r.created_at DESC
        """, "uid"), {"uid": user_id})
        rows = res.mappings().all()

    return [{
        "id": int(r["id"]),
        "name": r["name"],
        "alias": r["alias"],
        "has_password": bool(r["password_hash"]),
        "created_at": r["created_at"],
        "is_owner": bool(r["is_owner"]),
        "role": r["role"] or "member",
        "is_public": bool(r.get("is_public")),
        "is_readonly": bool(r.get("is_readonly")),
        "logo_url": f"/rooms/{r['id']}/logo" if r.get("logo_path") else None,
        "last_message_at": r["last_message_at"].isoformat() if r.get("last_message_at") else None,
        "last_seen_at": r["last_seen_at"].isoformat() if r.get("last_seen_at") else None,
    } for r in rows]

# ============================
# Public rooms: approval flow
# ============================

@app.get("/rooms/public/list")
async def rooms_public_list(authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT
              r.id, r.name, r.alias, r.password_hash, r.is_public, r.is_readonly, r.created_at,
              r.logo_path,
              (r.owner_user_id = :uid) AS is_owner,
              COALESCE(m.status, '') AS my_status
            FROM chat_rooms r
            LEFT JOIN chat_room_members m
              ON m.room_id = r.id AND m.user_id = :uid
            WHERE r.is_public = true
            ORDER BY r.created_at DESC
        """, "uid"), {"uid": int(u["user_id"])})
        rows = res.mappings().all()

    return [{
        "id": int(r["id"]),
        "name": r["name"],
        "alias": r["alias"],
        "has_password": bool(r["password_hash"]),
        "created_at": r["created_at"],
        "is_public": bool(r.get("is_public")),
        "is_readonly": bool(r.get("is_readonly")),
        "is_owner": bool(r["is_owner"]),
        "logo_url": f"/rooms/{r['id']}/logo" if r.get("logo_path") else None,
        "my_status": (r.get("my_status") or "") or None,  # None | requested | accepted
    } for r in rows]

@app.post("/rooms/{room_id}/join-request")
async def rooms_join_request(room_id: int, payload: RoomJoinRequestIn, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"]) 

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:joinreq:ip:{ip}:{int(room_id)}", RL_ROOMS_JOINREQ_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:joinreq:user:{user_id}:{int(room_id)}", RL_ROOMS_JOINREQ_USER_PER_10MIN, 600)

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT id, password_hash, is_public
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": int(room_id)})
        room = res.mappings().first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")

        if not bool(room.get("is_public")):
            raise HTTPException(status_code=400, detail="Room is not public")
        
        if room.get("password_hash"):
            p = (payload.password or "").strip()
            if not p or not verify_password(p, room["password_hash"]):
                raise HTTPException(status_code=403, detail="Bad room password")

        # Block kicked/rejected users from re-requesting — only owner can re-invite them
        cur = await session.execute(sql_i("""
            SELECT status FROM chat_room_members
            WHERE room_id = :rid AND user_id = :uid
            LIMIT 1
        """, "rid", "uid"), {"rid": int(room_id), "uid": user_id})
        existing_status = cur.scalar_one_or_none()
        if existing_status in ("kicked", "rejected"):
            raise HTTPException(status_code=403, detail="You cannot rejoin this room")

        await session.execute(sql_i("""
            INSERT INTO chat_room_members (room_id, user_id, role, invited_by, status)
            VALUES (:rid, :uid, 'member', NULL, 'requested')
            ON CONFLICT (room_id, user_id)
            DO UPDATE
              SET status = 'requested'
            WHERE chat_room_members.status IS DISTINCT FROM 'accepted'
              AND chat_room_members.status NOT IN ('kicked', 'rejected')
        """, "rid", "uid"), {"rid": int(room_id), "uid": user_id})

        await session.commit()

    return {"ok": True, "room_id": int(room_id), "status": "requested"}

@app.get("/rooms/{room_id}/join-requests")
async def rooms_join_requests(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    admin_id = int(u["user_id"])

    async with SessionLocal() as session:
        
        res = await session.execute(sql_i("""
            SELECT 1
            FROM chat_rooms
            WHERE id = :rid AND owner_user_id = :uid
            LIMIT 1
        """, "rid", "uid"), {"rid": int(room_id), "uid": admin_id})
        if not res.first():
            raise HTTPException(status_code=403, detail="Owner access required")

        res2 = await session.execute(sql_i("""
            SELECT u.username
            FROM chat_room_members m
            JOIN users u ON u.id = m.user_id
            WHERE m.room_id = :rid
              AND COALESCE(m.status,'') = 'requested'
            ORDER BY u.username
        """, "rid"), {"rid": int(room_id)})
        rows = res2.mappings().all()

    return [{"username": r["username"]} for r in rows]

@app.post("/rooms/{room_id}/join-requests/{username}/approve")
async def rooms_join_approve(room_id: int, username: str, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    admin_id = int(u["user_id"])
    
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:joinadm:ip:{ip}", RL_ROOMS_JOINADM_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:joinadm:user:{admin_id}", RL_ROOMS_JOINADM_USER_PER_10MIN, 600)
    
    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    async with SessionLocal() as session:
        
        res = await session.execute(sql_i("""
            SELECT 1
            FROM chat_rooms
            WHERE id = :rid AND owner_user_id = :uid
            LIMIT 1
        """, "rid", "uid"), {"rid": int(room_id), "uid": admin_id})
        if not res.first():
            raise HTTPException(status_code=403, detail="Owner access required")

        target_user_id = await get_user_id_by_username(username)
        if not target_user_id:
            raise HTTPException(status_code=404, detail="User not found")

        res2 = await session.execute(sql_i("""
            UPDATE chat_room_members
            SET status = 'accepted'
            WHERE room_id = :rid
              AND user_id = :uid
              AND status IN ('requested', 'pending')
            RETURNING user_id
        """, "rid", "uid"), {"rid": int(room_id), "uid": int(target_user_id)})
        if not res2.first():
            raise HTTPException(status_code=404, detail="Join request not found")

        await session.commit()

        # notify clients in the room: membership changed
    await manager.broadcast(str(room_id), {
        "type": "members_changed",
        "ts": int(time.time()),
        "room_id": int(room_id),
        "action": "join_approved",
        "username": username,
    })

    # (optional) presence refresh for UI
    await manager.broadcast(str(room_id), {
        "type": "presence",
        "ts": int(time.time()),
        "room_id": int(room_id),
        "online": manager.get_online(str(room_id)),
    })
    
    return {"ok": True, "room_id": int(room_id), "username": username, "status": "accepted"}

@app.post("/rooms/{room_id}/join-requests/{username}/reject")
async def rooms_join_reject(room_id: int, username: str, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    admin_id = int(u["user_id"])
    
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:joinadm:ip:{ip}", RL_ROOMS_JOINADM_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:joinadm:user:{admin_id}", RL_ROOMS_JOINADM_USER_PER_10MIN, 600)
    
    username = (username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    async with SessionLocal() as session:
        
        res = await session.execute(sql_i("""
            SELECT 1
            FROM chat_rooms
            WHERE id = :rid AND owner_user_id = :uid
            LIMIT 1
        """, "rid", "uid"), {"rid": int(room_id), "uid": admin_id})
        if not res.first():
            raise HTTPException(status_code=403, detail="Owner access required")

        target_user_id = await get_user_id_by_username(username)
        if not target_user_id:
            raise HTTPException(status_code=404, detail="User not found")

        res2 = await session.execute(sql_i("""
            UPDATE chat_room_members
            SET status = 'rejected'
            WHERE room_id = :rid
              AND user_id = :uid
              AND status IN ('requested', 'pending')
            RETURNING user_id
        """, "rid", "uid"), {"rid": int(room_id), "uid": int(target_user_id)})
        if not res2.first():
            raise HTTPException(status_code=404, detail="Join request not found")

        await session.commit()

    return {"ok": True, "room_id": int(room_id), "username": username, "status": "rejected"}

@app.get("/rooms/invites")
async def rooms_invites_incoming(authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT
              m.room_id,
              r.name AS room_name,
              r.alias AS room_alias,
              r.created_at AS room_created_at,
              m.invited_by,
              iu.username AS invited_by_username
            FROM chat_room_members m
            JOIN chat_rooms r ON r.id = m.room_id
            LEFT JOIN users iu ON iu.id = m.invited_by
            WHERE m.user_id = :uid AND m.status = 'pending'
            ORDER BY r.created_at DESC
        """, "uid"), {"uid": u["user_id"]})
        rows = res.mappings().all()

    return [
        {
            "room_id": int(x["room_id"]),
            "room_name": x["room_name"],
            "room_alias": x["room_alias"],
            "invited_by": int(x["invited_by"]) if x["invited_by"] is not None else None,
            "invited_by_username": x["invited_by_username"],
            "room_created_at": x["room_created_at"],
        }
        for x in rows
    ]

@app.post("/rooms/{room_id}/invites/accept")
async def rooms_invite_accept(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            UPDATE chat_room_members
            SET status = 'accepted'
            WHERE room_id = :rid AND user_id = :uid AND status = 'pending'
            RETURNING room_id
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        row = res.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Invite not found")
        await session.commit()

        actor_username = str(u.get("username") or "").strip()

    await manager.broadcast(str(room_id), {
        "type": "members_changed",
        "ts": int(time.time()),
        "room_id": int(room_id),
        "action": "invite_accepted",
        "username": actor_username or None,
    })

    await manager.broadcast(str(room_id), {
        "type": "presence",
        "ts": int(time.time()),
        "room_id": int(room_id),
        "online": manager.get_online(str(room_id)),
    })

    return {"ok": True, "room_id": int(room_id)}

@app.post("/rooms/{room_id}/invites/decline")
async def rooms_invite_decline(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            DELETE FROM chat_room_members
            WHERE room_id = :rid AND user_id = :uid AND status = 'pending'
            RETURNING room_id
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        row = res.scalar_one_or_none()
        if not row:
            raise HTTPException(status_code=404, detail="Invite not found")
        await session.commit()

    return {"ok": True, "room_id": int(room_id)}

@app.post("/rooms/{room_id}/leave", status_code=200)
async def rooms_leave(room_id: int, authorization: str | None = Header(default=None)):
    """Leave a room (remove yourself from members). Owner cannot leave (should delete the room)."""
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"])
    username = u.get("username") or ""

    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT id, owner_user_id
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": room_id})
        room = res.mappings().first()
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")

        if int(room["owner_user_id"]) == user_id:
            raise HTTPException(status_code=400, detail="Owner cannot leave; delete the room")

        r1 = await session.execute(sql_i("""
            DELETE FROM chat_room_members
            WHERE room_id = :rid AND user_id = :uid
        """, "rid", "uid"), {"rid": room_id, "uid": user_id})

        await session.execute(sql_i("""
            DELETE FROM chat_room_keys
            WHERE room_id = :rid AND user_id = :uid
        """, "rid", "uid"), {"rid": room_id, "uid": user_id})

        await session.commit()

    if username:
        await manager.kick_user(str(room_id), username, code=1000, reason="left")

    # NEW: notify everyone to refresh members list
    await manager.broadcast(str(room_id), {
        "type": "members_changed",
        "ts": int(time.time()),
        "room_id": int(room_id),
        "action": "leave",
        "username": username,
    })

    await manager.broadcast(str(room_id), {
        "type": "presence",
        "ts": int(time.time()),
        "room_id": room_id,
        "online": manager.get_online(str(room_id)),
    })

    return {"ok": True, "room_id": room_id, "removed": bool((r1.rowcount or 0) > 0)}

@app.post("/friends/request", status_code=201)
async def friends_request(request: Request, payload: FriendRequestIn, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:req:ip:{ip}", RL_FRIENDS_REQ_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:req:user:{int(u['user_id'])}", RL_FRIENDS_REQ_USER_PER_10MIN, 600)

    target_username = (payload.username or "").strip()
    if not target_username:
        raise HTTPException(status_code=400, detail="username required")

    target_user_id = await get_user_id_by_username(target_username)
    if not target_user_id:
        raise HTTPException(status_code=404, detail="User not found")

    if int(target_user_id) == int(u["user_id"]):
        raise HTTPException(status_code=400, detail="Cannot add yourself")

    async with SessionLocal() as session:
        await ensure_not_banned(session, int(u["user_id"]))

        res = await session.execute(text("""
            SELECT id, requester_id, addressee_id, status, responded_at
            FROM chat_friendships
            WHERE LEAST(requester_id, addressee_id) = LEAST(CAST(:a AS bigint), CAST(:b AS bigint))
              AND GREATEST(requester_id, addressee_id) = GREATEST(CAST(:a AS bigint), CAST(:b AS bigint))
            LIMIT 1
        """), {"a": u["user_id"], "b": target_user_id})
        row = res.mappings().first()

        if row:
            if row["status"] == "accepted":
                return {"ok": True, "status": "accepted", "message": "Already friends"}
            if row["status"] == "pending":
                return {"ok": True, "status": "pending", "message": "Request already exists"}

            if row["status"] in ("declined",):
                # Cooldown: prevent harassment via repeated re-requests
                if row.get("responded_at"):
                    cooldown_end = row["responded_at"] + timedelta(seconds=FRIENDS_DECLINE_COOLDOWN_SEC)
                    if datetime.now(timezone.utc) < cooldown_end:
                        raise HTTPException(status_code=429, detail="Request was declined recently; please wait before re-sending")

                await session.execute(sql_i("""
                    UPDATE chat_friendships
                        SET status='pending',
                        requester_id=CAST(:a AS bigint),
                        addressee_id=CAST(:b AS bigint),
                        created_at=now(),
                        responded_at=NULL
                    WHERE id=:id
                """, "id"), {"id": row["id"], "a": u["user_id"], "b": target_user_id})
                await session.commit()
                return {"ok": True, "status": "pending", "message": "Request re-sent"}

            raise HTTPException(status_code=403, detail=f"Cannot request: status={row['status']}")

        await session.execute(text("""
            INSERT INTO chat_friendships (requester_id, addressee_id, status)
            VALUES (CAST(:a AS bigint), CAST(:b AS bigint), 'pending')
        """), {"a": u["user_id"], "b": target_user_id})
        await session.commit()

    return {"ok": True, "status": "pending"}

@app.get("/friends/requests/incoming")
async def friends_requests_incoming(request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:list:ip:{ip}", RL_FRIENDS_LIST_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:list:user:{int(u['user_id'])}", RL_FRIENDS_LIST_USER_PER_10MIN, 600)
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT u1.username AS from_username, f.created_at
            FROM chat_friendships f
            JOIN users u1 ON u1.id = f.requester_id
            WHERE f.addressee_id = :uid AND f.status = 'pending'
            ORDER BY f.created_at DESC
        """, "uid"), {"uid": u["user_id"]})
        rows = res.mappings().all()
    return [{"from_username": r["from_username"], "created_at": r["created_at"]} for r in rows]

@app.get("/friends/requests/outgoing")
async def friends_requests_outgoing(request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:list:ip:{ip}", RL_FRIENDS_LIST_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:list:user:{int(u['user_id'])}", RL_FRIENDS_LIST_USER_PER_10MIN, 600)
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT u2.username AS to_username, f.created_at
            FROM chat_friendships f
            JOIN users u2 ON u2.id = f.addressee_id
            WHERE f.requester_id = :uid AND f.status = 'pending'
            ORDER BY f.created_at DESC
        """, "uid"), {"uid": u["user_id"]})
        rows = res.mappings().all()
    return [{"to_username": r["to_username"], "created_at": r["created_at"]} for r in rows]

@app.get("/friends/list")
async def friends_list(request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:list:ip:{ip}", RL_FRIENDS_LIST_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:list:user:{int(u['user_id'])}", RL_FRIENDS_LIST_USER_PER_10MIN, 600)
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT
              CASE
                WHEN f.requester_id = :uid THEN u2.username
                ELSE u1.username
              END AS username,
              f.created_at
            FROM chat_friendships f
            JOIN users u1 ON u1.id = f.requester_id
            JOIN users u2 ON u2.id = f.addressee_id
            WHERE (f.requester_id = :uid OR f.addressee_id = :uid)
              AND f.status = 'accepted'
            ORDER BY username ASC
        """, "uid"), {"uid": u["user_id"]})
        rows = res.mappings().all()
    return [{"username": r["username"], "created_at": r["created_at"]} for r in rows]

# main.py

@app.post("/friends/remove")
async def friends_remove(payload: FriendRequestActionIn, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:action:ip:{ip}", RL_FRIENDS_ACTION_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:action:user:{int(u['user_id'])}", RL_FRIENDS_ACTION_USER_PER_10MIN, 600)

    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    other_id = await get_user_id_by_username(username)
    if not other_id:
        raise HTTPException(status_code=404, detail="User not found")

    async with SessionLocal() as session:
        await ensure_not_banned(session, int(u["user_id"]))

        res = await session.execute(sql_i("""
            DELETE FROM chat_friendships
            WHERE status = 'accepted'
              AND (
                (requester_id = :me AND addressee_id = :other)
                OR
                (requester_id = :other AND addressee_id = :me)
              )
            RETURNING id
        """, "me", "other"), {"me": u["user_id"], "other": other_id})

        row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="Friendship not found")

        await session.commit()

    return {"ok": True, "removed": True}

@app.post("/friends/requests/accept")
async def friends_accept(payload: FriendRequestActionIn, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:action:ip:{ip}", RL_FRIENDS_ACTION_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:action:user:{int(u['user_id'])}", RL_FRIENDS_ACTION_USER_PER_10MIN, 600)

    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    other_id = await get_user_id_by_username(username)
    if not other_id:
        raise HTTPException(status_code=404, detail="User not found")

    async with SessionLocal() as session:
        await ensure_not_banned(session, int(u["user_id"]))

        res = await session.execute(sql_i("""
            UPDATE chat_friendships
            SET status='accepted', responded_at=now()
            WHERE requester_id=:other
              AND addressee_id=:me
              AND status='pending'
            RETURNING id
        """, "me", "other"), {"other": other_id, "me": u["user_id"]})
        row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="No pending request to accept")
        await session.commit()

    return {"ok": True, "status": "accepted"}

@app.post("/friends/requests/decline")
async def friends_decline(payload: FriendRequestActionIn, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"friends:action:ip:{ip}", RL_FRIENDS_ACTION_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"friends:action:user:{int(u['user_id'])}", RL_FRIENDS_ACTION_USER_PER_10MIN, 600)

    username = (payload.username or "").strip()
    if not username:
        raise HTTPException(status_code=400, detail="username required")

    other_id = await get_user_id_by_username(username)
    if not other_id:
        raise HTTPException(status_code=404, detail="User not found")

    async with SessionLocal() as session:
        await ensure_not_banned(session, int(u["user_id"]))

        res = await session.execute(sql_i("""
            UPDATE chat_friendships
            SET status='declined', responded_at=now()
            WHERE requester_id=:other
              AND addressee_id=:me
              AND status='pending'
            RETURNING id
        """, "me", "other"), {"other": other_id, "me": u["user_id"]})
        row = res.first()
        if not row:
            raise HTTPException(status_code=404, detail="No pending request to decline")
        await session.commit()

    return {"ok": True, "status": "declined"}

# ====================== REPORTS ======================

REPORT_REASONS = {"spam", "harassment", "hate_speech", "illegal_content", "impersonation", "other"}
REPORT_TARGET_TYPES = {"user", "message", "room"}

RL_REPORT_PER_5MIN = _env_int("RL_REPORT_PER_5MIN", 5)


class ReportIn(BaseModel):
    target_type: str
    target_id: int = 0
    target_username: str | None = None
    reason: str
    comment: str = ""
    reported_content: list[dict] | None = None


@app.post("/reports", status_code=201)
async def create_report(
    payload: ReportIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    uid = u["user_id"]

    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(
        f"report:ip:{ip}", RL_REPORT_PER_5MIN, 300,
        detail="Too many reports, please wait",
    )

    # ── валидация ──
    if payload.target_type not in REPORT_TARGET_TYPES:
        raise HTTPException(400, f"target_type must be one of: {', '.join(sorted(REPORT_TARGET_TYPES))}")
    if payload.reason not in REPORT_REASONS:
        raise HTTPException(400, f"reason must be one of: {', '.join(sorted(REPORT_REASONS))}")

    comment = (payload.comment or "").strip()[:2000]

    # ── E2E: reported_content ──
    reported_content_json = None
    if payload.reported_content is not None:
        # максимум 11 сообщений (1 целевое + 5 сверху + 5 снизу)
        items = payload.reported_content[:11]
        sanitized = []
        for item in items:
            sanitized.append({
                "author": str(item.get("author", ""))[:100],
                "text":   str(item.get("text", ""))[:5000],
                "ts":     str(item.get("ts", ""))[:50],
            })
        if sanitized:
            import json
            reported_content_json = json.dumps(sanitized, ensure_ascii=False)

    # resolve target_username → target_id для user reports
    if payload.target_type == "user" and not payload.target_id and payload.target_username:
        uname = payload.target_username.strip()
        if not uname:
            raise HTTPException(400, "target_username is empty")
        async with SessionLocal() as session:
            row = await session.execute(
                text("SELECT id FROM users WHERE LOWER(username)=LOWER(:u)"),
                {"u": uname},
            )
            found = row.scalars().first()
            if not found:
                raise HTTPException(404, "User not found")
            payload.target_id = int(found)

    if not payload.target_id:
        raise HTTPException(400, "target_id is required (or target_username for user reports)")

    if payload.target_type == "user" and payload.target_id == uid:
        raise HTTPException(400, "Cannot report yourself")

    async with SessionLocal() as session:
        await ensure_not_banned(session, uid)

        if payload.target_type == "user":
            row = await session.execute(
                text("SELECT id FROM users WHERE id=:id"), {"id": payload.target_id}
            )
            if not row.first():
                raise HTTPException(404, "User not found")

        elif payload.target_type == "room":
            row = await session.execute(
                text("SELECT id FROM chat_rooms WHERE id=:id"), {"id": payload.target_id}
            )
            if not row.first():
                raise HTTPException(404, "Room not found")

        elif payload.target_type == "message":
            row = await session.execute(
                text("""
                    SELECT m.id, m.room_id
                    FROM chat_messages m
                    WHERE m.id = :id
                """), {"id": payload.target_id}
            )
            msg_row = row.mappings().first()
            if not msg_row:
                raise HTTPException(404, "Message not found")
            # Verify reporter has access to the room containing the message
            if msg_row.get("room_id"):
                await require_room_access(session, int(msg_row["room_id"]), uid)

        # INSERT (unique index idx_reports_no_dup)
        try:
            await session.execute(
                text("""
                    INSERT INTO reports (reporter_id, target_type, target_id, reason, comment, reported_content)
                    VALUES (:reporter_id, :target_type, :target_id, :reason, :comment, (:reported_content)::jsonb)
                """),
                {
                    "reporter_id": uid,
                    "target_type": payload.target_type,
                    "target_id": payload.target_id,
                    "reason": payload.reason,
                    "comment": comment,
                    "reported_content": reported_content_json,
                },
            )
            await session.commit()
        except IntegrityError:
            raise HTTPException(409, "You already have an active report on this target")

    return {"ok": True, "message": "Report submitted"}

@app.post("/rooms/{room_id}/files", status_code=201)
async def upload_file(
    room_id: int,
    request: Request,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    content_length: int | None = Header(default=None, alias="Content-Length"),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"upload:ip:{ip}", RL_UPLOAD_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"upload:user:{int(u['user_id'])}", RL_UPLOAD_USER_PER_10MIN, 600)

    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="File required")
    
    if content_length is not None and content_length > (MAX_UPLOAD_BYTES + 2 * 1024 * 1024):
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    token = secrets.token_urlsafe(18)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=FILE_TTL_DAYS)

    safe_name = os.path.basename(file.filename)

    final_path = (UPLOAD_DIR / token).resolve()
    tmp_path = (UPLOAD_DIR / f"{token}.part").resolve()

    size = 0
    
    async with SessionLocal() as session:
        await _ensure_chat_files_dm_support(session)
        await require_room_access(session, room_id, u["user_id"])

        # Enforce read-only policy server-side as well (not only in UI).
        rr = await session.execute(sql_i("""
            SELECT is_readonly
            FROM chat_rooms
            WHERE id = :rid
            LIMIT 1
        """, "rid"), {"rid": int(room_id)})
        room_row = rr.mappings().first()
        if not room_row:
            raise HTTPException(status_code=404, detail="Room not found")
        if bool(room_row.get("is_readonly")):
            role = await get_room_role(session, int(room_id), int(u["user_id"]))
            if role not in (ROLE_OWNER, ROLE_ADMIN):
                raise HTTPException(status_code=403, detail="Room is read-only: only owner/admin can upload files")

    try:
        
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File too large (max 100MB)")
                out.write(chunk)
        
        os.replace(tmp_path, final_path)

        async with SessionLocal() as session:
            await _ensure_chat_files_dm_support(session)
            await require_room_access(session, room_id, u["user_id"])
            # Re-check right before DB insert to avoid race with room policy changes.
            rr = await session.execute(sql_i("""
                SELECT is_readonly
                FROM chat_rooms
                WHERE id = :rid
                LIMIT 1
            """, "rid"), {"rid": int(room_id)})
            room_row = rr.mappings().first()
            if not room_row:
                raise HTTPException(status_code=404, detail="Room not found")
            if bool(room_row.get("is_readonly")):
                role = await get_room_role(session, int(room_id), int(u["user_id"]))
                if role not in (ROLE_OWNER, ROLE_ADMIN):
                    raise HTTPException(status_code=403, detail="Room is read-only: only owner/admin can upload files")

            await session.execute(sql_i("""
                INSERT INTO chat_files
                  (token, room_id, thread_id, uploader_user_id, original_name, content_type, size_bytes, storage_path, expires_at)
                VALUES
                  (:token, :room_id, NULL, :uid, :oname, :ctype, :size, :spath, :exp)
            """, "room_id", "uid"), {
                "token": token,
                "room_id": room_id,
                "uid": u["user_id"],
                "oname": safe_name,
                "ctype": file.content_type or "application/octet-stream",
                "size": size,
                "spath": str(final_path),
                "exp": expires_at,
            })
            await session.commit()

    except HTTPException:
        
        for p in (tmp_path, final_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        raise
    except Exception:
        logging.getLogger("wsapp.upload").exception(
            "room upload failed: room=%s user=%s", room_id, u.get("user_id")
        )
        for p in (tmp_path, final_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail="Upload failed")
    finally:
        try:
            await file.close()
        except Exception:
            pass

    return {
        "token": token,
        "filename": safe_name,
        "content_type": file.content_type,
        "size_bytes": size,
        "expires_at": expires_at.isoformat(),
        "url": f"/files/{token}",
    }

@app.post("/dm/{thread_id}/files", status_code=201)
async def upload_dm_file(
    thread_id: int,
    request: Request,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    content_length: int | None = Header(default=None, alias="Content-Length"),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"dmupload:ip:{ip}", RL_UPLOAD_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"dmupload:user:{int(u['user_id'])}", RL_UPLOAD_USER_PER_10MIN, 600)

    if thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="File required")
    if content_length is not None and content_length > (MAX_UPLOAD_BYTES + 2 * 1024 * 1024):
        raise HTTPException(status_code=413, detail="File too large (max 100MB)")

    token = secrets.token_urlsafe(18)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=FILE_TTL_DAYS)
    safe_name = os.path.basename(file.filename)
    final_path = (UPLOAD_DIR / token).resolve()
    tmp_path = (UPLOAD_DIR / f"{token}.part").resolve()
    size = 0

    async with SessionLocal() as session:
        await _ensure_chat_files_dm_support(session)
        await require_dm_access(session, thread_id, u["user_id"])

    try:
        with open(tmp_path, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="File too large (max 100MB)")
                out.write(chunk)
        os.replace(tmp_path, final_path)

        async with SessionLocal() as session:
            await _ensure_chat_files_dm_support(session)
            await require_dm_access(session, thread_id, u["user_id"])
            await session.execute(text("""
                INSERT INTO chat_files
                  (token, room_id, thread_id, uploader_user_id, original_name, content_type, size_bytes, storage_path, expires_at)
                VALUES
                  (:token, NULL, :thread_id, :uid, :oname, :ctype, :size, :spath, :exp)
            """), {
                "token": token,
                "thread_id": int(thread_id),
                "uid": u["user_id"],
                "oname": safe_name,
                "ctype": file.content_type or "application/octet-stream",
                "size": size,
                "spath": str(final_path),
                "exp": expires_at,
            })
            await session.commit()
    except HTTPException:
        for p in (tmp_path, final_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        raise
    except Exception:
        logging.getLogger("wsapp.upload").exception(
            "dm upload failed: thread=%s user=%s", thread_id, u.get("user_id")
        )
        for p in (tmp_path, final_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail="Upload failed")
    finally:
        try:
            await file.close()
        except Exception:
            pass

    return {
        "token": token,
        "filename": safe_name,
        "content_type": file.content_type,
        "size_bytes": size,
        "expires_at": expires_at.isoformat(),
        "url": f"/files/{token}",
    }

@app.get("/files/{token}")
async def download_file(token: str, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        await _ensure_chat_files_dm_support(session)
        res = await session.execute(text("""
            SELECT f.token, f.room_id, f.thread_id, f.original_name, f.content_type, f.size_bytes,
                   f.storage_path, f.expires_at
            FROM chat_files f
            WHERE f.token = :t
        """), {"t": token})
        row = res.mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="File not found")
        
        now = datetime.now(timezone.utc)
        if row["expires_at"] and row["expires_at"] < now:
            try:
                if row["storage_path"] and os.path.exists(row["storage_path"]):
                    os.remove(row["storage_path"])
            except Exception:
                pass
            await session.execute(text("DELETE FROM chat_files WHERE token = :t"), {"t": token})
            await session.commit()
            raise HTTPException(status_code=404, detail="File expired")

        room_id = row["room_id"]
        thread_id = row["thread_id"]
        if thread_id is not None:
            await require_dm_access(session, int(thread_id), u["user_id"])
        elif room_id is not None:
            await require_room_access(session, int(room_id), u["user_id"])
        else:
            raise HTTPException(status_code=500, detail="File access binding is missing")

        path = row["storage_path"]
        if not path or not os.path.exists(path):
            raise HTTPException(status_code=404, detail="File missing on storage")

        return FileResponse(
            path,
            media_type=row["content_type"] or "application/octet-stream",
            filename=row["original_name"],
        )

import json
from fastapi import Header, HTTPException
from sqlalchemy import text

@app.post("/dm/open")
async def dm_open(payload: DmOpenIn, request: Request, authorization: str | None = Header(default=None)):
    me = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"dm:open:ip:{ip}", RL_DM_OPEN_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"dm:open:user:{int(me['user_id'])}", RL_DM_OPEN_USER_PER_10MIN, 600)
    peer_name = (payload.username or "").strip()
    if not peer_name:
        raise HTTPException(400, "username required")

    async with SessionLocal() as session:
        # peer id
        r = await session.execute(text("SELECT id FROM users WHERE LOWER(username)=LOWER(:u)"), {"u": peer_name})
        peer_id = r.scalar_one_or_none()
        if peer_id is None:
            raise HTTPException(404, "User not found")
        peer_id = int(peer_id)

        me_id = int(me["user_id"])

        if peer_id == me_id:
            raise HTTPException(400, "Cannot DM yourself")
        
        await session.execute(sql_i("""
            INSERT INTO chat_user_profiles(user_id, about, privacy)
            VALUES (:uid, '', CAST(:privacy AS jsonb))
            ON CONFLICT (user_id) DO NOTHING
        """, "uid"), {"uid": peer_id, "privacy": json.dumps(DEFAULT_PRIVACY)})

        pr = await session.execute(sql_i("""
            SELECT privacy
            FROM chat_user_profiles
            WHERE user_id = :uid
        """, "uid"), {"uid": peer_id})
        row = pr.mappings().first()

        privacy = row["privacy"] if row else None
        if isinstance(privacy, str):
            try:
                privacy = json.loads(privacy)
            except Exception:
                privacy = None
        if not isinstance(privacy, dict):
            privacy = dict(DEFAULT_PRIVACY)

        allow_dm_from_non_friends = bool(privacy.get("allow_dm_from_non_friends", False))
        
        if not allow_dm_from_non_friends:
            fr = await session.execute(sql_i("""
                SELECT 1
                FROM chat_friendships f
                WHERE (
                  (f.requester_id=:me AND f.addressee_id=:peer) OR
                  (f.requester_id=:peer AND f.addressee_id=:me)
                ) AND f.status='accepted'
                LIMIT 1
            """, "me"), {"me": me_id, "peer": peer_id})

            if not fr.scalar_one_or_none():
                raise HTTPException(403, "User doesn't accept DMs from non-friends")

        low, high = sorted([me_id, peer_id])

        r = await session.execute(sql_i("""
            SELECT thread_id FROM chat_dm_pairs
            WHERE user_low=:low AND user_high=:high
        """, "high", "low"), {"low": low, "high": high})
        tid = r.scalar_one_or_none()

        if tid is None:
            
            r = await session.execute(text("INSERT INTO chat_dm_threads DEFAULT VALUES RETURNING id"))
            tid = int(r.scalar_one())
           
            await session.execute(sql_i("""
                INSERT INTO chat_dm_pairs(user_low, user_high, thread_id)
                VALUES (:low, :high, :tid)
            """, "high", "low", "tid"), {"low": low, "high": high, "tid": tid})

            await session.execute(sql_i("""
                INSERT INTO chat_dm_members(thread_id, user_id)
                VALUES (:tid, :me), (:tid, :peer)
            """, "me", "tid"), {"tid": tid, "me": me_id, "peer": peer_id})
        else:
            tid = int(tid)

        # If one side previously deleted "for self", restore membership on reopen.
        await session.execute(text("""
            INSERT INTO chat_dm_members(thread_id, user_id)
            SELECT :tid, :uid
            WHERE NOT EXISTS (
                SELECT 1
                FROM chat_dm_members
                WHERE thread_id = :tid AND user_id = :uid
            )
        """), {"tid": int(tid), "uid": me_id})
        await session.execute(text("""
            INSERT INTO chat_dm_members(thread_id, user_id)
            SELECT :tid, :uid
            WHERE NOT EXISTS (
                SELECT 1
                FROM chat_dm_members
                WHERE thread_id = :tid AND user_id = :uid
            )
        """), {"tid": int(tid), "uid": peer_id})

        # Ensure delivery secret exists for this thread (idempotent — also fixes threads
        # created before this INSERT was added). Generated in Python — no pgcrypto needed.
        await session.execute(text("""
            INSERT INTO chat_dm_delivery(thread_id, delivery_secret, expires_at)
            VALUES (:tid, :secret, NOW() + INTERVAL '24 hours')
            ON CONFLICT (thread_id) DO NOTHING
        """), {"tid": tid, "secret": secrets.token_bytes(32)})

        await session.commit()

        return {"thread_id": int(tid), "peer_username": peer_name}

@app.get("/dm/list")
async def dm_list(authorization: str | None = Header(default=None)):
    me = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        rows = (await session.execute(sql_i("""
            SELECT
              t.id AS thread_id,
              t.last_message_at,
              u.username AS peer_username
            FROM chat_dm_members m
            JOIN chat_dm_threads t ON t.id = m.thread_id
            JOIN chat_dm_pairs p ON p.thread_id = t.id
            JOIN users u ON u.id = CASE
              WHEN p.user_low = :me THEN p.user_high
              ELSE p.user_low
            END
            WHERE m.user_id = :me
            ORDER BY COALESCE(t.last_message_at, t.created_at) DESC
        """, "me"), {"me": me["user_id"]})).mappings().all()

        return [dict(x) for x in rows]

@app.post("/dm/{thread_id}/delete")
async def dm_delete(
    thread_id: int,
    payload: DmDeleteIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    me = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"dm:delete:ip:{ip}", RL_DM_DELETE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"dm:delete:user:{int(me['user_id'])}", RL_DM_DELETE_USER_PER_10MIN, 600)
    if thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")
    scope = (payload.scope or "self").strip().lower()
    if scope not in ("self", "both"):
        raise HTTPException(status_code=400, detail="Invalid scope")

    confirm_ttl_sec = 10 * 60
    now = datetime.now(timezone.utc)

    async with SessionLocal() as session:
        await require_dm_access(session, thread_id, me["user_id"])
        await _ensure_dm_delete_requests_table(session)

        if scope == "self":
            await session.execute(text("""
                DELETE FROM chat_dm_delete_requests
                WHERE thread_id = :tid AND requester_id = :uid
            """), {"tid": int(thread_id), "uid": int(me["user_id"])})
            await session.execute(text("""
                DELETE FROM chat_dm_members
                WHERE thread_id = :tid AND user_id = :uid
            """), {"tid": int(thread_id), "uid": int(me["user_id"])})
            await session.execute(text("""
                DELETE FROM chat_dm_thread_keys
                WHERE thread_id = :tid AND user_id = :uid
            """), {"tid": int(thread_id), "uid": int(me["user_id"])})
            remaining = await session.execute(text("""
                SELECT COUNT(*) FROM chat_dm_members
                WHERE thread_id = :tid
            """), {"tid": int(thread_id)})
            if int(remaining.scalar_one() or 0) > 0:
                await _rotate_dm_delivery_secret(session, int(thread_id))
            await session.commit()

            # If thread became orphaned after removing current user, clear files too.
            await _purge_orphan_dm_thread_files(session)
            await session.commit()
            return {"ok": True, "thread_id": int(thread_id), "scope": "self"}

        # scope == "both": two-phase confirmation
        await session.execute(text("""
            DELETE FROM chat_dm_delete_requests
            WHERE expires_at < NOW()
        """))

        members = (await session.execute(text("""
            SELECT user_id
            FROM chat_dm_members
            WHERE thread_id = :tid
            ORDER BY user_id ASC
        """), {"tid": int(thread_id)})).mappings().all()
        member_ids = [int(x["user_id"]) for x in members]
        if int(me["user_id"]) not in member_ids:
            raise HTTPException(status_code=403, detail="Forbidden")

        # If the thread has no second participant anymore, allow immediate hard delete.
        if len(member_ids) >= 2:
            counterpart_ids = [uid for uid in member_ids if uid != int(me["user_id"])]
            counterpart_id = counterpart_ids[0] if counterpart_ids else None
            if counterpart_id:
                existing = (await session.execute(text("""
                    SELECT requester_id, expires_at
                    FROM chat_dm_delete_requests
                    WHERE thread_id = :tid
                      AND requester_id = :rid
                      AND scope = 'both'
                      AND expires_at >= NOW()
                    LIMIT 1
                """), {"tid": int(thread_id), "rid": int(counterpart_id)})).mappings().first()
                if not existing:
                    expires_at = now + timedelta(seconds=confirm_ttl_sec)
                    await session.execute(text("""
                        INSERT INTO chat_dm_delete_requests(thread_id, requester_id, scope, expires_at, created_at)
                        VALUES (:tid, :uid, 'both', :exp, NOW())
                        ON CONFLICT (thread_id, requester_id)
                        DO UPDATE SET scope='both', expires_at=:exp, created_at=NOW()
                    """), {"tid": int(thread_id), "uid": int(me["user_id"]), "exp": expires_at})
                    await session.commit()
                    return {
                        "ok": True,
                        "thread_id": int(thread_id),
                        "scope": "both",
                        "pending_confirmation": True,
                        "confirm_ttl_sec": confirm_ttl_sec,
                    }

        await session.execute(text("""
            DELETE FROM chat_dm_delete_requests
            WHERE thread_id = :tid
        """), {"tid": int(thread_id)})

        # confirmed or single-member thread -> hard delete contents + files
        await _delete_dm_files_for_thread(session, int(thread_id))
        await session.execute(text("DELETE FROM chat_dm_messages WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_ud_nonces WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_thread_keys WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_key_archive WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_delivery WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_members WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_pairs WHERE thread_id = :tid"), {"tid": int(thread_id)})
        await session.execute(text("DELETE FROM chat_dm_threads WHERE id = :tid"), {"tid": int(thread_id)})
        await session.commit()
        return {"ok": True, "thread_id": int(thread_id), "scope": "both"}

@app.get("/dm/{thread_id}/history")
async def dm_history(
    thread_id: int,
    limit: int = 50,
    before_id: int | None = Query(default=None),
    authorization: str | None = Header(default=None),
):
    me = require_user_from_bearer(authorization)
    limit = max(1, min(int(limit), 200))
    before = int(before_id) if (before_id is not None and int(before_id) > 0) else None
    lim_plus = limit + 1

    async with SessionLocal() as session:
        await require_dm_access(session, thread_id, me["user_id"])

        if before:
            rows = (await session.execute(sql_i("""
                SELECT m.id,
                       CASE WHEN m.is_sealed THEN NULL ELSE m.user_id END AS user_id,
                       CASE WHEN m.is_sealed THEN NULL ELSE COALESCE(u.username, 'Deleted account') END AS username,
                       m.text,
                       EXTRACT(EPOCH FROM m.ts)::bigint AS ts
                FROM chat_dm_messages m
                LEFT JOIN users u ON u.id = m.user_id
                WHERE m.thread_id = :tid
                  AND m.id < :before_id
                ORDER BY m.id DESC
                LIMIT :lim
            """, "lim", "tid", "before_id"), {"tid": thread_id, "before_id": before, "lim": lim_plus})).mappings().all()
        else:
            rows = (await session.execute(sql_i("""
                SELECT m.id,
                       CASE WHEN m.is_sealed THEN NULL ELSE m.user_id END AS user_id,
                       CASE WHEN m.is_sealed THEN NULL ELSE COALESCE(u.username, 'Deleted account') END AS username,
                       m.text,
                       EXTRACT(EPOCH FROM m.ts)::bigint AS ts
                FROM chat_dm_messages m
                LEFT JOIN users u ON u.id = m.user_id
                WHERE m.thread_id = :tid
                ORDER BY m.id DESC
                LIMIT :lim
            """, "lim", "tid"), {"tid": thread_id, "lim": lim_plus})).mappings().all()

        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]
        msgs = list(reversed([dict(x) for x in rows]))
        oldest_id = int(msgs[0]["id"]) if msgs else None
        return {"messages": msgs, "has_more": bool(has_more), "oldest_id": oldest_id}


dm_manager = ConnectionManager()

async def dm_broadcast(thread_id: int, payload: dict):
    key = f"dm:{int(thread_id)}"
    await dm_manager.broadcast(key, payload)

@app.websocket("/ws-dm")
async def websocket_dm(ws: WebSocket, thread_id: int = Query(...)):
    # 0) validate thread_id early
    try:
        thread_id = int(thread_id)
    except Exception:
        try:
            await ws.close(code=1008, reason="forbidden")
        except Exception:
            pass
        return

    if thread_id <= 0:
        try:
            await ws.close(code=1008, reason="forbidden")
        except Exception:
            pass
        return

    # 1) Origin check (CSWSH protection) BEFORE accept
    origin = ws.headers.get("origin")
    if not is_allowed_origin(origin):
        try:
            await ws.close(code=1008, reason="forbidden")
        except Exception:
            pass
        return

    await ws.accept()

    async def ws_forbid():
        await ws.close(code=1008, reason="forbidden")

    async def ws_try_later():
        await ws.close(code=1013, reason="try later")

    ip = get_client_ip_ws(ws)

    # rate limit connect
    retry = await rate_limiter.check(f"wsdm:connect:ip:{ip}", RL_WS_DM_CONNECT_IP_PER_MIN, 60)
    if retry is not None:
        await ws_try_later()
        return

    # first message must be auth
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5)
    except Exception:
        await ws_forbid()
        return

    if not isinstance(first, dict) or first.get("type") != "auth" or not first.get("token"):
        await ws_forbid()
        return

    token = first["token"]

    # token -> user
    try:
        u = get_user_from_token(token)
        user_id = int(u["user_id"])
        username = (u.get("username") or "").strip() or f"user_{user_id}"
        token_payload = decode_token(token)
    except Exception:
        await ws_forbid()
        return

    token_iat = _token_iat(token_payload)

    if await _is_token_revoked(user_id, token_iat):
        try:
            await ws.send_json({
                "type": "auth_state",
                "loggedIn": False,
                "reason": "session_revoked",
                "message": "Session revoked. Sign in again.",
            })
        except Exception:
            pass
        try:
            await ws.close(code=1008, reason="session revoked")
        finally:
            return

    # ---- BAN CHECKER (local closure) ----
    BAN_CHECK_INTERVAL = 10.0
    _last_ban_check = 0.0

    async def _check_ban_maybe(force: bool = False) -> bool:
        nonlocal _last_ban_check
        now = time.time()
        if (not force) and (now - _last_ban_check) < BAN_CHECK_INTERVAL:
            return True
        _last_ban_check = now

        async with SessionLocal() as s:
            banned, reason = await _fetch_user_ban_state(s, user_id)
            valid_after = await _fetch_tokens_valid_after(s, user_id)

        if token_iat < valid_after:
            try:
                await ws.send_json({
                    "type": "auth_state",
                    "loggedIn": False,
                    "reason": "session_revoked",
                    "message": "Session revoked. Sign in again.",
                })
            except Exception:
                pass
            try:
                await ws.close(code=1008, reason="session revoked")
            finally:
                return False

        if not banned:
            return True

        # (Optional privacy hardening: don't leak `reason` to client)
        try:
            await ws.send_json({
                "type": "auth_state",
                "loggedIn": False,
                "reason": "banned",
                "ban_reason": reason or "",
                "message": "User is banned" + (f": {reason}" if reason else ""),
            })
            try:
                await ws.send_json({
                    "type": "banned",
                    "ban_reason": reason or "",
                    "message": "User is banned" + (f": {reason}" if reason else ""),
                })
            except Exception:
                pass
        except Exception:
            pass

        try:
            close_reason = ("banned" + (f": {reason}" if reason else ""))[:120]
            await ws.close(code=1008, reason=close_reason)
        finally:
            return False

    if not await _check_ban_maybe(force=True):
        return
    # ------------------------------------

    # access check before connecting
    async with SessionLocal() as session:
        try:
            await require_dm_access(session, thread_id, user_id)
        except HTTPException:
            await ws_forbid()
            return

    key = f"dm:{thread_id}"
    dm_manager.connect(key, ws, username)

    # Sealed-sender hardening: broadcast presence event WITHOUT
    # online_count or usernames.  In a 2-party DM, even a count
    # lets the peer correlate connect/disconnect timing with sealed
    # messages, defeating sender anonymity (E-3).

    await dm_manager.broadcast(key, {
        "type": "dm_presence",
        "thread_id": thread_id,
    })

    try:
        while True:
            if not await _check_ban_maybe():
                return

            # 2) rate limit inbound messages (prevents JSON flood DoS)
            retry = await rate_limiter.check(
                f"wsdm:msg:ip:{ip}:{thread_id}",
                RL_WS_DM_MSG_IP_PER_10S,
                10
            )
            if retry is not None:
                await ws_try_later()
                return

            # Receive-only DM websocket: apply size cap before JSON parse.
            raw_msg = (await ws.receive_text()).strip()
            if not raw_msg:
                continue
            if len(raw_msg.encode("utf-8")) > MAX_WS_MSG_BYTES:
                await ws.close(code=1009, reason="message too big")
                return
            try:
                msg = json.loads(raw_msg)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue

            mtype = msg.get("type")

            if mtype == "ping":
                try:
                    await ws.send_json({"type": "pong", "ts": int(time.time())})
                except Exception:
                    pass
                continue

            # Block DM sending via WS (forces /ud/dm/send, prevents sender attribution via server/DB)
            if mtype == "send":
                try:
                    await ws.send_json({
                        "type": "error",
                        "message": "DM send is disabled on websocket. Use POST /ud/dm/send.",
                    })
                except Exception:
                    pass
                continue

            continue

    except WebSocketDisconnect:
        pass
    finally:
        dm_manager.disconnect(key, ws)
        await dm_manager.broadcast(key, {
            "type": "dm_presence",
            "thread_id": thread_id,
        })


# ---------------------------------------------------------------------------
# /ws-notify — per-user notification WebSocket (all rooms + DMs)
# ---------------------------------------------------------------------------

@app.websocket("/ws-notify")
async def websocket_notify(ws: WebSocket):
    # 1) Origin check (CSWSH protection) BEFORE accept
    origin = ws.headers.get("origin")
    if not is_allowed_origin(origin):
        try:
            await ws.close(code=1008, reason="forbidden")
        except Exception:
            pass
        return

    await ws.accept()

    async def ws_forbid():
        await ws.close(code=1008, reason="forbidden")

    async def ws_try_later():
        await ws.close(code=1013, reason="try later")

    # 2) Rate limit connect
    ip = get_client_ip_ws(ws)
    retry = await rate_limiter.check(f"wsnotify:connect:ip:{ip}", RL_WS_CONNECT_IP_PER_MIN, 60)
    if retry is not None:
        await ws_try_later()
        return

    # 3) Auth handshake — first message must be {type:"auth", token:"..."}
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5)
    except Exception:
        await ws_forbid()
        return

    if not isinstance(first, dict) or first.get("type") != "auth" or not first.get("token"):
        await ws_forbid()
        return

    try:
        u = get_user_from_token(first["token"])
        user_id = int(u["user_id"])
        token_payload = decode_token(first["token"])
    except Exception:
        await ws_forbid()
        return

    token_iat = _token_iat(token_payload)

    if await _is_token_revoked(user_id, token_iat):
        try:
            await ws.send_json({
                "type": "auth_state",
                "loggedIn": False,
                "reason": "session_revoked",
                "message": "Session revoked. Sign in again.",
            })
        except Exception:
            pass
        try:
            await ws.close(code=1008, reason="session revoked")
        finally:
            return

    # 4) Ban check
    BAN_CHECK_INTERVAL = 30.0
    _last_ban_check = 0.0

    async def _check_ban_maybe(force: bool = False) -> bool:
        nonlocal _last_ban_check
        now = time.time()
        if (not force) and (now - _last_ban_check) < BAN_CHECK_INTERVAL:
            return True
        _last_ban_check = now
        async with SessionLocal() as s:
            banned, reason = await _fetch_user_ban_state(s, user_id)
            valid_after = await _fetch_tokens_valid_after(s, user_id)
        if token_iat < valid_after:
            try:
                await ws.send_json({
                    "type": "auth_state",
                    "loggedIn": False,
                    "reason": "session_revoked",
                    "message": "Session revoked. Sign in again.",
                })
            except Exception:
                pass
            try:
                await ws.close(code=1008, reason="session revoked")
            finally:
                return False
        if not banned:
            return True
        try:
            await ws.send_json({
                "type": "auth_state", "loggedIn": False,
                "reason": "banned",
                "message": "User is banned" + (f": {reason}" if reason else ""),
            })
        except Exception:
            pass
        try:
            await ws.close(code=1008, reason=("banned" + (f": {reason}" if reason else ""))[:120])
        finally:
            return False

    if not await _check_ban_maybe(force=True):
        return

    # 5) Register this connection
    notify_manager.connect(user_id, ws)

    try:
        await ws.send_json({"type": "notify_ready", "ts": int(time.time())})

        while True:
            if not await _check_ban_maybe():
                return

            raw_msg = (await ws.receive_text()).strip()
            if not raw_msg:
                continue
            # Size cap
            if len(raw_msg.encode("utf-8")) > 512:
                await ws.close(code=1009, reason="message too big")
                return
            try:
                msg = json.loads(raw_msg)
            except Exception:
                continue
            if not isinstance(msg, dict):
                continue

            # Only accept ping — read-only connection
            if msg.get("type") == "ping":
                try:
                    await ws.send_json({"type": "pong", "ts": int(time.time())})
                except Exception:
                    pass

    except WebSocketDisconnect:
        pass
    finally:
        notify_manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Notification fan-out helpers
# ---------------------------------------------------------------------------

async def _notify_room_members(room_id: int, room_name: str, sender_username: str, exclude_user_ids: set | None = None):
    """
    Fan out a lightweight notification to all /ws-notify connections
    for members of the given room (excluding specified user IDs).
    Payload contains NO ciphertext — only metadata for local notification display.
    """
    if not notify_manager.connections:
        return
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT user_id FROM chat_room_members
            WHERE room_id = :rid AND status = 'accepted'
        """, "rid"), {"rid": room_id})
        member_ids = {int(r["user_id"]) for r in res.mappings().all()}
        # Also include owner
        res2 = await session.execute(sql_i(
            "SELECT owner_user_id FROM chat_rooms WHERE id = :rid", "rid"
        ), {"rid": room_id})
        owner_row = res2.mappings().first()
        if owner_row:
            member_ids.add(int(owner_row["owner_user_id"]))

    exclude = exclude_user_ids or set()
    payload = {
        "type": "notify_room_msg",
        "room_id": room_id,
        "room_name": room_name,
        "from": sender_username,
        "ts": int(time.time()),
    }
    for uid in member_ids:
        if uid not in exclude:
            await notify_manager.notify(uid, payload)


async def _notify_dm_thread(thread_id: int, sender_user_id: int):
    """
    Fan out a lightweight notification to all /ws-notify connections
    for participants of the given DM thread (excluding sender).
    Sealed sender: NO sender username in payload — only thread_id + ts.
    """
    if not notify_manager.connections:
        return
    async with SessionLocal() as session:
        res = await session.execute(sql_i("""
            SELECT user_id FROM chat_dm_members WHERE thread_id = :tid
        """, "tid"), {"tid": thread_id})
        member_ids = {int(r["user_id"]) for r in res.mappings().all()}

    payload = {
        "type": "notify_dm_msg",
        "thread_id": thread_id,
        "ts": int(time.time()),
    }
    for uid in member_ids:
        if uid != sender_user_id:
            await notify_manager.notify(uid, payload)


@app.post("/crypto/dm-key", status_code=201)
async def save_dm_key(
    payload: DmKeyIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    key_id = _normalize_key_id(payload.key_id)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"crypto:keywrite:ip:{ip}", RL_CRYPTO_KEYWRITE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"crypto:keywrite:user:{int(u['user_id'])}", RL_CRYPTO_KEYWRITE_USER_PER_10MIN, 600)

    if payload.thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")
    if not payload.encrypted_thread_key:
        raise HTTPException(status_code=400, detail="encrypted_thread_key required")

    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)
        await require_dm_access(session, payload.thread_id, u["user_id"])

        await session.execute(sql_i("""
            INSERT INTO chat_dm_thread_keys(thread_id, user_id, encrypted_thread_key)
            VALUES (:tid, :uid, :k)
            ON CONFLICT (thread_id, user_id)
            DO UPDATE SET encrypted_thread_key = EXCLUDED.encrypted_thread_key
        """, "tid", "uid"), {"tid": payload.thread_id, "uid": u["user_id"], "k": payload.encrypted_thread_key})
        if key_id:
            await session.execute(sql_i("""
                INSERT INTO chat_dm_key_archive(thread_id, user_id, key_id, encrypted_thread_key)
                VALUES (:tid, :uid, :kid, :k)
                ON CONFLICT (thread_id, user_id, key_id)
                DO NOTHING
            """, "tid", "uid"), {
                "tid": payload.thread_id,
                "uid": u["user_id"],
                "kid": key_id,
                "k": payload.encrypted_thread_key,
            })

        await session.commit()

    return {"ok": True}

@app.get("/crypto/dm-key/{thread_id}")
async def get_dm_key(thread_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    if thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")

    async with SessionLocal() as session:
        await require_dm_access(session, thread_id, u["user_id"])

        res = await session.execute(sql_i("""
            SELECT encrypted_thread_key
            FROM chat_dm_thread_keys
            WHERE thread_id = :tid AND user_id = :uid
        """, "tid", "uid"), {"tid": thread_id, "uid": u["user_id"]})

        row = res.mappings().first()

    if not row:
        raise HTTPException(status_code=404, detail="DM key not found")

    return {"encrypted_thread_key": row["encrypted_thread_key"]}

@app.get("/crypto/dm-key/{thread_id}/archive")
async def get_dm_key_archive(thread_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    if thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")

    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)
        await require_dm_access(session, thread_id, u["user_id"])
        res = await session.execute(sql_i("""
            SELECT key_id, encrypted_thread_key, created_at
            FROM chat_dm_key_archive
            WHERE thread_id = :tid AND user_id = :uid
            ORDER BY created_at DESC
        """, "tid", "uid"), {"tid": thread_id, "uid": u["user_id"]})
        rows = res.mappings().all()

    return {
        "thread_id": thread_id,
        "keys": [
            {
                "key_id": r["key_id"],
                "encrypted_thread_key": r["encrypted_thread_key"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ],
    }

@app.post("/crypto/dm/{thread_id}/share", status_code=201)
async def share_dm_key(
    thread_id: int,
    payload: DmKeyShareIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    username = (payload.username or "").strip()
    key_id = _normalize_key_id(payload.key_id)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"crypto:keywrite:ip:{ip}", RL_CRYPTO_KEYWRITE_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"crypto:keywrite:user:{int(u['user_id'])}", RL_CRYPTO_KEYWRITE_USER_PER_10MIN, 600)
    if thread_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid thread_id")
    if not username:
        raise HTTPException(status_code=400, detail="username required")
    if not payload.encrypted_thread_key:
        raise HTTPException(status_code=400, detail="encrypted_thread_key required")

    invitee_id = await get_user_id_by_username(username)
    if not invitee_id:
        raise HTTPException(status_code=404, detail="User not found")

    async with SessionLocal() as session:
        await _ensure_key_archive_tables(session)

        await require_dm_access(session, thread_id, u["user_id"])
        await require_dm_access(session, thread_id, invitee_id)

        # Only a user who actually holds the thread key may distribute it.
        # This prevents a thread member who never received the key from uploading
        # a forged key for another member (IDOR escalation in multi-party DMs).
        caller_key_res = await session.execute(
            text("SELECT 1 FROM chat_dm_thread_keys WHERE thread_id = :tid AND user_id = :uid LIMIT 1"),
            {"tid": thread_id, "uid": u["user_id"]},
        )
        if not caller_key_res.scalar_one_or_none():
            raise HTTPException(status_code=403, detail="You do not hold the thread key")

        await session.execute(sql_i("""
            INSERT INTO chat_dm_thread_keys(thread_id, user_id, encrypted_thread_key)
            VALUES (:tid, :uid, :k)
            ON CONFLICT (thread_id, user_id)
            DO UPDATE SET encrypted_thread_key = EXCLUDED.encrypted_thread_key
        """, "tid", "uid"), {"tid": thread_id, "uid": invitee_id, "k": payload.encrypted_thread_key})
        if key_id:
            await session.execute(sql_i("""
                INSERT INTO chat_dm_key_archive(thread_id, user_id, key_id, encrypted_thread_key)
                VALUES (:tid, :uid, :kid, :k)
                ON CONFLICT (thread_id, user_id, key_id)
                DO NOTHING
            """, "tid", "uid"), {
                "tid": thread_id,
                "uid": invitee_id,
                "kid": key_id,
                "k": payload.encrypted_thread_key,
            })

        await session.commit()

    return {"ok": True}

@app.post("/crypto/ed25519-key", status_code=201)
async def register_ed25519_key(
    payload: Ed25519KeyIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    """Register (or update) the caller's Ed25519 signing public key.

    Clients derive this key deterministically from their X25519 private key via
    HKDF and call this endpoint once after every unlock so peers can verify
    sealed-sender DM signatures.
    """
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"ed25519key:ip:{ip}", 10, 600)
    await enforce_http_rate_limit(f"ed25519key:user:{int(u['user_id'])}", 5, 600)

    pub_b64 = (payload.public_key or "").strip()
    if not pub_b64:
        raise HTTPException(status_code=400, detail="public_key required")
    try:
        raw = base64.b64decode(pub_b64 + "==", validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key must be valid base64")
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="public_key must be 32 bytes (Ed25519)")

    kid = hashlib.sha256(raw).hexdigest()[:32]

    async with SessionLocal() as session:
        await _ensure_ed25519_support(session)
        # Deactivate any previous Ed25519 key for this user.
        await session.execute(text(
            "UPDATE chat_user_keys SET is_active = false "
            "WHERE user_id = :uid AND alg = 'ed25519'"
        ), {"uid": u["user_id"]})
        # Upsert the new key as active.
        await session.execute(text("""
            INSERT INTO chat_user_keys(user_id, alg, kid, public_key, is_active)
            VALUES (:uid, 'ed25519', :kid, :pk, true)
            ON CONFLICT (user_id, alg, kid)
            DO UPDATE SET is_active = true, revoked_at = NULL, created_at = now()
        """), {"uid": u["user_id"], "kid": kid, "pk": pub_b64})
        await session.commit()

    return {"ok": True, "kid": kid}

@app.get("/rooms/{room_id}/meta", response_model=RoomMetaOut)
async def room_meta_get(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        await require_room_access(session, int(room_id), int(u["user_id"]))

        q = text("""
            SELECT description, logo_path, meta_updated_at, is_readonly
            FROM chat_rooms
            WHERE id = :rid
        """).bindparams(bindparam("rid", type_=Integer))

        res = await session.execute(q, {"rid": int(room_id)})
        row = res.mappings().first()

        if not row:
            raise HTTPException(status_code=404, detail="Not found")

    logo_path = row.get("logo_path")
    has_logo = bool(logo_path)
    return {
        "room_id": int(room_id),
        "description": row.get("description") or "",
        "has_logo": has_logo,
        "logo_url": (f"/rooms/{int(room_id)}/logo" if has_logo else None),
        "is_readonly": bool(row.get("is_readonly")),
        "updated_at": row.get("meta_updated_at").isoformat() if row.get("meta_updated_at") else None,
    }
    
@app.put("/rooms/{room_id}/meta", response_model=RoomMetaOut)
async def room_meta_put(
    room_id: int,
    payload: RoomMetaIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:meta:ip:{ip}", RL_ROOMS_META_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:meta:user:{int(u['user_id'])}", RL_ROOMS_META_USER_PER_10MIN, 600)
    desc = (payload.description or "").strip()

    async with SessionLocal() as session:
        await require_room_owner(session, int(room_id), int(u["user_id"]))

        await session.execute(sql_i("""
            UPDATE chat_rooms
            SET description = :d,
                meta_updated_at = now()
            WHERE id = :rid
        """, "rid"), {"rid": int(room_id), "d": desc})
        await session.commit()
        
        res = await session.execute(sql_i("""
            SELECT description, logo_path, meta_updated_at, is_readonly
            FROM chat_rooms
            WHERE id = :rid
        """, "rid"), {"rid": int(room_id)})
        row = res.mappings().first()

    has_logo = bool(row.get("logo_path"))
    return {
        "room_id": int(room_id),
        "description": row.get("description") or "",
        "has_logo": has_logo,
        "logo_url": (f"/rooms/{int(room_id)}/logo" if has_logo else None),
        "is_readonly": bool(row.get("is_readonly")),
        "updated_at": row.get("meta_updated_at").isoformat() if row.get("meta_updated_at") else None,
    }

class RoomPasswordIn(BaseModel):
    password: str = Field("", max_length=256)

class RoomNameIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)

@app.put("/rooms/{room_id}/password")
async def room_password_put(
    room_id: int,
    payload: RoomPasswordIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:password:ip:{ip}", RL_ROOMS_PASSWORD_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:password:user:{int(u['user_id'])}", RL_ROOMS_PASSWORD_USER_PER_10MIN, 600)

    async with SessionLocal() as session:
        await require_room_owner(session, int(room_id), int(u["user_id"]))

        new_pass = (payload.password or "").strip()
        ph = hash_password(new_pass) if new_pass else None

        await session.execute(sql_i("""
            UPDATE chat_rooms
            SET password_hash = :ph
            WHERE id = :rid
        """, "rid"), {"rid": int(room_id), "ph": ph})
        await session.commit()

    return {"ok": True, "has_password": ph is not None}

@app.put("/rooms/{room_id}/name")
async def room_name_put(
    room_id: int,
    payload: RoomNameIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:rename:ip:{ip}", RL_ROOMS_RENAME_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:rename:user:{int(u['user_id'])}", RL_ROOMS_RENAME_USER_PER_10MIN, 600)
    new_name = (payload.name or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="Room name required")

    async with SessionLocal() as session:
        await require_room_owner(session, int(room_id), int(u["user_id"]))
        try:
            await session.execute(sql_i("""
                UPDATE chat_rooms
                SET name = :n
                WHERE id = :rid
            """, "rid"), {"rid": int(room_id), "n": new_name})
            await session.commit()
        except IntegrityError as e:
            await session.rollback()
            diag = getattr(getattr(e, "orig", None), "diag", None)
            c = getattr(diag, "constraint_name", None)
            if c == "chat_rooms_owner_name_uq":
                raise HTTPException(status_code=409, detail="Room with this name already exists for this user")
            raise HTTPException(status_code=500, detail="Failed to rename room")

    return {"ok": True, "room_id": int(room_id), "name": new_name}

@app.post("/rooms/{room_id}/logo")
async def room_logo_upload(
    room_id: int,
    request: Request,
    file: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    content_length: int | None = Header(default=None, alias="Content-Length"),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:logo:ip:{ip}", RL_ROOMS_LOGO_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:logo:user:{int(u['user_id'])}", RL_ROOMS_LOGO_USER_PER_10MIN, 600)

    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="File required")

    ct = (file.content_type or "").lower()
    if not ct.startswith("image/"):
        raise HTTPException(status_code=415, detail="Logo must be image/*")

    if content_length is not None and content_length > (MAX_ROOM_LOGO_BYTES + 256 * 1024):
        raise HTTPException(status_code=413, detail="Logo too large (max 5MB)")

    ext_ct = _logo_ext_from_content_type(ct)
    if not ext_ct:
        raise HTTPException(status_code=415, detail="Unsupported image type (use png/jpg/webp)")

    async with SessionLocal() as session:
        await require_room_owner(session, int(room_id), int(u["user_id"]))

    try:
        async with _room_logo_lock(int(room_id)):
            if DEBUG:
                print(f"[LOGO UPLOAD][DEBUG] room={room_id} user={u['user_id']} ct={ct} filename={file.filename!r}")
            
            first = await file.read(64)
            if not first:
                raise HTTPException(status_code=400, detail="Empty file")

            sniffed_ext = _sniff_image_ext(first)
            if not sniffed_ext:
                raise HTTPException(status_code=415, detail="Unsupported image (bad signature)")

            ext = sniffed_ext
            suffix = secrets.token_urlsafe(8)

            final_path = (ROOM_LOGO_DIR / f"room_{int(room_id)}{ext}").resolve()
            tmp_path = (ROOM_LOGO_DIR / f"room_{int(room_id)}{ext}.{suffix}.part").resolve()

            _assert_within_dir(final_path, ROOM_LOGO_DIR)
            _assert_within_dir(tmp_path, ROOM_LOGO_DIR)
            
            if DEBUG:
                print(f"[LOGO UPLOAD] room={room_id} start")

            size = 0
            try:
                with open(tmp_path, "wb") as out:
                    out.write(first)
                    size += len(first)
                    if size > MAX_ROOM_LOGO_BYTES:
                        raise HTTPException(status_code=413, detail="Logo too large (max 5MB)")

                    while True:
                        chunk = await file.read(1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_ROOM_LOGO_BYTES:
                            raise HTTPException(status_code=413, detail="Logo too large (max 5MB)")
                        out.write(chunk)

                os.replace(tmp_path, final_path)

                if DEBUG:
                    actual_size = final_path.stat().st_size if final_path.exists() else -1
                    print(
                        f"[LOGO UPLOAD][DEBUG] moved tmp->final final={final_path.name} "
                        f"written={size} actual={actual_size}"
                    )
                
                for old_ext in (".png", ".jpg", ".webp"):
                    old = (ROOM_LOGO_DIR / f"room_{int(room_id)}{old_ext}").resolve()
                    if old != final_path and old.exists():
                        try:
                            old.unlink()
                        except Exception:
                            pass

                async with SessionLocal() as session:
                    await session.execute(
                        sql_i("""
                            UPDATE chat_rooms
                            SET logo_path = :p,
                                meta_updated_at = now()
                            WHERE id = :rid
                        """, "rid"),
                        {"rid": int(room_id), "p": str(final_path)},
                    )
                    await session.commit()
                
                if DEBUG:
                    print(f"[LOGO UPLOAD] room={room_id} ok ext={ext} size={size}")

            except HTTPException:
                for p in (tmp_path, final_path):
                    try:
                        if os.path.exists(p):
                            os.remove(p)
                    except Exception:
                        pass
                
                if DEBUG:
                    print(f"[LOGO UPLOAD] room={room_id} fail=http")
                raise

            except Exception:
                for p in (tmp_path, final_path):
                    try:
                        if os.path.exists(p):
                            os.remove(p)
                    except Exception:
                        pass
                
                if DEBUG:
                    print(f"[LOGO UPLOAD] room={room_id} fail=exception")
                raise HTTPException(status_code=500, detail="Logo upload failed")

    finally:
        try:
            await file.close()
        except Exception:
            pass

    return {
        "ok": True,
        "room_id": int(room_id),
        "token": None,
        "url": f"/rooms/{int(room_id)}/logo",
        "url_full": f"{APP_BASE_URL}/rooms/{int(room_id)}/logo" if APP_BASE_URL else None,
    }

@app.get("/rooms/{room_id}/logo")
async def room_logo_get(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        await require_room_access(session, int(room_id), int(u["user_id"]))

        res = await session.execute(
            sql_i(
                """
                SELECT logo_path
                FROM chat_rooms
                WHERE id = :rid
                """,
                "rid",
            ),
            {"rid": int(room_id)},
        )
        row = res.mappings().first()

        if DEBUG:
            print(f"[LOGO GET][DEBUG] Query result: {row}")

        if not row:
            if DEBUG:
                print(f"[LOGO GET] Room not found room={room_id}")
            raise HTTPException(status_code=404, detail="Room not found")

        path = (row.get("logo_path") or "").strip()
        if DEBUG:
            print(f"[LOGO GET] logo_path(db)={path!r}")

        if not path:
            if DEBUG:
                print(f"[LOGO GET] No logo room={room_id}")
            raise HTTPException(status_code=404, detail="No logo")

    path_on_disk = Path(path).resolve()
    _assert_within_dir(path_on_disk, ROOM_LOGO_DIR)

    if not path_on_disk.exists():
        if DEBUG:
            print(f"[LOGO GET] File not found on disk: {path_on_disk}")
        raise HTTPException(status_code=404, detail="File not found")

    ext = path_on_disk.suffix.lower()
    mt = {".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp"}.get(ext, "application/octet-stream")

    if DEBUG:
        file_size = path_on_disk.stat().st_size
        print(f"[LOGO GET] Serving file={path_on_disk.name} size={file_size} bytes ext={ext} mime={mt}")

    resp = FileResponse(str(path_on_disk), media_type=mt)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp

@app.get("/auth/csrf")
async def get_csrf(response: Response):
    token = secrets.token_urlsafe(32)
    response.set_cookie(
        "csrf_token",
        token,
        httponly=False,
        samesite="strict",
        secure=True,
        path="/",
    )
    return {"csrf_token": token}
    
@app.post("/rooms/{room_id}/mark_seen")
async def mark_room_seen(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    async with SessionLocal() as session:
        await require_room_access(session, room_id, u["user_id"])
        await session.execute(sql_i("""
            INSERT INTO room_seen (room_id, user_id, seen_at)
            VALUES (:rid, :uid, NOW())
            ON CONFLICT (room_id, user_id)
            DO UPDATE SET seen_at = NOW()
        """, "rid", "uid"), {"rid": room_id, "uid": u["user_id"]})
        await session.commit()
    return {"ok": True}


# ===== DELETE ACCOUNT =====

class DeleteAccountRequest(BaseModel):
    password: str = Field(..., min_length=1, max_length=128)
    confirmation: str = Field(..., pattern=r'^DELETE$')


@app.post("/auth/delete-account", status_code=200)
async def delete_account(
    payload: DeleteAccountRequest,
    request: Request,
    authorization: str | None = Header(default=None)
):
    """
    ÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â° ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â·ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â.
    ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¢ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¶ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â° "DELETE".
    
    ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¢ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬ÂÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¯ ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã‚ÂºÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¾ÃƒÆ’Ã‚ÂÃƒÂ¢Ã¢â€šÂ¬Ã…â€œÃƒÆ’Ã‚ÂÃƒâ€¹Ã…â€œÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â:
    - ÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â·ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â: ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‹Å“ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ
    - ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â² ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¶ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦: ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â° ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â³ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â·ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â "Deleted account"
    - DM: ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â° "Deleted account", ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¦ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â‚¬Å¡Ã‚Â¬ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â±ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¸ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂºÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°
    - ÃƒÆ’Ã‚ÂÃƒâ€¦Ã‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã‚Â¹ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Âµ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â·ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â²ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚Â: ÃƒÆ’Ã¢â‚¬ËœÃƒâ€ Ã¢â‚¬â„¢ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â´ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â°ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã‚ÂÃƒâ€šÃ‚ÂµÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¼ ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¿ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â»ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â½ÃƒÆ’Ã‚ÂÃƒâ€šÃ‚Â¾ÃƒÆ’Ã¢â‚¬ËœÃƒâ€šÃ‚ÂÃƒÆ’Ã¢â‚¬ËœÃƒÂ¢Ã¢â€šÂ¬Ã…Â¡ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã¢â‚¬â„¢ÃƒÆ’Ã¢â‚¬ËœÃƒâ€¦Ã‚Â½
    """
    u = require_user_from_bearer(authorization)
    user_id = int(u["user_id"])
    username = u["username"]
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"auth:delete-account:ip:{ip}", RL_DELETE_ACCOUNT_IP_PER_HOUR, 3600)
    await enforce_http_rate_limit(f"auth:delete-account:user:{user_id}", RL_DELETE_ACCOUNT_USER_PER_HOUR, 3600)
    
    async with SessionLocal() as session:
        
        res = await session.execute(
            text("SELECT password_hash FROM users WHERE id = :uid"),
            {"uid": user_id}
        )
        row = res.mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        
        if not verify_password(payload.password, row["password_hash"]):
            raise HTTPException(status_code=403, detail="Invalid password")              
        
        deleted_user = await session.execute(
            text("SELECT id FROM users WHERE username = :u AND password_hash = :marker"),
            {"u": "deleted account", "marker": "!SYSTEM_USER_NO_LOGIN!"}
        )
        deleted_user_row = deleted_user.mappings().first()

        if deleted_user_row:
            deleted_user_id = deleted_user_row["id"]
        else:

            res = await session.execute(
                text("""
                    INSERT INTO users (username, password_hash)
                    VALUES (:u, :ph)
                    ON CONFLICT (username) DO UPDATE SET password_hash = :ph
                    RETURNING id
                """),
                {"u": "deleted account", "ph": "!SYSTEM_USER_NO_LOGIN!"}
            )
            deleted_user_id = res.scalar_one()      
        
        async def safe_execute(query, params):
            try:
                await session.execute(query, params)
            except Exception as e:
                err_str = str(e) + str(type(e).__name__)
                if "UndefinedTable" in err_str or "does not exist" in err_str:
                    pass
                else:
                    raise       
        
        owned_rooms = await session.execute(
            sql_i("SELECT id FROM chat_rooms WHERE owner_user_id = :uid", "uid"),
            {"uid": user_id}
        )
        owned_room_ids = [r["id"] for r in owned_rooms.mappings().all()]
        
        for room_id in owned_room_ids:
            
            new_owner_query = await session.execute(
                sql_i("""
                    SELECT user_id, role FROM chat_room_members 
                    WHERE room_id = :rid 
                      AND user_id != :uid
                      AND status = 'accepted'
                    ORDER BY 
                      CASE role 
                        WHEN 'admin' THEN 1 
                        WHEN 'member' THEN 2 
                        ELSE 3 
                      END,
                      created_at ASC
                    LIMIT 1
                """, "rid", "uid"),
                {"rid": room_id, "uid": user_id}
            )
            new_owner = new_owner_query.mappings().first()
            
            if new_owner:
                
                new_owner_id = new_owner["user_id"]
                transfer_success = False

                async def _attempt_owner_transfer(rename_to: str | None = None) -> bool:
                    async with session.begin_nested():
                        await session.execute(
                            sql_i("DELETE FROM chat_room_members WHERE room_id = :rid AND user_id = :uid", "rid", "uid"),
                            {"rid": room_id, "uid": user_id}
                        )
                        await session.execute(
                            sql_i("UPDATE chat_room_members SET role = 'owner' WHERE room_id = :rid AND user_id = :new_uid", "rid", "new_uid"),
                            {"rid": room_id, "new_uid": new_owner_id}
                        )
                        if rename_to is None:
                            await session.execute(
                                sql_i("UPDATE chat_rooms SET owner_user_id = :new_uid WHERE id = :rid", "rid", "new_uid"),
                                {"rid": room_id, "new_uid": new_owner_id}
                            )
                        else:
                            await session.execute(
                                sql_i("""
                                    UPDATE chat_rooms
                                    SET owner_user_id = :new_uid, name = :new_name
                                    WHERE id = :rid
                                """, "rid", "new_uid"),
                                {"rid": room_id, "new_uid": new_owner_id, "new_name": rename_to}
                            )
                    return True
                
                try:
                    transfer_success = await _attempt_owner_transfer()
                    
                except Exception as e:
                    
                    if "UniqueViolation" in str(type(e).__name__) or "duplicate key" in str(e).lower():
                        room_info = await session.execute(
                            sql_i("SELECT name FROM chat_rooms WHERE id = :rid", "rid"),
                            {"rid": room_id}
                        )
                        room_row = room_info.mappings().first()
                        if room_row:
                            old_name = room_row["name"]
                            new_name = f"{old_name} (from {username})"
                            try:
                                transfer_success = await _attempt_owner_transfer(new_name)
                            except Exception:
                                new_name = f"{old_name} (from {username} {int(time.time())})"
                                try:
                                    transfer_success = await _attempt_owner_transfer(new_name)
                                except Exception:
                                    transfer_success = False
                    else:
                        raise

                # TODO(security/ownership-policy): add explicit confirmation flow for current admins
                # before ownership transfer on account deletion. Also support deterministic fallback:
                # transfer to the longest-tenured member and rename room as
                # "<room_name__from_<old_owner_username>>".
                
                if not transfer_success:

                    await _purge_room_storage_files(session, int(room_id))

                    await safe_execute(
                        sql_i("DELETE FROM chat_messages WHERE room_id = :rid", "rid"),
                        {"rid": room_id}
                    )
                    await safe_execute(
                        sql_i("DELETE FROM chat_room_members WHERE room_id = :rid", "rid"),
                        {"rid": room_id}
                    )
                    await safe_execute(
                        sql_i("DELETE FROM chat_room_keys WHERE room_id = :rid", "rid"),
                        {"rid": room_id}
                    )
                    await safe_execute(
                        sql_i("DELETE FROM room_seen WHERE room_id = :rid", "rid"),
                        {"rid": room_id}
                    )
                    await safe_execute(
                        sql_i("DELETE FROM chat_files WHERE room_id = :rid", "rid"),
                        {"rid": room_id}
                    )
                    await safe_execute(
                        sql_i("DELETE FROM chat_rooms WHERE id = :rid", "rid"),
                        {"rid": room_id}
                    )
            else:

                await _purge_room_storage_files(session, int(room_id))

                await safe_execute(
                    sql_i("DELETE FROM chat_messages WHERE room_id = :rid", "rid"),
                    {"rid": room_id}
                )
                await safe_execute(
                    sql_i("DELETE FROM chat_room_members WHERE room_id = :rid", "rid"),
                    {"rid": room_id}
                )
                await safe_execute(
                    sql_i("DELETE FROM chat_room_keys WHERE room_id = :rid", "rid"),
                    {"rid": room_id}
                )
                await safe_execute(
                    sql_i("DELETE FROM room_seen WHERE room_id = :rid", "rid"),
                    {"rid": room_id}
                )
                await safe_execute(
                    sql_i("DELETE FROM chat_files WHERE room_id = :rid", "rid"),
                    {"rid": room_id}
                )
                await safe_execute(
                    sql_i("DELETE FROM chat_rooms WHERE id = :rid", "rid"),
                    {"rid": room_id}
                )
                
        await session.execute(
            sql_i("UPDATE chat_messages SET user_id = :deleted_uid WHERE user_id = :uid", "uid", "deleted_uid"),
            {"uid": user_id, "deleted_uid": deleted_user_id}
        )
                
        await safe_execute(
            sql_i("DELETE FROM chat_room_members WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )
                
        await safe_execute(
            sql_i("DELETE FROM chat_room_keys WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )
                
        await safe_execute(
            sql_i("DELETE FROM room_seen WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )
                
        await safe_execute(
            sql_i("UPDATE chat_dm_messages SET user_id = :deleted_uid WHERE user_id = :uid", "uid", "deleted_uid"),
            {"uid": user_id, "deleted_uid": deleted_user_id}
        )
        dm_threads_before_removal = (
            await session.execute(text("""
                SELECT thread_id
                FROM chat_dm_members
                WHERE user_id = :uid
            """), {"uid": user_id})
        ).scalars().all()
                
        await safe_execute(
            sql_i("DELETE FROM chat_dm_members WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )
               
        await safe_execute(
            sql_i("DELETE FROM chat_dm_thread_keys WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )
        for tid in dm_threads_before_removal:
            left = await session.execute(text("""
                SELECT COUNT(*) FROM chat_dm_members
                WHERE thread_id = :tid
            """), {"tid": int(tid)})
            if int(left.scalar_one() or 0) > 0:
                await _rotate_dm_delivery_secret(session, int(tid))
                
        await safe_execute(
            sql_i("DELETE FROM chat_friendships WHERE requester_id = :uid OR addressee_id = :uid", "uid"),
            {"uid": user_id}
        )
                
        await safe_execute(
            sql_i("UPDATE chat_files SET uploader_user_id = :deleted_uid WHERE uploader_user_id = :uid", "uid", "deleted_uid"),
            {"uid": user_id, "deleted_uid": deleted_user_id}
        )
        try:
            await _purge_orphan_dm_thread_files(session)
        except Exception:
            pass
                
        await safe_execute(
            sql_i("UPDATE chat_room_members SET invited_by = NULL WHERE invited_by = :uid", "uid"),
            {"uid": user_id}
        )
        
        await safe_execute(
            sql_i("DELETE FROM chat_user_profiles WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )

        await safe_execute(
            sql_i("DELETE FROM refresh_tokens WHERE user_id = :uid", "uid"),
            {"uid": user_id}
        )

        await session.execute(
            sql_i("DELETE FROM users WHERE id = :uid", "uid"),
            {"uid": user_id}
        )
        
        await session.commit()

    # Invalidate local ban cache immediately and drop active WS sessions for this username.
    ban_cache_invalidate(user_id)
    tokens_valid_after_invalidate(user_id)
    try:
        await manager.kick_user_everywhere(username, code=1008, reason="account deleted")
    except Exception:
        pass
    try:
        await dm_manager.kick_user_everywhere(username, code=1008, reason="account deleted")
    except Exception:
        pass
    try:
        await notify_manager.kick_user(user_id, code=1008, reason="account deleted")
    except Exception:
        pass
    
    if DEBUG:
        print(f"[DELETE ACCOUNT] User {username} (id={user_id}) deleted successfully")
    
    return {
        "ok": True,
        "message": "Account deleted successfully"
    }
    
@app.get("/rooms/{room_id}/pin")
async def room_pin_get(room_id: int, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)

    async with SessionLocal() as session:
        await require_room_access(session, int(room_id), int(u["user_id"]))

        res = await session.execute(sql_i("""
            SELECT room_id, created_by, url, text, created_at, updated_at
            FROM chat_room_pins
            WHERE room_id = :rid
            LIMIT 1
        """, "rid"), {"rid": int(room_id)})

        row = res.mappings().first()
        if not row:
            return {"ok": True, "pin": None}

        return {
            "ok": True,
            "pin": {
                "room_id": int(row["room_id"]),
                "created_by": int(row["created_by"]),
                "url": row.get("url"),
                "text": row.get("text"),
                "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
            }
        }

@app.put("/rooms/{room_id}/pin")
async def room_pin_put(
    room_id: int,
    payload: RoomPinIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"rooms:pin:ip:{ip}", RL_ROOMS_PIN_IP_PER_10MIN, 600)
    await enforce_http_rate_limit(f"rooms:pin:user:{int(u['user_id'])}", RL_ROOMS_PIN_USER_PER_10MIN, 600)

    url = (payload.url or "").strip() or None
    text_ = (payload.text or "").strip() or None

    async with SessionLocal() as session:

        await require_room_moderator(session, int(room_id), int(u["user_id"]))
       
        if not url and not text_:
            await session.execute(sql_i("""
                DELETE FROM chat_room_pins WHERE room_id=:rid
            """, "rid"), {"rid": int(room_id)})
            await session.commit()
            return {"ok": True, "pin": None}

        await session.execute(sql_i("""
            INSERT INTO chat_room_pins (room_id, created_by, url, text, created_at, updated_at)
            VALUES (:rid, :uid, :url, :txt, now(), now())
            ON CONFLICT (room_id)
            DO UPDATE SET
              url = EXCLUDED.url,
              text = EXCLUDED.text,
              updated_at = now()
        """, "rid", "uid"), {
            "rid": int(room_id),
            "uid": int(u["user_id"]),
            "url": url,
            "txt": text_,
        })
        await session.commit()

    return {"ok": True}


RL_UD_DM_MSG_IP_PER_10S = 30
RL_UD_DM_MSG_IP_GLOBAL_PER_10S = 60

@app.post("/ud/dm/send")
async def ud_dm_send(payload: UdDmSendIn, request: Request):
    thread_id = int(payload.thread_id)
    ts = int(payload.ts)

    ip = get_client_ip_request(request)

# rate limit unauth endpoint (critical)
# 1) global per-IP (prevents bypass by rotating thread_id)
    retry = await rate_limiter.check(f"uddm:msg:ip:{ip}", RL_UD_DM_MSG_IP_GLOBAL_PER_10S, 10)
    if retry is not None:
        raise HTTPException(status_code=429, detail=f"rate limited; retry_after={retry}")

# 2) per-IP+thread (protects a конкретный тред от долбёжки)
    retry = await rate_limiter.check(f"uddm:msg:ip:{ip}:{thread_id}", RL_UD_DM_MSG_IP_PER_10S, 10)
    if retry is not None:
        raise HTTPException(status_code=429, detail=f"rate limited; retry_after={retry}")

    now_ms = int(time.time() * 1000)
    if abs(now_ms - ts) > 5 * 60 * 1000:
        raise HTTPException(status_code=400, detail="ts out of window")

    # hard caps BEFORE base64 decode (DoS protection; MAX_DM_MSG_BYTES=32KB)
    if len(payload.ciphertext_b64 or "") > 45000:
        raise HTTPException(status_code=400, detail="message too big")
    if len(payload.nonce_b64 or "") > 200:
        raise HTTPException(status_code=400, detail="bad nonce")
    if len(payload.tag_b64 or "") > 120:
        raise HTTPException(status_code=400, detail="bad tag")

    nonce = b64_to_bytes(payload.nonce_b64)
    if not (8 <= len(nonce) <= 64):
        raise HTTPException(status_code=400, detail="bad nonce")

    ciphertext_b = b64_to_bytes(payload.ciphertext_b64)
    if len(ciphertext_b) > MAX_DM_MSG_BYTES:
        raise HTTPException(status_code=400, detail="message too big")

    tag = b64_to_bytes(payload.tag_b64)
    if len(tag) != 32:
        raise HTTPException(status_code=400, detail="bad tag")

    async with SessionLocal() as session:
        async with session.begin():
            # Fetch delivery secret in one query — combines thread existence,
            # secret presence, and expiry check.  Returns nothing for
            # non-existent thread, missing secret, or expired secret.
            # All failures yield the same 403 to prevent enumeration (E-1/E-2).
            res = await session.execute(text("""
                SELECT d.delivery_secret
                FROM chat_dm_delivery d
                JOIN chat_dm_threads t ON t.id = d.thread_id
                WHERE d.thread_id = :tid
                  AND (d.expires_at IS NULL OR d.expires_at >= NOW())
                LIMIT 1
            """), {"tid": thread_id})
            row = res.mappings().first()
            if not row:
                raise HTTPException(status_code=403, detail="forbidden")
            secret = bytes(row["delivery_secret"])

            # HMAC verify BEFORE consuming nonce — invalid requests
            # should not burn anti-replay tokens.
            expected = hmac_tag(secret, thread_id, ts, nonce, ciphertext_b)
            if not hmac.compare_digest(expected, tag):
                raise HTTPException(status_code=403, detail="forbidden")

            # anti-replay (only after HMAC passes — caller proved they
            # hold the delivery secret, so 409 is safe to differentiate)
            try:
                await session.execute(text("""
                    INSERT INTO chat_dm_ud_nonces(thread_id, nonce, ts)
                    VALUES (:tid, :nonce, :ts)
                """), {"tid": thread_id, "nonce": nonce, "ts": ts})
            except IntegrityError:
                raise HTTPException(status_code=409, detail="replay")

            # store WITHOUT sender, ALWAYS sealed
            await session.execute(sql_i("""
                INSERT INTO chat_dm_messages(thread_id, user_id, text, is_sealed)
                VALUES (:tid, NULL, :text, true)
            """, "tid"), {"tid": thread_id, "text": payload.ciphertext_b64})

            await session.execute(sql_i("""
                UPDATE chat_dm_threads SET last_message_at = now()
                WHERE id = :tid
            """, "tid"), {"tid": thread_id})

    # realtime
    await dm_manager.broadcast(f"dm:{thread_id}", {
        "type": "dm_message",
        "thread_id": thread_id,
        "username": None,
        "text": payload.ciphertext_b64,
        "ts": int(time.time()),   # seconds (consistent with ws-dm)
        "sealed": True,
    })

    # Fan out lightweight notification to /ws-notify (sealed: no sender, no ciphertext)
    try:
        await _notify_dm_thread(thread_id, sender_user_id=0)
    except Exception:
        pass

    return {"ok": True}

async def cleanup_dm_ud_nonces(days: int = 7):
    async with SessionLocal() as session:
        async with session.begin():
            await session.execute(text("""
                DELETE FROM chat_dm_ud_nonces
                WHERE created_at < now() - (:days * interval '1 day')
            """), {"days": int(days)})


@app.get("/dm/{thread_id}/delivery-secret")
async def dm_delivery_secret(thread_id: int, request: Request, authorization: str | None = Header(default=None)):
    u = require_user_from_bearer(authorization)
    ip = get_client_ip_request(request)
    await enforce_http_rate_limit(f"dm:delivery_secret:ip:{ip}", RL_DM_DELIVERY_SECRET_IP_PER_MIN, 60)
    await enforce_http_rate_limit(f"dm:delivery_secret:user:{int(u['user_id'])}", RL_DM_DELIVERY_SECRET_USER_PER_MIN, 60)
    async with SessionLocal() as session:
        await require_dm_access(session, thread_id, u["user_id"])

        res = await session.execute(text("""
            SELECT delivery_secret, expires_at
            FROM chat_dm_delivery
            WHERE thread_id=:tid
            LIMIT 1
        """), {"tid": int(thread_id)})
        row = res.mappings().first()

        # Rotate if missing or expired
        if not row or (row["expires_at"] is not None and row["expires_at"] < datetime.now(timezone.utc)):
            await _rotate_dm_delivery_secret(session, int(thread_id))
            await session.commit()
            res2 = await session.execute(text("""
                SELECT delivery_secret, expires_at
                FROM chat_dm_delivery
                WHERE thread_id=:tid
                LIMIT 1
            """), {"tid": int(thread_id)})
            row = res2.mappings().first()
            if not row:
                raise HTTPException(status_code=500, detail="delivery secret missing after rotation")

        # отдаём base64url (удобнее для JS)
        sec = base64.urlsafe_b64encode(bytes(row["delivery_secret"])).decode("utf-8").rstrip("=")
        expires_at = row["expires_at"]
        return {
            "thread_id": int(thread_id),
            "delivery_secret_b64": sec,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        
# --- Config via env ---
# FEEDBACK_TO="support@yourdomain.com"
# SMTP_HOST="smtp.yourmail.com"
# SMTP_PORT="587"
# SMTP_USER="smtp-user"
# SMTP_PASS="smtp-pass"
# SMTP_FROM="WS Messenger <noreply@yourdomain.com>"   (optional; defaults to SMTP_USER)
# SMTP_TLS="1"                                       (optional; default 1)
_FEEDBACK_MAX_LEN = 1200

_re_strip_ctrl = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")  # remove control chars except \t,\n,\r
_re_header_injection = re.compile(r"[\r\n]")  # forbid newline in email headers


class FeedbackMeta(BaseModel):
    ts: int | None = None
    client: str | None = None
    
    ua: str | None = None

class FeedbackSendIn(BaseModel):
    message: str = Field(min_length=1, max_length=_FEEDBACK_MAX_LEN)
    meta: dict[str, Any] | FeedbackMeta | None = None

def _sanitize_text(s: str) -> str:
    s = (s or "").strip()
    s = _re_strip_ctrl.sub("", s)
    # normalize newlines
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return s


def _get_env_or_raise(name: str) -> str:
    v = (os.getenv(name) or "").strip()
    if not v:
        raise RuntimeError(f"env {name} is not configured")
    return v


def _send_feedback_email_sync(subject: str, body: str) -> None:
    host = _get_env_or_raise("SMTP_HOST")
    port = int((os.getenv("SMTP_PORT") or "587").strip())
    user = (os.getenv("SMTP_USER") or "").strip()
    password = (os.getenv("SMTP_PASS") or "").strip()
    use_tls = (os.getenv("SMTP_TLS") or "1").strip() == "1"

    to_addr = _get_env_or_raise("FEEDBACK_TO")
    from_addr = (os.getenv("SMTP_FROM") or user).strip()
    if not from_addr:
        raise RuntimeError("env SMTP_FROM (or SMTP_USER) is not configured")

    # Prevent header injection
    if _re_header_injection.search(subject) or _re_header_injection.search(to_addr) or _re_header_injection.search(from_addr):
        raise RuntimeError("invalid email headers")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=12) as s:
        s.ehlo()
        if use_tls:
            s.starttls()
            s.ehlo()
        if user and password:
            s.login(user, password)
        s.send_message(msg)


@app.post("/feedback/send")
async def feedback_send(
    payload: FeedbackSendIn,
    request: Request,
    authorization: str | None = Header(default=None),
):
    # --- Auth required ---
    me = require_user_from_bearer(authorization)  # your existing auth helper
    user_id = str(me.get("id") or me.get("sub") or me.get("user_id") or "")
    username = str(me.get("username") or me.get("name") or "").strip()

    if not user_id:
        raise HTTPException(status_code=401, detail="unauthorized")

    # --- Rate limit (IP + user) ---
    ip = get_client_ip_request(request)

    retry = await rate_limiter.check(f"fb:ip:{ip}", RL_FEEDBACK_IP_PER_10M, 600)
    if retry is not None:
        raise HTTPException(status_code=429, detail=f"rate limited; retry_after={retry}")

    retry = await rate_limiter.check(f"fb:user:{user_id}", RL_FEEDBACK_USER_PER_10M, 600)
    if retry is not None:
        raise HTTPException(status_code=429, detail=f"rate limited; retry_after={retry}")

    # --- Sanitize payload (text only) ---
    msg = _sanitize_text(payload.message)
    if not msg:
        raise HTTPException(status_code=400, detail="empty message")

    # defense-in-depth: enforce max len even after sanitization
    msg = msg[:_FEEDBACK_MAX_LEN]

    # --- Meta: whitelist + JSON-safe preview (avoid huge/untrusted dicts) ---
    meta_in = payload.meta or {}
    if isinstance(meta_in, FeedbackMeta):
        meta = meta_in.model_dump()
    elif isinstance(meta_in, dict):
        meta = {
            "ts": meta_in.get("ts"),
            "client": meta_in.get("client"),
            
        }
    else:
        meta = {}

    try:
        meta_preview = json.dumps(meta, ensure_ascii=False)
        if len(meta_preview) > 2000:
            meta_preview = meta_preview[:2000] + "...(truncated)"
    except Exception:
        meta_preview = "{meta: not json-serializable}"

    subj_user = username or f"user:{user_id}"
    subject = f"WS Messenger feedback ({subj_user})"

    body = (
        f"user_id: {user_id}\n"
        f"username: {username}\n"
        f"ip: {ip}\n"
        f"ua: {request.headers.get('user-agent','')}\n"
        f"meta: {meta_preview}\n"
        f"---\n"
        f"{msg}\n"
    )

    # --- Always store feedback to DB (authoritative) ---
    async with SessionLocal() as session:
        try:
            await _save_feedback_to_db(
                session,
                user_id=int(user_id),
                username=username,
                ip=(ip or None),
                ua=(request.headers.get("user-agent", "") or "")[:400],
                meta=meta,
                message=msg,
            )
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("feedback DB store failed (user_id=%s ip=%s)", user_id, ip)
            raise HTTPException(status_code=500, detail="failed to store feedback")

    # --- Optional: best-effort email (never fail request) ---
    mail_ok = False
    if os.getenv("SMTP_HOST", "").strip():
        try:
            await asyncio.to_thread(_send_feedback_email_sync, subject, body)
            mail_ok = True
        except Exception:
            mail_ok = False

    return {"ok": True, "mail": mail_ok, "stored": "db"}
