# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

# app/admin/router.py
from __future__ import annotations

import asyncio
from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

from .auth import (
    create_session, destroy_session, require_admin, set_session_cookie,
    check_rate_limit,
    get_csrf_token, verify_csrf,
)

templates = Jinja2Templates(directory="admin/templates")
router = APIRouter(prefix="/admin", tags=["admin"])


# ---------- helpers ----------
def _ctx(request: Request, **kwargs) -> dict:
    """Build template context with automatic CSRF token injection."""
    ctx = {"request": request, "csrf_token": get_csrf_token(request)}
    ctx.update(kwargs)
    return ctx


def _session_local(request: Request):
    sl = getattr(request.app.state, "SessionLocal", None)
    if sl is None:
        raise RuntimeError("SessionLocal is not configured. Set app.state.SessionLocal in main.py")
    return sl


async def _audit(db, request: Request, actor_id: int | None, actor: str, action: str, target: str, ok: bool, meta: dict | None = None):
    """
    Writes to admin_audit table (SQLAlchemy).
    Table schema we discussed:
      admin_audit(ts default now(), actor_id, actor, action, target, ok, ip, ua, meta jsonb)
    """
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")
    meta = meta or {}
    # jsonb casting
    await db.execute(
        text(
            """
            INSERT INTO admin_audit(actor_id, actor, action, target, ok, ip, ua, meta)
            VALUES (:actor_id, :actor, :action, :target, :ok, :ip, :ua, (:meta)::jsonb)
            """
        ),
        {
            "actor_id": actor_id,
            "actor": actor,
            "action": action,
            "target": target,
            "ok": ok,
            "ip": ip,
            "ua": ua,
            "meta": __json(meta),
        },
    )


def __json(d: dict) -> str:
    import json
    return json.dumps(d, ensure_ascii=False)


# ── Пункт 4: защита от эскалации между админами ──────────
ROLE_HIERARCHY = {"admin": 1, "superadmin": 2}


async def _assert_can_act_on_user(db, actor: "AdminPrincipal", target_user_id: int):
    """
    Проверяет, что actor имеет строго более высокий уровень привилегий,
    чем target (если target тоже админ). Обычных пользователей не защищает.
    Бросает HTTPException(403) при нарушении.
    """
    from .auth import AdminPrincipal  # noqa: already imported, just for clarity

    res = await db.execute(
        text("SELECT role FROM admin_users WHERE user_id=:id"),
        {"id": target_user_id},
    )
    target_adm = res.mappings().first()
    if not target_adm:
        return  # target — обычный пользователь, ограничений нет

    actor_level = ROLE_HIERARCHY.get(actor.role, 0)
    target_level = ROLE_HIERARCHY.get(target_adm["role"], 0)

    if target_level >= actor_level:
        raise HTTPException(
            status_code=403,
            detail="Cannot perform this action on an admin with equal or higher privileges",
        )


# ---------- auth ----------
@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", _ctx(request))


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    # ── пункт 1: rate limit ──
    if check_rate_limit(request, username):
        return templates.TemplateResponse(
            "login.html",
            _ctx(request, error="Too many attempts. Try again later."),
            status_code=429,
        )

    verify = getattr(request.app.state, "verify_password", None)
    if verify is None:
        # лучше упасть явно, чем случайно открыть доступ
        return templates.TemplateResponse(
            "login.html",
            _ctx(request, error="Server misconfigured (no verify_password)"),
            status_code=500,
        )

    SessionLocal = _session_local(request)

    # Единое сообщение об ошибке (пункт 7 — user enumeration)
    GENERIC_ERROR = "Invalid credentials"

    async with SessionLocal() as db:
        # 1) load user
        ures = await db.execute(
            text("SELECT id, username, password_hash, COALESCE(is_banned,false) AS is_banned FROM users WHERE username=:u"),
            {"u": username},
        )
        u = ures.mappings().first()

        if not u:
            dummy_hash = getattr(request.app.state, "admin_dummy_hash", "")
            # Пункт 7/9: timing-safe — вызываем verify с dummy hash,
            # чтобы время ответа не отличалось от случая «пользователь найден».
            if isinstance(dummy_hash, str) and dummy_hash:
                await verify(password, dummy_hash)
            else:
                # Fallback for misconfigured app.state in tests/dev.
                await asyncio.sleep(0.08)
            await _audit(db, request, None, "unknown", "admin_login_failed", username, False)
            await db.commit()
            return templates.TemplateResponse(
                "login.html",
                _ctx(request, error=GENERIC_ERROR),
                status_code=401,
            )

        # 2) verify password (same as your normal login)
        ok = await verify(password, u["password_hash"])
        if not ok:
            await _audit(db, request, u["id"], u["username"], "admin_login_failed", username, False)
            await db.commit()
            return templates.TemplateResponse(
                "login.html",
                _ctx(request, error=GENERIC_ERROR),
                status_code=401,
            )

        # Пункт 7: бан проверяем ПОСЛЕ пароля, и тоже с generic error
        if u["is_banned"]:
            await _audit(db, request, u["id"], u["username"], "admin_login_failed_banned", username, False)
            await db.commit()
            return templates.TemplateResponse(
                "login.html",
                _ctx(request, error=GENERIC_ERROR),
                status_code=401,
            )

        # 3) check admin role
        ares = await db.execute(
            text("SELECT role FROM admin_users WHERE user_id=:id"),
            {"id": u["id"]},
        )
        adm = ares.mappings().first()
        if not adm:
            await _audit(db, request, u["id"], u["username"], "admin_login_denied_not_admin", username, False)
            await db.commit()
            return templates.TemplateResponse(
                "login.html",
                _ctx(request, error=GENERIC_ERROR),
                status_code=401,
            )

        sid = create_session(int(u["id"]), str(u["username"]), str(adm["role"]))
        await _audit(db, request, u["id"], u["username"], "admin_login_ok", u["username"], True, {"role": adm["role"]})
        await db.commit()

    resp = RedirectResponse(url="/admin", status_code=302)
    set_session_cookie(resp, sid)
    return resp


@router.post("/logout")
async def logout(request: Request):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    sid = request.cookies.get("admin_session")
    if sid:
        destroy_session(sid)

    async with SessionLocal() as db:
        await _audit(db, request, p.user_id, p.username, "admin_logout", "-", True)
        await db.commit()

    resp = RedirectResponse(url="/admin/login", status_code=302)
    resp.delete_cookie("admin_session", path="/admin")
    return resp


# ---------- dashboard ----------
@router.get("", response_class=HTMLResponse)
async def dashboard(request: Request):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        users_cnt = (await db.execute(text("SELECT COUNT(*) FROM users"))).scalar_one()
        rooms_cnt = (await db.execute(text("SELECT COUNT(*) FROM chat_rooms"))).scalar_one()
        users_2fa = (await db.execute(text("SELECT COUNT(*) FROM users WHERE totp_secret IS NOT NULL"))).scalar_one()
        users_no_pub = (await db.execute(text("SELECT COUNT(*) FROM users WHERE public_key IS NULL"))).scalar_one()
        reports_new = (await db.execute(text("SELECT COUNT(*) FROM reports WHERE status IN ('new','in_review')"))).scalar_one()

    return templates.TemplateResponse(
        "dashboard.html",
        _ctx(request,
            me=p,
            stats={
                "users": int(users_cnt),
                "rooms": int(rooms_cnt),
                "users_2fa": int(users_2fa),
                "users_no_pubkey": int(users_no_pub),
                "reports_pending": int(reports_new),
            },
        ),
    )


# ---------- users ----------
@router.get("/users", response_class=HTMLResponse)
async def users_list(request: Request, q: str = ""):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        res = await db.execute(
            text(
                """
                SELECT id, username, created_at,
                       (public_key IS NOT NULL) AS has_pubkey,
                       (totp_secret IS NOT NULL) AS has_2fa,
                       COALESCE(is_banned,false) AS is_banned
                FROM users
                WHERE (:q = '' OR username ILIKE ('%'||:q||'%'))
                ORDER BY id DESC
                LIMIT 200
                """
            ),
            {"q": q or ""},
        )
        users = [dict(r) for r in res.mappings().all()]

    return templates.TemplateResponse("users.html", _ctx(request, me=p, q=q, users=users))


@router.get("/users/{user_id}", response_class=HTMLResponse)
async def user_detail(request: Request, user_id: int):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        ures = await db.execute(
            text(
                """
                SELECT id, username, created_at, public_key,
                       (totp_secret IS NOT NULL) AS has_2fa,
                       COALESCE(is_banned,false) AS is_banned,
                       banned_at, banned_reason
                FROM users
                WHERE id=:id
                """
            ),
            {"id": user_id},
        )
        u = ures.mappings().first()
        if not u:
            return RedirectResponse("/admin/users", status_code=302)

        # Active/Total refresh tokens
        tok_active = (await db.execute(
            text(
                """
                SELECT COUNT(*) FROM refresh_tokens
                WHERE user_id=:id
                  AND revoked_at IS NULL
                  AND expires_at > now()
                """
            ),
            {"id": user_id},
        )).scalar_one()

        tok_all = (await db.execute(
            text("SELECT COUNT(*) FROM refresh_tokens WHERE user_id=:id"),
            {"id": user_id},
        )).scalar_one()

        # Family breakdown
        fres = await db.execute(
            text(
                """
                SELECT family_id,
                       COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE revoked_at IS NULL AND expires_at > now()) AS active,
                       MAX(created_at) AS last_issued
                FROM refresh_tokens
                WHERE user_id=:id
                GROUP BY family_id
                ORDER BY MAX(created_at) DESC
                LIMIT 50
                """
            ),
            {"id": user_id},
        )
        families = [dict(r) for r in fres.mappings().all()]

    return templates.TemplateResponse(
        "user_detail.html",
        _ctx(request,
            me=p,
            u=dict(u),
            tok_active=int(tok_active),
            tok_all=int(tok_all),
            families=families,
        ),
    )


@router.post("/users/{user_id}/reset-2fa")
async def user_reset_2fa(request: Request, user_id: int):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await _assert_can_act_on_user(db, p, user_id)
        await db.execute(
            text(
                """
                UPDATE users
                SET totp_secret=NULL,
                    totp_pending_secret=NULL,
                    totp_backup_codes=NULL
                WHERE id=:id
                """
            ),
            {"id": user_id},
        )
        await _audit(db, request, p.user_id, p.username, "user_reset_2fa", str(user_id), True)
        await db.commit()

    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


@router.post("/users/{user_id}/revoke-sessions")
async def user_revoke_sessions(request: Request, user_id: int):
    """
    Revoke all active refresh tokens for user: set revoked_at=now() where revoked_at is NULL.
    """
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await _assert_can_act_on_user(db, p, user_id)
        r = await db.execute(
            text(
                """
                UPDATE refresh_tokens
                SET revoked_at = now()
                WHERE user_id=:id
                  AND revoked_at IS NULL
                """
            ),
            {"id": user_id},
        )
        await _audit(
            db, request,
            p.user_id, p.username,
            "user_revoke_sessions", str(user_id), True,
            {"mode": "set_revoked_at", "rowcount": int(getattr(r, "rowcount", 0) or 0)},
        )
        await db.commit()

    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


@router.post("/users/{user_id}/revoke-family")
async def user_revoke_family(request: Request, user_id: int, family_id: str = Form(...)):
    """
    Revoke only one refresh-token family for the user.
    """
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await _assert_can_act_on_user(db, p, user_id)
        r = await db.execute(
            text(
                """
                UPDATE refresh_tokens
                SET revoked_at = now()
                WHERE user_id=:id
                  AND family_id=:fid
                  AND revoked_at IS NULL
                """
            ),
            {"id": user_id, "fid": family_id},
        )
        await _audit(
            db, request,
            p.user_id, p.username,
            "user_revoke_family", f"{user_id}:{family_id}", True,
            {"mode": "set_revoked_at", "rowcount": int(getattr(r, "rowcount", 0) or 0)},
        )
        await db.commit()

    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


@router.post("/users/{user_id}/ban")
async def user_ban(request: Request, user_id: int, reason: str = Form("")):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await _assert_can_act_on_user(db, p, user_id)
        await db.execute(
            text(
                """
                UPDATE users
                SET is_banned=true,
                    banned_at=now(),
                    banned_reason=:reason
                WHERE id=:id
                """
            ),
            {"id": user_id, "reason": reason},
        )
        await _audit(db, request, p.user_id, p.username, "user_ban", str(user_id), True, {"reason": reason})
        await db.commit()

    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


@router.post("/users/{user_id}/unban")
async def user_unban(request: Request, user_id: int):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await _assert_can_act_on_user(db, p, user_id)
        await db.execute(
            text(
                """
                UPDATE users
                SET is_banned=false,
                    banned_at=NULL,
                    banned_reason=NULL
                WHERE id=:id
                """
            ),
            {"id": user_id},
        )
        await _audit(db, request, p.user_id, p.username, "user_unban", str(user_id), True)
        await db.commit()

    return RedirectResponse(url=f"/admin/users/{user_id}", status_code=302)


# ---------- rooms ----------
@router.get("/rooms", response_class=HTMLResponse)
async def rooms_list(request: Request, q: str = ""):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        res = await db.execute(
            text(
                """
                SELECT r.id, r.name, r.alias, r.is_public, r.join_policy, r.created_at,
                       r.owner_user_id, u.username AS owner_name,
                       (SELECT COUNT(*) FROM chat_room_members m
                         WHERE m.room_id=r.id AND m.status='accepted') AS members
                FROM chat_rooms r
                JOIN users u ON u.id = r.owner_user_id
                WHERE (:q = '' OR r.name ILIKE ('%'||:q||'%') OR r.alias ILIKE ('%'||:q||'%'))
                ORDER BY r.id DESC
                LIMIT 200
                """
            ),
            {"q": q or ""},
        )
        rooms = [dict(r) for r in res.mappings().all()]

    return templates.TemplateResponse("rooms.html", _ctx(request, me=p, q=q, rooms=rooms))


@router.get("/rooms/{room_id}", response_class=HTMLResponse)
async def room_detail(request: Request, room_id: int):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        rres = await db.execute(
            text(
                """
                SELECT r.*, u.username AS owner_name
                FROM chat_rooms r
                JOIN users u ON u.id=r.owner_user_id
                WHERE r.id=:id
                """
            ),
            {"id": room_id},
        )
        r = rres.mappings().first()
        if not r:
            return RedirectResponse("/admin/rooms", status_code=302)

        mres = await db.execute(
            text(
                """
                SELECT m.user_id, u.username, m.role, m.status, m.created_at
                FROM chat_room_members m
                JOIN users u ON u.id=m.user_id
                WHERE m.room_id=:id
                ORDER BY (m.role='owner') DESC, (m.role='admin') DESC, u.username
                """
            ),
            {"id": room_id},
        )
        members = [dict(m) for m in mres.mappings().all()]

    return templates.TemplateResponse("room_detail.html", _ctx(request, me=p, r=dict(r), members=members))


@router.post("/rooms/{room_id}/members/{user_id}/set-role")
async def room_set_role(request: Request, room_id: int, user_id: int, role: str = Form(...)):
    # Пункт 2: валидация допустимых ролей
    role = (role or "").strip().lower()
    ALLOWED_ROOM_ROLES = {"member", "admin"}
    if role not in ALLOWED_ROOM_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {', '.join(sorted(ALLOWED_ROOM_ROLES))}")

    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await db.execute(
            text("UPDATE chat_room_members SET role=:role WHERE room_id=:rid AND user_id=:uid"),
            {"role": role, "rid": room_id, "uid": user_id},
        )
        await _audit(
            db, request,
            p.user_id, p.username,
            "room_member_set_role", f"{room_id}:{user_id}", True,
            {"role": role},
        )
        await db.commit()

    return RedirectResponse(url=f"/admin/rooms/{room_id}", status_code=302)


@router.post("/rooms/{room_id}/members/{user_id}/kick")
async def room_kick(request: Request, room_id: int, user_id: int):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        await db.execute(
            text("DELETE FROM chat_room_members WHERE room_id=:rid AND user_id=:uid"),
            {"rid": room_id, "uid": user_id},
        )
        await _audit(db, request, p.user_id, p.username, "room_member_kick", f"{room_id}:{user_id}", True)
        await db.commit()

    return RedirectResponse(url=f"/admin/rooms/{room_id}", status_code=302)


# ---------- reports / moderation ----------
REPORT_STATUSES = {"new", "in_review", "resolved", "dismissed"}


@router.get("/reports", response_class=HTMLResponse)
async def reports_list(request: Request, status: str = "new", q: str = ""):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    if status and status not in REPORT_STATUSES:
        status = "new"

    async with SessionLocal() as db:
        res = await db.execute(
            text(
                """
                SELECT r.id, r.target_type, r.target_id, r.reason, r.status,
                       r.created_at, r.comment,
                       u_rep.username AS reporter_name,
                       r.reviewer_id,
                       u_rev.username AS reviewer_name,
                       r.reviewed_at,
                       -- подтягиваем имя цели для удобства
                       CASE r.target_type
                           WHEN 'user'    THEN (SELECT username FROM users WHERE id=r.target_id)
                           WHEN 'room'    THEN (SELECT name FROM chat_rooms WHERE id=r.target_id)
                           WHEN 'message' THEN (SELECT 'msg#' || r.target_id)
                       END AS target_name
                FROM reports r
                JOIN users u_rep ON u_rep.id = r.reporter_id
                LEFT JOIN users u_rev ON u_rev.id = r.reviewer_id
                WHERE (:status = '' OR r.status = :status)
                  AND (:q = '' OR u_rep.username ILIKE ('%'||:q||'%')
                       OR r.comment ILIKE ('%'||:q||'%'))
                ORDER BY
                    CASE r.status
                        WHEN 'new'       THEN 0
                        WHEN 'in_review' THEN 1
                        ELSE 2
                    END,
                    r.created_at DESC
                LIMIT 200
                """
            ),
            {"status": status or "", "q": q or ""},
        )
        reports = [dict(row) for row in res.mappings().all()]

        # счётчики по статусам для табов
        cnt_res = await db.execute(
            text(
                """
                SELECT status, COUNT(*) AS cnt
                FROM reports
                GROUP BY status
                """
            )
        )
        status_counts = {row["status"]: row["cnt"] for row in cnt_res.mappings().all()}

    return templates.TemplateResponse(
        "reports.html",
        _ctx(request,
            me=p,
            reports=reports,
            current_status=status,
            q=q,
            status_counts=status_counts,
        ),
    )


@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: int):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        rres = await db.execute(
            text(
                """
                SELECT r.*,
                       u_rep.username AS reporter_name,
                       u_rev.username AS reviewer_name
                FROM reports r
                JOIN users u_rep ON u_rep.id = r.reporter_id
                LEFT JOIN users u_rev ON u_rev.id = r.reviewer_id
                WHERE r.id = :id
                """
            ),
            {"id": report_id},
        )
        report = rres.mappings().first()
        if not report:
            return RedirectResponse("/admin/reports", status_code=302)
        report = dict(report)

        # подтягиваем контекст цели
        target_info = {}
        if report["target_type"] == "user":
            tres = await db.execute(
                text(
                    """
                    SELECT id, username, created_at,
                           COALESCE(is_banned,false) AS is_banned
                    FROM users WHERE id=:id
                    """
                ),
                {"id": report["target_id"]},
            )
            target_info = dict(tres.mappings().first() or {})

        elif report["target_type"] == "room":
            tres = await db.execute(
                text(
                    """
                    SELECT r.id, r.name, r.alias, r.is_public, r.owner_user_id,
                           u.username AS owner_name
                    FROM chat_rooms r
                    JOIN users u ON u.id=r.owner_user_id
                    WHERE r.id=:id
                    """
                ),
                {"id": report["target_id"]},
            )
            target_info = dict(tres.mappings().first() or {})

        elif report["target_type"] == "message":
            tres = await db.execute(
                text(
                    """
                    SELECT m.id, m.room_id, m.user_id, m.text, m.created_at,
                           u.username AS author_name
                    FROM chat_messages m
                    JOIN users u ON u.id = m.user_id
                    WHERE m.id=:id
                    """
                ),
                {"id": report["target_id"]},
            )
            target_info = dict(tres.mappings().first() or {})

        # история репортов на эту же цель
        hist_res = await db.execute(
            text(
                """
                SELECT r.id, r.reason, r.status, r.created_at,
                       u.username AS reporter_name
                FROM reports r
                JOIN users u ON u.id = r.reporter_id
                WHERE r.target_type = :tt AND r.target_id = :tid AND r.id != :rid
                ORDER BY r.created_at DESC
                LIMIT 20
                """
            ),
            {"tt": report["target_type"], "tid": report["target_id"], "rid": report_id},
        )
        related = [dict(row) for row in hist_res.mappings().all()]

    return templates.TemplateResponse(
        "report_detail.html",
        _ctx(request,
            me=p,
            report=report,
            target_info=target_info,
            related=related,
        ),
    )


@router.post("/reports/{report_id}/status")
async def report_set_status(
    request: Request,
    report_id: int,
    status: str = Form(...),
    review_note: str = Form(""),
):
    await verify_csrf(request)
    p = require_admin(request)
    SessionLocal = _session_local(request)

    if status not in REPORT_STATUSES:
        raise HTTPException(400, f"Invalid status. Allowed: {', '.join(sorted(REPORT_STATUSES))}")

    review_note = (review_note or "").strip()[:2000]

    async with SessionLocal() as db:
        # проверяем что репорт существует
        rres = await db.execute(
            text("SELECT id, status FROM reports WHERE id=:id"),
            {"id": report_id},
        )
        report = rres.mappings().first()
        if not report:
            raise HTTPException(404, "Report not found")

        await db.execute(
            text(
                """
                UPDATE reports
                SET status = :status,
                    reviewer_id = :reviewer_id,
                    review_note = :review_note,
                    reviewed_at = now()
                WHERE id = :id
                """
            ),
            {
                "id": report_id,
                "status": status,
                "reviewer_id": p.user_id,
                "review_note": review_note,
            },
        )
        await _audit(
            db, request,
            p.user_id, p.username,
            "report_set_status", str(report_id), True,
            {"old_status": report["status"], "new_status": status},
        )
        await db.commit()

    return RedirectResponse(url=f"/admin/reports/{report_id}", status_code=302)


# ---------- audit page ----------
@router.get("/audit", response_class=HTMLResponse)
async def audit_list(request: Request):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        res = await db.execute(
            text(
                """
                SELECT ts, actor, action, target, ok, ip
                FROM admin_audit
                ORDER BY id DESC
                LIMIT 200
                """
            )
        )
        rows = [dict(x) for x in res.mappings().all()]

    return templates.TemplateResponse("audit.html", _ctx(request, me=p, rows=rows))

# ---------- feedback ----------
@router.get("/feedback", response_class=HTMLResponse)
async def feedback_list(request: Request, q: str = "", user_id: int | None = None):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    q = (q or "").strip()
    params: dict = {}
    wh = []

    if user_id is not None:
        wh.append("user_id = :uid")
        params["uid"] = int(user_id)

    if q:
        wh.append("(username ILIKE :q OR message ILIKE :q)")
        params["q"] = f"%{q}%"

    where_sql = ("WHERE " + " AND ".join(wh)) if wh else ""

    sql = text(f"""
        SELECT id, created_at, user_id, username, ip,
               left(ua, 120) AS ua_short,
               left(message, 200) AS msg_short
        FROM chat_feedback
        {where_sql}
        ORDER BY id DESC
        LIMIT 200
    """)

    async with SessionLocal() as db:
        res = await db.execute(sql, params)
        rows = [dict(r) for r in res.mappings().all()]

    return templates.TemplateResponse(
        "feedback.html",
        _ctx(request, me=p, q=q, user_id=user_id, rows=rows),
    )


@router.get("/feedback/{fid}", response_class=HTMLResponse)
async def feedback_detail(request: Request, fid: int):
    p = require_admin(request)
    SessionLocal = _session_local(request)

    async with SessionLocal() as db:
        res = await db.execute(
            text(
                """
                SELECT id, created_at, user_id, username, ip, ua, meta_json, message
                FROM chat_feedback
                WHERE id = :id
                """
            ),
            {"id": fid},
        )
        row = res.mappings().first()
        if not row:
            return RedirectResponse("/admin/feedback", status_code=302)

    return templates.TemplateResponse(
        "feedback_detail.html",
        _ctx(request, me=p, row=dict(row)),
    )


# ---------- broadcast notice ----------
NOTICE_TYPES = {"info", "warning", "maintenance"}


@router.get("/broadcast", response_class=HTMLResponse)
async def broadcast_page(request: Request):
    p = require_admin(request)
    notice = getattr(request.app.state, "broadcast_notice", None)
    return templates.TemplateResponse("broadcast.html", _ctx(request, me=p, notice=notice))


@router.post("/broadcast")
async def broadcast_set(
    request: Request,
    message: str = Form(...),
    notice_type: str = Form("info"),
):
    await verify_csrf(request)
    p = require_admin(request)

    notice_type = notice_type if notice_type in NOTICE_TYPES else "info"
    message = (message or "").strip()[:1000]
    if not message:
        notice = getattr(request.app.state, "broadcast_notice", None)
        return templates.TemplateResponse(
            "broadcast.html",
            _ctx(request, me=p, notice=notice, error="Message cannot be empty."),
            status_code=400,
        )

    request.app.state.broadcast_notice = {
        "message": message,
        "type": notice_type,
        "updated_by": p.username,
    }

    SessionLocal = _session_local(request)
    async with SessionLocal() as db:
        await _audit(
            db, request, p.user_id, p.username,
            "broadcast_set", "-", True,
            {"type": notice_type, "message": message[:100]},
        )
        await db.commit()

    return RedirectResponse(url="/admin/broadcast", status_code=302)


@router.post("/broadcast/clear")
async def broadcast_clear(request: Request):
    await verify_csrf(request)
    p = require_admin(request)

    request.app.state.broadcast_notice = None

    SessionLocal = _session_local(request)
    async with SessionLocal() as db:
        await _audit(db, request, p.user_id, p.username, "broadcast_clear", "-", True)
        await db.commit()

    return RedirectResponse(url="/admin/broadcast", status_code=302)
