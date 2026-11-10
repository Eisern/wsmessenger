# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
An account's own safety switches, held to what they promise: turning 2FA off
takes one of the two factors and never neither; a revoked session is turned
away by every socket; and an owner who deletes their account leaves each room
to one of its members rather than taking it down with them.
"""

from __future__ import annotations

import asyncio
import json
import time

import asyncpg
import httpx
import pyotp
import pytest
from conftest import create_room, register

PASSWORD = "Testpass!12345"   # what conftest.register signs everybody up with


# --- 2FA ---------------------------------------------------------------------

def _enable_totp(island, who) -> str:
    r = httpx.post(island.base + "/auth/totp/setup", headers=who.h)
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = httpx.post(island.base + "/auth/totp/verify-setup", headers=who.h,
                   json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return secret


def _wrong_code(secret: str) -> str:
    # The server accepts the codes either side of now as well, so "wrong" has
    # to miss all three.
    totp, now = pyotp.TOTP(secret), time.time()
    taken = {totp.at(now + d) for d in (-60, -30, 0, 30, 60)}
    return next(f"{n:06d}" for n in range(1000000) if f"{n:06d}" not in taken)


def _enabled(island, who) -> bool:
    r = httpx.get(island.base + "/auth/totp/status", headers=who.h)
    assert r.status_code == 200, r.text
    return r.json()["enabled"]


def _disable(island, who, **body) -> httpx.Response:
    return httpx.post(island.base + "/auth/totp/disable", headers=who.h, json=body)


def test_turning_2fa_off_takes_either_factor_and_never_neither(island):
    who = register(island, "tfa")

    secret = _enable_totp(island, who)
    assert _disable(island, who).status_code == 400
    assert _disable(island, who, code=_wrong_code(secret), password="Wrongpass!12345").status_code == 401
    assert _disable(island, who, password="Wrongpass!12345").status_code == 401
    assert _disable(island, who, code=_wrong_code(secret)).status_code == 401
    assert _enabled(island, who), "a refused attempt must leave 2FA on"

    # A wrong code does not stop a right password ...
    r = _disable(island, who, code=_wrong_code(secret), password=PASSWORD)
    assert r.status_code == 200, r.text
    assert not _enabled(island, who)
    assert _disable(island, who, password=PASSWORD).status_code == 400, "nothing left to turn off"

    # ... nor a wrong password a right code ...
    secret = _enable_totp(island, who)
    r = _disable(island, who, code=pyotp.TOTP(secret).now(), password="Wrongpass!12345")
    assert r.status_code == 200, r.text
    assert not _enabled(island, who)

    # ... and either alone is enough.
    _enable_totp(island, who)
    assert _disable(island, who, password=PASSWORD).status_code == 200
    assert not _enabled(island, who)
    secret = _enable_totp(island, who)
    assert _disable(island, who, code=pyotp.TOTP(secret).now()).status_code == 200
    assert not _enabled(island, who)


# --- revoked sessions --------------------------------------------------------

@pytest.mark.parametrize("path", ["/ws", "/ws-dm?thread_id=1", "/ws-notify"])
def test_a_revoked_session_is_turned_away_by_every_socket(island, path):
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect

    who = register(island, "rev")
    r = httpx.post(island.base + "/auth/logout-all", headers=who.h)
    assert r.status_code == 200, r.text

    frames = []
    with connect(island.ws_base + path, additional_headers={"Origin": "chrome-extension://test"}) as ws:
        ws.send(json.dumps({"type": "auth", "token": who.token}))
        with pytest.raises(ConnectionClosed) as closed:
            while True:
                frames.append(json.loads(ws.recv(timeout=10)))
    # Told why, then closed for that reason - not merely refused, which a bad
    # token would also get ("forbidden").
    assert closed.value.rcvd.code == 1008
    assert closed.value.rcvd.reason == "session revoked"
    assert any(f.get("type") == "auth_state" and f.get("reason") == "session_revoked" for f in frames), frames


def test_a_session_revoked_while_connected_is_closed_on_its_next_move(island, db_url):
    # Revoked behind the socket's back - straight in the database, without the
    # kick /auth/logout-all also sends - so what closes it is the socket's own
    # check. On /ws-dm that runs at most every ten seconds, and reads a value
    # cached for as long (/ws-notify waits thirty, too long for a test).
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect

    who = register(island, "liv")

    async def db(sql: str, *args):
        conn = await asyncpg.connect(db_url)
        try:
            return await conn.fetchval(sql, *args)
        finally:
            await conn.close()

    uid = asyncio.run(db("SELECT id FROM users WHERE username = $1", who.username))
    tid = asyncio.run(db("INSERT INTO chat_dm_threads DEFAULT VALUES RETURNING id"))
    asyncio.run(db("INSERT INTO chat_dm_members(thread_id, user_id) VALUES ($1, $2)", tid, uid))

    frames = []
    with connect(island.ws_base + f"/ws-dm?thread_id={tid}",
                 additional_headers={"Origin": "chrome-extension://test"}) as ws:
        ws.send(json.dumps({"type": "auth", "token": who.token}))
        while json.loads(ws.recv(timeout=10)).get("type") != "dm_presence":
            pass
        ws.send(json.dumps({"type": "ping"}))
        assert json.loads(ws.recv(timeout=10)).get("type") == "pong", "connected and answering"
        asyncio.run(db("UPDATE users SET tokens_valid_after = $1 WHERE id = $2", time.time(), uid))
        time.sleep(11.5)
        ws.send(json.dumps({"type": "ping"}))
        with pytest.raises(ConnectionClosed) as closed:
            while True:
                frames.append(json.loads(ws.recv(timeout=10)))
    assert closed.value.rcvd.code == 1008
    assert closed.value.rcvd.reason == "session revoked"
    assert any(f.get("type") == "auth_state" and f.get("reason") == "session_revoked" for f in frames), frames


# --- deleting an owner -------------------------------------------------------

def _join(island, owner, room: int, member) -> None:
    r = httpx.put(island.base + "/profile/me", headers=member.h,
                  json={"privacy": {"allow_group_invites_from_non_friends": True}})
    assert r.status_code == 200, r.text
    r = httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h, json={"username": member.username})
    assert r.status_code == 201, r.text
    r = httpx.post(f"{island.base}/rooms/{room}/invites/accept", headers=member.h, json={})
    assert r.status_code == 200, r.text


def _delete_account(island, who) -> None:
    r = httpx.post(island.base + "/auth/delete-account", headers=who.h,
                   json={"password": PASSWORD, "confirmation": "DELETE"})
    assert r.status_code == 200, r.text


def _rooms(db_url, *room_ids: int) -> dict[int, dict]:
    async def read():
        conn = await asyncpg.connect(db_url)
        try:
            rows = await conn.fetch("""
                SELECT r.id, r.name, u.username AS owner,
                       (SELECT array_agg(m.role || ':' || mu.username ORDER BY mu.username)
                          FROM chat_room_members m JOIN users mu ON mu.id = m.user_id
                         WHERE m.room_id = r.id) AS members
                  FROM chat_rooms r JOIN users u ON u.id = r.owner_user_id
                 WHERE r.id = ANY($1::int[])
            """, list(room_ids))
            return {r["id"]: {"name": r["name"], "owner": r["owner"], "members": list(r["members"] or [])}
                    for r in rows}
        finally:
            await conn.close()
    return asyncio.run(read())


def test_deleting_an_owner_leaves_each_room_to_its_own_member(island, db_url):
    # Two rooms with a different heir each, and one with nobody to inherit it:
    # each room goes to its own member, and the empty one goes away.
    owner, bea, cid = register(island, "own"), register(island, "bea"), register(island, "cid")
    first, second = create_room(island, owner, "first"), create_room(island, owner, "second")
    empty = create_room(island, owner, "empty")
    _join(island, owner, first, bea)
    _join(island, owner, second, cid)

    _delete_account(island, owner)

    rooms = _rooms(db_url, first, second, empty)
    assert rooms[first] == {"name": "first", "owner": bea.username, "members": [f"owner:{bea.username}"]}
    assert rooms[second] == {"name": "second", "owner": cid.username, "members": [f"owner:{cid.username}"]}
    assert empty not in rooms


def test_an_heir_with_a_room_of_that_name_gets_it_renamed_not_lost(island, db_url):
    owner, bea = register(island, "own"), register(island, "bea")
    hers = create_room(island, bea, "same")
    inherited = create_room(island, owner, "same")
    _join(island, owner, inherited, bea)

    _delete_account(island, owner)

    rooms = _rooms(db_url, hers, inherited)
    assert rooms[hers]["name"] == "same" and rooms[hers]["owner"] == bea.username
    assert rooms[inherited] == {
        "name": f"same (from {owner.username})",
        "owner": bea.username,
        "members": [f"owner:{bea.username}"],
    }
