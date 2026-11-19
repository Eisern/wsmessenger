# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
Changing a room's key.

After somebody is removed, the owner gives the room a new key so that what is
written from then on is closed to them. That used to be one request per member:
stopped half way, it left some members on the new key and the rest - the owner
included - on the old one. POST /crypto/room/{id}/rotate changes every copy in
one transaction or none, and these tests hold it to that: who may call it, that
the list must be the room's members exactly, what happens to a member the key
cannot go to yet, and that the key-write limit no longer cuts a rotation short.
"""

from __future__ import annotations

import contextlib
import json
import os

import httpx
import pytest
from conftest import b64, create_room, register, start_island, stop_island


def wrap() -> str:
    """A wrapped key as the server sees it: opaque."""
    return b64(os.urandom(120))


def kid() -> str:
    return os.urandom(8).hex()


def join(island, owner, room: int, member) -> None:
    r = httpx.put(island.base + "/profile/me", headers=member.h,
                  json={"privacy": {"allow_group_invites_from_non_friends": True}})
    assert r.status_code == 200, r.text
    r = httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h, json={"username": member.username})
    assert r.status_code == 201, r.text
    r = httpx.post(f"{island.base}/rooms/{room}/invites/accept", headers=member.h, json={})
    assert r.status_code == 200, r.text


def room_with(island, n: int):
    """A room, its owner, and n members who each hold a copy of its key."""
    owner = register(island, "own")
    room = create_room(island, owner)
    members = []
    for _ in range(n):
        m = register(island, "mem")
        join(island, owner, room, m)
        r = httpx.post(f"{island.base}/crypto/room/{room}/share", headers=owner.h,
                       params={"target_username": m.username},
                       json={"encrypted_room_key": wrap(), "key_id": "aa" * 8})
        assert r.status_code == 200, r.text
        members.append(m)
    return owner, room, members


def rotate(island, who, room: int, keys: dict[str, str], without=(), key_id: str | None = None) -> httpx.Response:
    return httpx.post(f"{island.base}/crypto/room/{room}/rotate", headers=who.h, json={
        "key_id": key_id or kid(),
        "keys": [{"username": n, "encrypted_room_key": k} for n, k in keys.items()],
        "without": list(without),
    })


def current(island, who, room: int) -> str | None:
    r = httpx.get(f"{island.base}/crypto/room-key/{room}", headers=who.h)
    return r.json()["encrypted_room_key"] if r.status_code == 200 else None


def archived(island, who, room: int) -> dict[str, str]:
    r = httpx.get(f"{island.base}/crypto/room-key/{room}/archive", headers=who.h)
    assert r.status_code == 200, r.text
    return {k["key_id"]: k["encrypted_room_key"] for k in r.json()["keys"]}


# --- everybody, at once ----------------------------------------------------------

def test_every_member_gets_their_own_new_copy_in_one_request(island):
    owner, room, (a, b) = room_with(island, 2)
    new = {owner.username: wrap(), a.username: wrap(), b.username: wrap()}
    new_kid = kid()

    r = rotate(island, owner, room, new, key_id=new_kid)
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "rotated": 3, "without": 0}

    for who in (owner, a, b):
        assert current(island, who, room) == new[who.username]
        # The copy is also filed under its id, next to the one it replaced:
        # yesterday's messages stay readable.
        assert archived(island, who, room)[new_kid] == new[who.username]
    assert "aa" * 8 in archived(island, a, room)


def test_names_are_matched_whatever_their_case(island):
    owner, room, (a,) = room_with(island, 1)
    new = {owner.username.upper(): wrap(), a.username.title(): wrap()}
    assert rotate(island, owner, room, new).status_code == 200
    assert current(island, a, room) == new[a.username.title()]


# --- who may ---------------------------------------------------------------------

def test_only_the_owner_changes_the_key(island):
    owner, room, (admin, member) = room_with(island, 2)
    r = httpx.post(f"{island.base}/rooms/{room}/members/{admin.username}/role",
                   headers=owner.h, json={"role": "admin"})
    assert r.status_code == 200, r.text
    stranger = register(island, "str")
    before = {w.username: current(island, w, room) for w in (owner, admin, member)}
    everyone = {owner.username: wrap(), admin.username: wrap(), member.username: wrap()}

    # An admin may hand out the key the room has; what that key is, is the owner's.
    assert rotate(island, admin, room, everyone).status_code == 403
    assert rotate(island, member, room, everyone).status_code == 403
    assert rotate(island, stranger, room, everyone).status_code == 403
    assert httpx.post(f"{island.base}/crypto/room/{room}/rotate", json={
        "key_id": kid(), "keys": [{"username": owner.username, "encrypted_room_key": wrap()}],
    }).status_code == 401
    assert rotate(island, owner, 999_999_999, everyone).status_code == 404

    assert {w.username: current(island, w, room) for w in (owner, admin, member)} == before


# --- the list is the room, exactly ------------------------------------------------

def test_a_list_that_is_not_the_rooms_members_changes_nothing(island):
    owner, room, (a, b) = room_with(island, 2)
    outsider = register(island, "out")
    before = {w.username: current(island, w, room) for w in (owner, a, b)}

    # Somebody joined since the owner looked: they would be left on no key at
    # all, or - handed the old one by an admin - on the key just retired.
    missing = rotate(island, owner, room, {owner.username: wrap(), a.username: wrap()})
    assert missing.status_code == 409, missing.text
    # Somebody left since the owner looked - or was never there.
    extra = rotate(island, owner, room, {
        owner.username: wrap(), a.username: wrap(), b.username: wrap(), outsider.username: wrap()})
    assert extra.status_code == 409, extra.text
    nobody = rotate(island, owner, room, {
        owner.username: wrap(), a.username: wrap(), b.username: wrap(), "no_such_user_at_all": wrap()})
    assert nobody.status_code == 409, nobody.text

    assert {w.username: current(island, w, room) for w in (owner, a, b)} == before


def test_a_removed_member_cannot_be_given_the_new_key(island):
    owner, room, (a, gone) = room_with(island, 2)
    r = httpx.post(f"{island.base}/rooms/{room}/kick", headers=owner.h, json={"username": gone.username})
    assert r.status_code == 200 and r.json()["removed"], r.text

    with_them = rotate(island, owner, room, {owner.username: wrap(), a.username: wrap(), gone.username: wrap()})
    assert with_them.status_code == 409
    assert rotate(island, owner, room, {owner.username: wrap(), a.username: wrap()}).status_code == 200
    assert httpx.get(f"{island.base}/crypto/room-key/{room}", headers=gone.h).status_code in (403, 404)


def test_somebody_invited_but_not_yet_in_is_not_part_of_it(island):
    owner, room, (a,) = room_with(island, 1)
    invited = register(island, "inv")
    httpx.put(island.base + "/profile/me", headers=invited.h,
              json={"privacy": {"allow_group_invites_from_non_friends": True}})
    assert httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h,
                      json={"username": invited.username}).status_code == 201

    assert rotate(island, owner, room, {owner.username: wrap(), a.username: wrap()}).status_code == 200
    assert rotate(island, owner, room, {
        owner.username: wrap(), a.username: wrap(), invited.username: wrap()}).status_code == 409


@pytest.mark.parametrize("why, body", [
    ("no key id", lambda o, a: {"key_id": "", "keys": [{"username": o, "encrypted_room_key": "x"}]}),
    ("a key id that is not hex", lambda o, a: {"key_id": "zz", "keys": [{"username": o, "encrypted_room_key": "x"}]}),
    ("nobody", lambda o, a: {"key_id": "ab12", "keys": []}),
    ("a name twice", lambda o, a: {"key_id": "ab12", "keys": [
        {"username": o, "encrypted_room_key": "x"}, {"username": a, "encrypted_room_key": "x"},
        {"username": a.upper(), "encrypted_room_key": "y"}]}),
    ("a name on both lists", lambda o, a: {"key_id": "ab12", "without": [a], "keys": [
        {"username": o, "encrypted_room_key": "x"}, {"username": a, "encrypted_room_key": "x"}]}),
    ("an empty copy", lambda o, a: {"key_id": "ab12", "keys": [
        {"username": o, "encrypted_room_key": "x"}, {"username": a, "encrypted_room_key": ""}]}),
    ("the owner left without", lambda o, a: {"key_id": "ab12", "without": [o], "keys": [
        {"username": a, "encrypted_room_key": "x"}]}),
])
def test_a_malformed_rotation_is_refused_whole(island, why, body):
    owner, room, (a,) = room_with(island, 1)
    before = {w.username: current(island, w, room) for w in (owner, a)}
    r = httpx.post(f"{island.base}/crypto/room/{room}/rotate", headers=owner.h,
                   json=body(owner.username, a.username))
    assert r.status_code in (400, 422), f"{why}: {r.status_code} {r.text}"
    assert {w.username: current(island, w, room) for w in (owner, a)} == before, why


# --- a member the key cannot go to yet -------------------------------------------

def test_a_member_left_without_becomes_a_gap_and_is_filled_like_any_other(island):
    """
    Their key changed and nobody has checked it, say. The room must not stay on
    the old key for that, and they must not keep a copy of it as if it were
    current: they hold nothing until somebody hands them the new one.
    """
    owner, room, (a, unverified) = room_with(island, 2)
    new = {owner.username: wrap(), a.username: wrap()}

    r = rotate(island, owner, room, new, without=[unverified.username])
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "rotated": 2, "without": 1}
    assert current(island, a, room) == new[a.username]
    assert current(island, unverified, room) is None
    # Still a member, and what they could read before they still can.
    assert httpx.get(f"{island.base}/rooms/{room}/members", headers=unverified.h).status_code == 200
    assert "aa" * 8 in archived(island, unverified, room)

    gaps = httpx.get(f"{island.base}/crypto/rooms/key-gaps", headers=owner.h, params={"room_id": room})
    assert gaps.status_code == 200, gaps.text
    assert [g["username"] for g in gaps.json()["gaps"]] == [unverified.username]

    later = wrap()
    r = httpx.post(f"{island.base}/crypto/room/{room}/share", headers=owner.h,
                   params={"target_username": unverified.username},
                   json={"encrypted_room_key": later, "key_id": kid(), "if_absent": True})
    assert r.status_code == 200 and r.json()["written"] is True, r.text
    assert current(island, unverified, room) == later


# --- the limit that used to cut it short ------------------------------------------

def test_a_rotation_is_one_key_write_however_many_members(db_url, tmp_path):
    """
    The island allows so many key writes in ten minutes. One request per member
    reached that in a room of any size - at once, or on the second removal in a
    row - and what stopped was the middle of a rotation. The suite's own island
    has every limit raised, so this one keeps the real mechanism with a small
    number: more members than writes allowed.
    """
    isl = start_island(db_url, "island-a.test", tmp_path,
                       RL_CRYPTO_KEYWRITE_USER_PER_10MIN="4", RL_CRYPTO_KEYWRITE_IP_PER_10MIN="1000")
    try:
        owner = register(isl, "own")
        room = create_room(isl, owner)
        members = [register(isl, "mem") for _ in range(6)]
        for m in members:
            join(isl, owner, room, m)

        new = {w.username: wrap() for w in [owner, *members]}
        r = rotate(isl, owner, room, new)
        assert r.status_code == 200, r.text
        assert all(current(isl, m, room) == new[m.username] for m in members)

        # The same six, one request each - what both clients used to do.
        answers = [
            httpx.post(f"{isl.base}/crypto/room/{room}/share", headers=owner.h,
                       params={"target_username": m.username},
                       json={"encrypted_room_key": wrap(), "key_id": kid()}).status_code
            for m in members
        ]
        assert 429 in answers, answers
    finally:
        stop_island(isl)


# --- telling the room -------------------------------------------------------------

def test_members_are_woken_to_read_the_new_key(island):
    """
    Until a member reads the new key they go on writing under the old one - the
    one the removed member holds. The wake-up carries no key and no names.
    """
    from websockets.sync.client import connect

    owner, room, (a, b) = room_with(island, 2)

    def listen(stack, who):
        ws = stack.enter_context(connect(island.ws_base + "/ws-notify",
                                         additional_headers={"Origin": "chrome-extension://test"}))
        ws.send(json.dumps({"type": "auth", "token": who.token}))
        while json.loads(ws.recv(timeout=10)).get("type") != "notify_ready":
            pass
        return ws

    def frames(ws) -> list[dict]:
        out = []
        try:
            while True:
                out.append(json.loads(ws.recv(timeout=1.5)))
        except TimeoutError:
            return out

    with contextlib.ExitStack() as stack:
        socks = {w.username: listen(stack, w) for w in (owner, a, b)}
        assert rotate(island, owner, room, {owner.username: wrap(), a.username: wrap()},
                      without=[b.username]).status_code == 200
        got = {name: frames(ws) for name, ws in socks.items()}

    def kinds(name):
        return [f["type"] for f in got[name] if f.get("room_id") == room]

    assert kinds(a.username) == ["notify_room_key"]
    assert set(got[a.username][0]) == {"type", "room_id", "ts"}
    # The owner made the key; what it is told is that somebody is missing one.
    assert kinds(owner.username) == ["notify_key_gap"]
    # Left without: nothing to read yet.
    assert kinds(b.username) == []
