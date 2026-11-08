# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
Guests: people from other islands in rooms here.

The server half of docs/internal/cross-island-rooms-assessment.md, held to
what it promises: a guest exists only because a room moderator invited a card
that holds up; signs in with the key on that card and nothing else; and reaches
the rooms they were invited to - and nothing else, however their token was
obtained or refreshed.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess

import httpx
import pytest
from conftest import (
    b64,
    create_room,
    foreigner,
    guest_session,
    register,
    start_island,
    stop_island,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def invite(island, moderator, room_id, card):
    return httpx.post(f"{island.base}/rooms/{room_id}/guests", headers=moderator.h, json={"card": card})


def signed_in_guest(island, owner, room_id, who):
    r = invite(island, owner, room_id, who.card)
    assert r.status_code == 201, r.text
    s = guest_session(island, who)
    assert s.status_code == 200, s.text
    return r.json()["guest_username"], s.json()


# --- inviting ----------------------------------------------------------------

def test_a_moderator_invites_a_card_and_the_guest_is_named_after_it(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    r = invite(island, owner, room, bob.card)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "invited"
    assert body["island_id"] == "island-a.test"
    # Display name, home island, and a slice of the key: never a name a local
    # account could have registered (those match ^[a-zA-Z][a-zA-Z0-9_]*$).
    assert body["guest_username"] == f"bob@island-b.test~{bob.kid[:6]}"

    # The same card again is the same guest, already invited.
    again = invite(island, owner, room, bob.card)
    assert again.status_code == 201
    assert again.json()["guest_username"] == body["guest_username"]
    assert again.json()["status"] == "already_invited"


def test_only_a_moderator_may_invite_a_guest(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    stranger = register(island, "str")
    r = invite(island, stranger, room, foreigner().card)
    assert r.status_code == 403


@pytest.mark.parametrize("break_it, why", [
    (lambda c: c["payload"].__setitem__("display_name", "mallory"), "a field changed after signing"),
    (lambda c: c.__setitem__("sig_b64", b64(bytes(64))), "a signature that is not one"),
    (lambda c: c["payload"].__setitem__("kid", "0" * 32), "a kid that is not the key's"),
])
def test_a_card_that_does_not_hold_up_is_refused(island, break_it, why):
    owner = register(island, "own")
    room = create_room(island, owner)
    card = json.loads(json.dumps(foreigner().card))
    break_it(card)
    assert invite(island, owner, room, card).status_code == 400, why


def test_a_card_from_this_island_is_not_a_guest(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    local_card = foreigner(island_id="island-a.test").card
    r = invite(island, owner, room, local_card)
    assert r.status_code == 400
    assert "this island" in r.json()["detail"]


def test_one_key_cannot_come_back_with_another_signing_key(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    assert invite(island, owner, room, bob.card).status_code == 201
    # Same X25519 key (same kid), a different Ed25519 key: not the same person.
    impostor = foreigner("bob", ed=Ed25519PrivateKey.generate())
    impostor.card["payload"]["x25519_pub_b64"] = bob.card["payload"]["x25519_pub_b64"]
    impostor.card["payload"]["kid"] = bob.kid
    from conftest import canonical_json
    impostor.card["sig_b64"] = b64(impostor.ed.sign(
        b"ws-contact-v1" + canonical_json(impostor.card["payload"]).encode()))
    assert invite(island, owner, room, impostor.card).status_code == 409


def test_a_card_built_by_the_client_itself_is_accepted(island, tmp_path):
    """
    The server re-checks a signature the JavaScript client made, over JSON the
    client canonicalised - so the two canonical forms must agree byte for byte,
    including a name that is not ASCII. Built with the real foreign-dm.js.
    """
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    script = tmp_path / "card.js"
    script.write_text(r"""
const crypto = require('crypto');
const FD = require(process.argv[2]);
(async () => {
  const x = crypto.generateKeyPairSync('x25519');
  const ed = crypto.generateKeyPairSync('ed25519');
  const raw = (k) => k.export({ format: 'der', type: 'spki' }).subarray(-32);
  const xPub = raw(x.publicKey), edPub = raw(ed.publicKey);
  const kid = crypto.createHash('sha256').update(xPub).digest('hex').slice(0, 32);
  const blob = await FD.buildContactBlob(
    { kid, x25519PubB64: xPub.toString('base64'), ed25519PubB64: edPub.toString('base64'),
      displayName: 'Евгений «тест»' },
    { islandId: 'island-b.test', signingKeyB64: '',
      entryPoints: [{ apiBase: 'https://b.test', wsBase: 'wss://b.test', label: 'основной' }] },
    async (bytes) => crypto.sign(null, Buffer.from(bytes), ed.privateKey),
  );
  process.stdout.write(JSON.stringify(blob));
})();
""", encoding="utf-8")
    fd = os.path.join(repo, "chrome_extension", "foreign-dm.js")
    out = subprocess.run([node, str(script), fd], capture_output=True, text=True, encoding="utf-8", check=True)
    card = json.loads(out.stdout)

    owner = register(island, "own")
    room = create_room(island, owner)
    r = invite(island, owner, room, card)
    assert r.status_code == 201, r.text
    # Letters of any script survive; spaces and the «» quotes do not.
    assert r.json()["guest_username"].startswith("Евгенийтест@island-b.test~")


# --- signing in ---------------------------------------------------------------

def test_a_guest_signs_in_with_the_key_on_their_card(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    name, session = signed_in_guest(island, owner, room, bob)
    assert session["guest"] is True
    assert session["username"] == name
    assert session["island_id"] == "island-a.test"
    assert session["access_token"] and session["refresh_token"]


def test_anybody_else_signing_is_refused(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    assert invite(island, owner, room, bob.card).status_code == 201
    r = guest_session(island, bob, sign_with=Ed25519PrivateKey.generate())
    assert r.status_code == 403


def test_a_key_nobody_invited_cannot_sign_in(island):
    assert guest_session(island, foreigner("nobody")).status_code == 403


def test_a_nonce_is_spent_even_by_a_refusal(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    assert invite(island, owner, room, bob.card).status_code == 201
    nonce = httpx.get(island.base + "/foreign/challenge").json()["nonce_b64"]
    # A wrong signature spends it...
    assert guest_session(island, bob, sign_with=Ed25519PrivateKey.generate(), nonce_b64=nonce).status_code == 403
    # ...so the right one, on the same nonce, comes too late.
    assert guest_session(island, bob, nonce_b64=nonce).status_code == 403


def test_the_mailbox_claim_spends_its_nonce_on_a_refusal_too(island, db_url):
    # The same bug lived in /foreign/claim: the nonce was deleted inside the
    # transaction every refusal rolled back.
    import asyncio

    import asyncpg

    nonce = httpx.get(island.base + "/foreign/challenge").json()["nonce_b64"]
    body = {"kid": "a" * 32, "nonce_b64": nonce, "sig_b64": b64(bytes(64))}
    assert httpx.post(island.base + "/foreign/claim", json=body).status_code == 403

    async def still_there():
        conn = await asyncpg.connect(db_url)
        try:
            return await conn.fetchval(
                "SELECT count(*) FROM chat_foreign_challenges WHERE nonce = $1", base64.b64decode(nonce))
        finally:
            await conn.close()
    assert asyncio.run(still_there()) == 0


def test_a_guest_cannot_log_in_with_a_password(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    name, _ = signed_in_guest(island, owner, room, foreigner("bob"))
    for pw in ("!guest", "", "Testpass!12345"):
        r = httpx.post(island.base + "/auth/login", json={"username": name, "password": pw or "x"})
        assert r.status_code in (401, 422), (pw, r.status_code)


# --- what a guest can reach ------------------------------------------------------

def _guest_in_room(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    bob = foreigner("bob")
    name, session = signed_in_guest(island, owner, room, bob)
    h = {"Authorization": f"Bearer {session['access_token']}"}
    return owner, room, bob, name, session, h


def test_a_guest_accepts_reads_and_holds_a_room_key(island):
    owner, room, bob, name, _, h = _guest_in_room(island)
    invites = httpx.get(island.base + "/rooms/invites", headers=h)
    assert invites.status_code == 200, invites.text
    assert room in [int(i.get("room_id") or i.get("id")) for i in invites.json()]

    assert httpx.post(f"{island.base}/rooms/{room}/invites/accept", headers=h, json={}).status_code == 200
    assert httpx.get(f"{island.base}/rooms/{room}/history", headers=h).status_code == 200
    members = httpx.get(f"{island.base}/rooms/{room}/members", headers=h)
    assert name in [m["username"] for m in members.json()]

    # Their own copy of the room key, as any member writes it.
    r = httpx.post(island.base + "/crypto/room-key", headers=h,
                   json={"room_id": room, "encrypted_room_key": b64(os.urandom(96))})
    assert r.status_code == 201, r.text

    # Members see exactly the keys the card carried - nothing the island chose.
    keys = httpx.get(f"{island.base}/keys/{name}", headers=owner.h)
    assert keys.status_code == 200, keys.text
    assert keys.json()["public_key"] == bob.card["payload"]["x25519_pub_b64"]
    assert keys.json()["ed25519_public_key"] == bob.ed_pub_b64


@pytest.mark.parametrize("method, path", [
    ("GET", "/dm/list"),
    ("POST", "/dm/open"),
    ("GET", "/friends/list"),
    ("POST", "/rooms"),
    ("GET", "/rooms/public/list"),
    ("GET", "/profile/me"),
    ("POST", "/crypto/ed25519-key"),   # the signing key is the card's, and stays it
    ("POST", "/keys/me"),
    ("POST", "/auth/change-password"),
    ("POST", "/auth/delete-account"),
    ("GET", "/foreign/boxes"),
    ("GET", "/crypto/rooms/key-gaps"),  # moderation is not a guest's, whatever their role
    ("GET", "/dm/list/"),               # a trailing slash is not a way round the list
])
def test_a_guest_reaches_nothing_else(island, method, path):
    *_, h = _guest_in_room(island)
    r = httpx.request(method, island.base + path, headers=h, json={})
    assert r.status_code == 403, (method, path, r.status_code, r.text)
    assert r.json().get("reason") == "guest"


def test_moderation_endpoints_are_closed_to_a_guest_in_the_room(island):
    owner, room, _, _, _, h = _guest_in_room(island)
    victim = register(island, "vic")
    for method, path, body in [
        ("POST", f"/rooms/{room}/invite", {"username": victim.username}),
        ("POST", f"/rooms/{room}/kick", {"username": owner.username}),
        ("POST", f"/rooms/{room}/guests", {"card": foreigner().card}),
        ("PUT", f"/rooms/{room}/name", {"name": "taken over"}),
    ]:
        r = httpx.request(method, island.base + path, headers=h, json=body)
        assert r.status_code == 403, (path, r.status_code)


def test_a_refreshed_token_is_still_a_guest_token(island):
    """Guest-ness comes from the database: /auth/refresh issues a plain token."""
    *_, session, _ = _guest_in_room(island)
    r = httpx.post(island.base + "/auth/refresh", json={"refresh_token": session["refresh_token"]})
    assert r.status_code == 200, r.text
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    assert httpx.get(island.base + "/dm/list", headers=h).status_code == 403
    assert httpx.get(island.base + "/rooms/invites", headers=h).status_code == 200


def test_the_dm_socket_refuses_a_guest(island, db_url):
    import asyncio

    import asyncpg
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.client import connect

    *_, name, session, _ = _guest_in_room(island)

    # A guest cannot open a DM, so normally the socket would refuse them anyway,
    # for not being in the thread. Put them in one directly - a stray row, a
    # future bug - so that what is tested is the guest rule itself.
    async def thread_with_guest():
        conn = await asyncpg.connect(db_url)
        try:
            uid = await conn.fetchval("SELECT id FROM users WHERE username = $1", name)
            tid = await conn.fetchval("INSERT INTO chat_dm_threads DEFAULT VALUES RETURNING id")
            await conn.execute("INSERT INTO chat_dm_members(thread_id, user_id) VALUES ($1, $2)", tid, uid)
            return tid
        finally:
            await conn.close()
    tid = asyncio.run(thread_with_guest())

    with connect(island.ws_base + f"/ws-dm?thread_id={tid}",
                 additional_headers={"Origin": "chrome-extension://test"}) as ws:
        ws.send(json.dumps({"type": "auth", "token": session["access_token"]}))
        with pytest.raises(ConnectionClosed) as closed:
            while True:
                ws.recv(timeout=10)
    assert closed.value.rcvd.code == 1008


def test_kicking_a_guest_ends_their_access_to_the_room(island):
    owner, room, _, name, _, h = _guest_in_room(island)
    assert httpx.post(f"{island.base}/rooms/{room}/invites/accept", headers=h, json={}).status_code == 200
    assert httpx.get(f"{island.base}/rooms/{room}/history", headers=h).status_code == 200
    r = httpx.post(f"{island.base}/rooms/{room}/kick", headers=owner.h, json={"username": name})
    assert r.status_code == 200, r.text
    assert httpx.get(f"{island.base}/rooms/{room}/history", headers=h).status_code in (403, 404)


# --- the local invite still behaves (it now shares the state machine) ---------

def test_inviting_a_local_member_still_works_end_to_end(island):
    owner = register(island, "own")
    room = create_room(island, owner)
    alice = register(island, "ali")
    # Alice accepts group invites from anybody, so the friends-only check passes.
    r = httpx.put(island.base + "/profile/me", headers=alice.h,
                  json={"privacy": {"allow_group_invites_from_non_friends": True}})
    assert r.status_code == 200, r.text
    r = httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h, json={"username": alice.username})
    assert r.status_code == 201 and r.json()["status"] == "invited", r.text
    again = httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h, json={"username": alice.username})
    assert again.json()["status"] == "already_invited"
    assert httpx.post(f"{island.base}/rooms/{room}/invites/accept", headers=alice.h, json={}).status_code == 200
    member = httpx.post(f"{island.base}/rooms/{room}/invite", headers=owner.h, json={"username": alice.username})
    assert member.json()["status"] == "already_member"
    # A local member is not a guest: the rest of the API is theirs.
    assert httpx.get(island.base + "/dm/list", headers=alice.h).status_code == 200


# --- the island switch ----------------------------------------------------------

def test_an_island_can_refuse_guests(db_url, tmp_path):
    isl = start_island(db_url, "island-c.test", tmp_path, ISLAND_ACCEPT_GUESTS="0")
    try:
        owner = register(isl, "own")
        room = create_room(isl, owner)
        assert invite(isl, owner, room, foreigner().card).status_code == 404
        assert guest_session(isl, foreigner()).status_code == 404
        assert "guests from other islands in rooms here: off" in isl.log()
    finally:
        stop_island(isl)


def test_the_startup_log_says_guests_are_on(island):
    assert "guests from other islands in rooms here: on" in island.log()
