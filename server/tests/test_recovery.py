# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
Recovering an account with its recovery phrase (/auth/recover-start, /auth/recover,
/auth/recovery-key).

An account recovers by signing the server's nonce, with the account name and the
new password, under its recovery key: a request seen once is good for nothing.
An account from before holds only the hash of a fixed secret; it recovers with
that until its owner next unlocks and moves it to a key, and from then on the
secret opens nothing.

What a stranger who knows only a name must not be able to do: lock that person
out of their own recovery, void the recovery they have in progress, learn which
accounts exist or can be recovered, or - with a stolen session - plant a
recovery key of their own. And the log is not told who tried.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import uuid

import httpx
import pytest
from conftest import start_island, stop_island
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PASSWORD = "Testpass!12345"
NEW_PASSWORD = "Newpass!67890"
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


@pytest.fixture(scope="module")
def isl(db_url, tmp_path_factory):
    # The real per-account number; the address limit raised, since every
    # request here comes from one address.
    island = start_island(db_url, "island-a.test", tmp_path_factory.mktemp("recover"),
                          RL_RECOVER_USER_PER_HOUR="3", RL_RECOVER_IP_PER_HOUR="1000")
    yield island
    stop_island(island)


class Acc:
    def __init__(self, name: str, auth: bytes | None, key: Ed25519PrivateKey | None):
        self.name, self.auth, self.key = name, auth, key


def account(isl, kind: str = "key") -> Acc:
    """kind: "key" (a client of today), "hash" (from before), "none"."""
    name = f"rec{uuid.uuid4().hex[:8]}"
    pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    auth = os.urandom(32) if kind in ("key", "hash") else None
    key = Ed25519PrivateKey.generate() if kind == "key" else None
    body = {"username": name, "password": PASSWORD, "public_key": b64(pub)}
    if auth:
        # Today's client sends both, so an older server still gets the hash.
        body["recovery_key_hash"] = hashlib.sha256(auth).hexdigest()
    if key:
        body["recovery_pub"] = b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    r = httpx.post(isl.base + "/auth/register", json=body)
    assert r.status_code == 201, r.text
    return Acc(name, auth, key)


def challenge(name: str, nonce: str, new_password: str) -> bytes:
    """account-recovery.js challengeBytes, written out again."""
    return (b"ws-recover-v1\x00" + name.lower().encode() + b"\x00" + nonce.encode() + b"\x00"
            + hashlib.sha256(new_password.encode()).digest())


def start(isl, name: str) -> str:
    r = httpx.post(isl.base + "/auth/recover-start", json={"username": name})
    assert r.status_code == 200, r.text
    return r.json()["nonce"]


def with_secret(isl, name: str, nonce: str, auth: bytes) -> httpx.Response:
    return httpx.post(isl.base + "/auth/recover", json={
        "username": name, "nonce": nonce, "recovery_auth_b64": b64(auth), "new_password": NEW_PASSWORD,
    })


def with_signature(isl, name: str, nonce: str, key: Ed25519PrivateKey, signed: bytes | None = None,
                   new_password: str = NEW_PASSWORD) -> httpx.Response:
    sig = key.sign(signed if signed is not None else challenge(name, nonce, new_password))
    # As both clients send it: base64url, unpadded (CryptoUtils.ed25519Sign).
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return httpx.post(isl.base + "/auth/recover", json={
        "username": name, "nonce": nonce, "signature_b64": sig_b64, "new_password": new_password,
    })


def stored_hash(db_url: str, name: str):
    """What the server keeps of the old secret, read from the database itself."""
    async def go():
        import asyncpg
        conn = await asyncpg.connect(db_url)
        try:
            return await conn.fetchval("SELECT recovery_key_hash FROM users WHERE username = $1", name)
        finally:
            await conn.close()
    return asyncio.run(go())


def logs_in(isl, name: str, password: str) -> str | None:
    r = httpx.post(isl.base + "/auth/login", json={"username": name, "password": password})
    return r.json()["access_token"] if r.status_code == 200 else None


def state(isl, token: str) -> str:
    r = httpx.get(isl.base + "/auth/recovery-key", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r.json()["state"]


def move(isl, token: str, auth: bytes, key: Ed25519PrivateKey) -> httpx.Response:
    return httpx.post(isl.base + "/auth/recovery-key", headers={"Authorization": f"Bearer {token}"}, json={
        "recovery_auth_b64": b64(auth),
        "recovery_pub": b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
    })


# --- a recovery key ------------------------------------------------------------

def test_a_signature_over_the_nonce_resets_the_password(isl):
    a = account(isl)
    r = with_signature(isl, a.name, start(isl, a.name), a.key)
    assert r.status_code == 200, r.text
    assert logs_in(isl, a.name, NEW_PASSWORD)
    assert not logs_in(isl, a.name, PASSWORD)


def test_a_signature_is_good_for_its_own_nonce_name_and_password_only(isl):
    a = account(isl)
    old = start(isl, a.name)
    # Seen once, replayed: its nonce is spent.
    assert with_signature(isl, a.name, old, a.key).status_code == 200
    replay = httpx.post(isl.base + "/auth/recover", json={
        "username": a.name, "nonce": old, "new_password": NEW_PASSWORD,
        "signature_b64": b64(a.key.sign(challenge(a.name, old, NEW_PASSWORD))),
    })
    assert replay.status_code == 401
    # Over another nonce, another account, another password: refused (by the
    # fourth, the failure limit answers - a refusal too).
    n = start(isl, a.name)
    assert with_signature(isl, a.name, n, a.key, signed=challenge(a.name, old, NEW_PASSWORD)).status_code in (401, 429)
    n = start(isl, a.name)
    assert with_signature(isl, a.name, n, a.key, signed=challenge("someone", n, NEW_PASSWORD)).status_code in (401, 429)
    n = start(isl, a.name)
    assert with_signature(isl, a.name, n, a.key, signed=challenge(a.name, n, "Otherpass!123")).status_code in (401, 429)
    assert logs_in(isl, a.name, NEW_PASSWORD)


def test_an_account_with_a_key_is_not_opened_by_the_old_secret(isl, db_url):
    # Registered with both, as today's client does: the hash is not kept.
    a = account(isl)
    assert stored_hash(db_url, a.name) is None
    assert with_secret(isl, a.name, start(isl, a.name), a.auth).status_code == 401
    assert logs_in(isl, a.name, PASSWORD)


def test_another_key_signs_nothing(isl):
    a = account(isl)
    assert with_signature(isl, a.name, start(isl, a.name), Ed25519PrivateKey.generate()).status_code == 401


# --- an account from before ------------------------------------------------------

def test_an_account_from_before_still_recovers_with_its_secret(isl):
    a = account(isl, "hash")
    assert with_secret(isl, a.name, start(isl, a.name), a.auth).status_code == 200
    assert logs_in(isl, a.name, NEW_PASSWORD)


def test_moving_to_a_key_spends_the_old_secret(isl, db_url):
    a = account(isl, "hash")
    assert stored_hash(db_url, a.name)
    token = logs_in(isl, a.name, PASSWORD)
    assert state(isl, token) == "hash"
    key = Ed25519PrivateKey.generate()

    assert move(isl, token, os.urandom(32), key).status_code == 401
    assert state(isl, token) == "hash"

    assert move(isl, token, a.auth, key).status_code == 200
    assert state(isl, token) == "key"
    assert stored_hash(db_url, a.name) is None
    assert move(isl, token, a.auth, key).status_code == 200          # again: the same key, fine
    other = move(isl, token, a.auth, Ed25519PrivateKey.generate())
    assert other.status_code == 409 and "already" in other.json()["detail"], other.text

    assert with_secret(isl, a.name, start(isl, a.name), a.auth).status_code == 401
    assert with_signature(isl, a.name, start(isl, a.name), key).status_code == 200


def test_a_session_alone_cannot_plant_a_recovery_key(isl):
    # A stolen password must not become a way back in after the owner changes it.
    a = account(isl, "none")
    token = logs_in(isl, a.name, PASSWORD)
    assert state(isl, token) == "none"
    assert move(isl, token, os.urandom(32), Ed25519PrivateKey.generate()).status_code == 409
    assert state(isl, token) == "none"


# --- what a name alone can do ----------------------------------------------------------

def test_requests_in_somebodys_name_do_not_lock_them_out(isl):
    # Counted on every request, three of these used to close that person's
    # recovery for an hour - with nothing but their name.
    a = account(isl)
    for _ in range(6):
        r = with_signature(isl, a.name, "made-up", Ed25519PrivateKey.generate())
        assert r.status_code in (401, 429), r.text
    assert with_signature(isl, a.name, start(isl, a.name), a.key).status_code == 200


def test_a_made_up_nonce_does_not_void_the_one_in_progress(isl):
    a = account(isl)
    nonce = start(isl, a.name)
    assert with_signature(isl, a.name, "f" * 64, a.key).status_code == 401
    assert with_signature(isl, a.name, nonce, a.key).status_code == 200


def test_wrong_attempts_are_limited_without_closing_the_right_one(isl):
    a = account(isl)
    codes = [with_signature(isl, a.name, start(isl, a.name), Ed25519PrivateKey.generate()).status_code
             for _ in range(5)]
    assert codes[:3] == [401, 401, 401], codes
    assert 429 in codes[3:], codes
    # The limit is for noise: the owner of the phrase still gets in.
    assert with_signature(isl, a.name, start(isl, a.name), a.key).status_code == 200


def test_who_exists_and_who_can_recover_is_not_told(isl):
    answers = []
    for kind in ("none", "hash", "key"):
        a = account(isl, kind)
        r = with_signature(isl, a.name, start(isl, a.name), Ed25519PrivateKey.generate())
        answers.append((r.status_code, r.json()))
    ghost = f"nobody{uuid.uuid4().hex[:6]}"
    r = with_signature(isl, ghost, start(isl, ghost), Ed25519PrivateKey.generate())
    answers.append((r.status_code, r.json()))
    a = account(isl)
    r = with_signature(isl, a.name, "f" * 64, a.key)      # a nonce that is not the one
    answers.append((r.status_code, r.json()))
    assert all(x == answers[0] for x in answers), answers


def test_the_log_is_not_told_who_tried(isl):
    a = account(isl)
    with_signature(isl, a.name, start(isl, a.name), Ed25519PrivateKey.generate())
    with_signature(isl, a.name, "made-up", a.key)
    assert a.name not in isl.log()
