# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
Recovering an account with its recovery phrase (/auth/recover-start, /auth/recover).

What a stranger who knows only a name must not be able to do: lock that person
out of their own recovery, void the recovery they have in progress, or learn
which accounts can be recovered at all. And the log is not told who tried.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid

import httpx
import pytest
from conftest import start_island, stop_island
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PASSWORD = "Testpass!12345"
NEW_PASSWORD = "Newpass!67890"


@pytest.fixture(scope="module")
def isl(db_url, tmp_path_factory):
    # The real per-account number; the address limit raised, since every
    # request here comes from one address.
    island = start_island(db_url, "island-a.test", tmp_path_factory.mktemp("recover"),
                          RL_RECOVER_USER_PER_HOUR="3", RL_RECOVER_IP_PER_HOUR="1000")
    yield island
    stop_island(island)


def account(isl, with_phrase: bool = True) -> tuple[str, bytes | None]:
    name = f"rec{uuid.uuid4().hex[:8]}"
    pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    auth = os.urandom(32) if with_phrase else None
    body = {"username": name, "password": PASSWORD, "public_key": base64.b64encode(pub).decode()}
    if auth:
        body["recovery_key_hash"] = hashlib.sha256(auth).hexdigest()
    r = httpx.post(isl.base + "/auth/register", json=body)
    assert r.status_code == 201, r.text
    return name, auth


def start(isl, name: str) -> str:
    r = httpx.post(isl.base + "/auth/recover-start", json={"username": name})
    assert r.status_code == 200, r.text
    return r.json()["nonce"]


def recover(isl, name: str, nonce: str, auth: bytes) -> httpx.Response:
    return httpx.post(isl.base + "/auth/recover", json={
        "username": name, "nonce": nonce,
        "recovery_auth_b64": base64.b64encode(auth).decode(), "new_password": NEW_PASSWORD,
    })


def logs_in(isl, name: str, password: str) -> bool:
    return httpx.post(isl.base + "/auth/login", json={"username": name, "password": password}).status_code == 200


def test_the_phrase_resets_the_password(isl):
    name, auth = account(isl)
    r = recover(isl, name, start(isl, name), auth)
    assert r.status_code == 200, r.text
    assert logs_in(isl, name, NEW_PASSWORD)
    assert not logs_in(isl, name, PASSWORD)


def test_requests_in_somebodys_name_do_not_lock_them_out(isl):
    # Counted on every request, three of these used to close that person's
    # recovery for an hour - with nothing but their name.
    name, auth = account(isl)
    for _ in range(6):
        r = recover(isl, name, "made-up", os.urandom(32))
        assert r.status_code == 400, r.text
    r = recover(isl, name, start(isl, name), auth)
    assert r.status_code == 200, r.text


def test_a_made_up_nonce_does_not_void_the_one_in_progress(isl):
    name, auth = account(isl)
    nonce = start(isl, name)
    r = recover(isl, name, "f" * 64, os.urandom(32))
    assert r.status_code == 400, r.text
    r = recover(isl, name, nonce, auth)
    assert r.status_code == 200, r.text


def test_a_nonce_is_good_once(isl):
    name, auth = account(isl)
    nonce = start(isl, name)
    assert recover(isl, name, nonce, os.urandom(32)).status_code == 401
    assert recover(isl, name, nonce, auth).status_code == 400


def test_wrong_phrases_are_limited_without_closing_the_right_one(isl):
    name, auth = account(isl)
    codes = [recover(isl, name, start(isl, name), os.urandom(32)).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401], codes
    assert 429 in codes[3:], codes
    # A 256-bit phrase is not guessed; the limit is for noise, and the owner of
    # the phrase still gets in.
    assert recover(isl, name, start(isl, name), auth).status_code == 200


def test_which_accounts_can_be_recovered_is_not_told(isl):
    bare, _ = account(isl, with_phrase=False)
    phrased, _ = account(isl)
    a = recover(isl, bare, start(isl, bare), os.urandom(32))
    b = recover(isl, phrased, start(isl, phrased), os.urandom(32))
    assert (a.status_code, a.json()) == (b.status_code, b.json())


def test_the_log_is_not_told_who_tried(isl):
    name, auth = account(isl)
    recover(isl, name, start(isl, name), os.urandom(32))
    recover(isl, name, "made-up", os.urandom(32))
    assert name not in isl.log()
