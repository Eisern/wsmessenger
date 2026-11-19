# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
The nonces that keep a sealed DM (/ud/dm/send) from being delivered twice.

A nonce only has to outlive the window its message is accepted in. The purge
for them existed and was never called, so every sealed DM left a row for good:
a table that only grew, and a record of when each thread was written to.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import time

import httpx
import pytest
from conftest import register, start_island, stop_island


@pytest.fixture(scope="module")
def isl(db_url, tmp_path_factory):
    island = start_island(db_url, "island-a.test", tmp_path_factory.mktemp("udnonce"),
                          UD_NONCE_PURGE_EVERY_S="0")
    yield island
    stop_island(island)


def thread_between(isl) -> tuple[int, bytes]:
    a, b = register(isl, "uda"), register(isl, "udb")
    r = httpx.put(isl.base + "/profile/me", headers=b.h, json={"privacy": {"allow_dm_from_non_friends": True}})
    assert r.status_code == 200, r.text
    r = httpx.post(isl.base + "/dm/open", headers=a.h, json={"username": b.username})
    assert r.status_code in (200, 201), r.text
    tid = int(r.json().get("thread_id") or r.json().get("id"))
    r = httpx.get(f"{isl.base}/dm/{tid}/delivery-secret", headers=a.h)
    assert r.status_code == 200, r.text
    s = r.json()["delivery_secret_b64"]
    return tid, base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def send(isl, tid: int, secret: bytes, nonce: bytes | None = None) -> tuple[httpx.Response, bytes]:
    nonce = nonce or os.urandom(16)
    ts = int(time.time() * 1000)
    ct = os.urandom(80)
    msg = str(tid).encode() + b"|" + str(ts).encode() + b"|" + nonce + b"|" + hashlib.sha256(ct).digest()
    tag = hmac.new(secret, msg, hashlib.sha256).digest()
    r = httpx.post(isl.base + "/ud/dm/send", json={
        "thread_id": tid, "ts": ts,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "ciphertext_b64": base64.b64encode(ct).decode(),
        "tag_b64": base64.b64encode(tag).decode(),
    })
    return r, nonce


def sql(db_url: str, query: str, *args):
    async def go():
        import asyncpg
        conn = await asyncpg.connect(db_url)
        try:
            return await conn.fetch(query, *args)
        finally:
            await conn.close()
    return asyncio.run(go())


def test_old_nonces_go_and_a_replay_is_still_refused(isl, db_url):
    tid, secret = thread_between(isl)
    # One from long ago, as the table holds today.
    sql(db_url, "INSERT INTO chat_dm_ud_nonces(thread_id, nonce, ts, created_at) "
                "VALUES ($1, $2, 0, now() - interval '2 hours')", tid, os.urandom(16))

    r, nonce = send(isl, tid, secret)
    assert r.status_code == 200, r.text

    rows = sql(db_url, "SELECT nonce, created_at < now() - interval '1 hour' AS old "
                       "FROM chat_dm_ud_nonces WHERE thread_id = $1", tid)
    assert [bool(x["old"]) for x in rows] == [False]
    assert bytes(rows[0]["nonce"]) == nonce

    # What the nonce is for still holds.
    again, _ = send(isl, tid, secret, nonce=nonce)
    assert again.status_code == 409, again.text
