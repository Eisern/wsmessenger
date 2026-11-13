# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
What the island learns about a file: nothing.

Clients encrypt a file before it leaves them (chrome_extension/file-crypt.js)
and upload an opaque blob; the name, the type and the key travel inside the
encrypted message that announces it. The server's side of that bargain is
checked here: it takes only such blobs, keeps no name and no type whatever the
upload claims, hands back the bytes it was given to the people of that
conversation and nobody else, and does not keep a file past its time.
"""

from __future__ import annotations

import asyncio
import os
import pathlib

import asyncpg
import httpx
from conftest import create_room, register

MAGIC = b"WSF3"


def blob(n: int = 4123) -> bytes:
    """What a client uploads: the format's four bytes, then ciphertext."""
    return MAGIC + os.urandom(n - len(MAGIC))


def upload(island, who, path: str, data: bytes, name: str = "blob",
           ctype: str = "application/octet-stream") -> httpx.Response:
    return httpx.post(island.base + path, headers=who.h, files={"file": (name, data, ctype)})


def file_rows(db_url, *tokens: str) -> dict[str, dict]:
    async def run():
        conn = await asyncpg.connect(db_url)
        try:
            rows = await conn.fetch(
                "SELECT token, original_name, content_type, size_bytes, storage_path "
                "FROM chat_files WHERE token = ANY($1::text[])", list(tokens))
        finally:
            await conn.close()
        return {r["token"]: dict(r) for r in rows}
    return asyncio.run(run())


def open_dm(island, a, b) -> int:
    r = httpx.put(island.base + "/profile/me", headers=b.h,
                  json={"about": "", "privacy": {"allow_dm_from_non_friends": True}})
    assert r.status_code == 200, r.text
    r = httpx.post(island.base + "/dm/open", headers=a.h, json={"username": b.username})
    assert r.status_code == 200, r.text
    return int(r.json()["thread_id"])


# --- what is taken -------------------------------------------------------------

def test_a_file_that_was_not_encrypted_is_refused(island, db_url):
    owner = register(island)
    room = create_room(island, owner)
    plain = b"%PDF-1.7 the quarterly figures, as they are"

    r = upload(island, owner, f"/rooms/{room}/files", plain, "figures.pdf", "application/pdf")
    assert r.status_code == 400, r.text
    assert "encrypted" in r.json()["detail"]

    # Refused means not kept: no row, and no bytes left lying in the upload dir.
    async def count():
        conn = await asyncpg.connect(db_url)
        try:
            return await conn.fetchval("SELECT count(*) FROM chat_files WHERE room_id = $1", room)
        finally:
            await conn.close()
    assert asyncio.run(count()) == 0


def test_a_direct_message_file_that_was_not_encrypted_is_refused(island):
    a, b = register(island), register(island)
    thread = open_dm(island, a, b)
    r = upload(island, a, f"/dm/{thread}/files", b"\x89PNG\r\n\x1a\n a photo", "me.png", "image/png")
    assert r.status_code == 400, r.text


def test_an_empty_upload_is_refused(island):
    owner = register(island)
    room = create_room(island, owner)
    assert upload(island, owner, f"/rooms/{room}/files", b"").status_code in (400, 422)


def test_the_largest_file_the_apps_send_fits_and_a_larger_blob_does_not(island):
    """
    The apps stop at a 100 MiB file. Encrypted, that is the 100 MiB, an 11-byte
    header and a 16-byte tag for each 1 MiB chunk: the limit has to leave room
    for exactly that kind of excess, or the largest allowed file never arrives.
    """
    owner = register(island)
    room = create_room(island, owner)
    mib = 1024 * 1024
    biggest = 11 + 100 * mib + 16 * 100

    r = upload(island, owner, f"/rooms/{room}/files", MAGIC + bytes(biggest - len(MAGIC)))
    assert r.status_code == 201, r.text
    assert r.json()["size_bytes"] == biggest

    over = 100 * mib + 64 * 1024 + 1
    r = upload(island, owner, f"/rooms/{room}/files", MAGIC + bytes(over - len(MAGIC)))
    assert r.status_code == 413, r.text


# --- what is kept --------------------------------------------------------------

def test_no_name_and_no_type_are_kept_whatever_the_upload_says(island, db_url):
    """
    A client that still sent the real name and type with the blob - a bug, or
    an old habit - must not get them stored: the row is what backups carry.
    """
    owner = register(island)
    room = create_room(island, owner)
    a, b = owner, register(island)
    thread = open_dm(island, a, b)

    in_room = upload(island, owner, f"/rooms/{room}/files", blob(), "passport scan.jpg", "image/jpeg")
    in_dm = upload(island, a, f"/dm/{thread}/files", blob(), "passport scan.jpg", "image/jpeg")
    assert in_room.status_code == 201, in_room.text
    assert in_dm.status_code == 201, in_dm.text

    for r in (in_room, in_dm):
        body = r.json()
        assert body["filename"] == "blob"
        assert body["content_type"] == "application/octet-stream"
        assert "passport" not in r.text and "jpeg" not in r.text

    rows = file_rows(db_url, in_room.json()["token"], in_dm.json()["token"])
    assert len(rows) == 2
    for row in rows.values():
        assert row["original_name"] == "blob"
        assert row["content_type"] == "application/octet-stream"
        assert "passport" not in pathlib.Path(row["storage_path"]).name


def test_the_bytes_come_back_as_they_went_in_with_nothing_said_about_them(island):
    owner = register(island)
    room = create_room(island, owner)
    data = blob(70_000)

    token = upload(island, owner, f"/rooms/{room}/files", data, "notes.txt", "text/plain").json()["token"]
    r = httpx.get(island.base + f"/files/{token}", headers=owner.h)

    assert r.status_code == 200
    assert r.content == data
    assert r.headers["content-type"] == "application/octet-stream"
    assert "notes" not in r.headers.get("content-disposition", "")
    assert 'filename="blob"' in r.headers.get("content-disposition", "")


def test_a_file_from_before_encryption_is_served_without_its_name_or_type(island, db_url):
    """
    Rows written before this still hold a real name and type. The file stays
    downloadable until it expires - the conversation's old message names it -
    but the server no longer repeats what it should never have known.
    """
    owner = register(island)
    room = create_room(island, owner)
    token = upload(island, owner, f"/rooms/{room}/files", blob()).json()["token"]

    async def age():
        conn = await asyncpg.connect(db_url)
        try:
            await conn.execute(
                "UPDATE chat_files SET original_name = 'tax return.pdf', content_type = 'application/pdf' "
                "WHERE token = $1", token)
        finally:
            await conn.close()
    asyncio.run(age())

    r = httpx.get(island.base + f"/files/{token}", headers=owner.h)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/octet-stream"
    assert "tax" not in r.headers.get("content-disposition", "")


# --- who may have it -----------------------------------------------------------

def test_only_the_conversation_can_fetch_its_file(island):
    owner, stranger = register(island), register(island)
    room = create_room(island, owner)
    a, b = register(island), register(island)
    thread = open_dm(island, a, b)

    room_token = upload(island, owner, f"/rooms/{room}/files", blob()).json()["token"]
    dm_token = upload(island, a, f"/dm/{thread}/files", blob()).json()["token"]

    assert httpx.get(island.base + f"/files/{room_token}", headers=stranger.h).status_code in (403, 404)
    assert httpx.get(island.base + f"/files/{dm_token}", headers=stranger.h).status_code in (403, 404)
    assert httpx.get(island.base + f"/files/{dm_token}", headers=b.h).status_code == 200
    assert httpx.get(island.base + f"/files/{room_token}").status_code in (401, 403)

    # And nobody uploads into a conversation they are not in.
    assert upload(island, stranger, f"/rooms/{room}/files", blob()).status_code in (403, 404)
    assert upload(island, stranger, f"/dm/{thread}/files", blob()).status_code in (403, 404)


# --- how long it is kept ---------------------------------------------------------

def test_an_expired_file_is_deleted_without_anybody_asking_for_it(island, db_url):
    """
    A download used to be the only thing that removed an expired file: one
    nobody asked for again stayed on disk for good.
    """
    owner = register(island)
    room = create_room(island, owner)
    old = upload(island, owner, f"/rooms/{room}/files", blob()).json()["token"]
    path = pathlib.Path(file_rows(db_url, old)[old]["storage_path"])
    assert path.exists()

    async def expire():
        conn = await asyncpg.connect(db_url)
        try:
            await conn.execute(
                "UPDATE chat_files SET expires_at = now() - interval '1 minute' WHERE token = $1", old)
        finally:
            await conn.close()
    asyncio.run(expire())

    # Somebody else, somewhere else, uploads something.
    other = register(island)
    new = upload(island, other, f"/rooms/{create_room(island, other)}/files", blob()).json()["token"]

    rows = file_rows(db_url, old, new)
    assert old not in rows and new in rows
    assert not path.exists()
    assert pathlib.Path(rows[new]["storage_path"]).exists()
