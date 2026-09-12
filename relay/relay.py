# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
WS Messenger message relay.

Carries sealed direct messages to an island and cannot read them. It holds no
database, no user data and no island certificate - one keypair's worth of
shared secret per island it serves, and a whitelist of where it may forward.

What it sees: the size of an envelope, the time it passed through, and which
island it was bound for. Not the thread, not the participants, not the content.

What it deliberately cannot do:
  - forward anywhere the operator has not listed (`next` is a NAME, not an
    address - a free-form destination would make this an open proxy);
  - read or alter an envelope (sealed to the island's transport key);
  - forge a delivery (the island's answer is sealed to the client);
  - replay a message (the island de-duplicates on (thread_id, nonce)).

See docs/internal/message-relay-assessment.md for the reasoning.

Run:
    RELAY_CONFIG=relay.config.json uvicorn relay:app --host 0.0.0.0 --port 8800
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request, Response

MAX_ENVELOPE_BYTES = 64 * 1024
UPSTREAM_TIMEOUT_S = 15.0


def b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _load_config() -> dict:
    path = os.getenv("RELAY_CONFIG") or "relay.config.json"
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    if not cfg.get("relay_id"):
        raise RuntimeError("relay_id is required")
    if not cfg.get("islands"):
        raise RuntimeError("at least one island must be configured")
    for island_id, island in cfg["islands"].items():
        if not island.get("url") or not island.get("key_b64"):
            raise RuntimeError(f"island {island_id}: url and key_b64 are required")
    return cfg


CONFIG = _load_config()
RELAY_ID: str = CONFIG["relay_id"]
ISLANDS: dict[str, dict] = CONFIG["islands"]

app = FastAPI(title="WS Messenger relay", docs_url=None, redoc_url=None, openapi_url=None)
_client = httpx.AsyncClient(timeout=UPSTREAM_TIMEOUT_S)


@app.get("/health")
async def health() -> dict:
    # Deliberately says nothing about traffic, only that the relay is alive and
    # which islands it is willing to carry for - that list is public anyway.
    return {"status": "ok", "relay_id": RELAY_ID, "islands": sorted(ISLANDS)}


@app.post("/forward")
async def forward(request: Request) -> Response:
    """
    { "next": "<island id>", "blob": "<base64 envelope>" }  ->  sealed answer.

    The relay never parses `blob`; it cannot. `next` is resolved against the
    operator's own list, so a client cannot point this relay at an arbitrary
    host.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="bad request")

    island_id = str(body.get("next") or "").strip()
    island = ISLANDS.get(island_id)
    if not island:
        # Same answer for "not in my list" and "malformed": a probe should not
        # be able to enumerate which islands this relay serves.
        raise HTTPException(status_code=404, detail="unknown destination")

    try:
        envelope = b64d(str(body.get("blob") or ""))
    except Exception:
        raise HTTPException(status_code=400, detail="bad request")
    if not (49 < len(envelope) <= MAX_ENVELOPE_BYTES):
        raise HTTPException(status_code=400, detail="bad request")

    ts = str(int(time.time() * 1000))
    nonce = base64.b64encode(os.urandom(16)).decode("utf-8")
    signed = b"|".join(
        [
            RELAY_ID.encode("utf-8"),
            ts.encode("utf-8"),
            nonce.encode("utf-8"),
            hashlib.sha256(envelope).digest(),
        ]
    )
    sig = hmac.new(b64d(island["key_b64"]), signed, hashlib.sha256).digest()

    try:
        upstream = await _client.post(
            island["url"].rstrip("/") + "/relay/in",
            content=envelope,
            headers={
                "content-type": "application/octet-stream",
                "x-relay-id": RELAY_ID,
                "x-relay-ts": ts,
                "x-relay-nonce": nonce,
                "x-relay-sig": base64.b64encode(sig).decode("utf-8"),
            },
        )
    except httpx.HTTPError:
        # The island is unreachable through this relay. The client retries via
        # another one; that is safe by construction, because a message that did
        # arrive will be rejected as a duplicate on (thread_id, nonce).
        raise HTTPException(status_code=502, detail="upstream unreachable")

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/octet-stream"),
    )
