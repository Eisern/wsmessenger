# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
The island's signed list: where to reach it, and which keys to trust.

One document serves two features that would otherwise each need their own
trust root:

  * entry points, so a client can fail over between several addresses of this
    island without any of them being substitutable by whoever answers first;
  * relay transport keys, so a relayed direct message is sealed to a key the
    client can authenticate. Whoever substitutes that key reads the metadata of
    every envelope - which is the whole property the relay network exists to
    protect. See docs/internal/message-relay-assessment.md §7.5.

Clients pin the signing key on first contact and refuse anything not signed by
it afterwards. That is trust-on-first-use, with the same weakness as every
TOFU: the first contact must be honest.

## Canonical form

The signature covers

    b"ws-island-list-v1" + utf8(canonical_json(payload))

Domain-separated, so a signature made here can never be replayed as a
signature over something else.

`canonical_json` must produce, byte for byte, what `_stableJson` in both
clients' crypto-utils produces. That holds only if the payload obeys two
rules, which are enforced below rather than trusted:

  * no floats - JSON.stringify(1.0) is "1" while Python would write "1.0";
  * ASCII object keys - JS sorts keys by UTF-16 code unit and Python by code
    point, which differ above the BMP.

String VALUES may be any Unicode: ensure_ascii=False makes Python emit raw
characters exactly as JSON.stringify does.
"""

from __future__ import annotations

import base64
import json
import os
import time
from typing import Any

from fastapi import APIRouter, HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SIGN_DOMAIN = b"ws-island-list-v1"


def b64d(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _assert_canonicalizable(value: Any, path: str = "payload") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are not canonicalizable across clients")
    if isinstance(value, int):
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _assert_canonicalizable(v, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str) or not k.isascii():
                raise ValueError(f"{path}: object keys must be ASCII, got {k!r}")
            _assert_canonicalizable(v, f"{path}.{k}")
        return
    raise ValueError(f"{path}: unsupported type {type(value).__name__}")


def canonical_json(payload: dict) -> str:
    """Byte-identical to `_stableJson` in both clients, given the rules above."""
    _assert_canonicalizable(payload)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def signing_message(payload: dict) -> bytes:
    return SIGN_DOMAIN + canonical_json(payload).encode("utf-8")


class IslandListConfig:
    def __init__(self) -> None:
        raw = (os.getenv("ISLAND_SIGNING_KEY_B64") or "").strip()
        self.signing_key: Ed25519PrivateKey | None = (
            Ed25519PrivateKey.from_private_bytes(b64d(raw)) if raw else None
        )
        self.island_id = (os.getenv("ISLAND_ID") or "").strip()
        self.version = int(os.getenv("ISLAND_LIST_VERSION") or "1")
        self.entry_points = json.loads(os.getenv("ISLAND_ENTRY_POINTS") or "[]")
        self.relays = json.loads(os.getenv("ISLAND_RELAYS") or "[]")

    @property
    def enabled(self) -> bool:
        return self.signing_key is not None and bool(self.island_id)

    def public_key_bytes(self) -> bytes:
        assert self.signing_key is not None
        return self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


# The document changes only when the operator changes the configuration, but
# `issued_at` moves with the clock. Re-signing on every request would make an
# unauthenticated endpoint do public-key work on demand, which is a cheap way to
# burn someone else's CPU. Sign at most this often; freshness at this
# granularity is far finer than the staleness window clients apply.
LIST_CACHE_S = 60


def build_router(*, transport_keys: list[dict] | None = None) -> APIRouter:
    """
    transport_keys: [{"kid": "<b64>", "public_key_b64": "<b64>"}] - the relay
    ingress keys this island will accept envelopes for. Passed in rather than
    read here, because relay_ingress owns them.
    """
    router = APIRouter()
    cfg = IslandListConfig()
    cached: dict[str, Any] = {"at": 0.0, "doc": None}

    @router.get("/.well-known/wsapp-island")
    async def island_list() -> dict[str, Any]:
        if not cfg.enabled:
            raise HTTPException(status_code=404, detail="island list not configured")

        nowf = time.time()
        if cached["doc"] is not None and nowf - cached["at"] < LIST_CACHE_S:
            return cached["doc"]

        payload: dict[str, Any] = {
            "island_id": cfg.island_id,
            "version": cfg.version,
            # Seconds, not milliseconds, and an int: a float would not
            # canonicalize identically in both languages.
            "issued_at": int(time.time()),
            "entry_points": cfg.entry_points,
            "relays": cfg.relays,
            "transport_keys": transport_keys or [],
        }

        sig = cfg.signing_key.sign(signing_message(payload))
        doc = {
            "payload": payload,
            "sig_b64": b64e(sig),
            # Present for trust-on-first-use only. After the first contact a
            # client MUST verify against the key it pinned and ignore this
            # field entirely - otherwise the signature proves nothing, since
            # an attacker would simply ship their own key alongside it.
            "signing_key_b64": b64e(cfg.public_key_bytes()),
        }
        cached["at"] = nowf
        cached["doc"] = doc
        return doc

    return router
