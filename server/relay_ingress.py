# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
Relay ingress: the door a relayed direct message comes in through.

A relay carries an opaque envelope and learns nothing from it. This module is
the only place that opens one. See docs/internal/message-relay-assessment.md.

The order of operations is the security design, not an implementation detail
(§7.2 of that document):

    relay signature  ->  relay quota  ->  relay replay  ->  UNSEAL  ->
    envelope replay  ->  the ordinary DM acceptance path

Everything cheap runs before anything expensive. An unauthenticated request is
rejected for the price of one HMAC, never for the price of an X25519 exchange,
because /relay/in would otherwise be a decryption oracle and a CPU exhaustion
vector for anyone who can reach it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Awaitable, Callable

from fastapi import APIRouter, HTTPException, Request, Response
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ENVELOPE_VERSION = 0x03
INFO_REQ = b"ws-relay-seal-v1:req"
INFO_RESP = b"ws-relay-seal-v1:resp"

# A relayed request and the envelope inside it each carry their own timestamp.
# Both windows are deliberately much tighter than the ±5 min the DM layer
# allows: a relay hop is fast, and a wide window is a wide replay window.
RELAY_TS_WINDOW_MS = 120_000
ENVELOPE_TS_WINDOW_MS = 120_000

MAX_ENVELOPE_BYTES = 64 * 1024


def b64d(s: str | bytes) -> bytes:
    if isinstance(s, bytes):
        s = s.decode("utf-8")
    s = s.strip().replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


class SeenCache:
    """Bounded in-memory replay cache. Rejects a repeat before it costs a query."""

    def __init__(self, ttl_ms: int, cap: int = 200_000) -> None:
        self._ttl = ttl_ms
        self._cap = cap
        self._seen: dict[bytes, int] = {}

    def _evict(self, now_ms: int) -> None:
        if len(self._seen) < self._cap:
            return
        dead = [k for k, exp in self._seen.items() if exp <= now_ms]
        for k in dead:
            self._seen.pop(k, None)
        if len(self._seen) >= self._cap:
            # Still full of live entries: this is abuse, not traffic. Drop the
            # oldest half rather than grow without bound.
            for k in sorted(self._seen, key=self._seen.get)[: self._cap // 2]:
                self._seen.pop(k, None)

    def check_and_add(self, key: bytes, now_ms: int) -> bool:
        """True if fresh, False if already seen."""
        exp = self._seen.get(key)
        if exp is not None and exp > now_ms:
            return False
        self._evict(now_ms)
        self._seen[key] = now_ms + self._ttl
        return True


class RelayConfig:
    """Relays this island accepts traffic from, and the island's transport key."""

    def __init__(self) -> None:
        raw_key = (os.getenv("RELAY_TRANSPORT_KEY_B64") or "").strip()
        self.private_key: X25519PrivateKey | None = None
        self.kid = b""
        if raw_key:
            self.private_key = X25519PrivateKey.from_private_bytes(b64d(raw_key))
            # Self-certifying key id, so a client can tell which transport key
            # an envelope was sealed to across a rotation (§7.6).
            self.kid = hashlib.sha256(self.public_key_bytes()).digest()[:4]

        peers: dict[str, bytes] = {}
        raw_peers = (os.getenv("RELAY_PEERS") or "").strip()
        if raw_peers:
            for relay_id, key_b64 in json.loads(raw_peers).items():
                peers[str(relay_id)] = b64d(key_b64)
        self.peers = peers

        self.quota_per_10s = int(os.getenv("RELAY_QUOTA_PER_10S") or "600")

    @property
    def enabled(self) -> bool:
        return self.private_key is not None and bool(self.peers)

    def public_key_bytes(self) -> bytes:
        assert self.private_key is not None
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return self.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _derive(shared: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=salt, info=info).derive(shared)


def build_router(
    *,
    accept_dm: Callable[..., Awaitable[dict[str, Any]]],
    rate_limit: Callable[[str, int, int], Awaitable[int | None]],
) -> APIRouter:
    """
    accept_dm(payload: dict, source: dict) -> dict
        The ordinary DM acceptance path, with the request source passed in
        instead of being read from the socket - a relayed message must not be
        rate-limited by the relay's IP (§7.7).
    rate_limit(key, limit, window_s) -> retry_after | None
    """
    router = APIRouter()
    cfg = RelayConfig()
    relay_seen = SeenCache(RELAY_TS_WINDOW_MS)
    envelope_seen = SeenCache(ENVELOPE_TS_WINDOW_MS)

    @router.get("/relay/key")
    async def relay_key() -> dict[str, Any]:
        """
        The island's transport public key.

        Serving it here is a convenience for development only. In production a
        client must take this key from the SIGNED entry-point list and pin it:
        whoever substitutes this key reads every envelope's metadata (§7.5).
        """
        if not cfg.enabled:
            raise HTTPException(status_code=404, detail="relay ingress disabled")
        return {
            "public_key_b64": b64e(cfg.public_key_bytes()),
            "kid_b64": b64e(cfg.kid),
            "unauthenticated": True,
        }

    @router.post("/relay/in")
    async def relay_in(request: Request) -> Response:
        if not cfg.enabled:
            raise HTTPException(status_code=404, detail="relay ingress disabled")

        now_ms = int(time.time() * 1000)

        # ---- 1. relay identity, before anything expensive -------------------
        relay_id = (request.headers.get("x-relay-id") or "").strip()
        peer_key = cfg.peers.get(relay_id)
        if not peer_key:
            raise HTTPException(status_code=403, detail="unknown relay")

        try:
            relay_ts = int(request.headers.get("x-relay-ts") or "0")
        except ValueError:
            raise HTTPException(status_code=403, detail="bad relay ts")
        if abs(now_ms - relay_ts) > RELAY_TS_WINDOW_MS:
            raise HTTPException(status_code=403, detail="relay ts out of window")

        nonce_hdr = (request.headers.get("x-relay-nonce") or "").strip()
        sig_hdr = (request.headers.get("x-relay-sig") or "").strip()
        if not nonce_hdr or not sig_hdr:
            raise HTTPException(status_code=403, detail="unsigned relay request")

        body = await request.body()
        if len(body) > MAX_ENVELOPE_BYTES:
            raise HTTPException(status_code=413, detail="envelope too big")

        signed = b"|".join(
            [
                relay_id.encode("utf-8"),
                str(relay_ts).encode("utf-8"),
                nonce_hdr.encode("utf-8"),
                hashlib.sha256(body).digest(),
            ]
        )
        expected = hmac.new(peer_key, signed, hashlib.sha256).digest()
        try:
            given = b64d(sig_hdr)
        except Exception:
            raise HTTPException(status_code=403, detail="bad relay signature")
        if not hmac.compare_digest(expected, given):
            raise HTTPException(status_code=403, detail="bad relay signature")

        # ---- 2. quota, still before any asymmetric work --------------------
        retry = await rate_limit(f"relay:in:{relay_id}", cfg.quota_per_10s, 10)
        if retry is not None:
            raise HTTPException(status_code=429, detail=f"rate limited; retry_after={retry}")

        # ---- 3. this exact relayed request must not be replayable ----------
        if not relay_seen.check_and_add(
            b"r|" + relay_id.encode() + b"|" + nonce_hdr.encode(), now_ms
        ):
            raise HTTPException(status_code=409, detail="relay replay")

        # ---- 4. only now: open the envelope --------------------------------
        if len(body) < 1 + 4 + 32 + 12 + 16 or body[0] != ENVELOPE_VERSION:
            raise HTTPException(status_code=400, detail="bad envelope")
        kid = body[1:5]
        eph_pub = body[5:37]
        iv = body[37:49]
        sealed = body[49:]
        if not hmac.compare_digest(kid, cfg.kid):
            raise HTTPException(status_code=400, detail="unknown transport key")

        try:
            shared = cfg.private_key.exchange(X25519PublicKey.from_public_bytes(eph_pub))
            key_req = _derive(shared, eph_pub, INFO_REQ)
            aad = body[0:37]
            plain = AESGCM(key_req).decrypt(iv, sealed, aad)
            inner = json.loads(plain.decode("utf-8"))
        except Exception:
            # Uniform answer: distinguishing "bad key" from "bad payload" would
            # hand an attacker an oracle.
            raise HTTPException(status_code=400, detail="bad envelope")

        # From here on the client's response key exists, so EVERY outcome is
        # sealed. If some outcomes stayed in the clear, a relay could tell
        # "duplicate" from "delivered" by the status code — and, worse, could
        # forge a 409 to stop the client from retrying elsewhere.
        key_resp = _derive(shared, eph_pub, INFO_RESP)

        def sealed(status: int, payload: dict[str, Any]) -> Response:
            # A separate key from a separate info string: one key in both
            # directions would reuse the IV space of AES-GCM (§7.4).
            resp_iv = os.urandom(12)
            out = json.dumps({"status": status, **payload}).encode("utf-8")
            return Response(
                content=bytes([ENVELOPE_VERSION])
                + resp_iv
                + AESGCM(key_resp).encrypt(resp_iv, out, bytes([ENVELOPE_VERSION])),
                media_type="application/octet-stream",
                # Always 200 on the outside: the real status is inside, so a
                # relay learns nothing from watching status codes.
                status_code=200,
            )

        # ---- 5. envelope replay, bound to the CLIENT, not to the relay -----
        # These live inside the sealed blob on purpose: a relay must not be the
        # one supplying the anti-replay material for a hop it cannot read.
        try:
            env_ts = int(inner["env_ts"])
            env_nonce = b64d(inner["env_nonce_b64"])
        except Exception:
            return sealed(400, {"detail": "bad envelope"})
        if abs(now_ms - env_ts) > ENVELOPE_TS_WINDOW_MS:
            return sealed(400, {"detail": "envelope ts out of window"})
        if not (8 <= len(env_nonce) <= 64):
            return sealed(400, {"detail": "bad envelope"})
        if not envelope_seen.check_and_add(b"e|" + env_nonce, now_ms):
            return sealed(409, {"detail": "envelope replay"})

        # ---- 6. the ordinary DM path, told where the request came from -----
        status = 200
        payload: dict[str, Any]
        try:
            payload = await accept_dm(
                {
                    "thread_id": inner["thread_id"],
                    "ts": inner["ts"],
                    "nonce_b64": inner["nonce_b64"],
                    "ciphertext_b64": inner["ciphertext_b64"],
                    "tag_b64": inner["tag_b64"],
                },
                {"kind": "relay", "relay_id": relay_id, "thread_id": inner["thread_id"]},
            )
        except HTTPException as e:
            status = e.status_code
            payload = {"detail": e.detail}
        except Exception:
            status = 500
            payload = {"detail": "internal error"}

        # ---- 7. the answer, sealed so the relay cannot fake delivery -------
        return sealed(status, payload)

    return router
