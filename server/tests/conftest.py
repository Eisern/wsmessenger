# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
The real server, against a real PostgreSQL.

Every test here talks HTTP (and WebSocket) to `uvicorn main:app` running as a
subprocess on a freshly created database with server/schema.sql applied - the
same process and schema a self-hoster runs, not an in-process stand-in. That is
the point: the guest scope is a middleware, the nonce is a transaction, and
neither can be trusted to a mock.

Database, in order of preference:
  - TEST_DATABASE_URL: an admin URL (postgresql://user:pw@host:port/postgres)
    on which a database per run is created and dropped. CI sets this.
  - pgserver (pip install pgserver): a throwaway PostgreSQL in a temp dir, for
    running the suite on a machine with nothing installed.
Neither available: the suite skips, it does not fail.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field

import httpx
import pytest

SERVER_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVER_DIR))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from island_list import canonical_json  # noqa: E402


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _admin_url() -> str:
    url = (os.getenv("TEST_DATABASE_URL") or "").strip()
    if url:
        return url
    try:
        import pgserver
    except ImportError:
        pytest.skip("server tests need TEST_DATABASE_URL or `pip install pgserver`")
    data = pathlib.Path(tempfile.gettempdir()) / "wsapp-test-pgdata"
    return pgserver.get_server(str(data), cleanup_mode=None).get_uri()


async def _create_db(admin_url: str, name: str) -> str:
    import asyncpg

    conn = await asyncpg.connect(admin_url)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()
    db_url = admin_url.rsplit("/", 1)[0] + "/" + name
    conn = await asyncpg.connect(db_url)
    try:
        await conn.execute((SERVER_DIR / "schema.sql").read_text(encoding="utf-8"))
    finally:
        await conn.close()
    return db_url


async def _drop_db(admin_url: str, name: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(admin_url)
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await conn.close()


def _rate_limit_env() -> dict[str, str]:
    # Every limit the server reads, raised: a suite that logs in per test from
    # one address would otherwise be testing the rate limiter.
    src = (SERVER_DIR / "main.py").read_text(encoding="utf-8")
    names = set(re.findall(r'_env_int\("(RL_[A-Z0-9_]+)"', src))
    return {n: "100000" for n in names}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class Island:
    base: str
    island_id: str
    proc: subprocess.Popen
    log_path: pathlib.Path

    def log(self) -> str:
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    @property
    def ws_base(self) -> str:
        return self.base.replace("http://", "ws://", 1)


def start_island(db_url: str, island_id: str, tmp: pathlib.Path, **extra_env: str) -> Island:
    port = _free_port()
    log_path = tmp / f"server-{port}.log"
    env = dict(os.environ)
    env.update(_rate_limit_env())
    env.update({
        "DATABASE_URL": db_url.replace("postgresql://", "postgresql+asyncpg://", 1),
        "JWT_SECRET": "t" * 64,
        "ENV": "dev",
        "CORS_ORIGINS": "https://island.test",
        "UPLOAD_DIR": str(tmp / f"uploads-{port}"),
        "ISLAND_ID": island_id,
    })
    env.update(extra_env)
    log = open(log_path, "w", encoding="utf-8")  # noqa: SIM115 - lives as long as the server
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1",
         "--port", str(port), "--workers", "1"],
        cwd=str(SERVER_DIR), env=env, stdout=log, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("server exited:\n" + log_path.read_text(encoding="utf-8", errors="replace"))
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                return Island(base, island_id, proc, log_path)
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    proc.kill()
    raise RuntimeError("server did not come up:\n" + log_path.read_text(encoding="utf-8", errors="replace"))


def stop_island(island: Island) -> None:
    island.proc.terminate()
    try:
        island.proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        island.proc.kill()


@pytest.fixture(scope="session")
def admin_url() -> str:
    return _admin_url()


@pytest.fixture(scope="session")
def db_url(admin_url):
    name = f"wsapp_test_{uuid.uuid4().hex[:8]}"
    url = asyncio.run(_create_db(admin_url, name))
    yield url
    asyncio.run(_drop_db(admin_url, name))


@pytest.fixture(scope="session")
def island(db_url, tmp_path_factory) -> Island:
    isl = start_island(db_url, "island-a.test", tmp_path_factory.mktemp("island"))
    yield isl
    stop_island(isl)


# --- people ------------------------------------------------------------------

@dataclass
class Local:
    username: str
    token: str
    refresh: str = ""

    @property
    def h(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}


def register(isl: Island, prefix: str = "u") -> Local:
    name = f"{prefix}{uuid.uuid4().hex[:8]}"
    pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    r = httpx.post(isl.base + "/auth/register",
                   json={"username": name, "password": "Testpass!12345", "public_key": b64(pub)})
    assert r.status_code == 201, r.text
    r = httpx.post(isl.base + "/auth/login", json={"username": name, "password": "Testpass!12345"})
    assert r.status_code == 200, r.text
    return Local(name, r.json()["access_token"], r.json()["refresh_token"])


def create_room(isl: Island, owner: Local, name: str = "room") -> int:
    r = httpx.post(isl.base + "/rooms", headers=owner.h, json={
        "name": name, "encrypted_room_key": b64(os.urandom(96)), "is_public": False,
    })
    assert r.status_code in (200, 201), r.text
    return int(r.json().get("id") or r.json().get("room_id"))


@dataclass
class Foreigner:
    """Somebody from another island: a key pair and the card that names it."""
    display: str
    island_id: str
    x_pub: bytes
    ed: Ed25519PrivateKey
    kid: str
    card: dict = field(default_factory=dict)

    @property
    def ed_pub_b64(self) -> str:
        return b64(self.ed.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def foreigner(display: str = "bob", island_id: str = "island-b.test",
              ed: Ed25519PrivateKey | None = None) -> Foreigner:
    x_pub = X25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ed = ed or Ed25519PrivateKey.generate()
    kid = hashlib.sha256(x_pub).hexdigest()[:32]
    f = Foreigner(display, island_id, x_pub, ed, kid)
    payload = {
        "v": 1,
        "kid": kid,
        "x25519_pub_b64": b64(x_pub),
        "ed25519_pub_b64": f.ed_pub_b64,
        "display_name": display,
        "island_id": island_id,
        "island_signing_key_b64": "",
        "entry_points": [{"apiBase": "https://b.test", "wsBase": "wss://b.test", "label": ""}],
    }
    sig = ed.sign(b"ws-contact-v1" + canonical_json(payload).encode("utf-8"))
    f.card = {"payload": payload, "sig_b64": b64(sig)}
    return f


def guest_session(isl: Island, who: Foreigner, *, sign_with: Ed25519PrivateKey | None = None,
                  nonce_b64: str | None = None) -> httpx.Response:
    if nonce_b64 is None:
        ch = httpx.get(isl.base + "/foreign/challenge")
        assert ch.status_code == 200, ch.text
        nonce_b64 = ch.json()["nonce_b64"]
    nonce = base64.b64decode(nonce_b64)
    msg = b"ws-guest-session-v1" + isl.island_id.encode() + who.kid.encode() + nonce
    sig = (sign_with or who.ed).sign(msg)
    return httpx.post(isl.base + "/foreign/guest/session",
                      json={"kid": who.kid, "nonce_b64": nonce_b64, "sig_b64": b64(sig)})
