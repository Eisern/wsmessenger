# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
# This file is part of WS Messenger. See LICENSE for terms.

"""
A local stand for the client integration suites (Android/src/services/__tests__/
integration): two independent islands and a relay, from this checkout, against
one PostgreSQL.

  island A  http://127.0.0.1:8000   ISLAND_ID=island-test   database wsapp
  island B  http://127.0.0.1:8001   ISLAND_ID=island-b      database wsapp_b
  relay     http://127.0.0.1:18800  relay-alpha, serving both

Each island has its own JWT secret, signing key, relay transport key and relay
peer key; every rate limit is raised. Island A's signed list names two entry
points nobody listens on (the failover ports) before its real one, as the suites
expect. Both databases are dropped and recreated from server/schema.sql.

  python scripts/integration_stand.py up     # (re)start
  python scripts/integration_stand.py down

Needs the server's and the relay's requirements installed in this interpreter,
and a PostgreSQL superuser URL in WSAPP_STAND_PG (default
postgresql://postgres:pgtest@127.0.0.1:55432), e.g.:

  docker run -d --name wsapp-test-pg -e POSTGRES_PASSWORD=pgtest \\
    -p 127.0.0.1:55432:5432 postgres:17

Then, from Android/:

  ISLAND_A_CONTAINER=wsapp-test-pg npx jest --selectProjects integration --runInBand --forceExit

On Windows, Hyper-V often reserves the default failover ports; set
WSAPP_STAND_FAILOVER_PORTS=19101,19102 here and pass the same ports to the tests
(see the integration README).
"""

import asyncio
import base64
import contextlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = ROOT / ".integration-stand"
PG = os.getenv("WSAPP_STAND_PG", "postgresql://postgres:pgtest@127.0.0.1:55432").rstrip("/")
FAILOVER = [int(p) for p in (os.getenv("WSAPP_STAND_FAILOVER_PORTS") or "18101,18102").split(",")]


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def priv_raw(k) -> bytes:
    return k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def rate_limits() -> dict:
    src = (ROOT / "server" / "main.py").read_text(encoding="utf-8")
    return {n: "100000" for n in set(re.findall(r'_env_int\("(RL_[A-Z0-9_]+)"', src))}


async def fresh_db(name: str) -> None:
    import asyncpg
    conn = await asyncpg.connect(PG + "/postgres")
    try:
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()
    conn = await asyncpg.connect(f"{PG}/{name}")
    try:
        await conn.execute((ROOT / "server" / "schema.sql").read_text(encoding="utf-8"))
    finally:
        await conn.close()


def spawn(name: str, args, cwd, env) -> int:
    log = open(RUN / f"{name}.log", "w", encoding="utf-8")  # noqa: SIM115 - lives as long as the process
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(  # noqa: S603 - our own interpreter and arguments
        args, cwd=str(cwd), env=env, stdout=log, stderr=subprocess.STDOUT, **kw).pid


def wait_up(url: str, name: str) -> None:
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise SystemExit(f"{name} did not come up:\n" + (RUN / f"{name}.log").read_text(errors="replace")[-3000:])


def island_env(island_id, port, db, jwt, relay_key, entry_points) -> dict:
    env = dict(os.environ)
    env.update(rate_limits())
    pg = PG.replace("postgresql://", "postgresql+asyncpg://", 1)
    env.update({
        "DATABASE_URL": f"{pg}/{db}",
        "JWT_SECRET": jwt,
        "ENV": "dev",
        "CORS_ORIGINS": "https://island.test",
        "UPLOAD_DIR": str(RUN / f"uploads-{port}"),
        "ISLAND_ID": island_id,
        "ISLAND_SIGNING_KEY_B64": b64(priv_raw(Ed25519PrivateKey.generate())),
        "ISLAND_LIST_VERSION": "3",
        "ISLAND_ENTRY_POINTS": json.dumps(entry_points, ensure_ascii=False),
        "ISLAND_RELAYS": json.dumps([{"id": "relay-alpha", "url": "http://127.0.0.1:18800"}]),
        "RELAY_TRANSPORT_KEY_B64": b64(priv_raw(X25519PrivateKey.generate())),
        "RELAY_PEERS": json.dumps({"relay-alpha": b64(relay_key)}),
        "PYTHONIOENCODING": "utf-8",
    })
    return env


def up() -> None:
    down(quiet=True)
    RUN.mkdir(exist_ok=True)
    asyncio.run(fresh_db("wsapp"))      # chainTamper edits it by this name
    asyncio.run(fresh_db("wsapp_b"))

    key_a, key_b = os.urandom(32), os.urandom(32)
    entry_a = [
        # A non-ASCII label: islandList.test checks the canonical form with one.
        {"apiBase": f"http://127.0.0.1:{FAILOVER[0]}", "wsBase": f"ws://127.0.0.1:{FAILOVER[0]}", "label": "основной"},
        {"apiBase": f"http://127.0.0.1:{FAILOVER[1]}", "wsBase": f"ws://127.0.0.1:{FAILOVER[1]}", "label": "mirror"},
        {"apiBase": "http://127.0.0.1:8000", "wsBase": "ws://127.0.0.1:8000", "label": "direct"},
    ]
    entry_b = [{"apiBase": "http://127.0.0.1:8001", "wsBase": "ws://127.0.0.1:8001", "label": "b"}]
    py = sys.executable
    pids = {
        "island-a": spawn("island-a", [py, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000",
                                       "--workers", "1"], ROOT / "server",
                          island_env("island-test", 8000, "wsapp", "a" * 64, key_a, entry_a)),
        "island-b": spawn("island-b", [py, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8001",
                                       "--workers", "1"], ROOT / "server",
                          island_env("island-b", 8001, "wsapp_b", "b" * 64, key_b, entry_b)),
    }
    (RUN / "relay.config.json").write_text(json.dumps({
        "relay_id": "relay-alpha",
        "islands": {
            "island-test": {"url": "http://127.0.0.1:8000", "key_b64": b64(key_a)},
            "island-b": {"url": "http://127.0.0.1:8001", "key_b64": b64(key_b)},
        },
    }), encoding="utf-8")
    renv = dict(os.environ, RELAY_CONFIG=str(RUN / "relay.config.json"), PYTHONIOENCODING="utf-8")
    pids["relay"] = spawn("relay", [py, "-m", "uvicorn", "relay:app", "--host", "127.0.0.1", "--port", "18800"],
                          ROOT / "relay", renv)
    (RUN / "pids.json").write_text(json.dumps(pids), encoding="utf-8")

    wait_up("http://127.0.0.1:8000/health", "island-a")
    wait_up("http://127.0.0.1:8001/health", "island-b")
    wait_up("http://127.0.0.1:18800/", "relay")
    print("stand up:", pids, "- logs in", RUN)


def down(quiet: bool = False) -> None:
    f = RUN / "pids.json"
    if not f.exists():
        return
    for name, pid in json.loads(f.read_text(encoding="utf-8")).items():
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)  # noqa: S603,S607
        else:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGTERM)
        if not quiet:
            print("stopped", name, pid)
    f.unlink()


if __name__ == "__main__":
    {"up": up, "down": down}[sys.argv[1] if len(sys.argv) > 1 else "up"]()
