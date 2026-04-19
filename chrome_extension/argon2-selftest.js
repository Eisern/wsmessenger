// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

(() => {
  if (globalThis.__argon2SelfTestStarted) return;
  globalThis.__argon2SelfTestStarted = true;
  const ALERT_KEY = "__argon2_missing_alert_v1";
  const EXPECTED_WASM_SHA256 = {
    "argon2id/argon2.wasm": "0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7",
    "argon2id/argon2-simd.wasm": "b1a948019a8f4a798401f3f6abc669d8ed5b2ffb3f6b59d08b7f74b6834f8620",
  };

  const TEST_PASS = "wsapp-argon2-selftest";
  const TEST_SALT = new TextEncoder().encode("wsapp-selftest-salt-16b");

  function toHex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function sha256Hex(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return toHex(new Uint8Array(digest));
  }

  async function verifyWasmIntegrity() {
    for (const [path, expected] of Object.entries(EXPECTED_WASM_SHA256)) {
      const url = (globalThis.chrome?.runtime?.getURL?.(path)) || path;
      const r = await fetch(url, { cache: "no-store" });
      if (!r.ok) throw new Error(`argon2 resource missing: ${path}`);
      const buf = await r.arrayBuffer();
      const got = await sha256Hex(buf);
      if (got !== expected) {
        throw new Error(`argon2 resource integrity check failed: ${path}`);
      }
    }
  }

  async function runArgon2SelfTest() {
    await verifyWasmIntegrity();
    const a2 = globalThis.argon2;
    if (!a2 || typeof a2.hash !== "function") {
      throw new Error("argon2 runtime is not loaded (window.argon2.hash missing)");
    }

    const type =
      (a2.ArgonType && (a2.ArgonType.Argon2id ?? a2.ArgonType.ID)) ??
      a2.ARGON2ID ??
      2;

    const t0 = performance.now();
    const out = await a2.hash({
      pass: TEST_PASS,
      salt: TEST_SALT,
      time: 2,
      mem: 32768,       // 32 MiB
      parallelism: 1,
      hashLen: 32,
      type,
      version: 19,
      raw: true,
    });
    const dt = Math.round(performance.now() - t0);

    const hashU8 = out?.hash instanceof Uint8Array ? out.hash : new Uint8Array(out?.hash || []);
    if (hashU8.byteLength !== 32) {
      throw new Error(`argon2 self-test invalid output length: ${hashU8.byteLength}`);
    }

    const head = toHex(hashU8.slice(0, 6));

    console.info(`[Argon2] self-test OK in ${dt} ms (hash head: ${head}...)`);
    return { ok: true, ms: dt, hashHead: head };
  }

  globalThis.__argon2SelfTest = runArgon2SelfTest()
    .then((res) => {
      globalThis.__argon2Ready = true;
      return res;
    })
    .catch((err) => {
      globalThis.__argon2Ready = false;
      const message = String(err?.message || err || "unknown error");
      console.error("[Argon2] self-test FAILED:", message);
      try {
        const alreadyShown = sessionStorage.getItem(ALERT_KEY) === "1";
        if (!alreadyShown) {
          sessionStorage.setItem(ALERT_KEY, "1");
          alert(
            "Security error: Argon2 runtime/integrity check failed.\n" +
            "Password-based key protection is unavailable.\n" +
            "Please reload the extension and verify argon2 library files."
          );
        }
      } catch {}
      return { ok: false, error: message };
    });
})();
