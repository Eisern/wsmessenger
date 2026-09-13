// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * The paths people use every day, run headless against a real island.
 *
 * These had no automated coverage at all. Everything the extension does with
 * room keys and local direct messages was checked by one person clicking, and
 * the failure mode of all of it is silent: a wrong key does not raise an
 * error, it produces a message nobody can read - sometimes only for the
 * messages sent before whatever broke, which is exactly the case a person
 * clicking through a fresh conversation never sees.
 *
 * The cross-island suite next door found two real bugs on its first run for the
 * same reason: it called the client's own functions rather than a reimplementation
 * of what they were supposed to do. Same method here.
 *
 * Requires island A; see integration/README.md.
 */

const { makePanel, setUp, http, udDecode, lastMessage } = require('./helpers/panelHarness');

const ISLAND = process.env.TWO_ISLANDS_A || 'http://127.0.0.1:8000';

// Delivering a DM needs the sealed path, the same one the worker uses.
function wireDeps(panel) {
  return {
    fetchJson: async (url, opts) => {
      const r = await fetch(url, opts);
      let body = null;
      try { body = await r.json(); } catch { /* empty body */ }
      return { ok: r.ok, status: r.status, body };
    },
    sha256: async (b) => new Uint8Array(await panel.CU.sha256Raw(b)),
    hmacSha256: async (k, m) => {
      const key = await globalThis.crypto.subtle.importKey(
        'raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
      );
      return new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, m));
    },
    randomBytes: (n) => globalThis.crypto.getRandomValues(new Uint8Array(n)),
    now: () => Date.now(),
  };
}

async function deliverDm(panel, threadId, ciphertext, token) {
  const secret = await http(ISLAND, `/dm/${threadId}/delivery-secret`, { token });
  expect(secret.ok).toBe(true);
  const res = await panel.sandbox.WSForeignDm.deliver(
    wireDeps(panel),
    { apiBase: ISLAND, threadId, secretB64: secret.data.delivery_secret_b64 },
    ciphertext,
  );
  expect(res.ok).toBe(true);
  return res;
}

let alice;
let bob;
let stamp;

jest.setTimeout(120000);

beforeAll(async () => {
  const h = await fetch(`${ISLAND}/health`).then((r) => r.json()).catch(() => null);
  if (!h || h.status !== 'ok') throw new Error(`island not reachable at ${ISLAND}`);

  stamp = Date.now().toString().slice(-7);
  alice = await setUp(ISLAND, 'island-local', `loc_a_${stamp}`);
  bob = await setUp(ISLAND, 'island-local', `loc_b_${stamp}`);

  // Both must accept DMs and invites from strangers: these two are not friends,
  // and the island refuses either otherwise.
  for (const who of [alice, bob]) {
    const r = await http(ISLAND, '/profile/me', {
      method: 'PUT', token: who.token,
      body: {
        privacy: {
          allow_dm_from_non_friends: true,
          allow_group_invites_from_non_friends: true,
        },
      },
    });
    if (!r.ok) throw new Error(`could not open ${who.username} to DMs: ${r.status}`);
  }
});

describe('a direct message between two people on one island', () => {
  let threadId;

  it('opens a thread and establishes a key both sides can use', async () => {
    const opened = await http(ISLAND, '/dm/open', {
      method: 'POST', token: alice.token, body: { username: bob.username },
    });
    expect(opened.ok).toBe(true);
    threadId = Number(opened.data.thread_id);

    // Alice's client mints the thread key and wraps it for both of them. This
    // is the step that has to happen exactly once: two clients each creating
    // one would leave half the conversation unreadable to the other.
    await alice.sandbox.ensureDmKeyReady(threadId, bob.username);
    expect(alice.manager.roomKeys.has(alice.sandbox.dmRid(threadId))).toBe(true);

    await bob.sandbox.ensureDmKeyReady(threadId, alice.username);
    expect(bob.manager.roomKeys.has(bob.sandbox.dmRid(threadId))).toBe(true);
  });

  it('carries the sender inside the ciphertext, not beside it', async () => {
    const text = 'привет, это локальная личка';
    const enc = await alice.sandbox.encryptDm(threadId, text, bob.username, alice.username);
    await deliverDm(alice, threadId, enc, alice.token);

    const row = (await http(ISLAND, `/dm/${threadId}/history`, { token: bob.token })).data;
    const rows = row.messages || row;
    // The island stored it with no sender at all: that is the whole point of
    // the sealed path, and a regression here would be invisible in the UI.
    expect(rows[rows.length - 1].username == null).toBe(true);

    const got = await bob.sandbox.decryptDm(
      threadId, udDecode(rows[rows.length - 1].text), alice.username, Date.now(),
    );
    expect(got.text).toBe(text);
    expect(got.sealedFrom).toBe(alice.username);
    expect(got.sigValid).toBe(true);
  });

  it('refuses a message whose sender field was swapped', async () => {
    // The signature covers (thread, from, body). Rewriting `from` inside the
    // envelope is what the signature exists to catch - and the only thing
    // standing between a dishonest server and a convincing impersonation.
    const enc = await alice.sandbox.encryptDm(threadId, 'кто это написал?', bob.username, alice.username);
    const parsed = JSON.parse(enc);
    const plain = JSON.parse(await alice.manager.decryptMessage(alice.sandbox.dmRid(threadId), parsed));
    plain.from = bob.username;

    const rid = alice.sandbox.dmRid(threadId);
    const forged = await alice.manager.encryptMessage(rid, JSON.stringify(plain));
    await deliverDm(alice, threadId, forged, alice.token);

    const got = await bob.sandbox.decryptDm(
      threadId, await lastMessage(ISLAND, threadId, bob.token), alice.username, Date.now(),
    );
    expect(got.sealedFrom).toBe(bob.username);
    expect(got.sigValid).toBe(false);
  });
});

describe('room keys and the history they have to keep readable', () => {
  let roomId;

  it('creates a room with a key that existed before the room did', async () => {
    // The island refuses to create a room without one. That ordering is the
    // point: there is no window in which the room exists unencrypted, and no
    // moment at which the server could have supplied the key itself.
    const roomKeyB64 = await alice.CU.exportRoomKey(await alice.CU.generateRoomKey(true));
    const wrapped = await alice.CU.encryptRoomKeyForUser(alice.manager.userPublicKeyB64, roomKeyB64);

    const created = await http(ISLAND, '/rooms', {
      method: 'POST',
      token: alice.token,
      body: {
        name: `loc_room_${stamp}`,
        password: null,
        encrypted_room_key: wrapped,
        is_public: false,
        is_readonly: false,
      },
    });
    expect(created.ok).toBe(true);
    roomId = Number(created.data.id ?? created.data.room_id);
    expect(roomId).toBeGreaterThan(0);

    // What the panel does after the worker answers: adopt the key it just
    // minted, so the first message can be sent without another round trip.
    expect(await alice.manager.loadRoomKey(roomId, roomKeyB64)).toBe(true);
    expect(alice.manager.roomKeys.has(roomId)).toBe(true);
  });

  it('reads back a message it encrypted', async () => {
    const text = 'сообщение под первым ключом';
    const enc = await alice.sandbox.encryptMessageForRoom(roomId, text);
    expect(JSON.parse(enc).encrypted).toBe(true);
    expect(await alice.manager.decryptMessage(roomId, JSON.parse(enc))).toBe(text);
  });

  it('still reads yesterday after the key is rotated', async () => {
    // Rotation is what happens when somebody is removed. If the old key were
    // dropped instead of archived, every message sent before this moment would
    // become unreadable - and nothing would say so until somebody scrolled up.
    const before = await alice.sandbox.encryptMessageForRoom(roomId, 'до ротации');
    const oldKid = JSON.parse(before).kid;

    const rotated = await alice.sandbox.rotateRoomKey(roomId);
    expect(rotated.ok).toBe(true);

    const after = await alice.sandbox.encryptMessageForRoom(roomId, 'после ротации');
    const newKid = JSON.parse(after).kid;
    expect(newKid).not.toBe(oldKid);

    expect(await alice.manager.decryptMessage(roomId, JSON.parse(after))).toBe('после ротации');
    expect(await alice.manager.decryptMessage(roomId, JSON.parse(before))).toBe('до ротации');
  });

  it('recovers both keys from the server after everything local is gone', async () => {
    // A reinstall, or simply another device. The archive lives on the island
    // wrapped per member, so a client that has never seen this room must end
    // up able to read all of its history, not just what was said after it
    // arrived.
    const fresh = makePanel({
      apiBase: ISLAND, islandId: 'island-local', username: alice.username, token: alice.token,
    });
    // The same identity, unlocked from the same encrypted container - which is
    // all a reinstall has: the private key never leaves the device, and the
    // island returns 410 to anyone who asks for it.
    const ok = await fresh.manager.initializeUserKeyWithKek(
      alice.identity.encrypted, alice.identity.aesKey,
      alice.identity.publicKeyB64, alice.username.toLowerCase(),
    );
    expect(ok).toBe(true);

    const loaded = await fresh.sandbox.loadRoomKey(roomId);
    expect(loaded.ok).toBe(true);

    const beforeRotation = await alice.sandbox.encryptMessageForRoom(roomId, 'проверка архива');
    // Encrypted with the CURRENT key by Alice; the fresh client must read it.
    expect(await fresh.manager.decryptMessage(roomId, JSON.parse(beforeRotation)))
      .toBe('проверка архива');
    expect(fresh.manager.roomKeyArchive.get(roomId)?.size ?? 0).toBeGreaterThan(0);
  });
});

describe('a second person joining a room', () => {
  let roomId;
  let roomKeyB64;

  it('creates the room and invites them', async () => {
    roomKeyB64 = await alice.CU.exportRoomKey(await alice.CU.generateRoomKey(true));
    const created = await http(ISLAND, '/rooms', {
      method: 'POST',
      token: alice.token,
      body: {
        name: `loc_join_${stamp}`,
        password: null,
        encrypted_room_key: await alice.CU.encryptRoomKeyForUser(
          alice.manager.userPublicKeyB64, roomKeyB64,
        ),
        is_public: false,
        is_readonly: false,
      },
    });
    expect(created.ok).toBe(true);
    roomId = Number(created.data.id ?? created.data.room_id);
    await alice.manager.loadRoomKey(roomId, roomKeyB64);

    const invited = await http(ISLAND, `/rooms/${roomId}/invite`, {
      method: 'POST', token: alice.token, body: { username: bob.username },
    });
    expect(invited.ok).toBe(true);
  });

  it('leaves a gap the moment they accept, and nothing else does', async () => {
    // The island does not hold the room key and cannot mint one, so a new
    // member is simply a member with no key row. That gap is derived from
    // membership rather than recorded anywhere, which is what makes it
    // impossible to lose.
    const accepted = await http(ISLAND, `/rooms/${roomId}/invites/accept`, {
      method: 'POST', token: bob.token, body: {},
    });
    expect(accepted.ok).toBe(true);

    const gaps = await http(ISLAND, `/crypto/rooms/key-gaps?room_id=${roomId}`, {
      token: alice.token,
    });
    expect(gaps.ok).toBe(true);
    const names = (gaps.data.gaps || []).map((g) => g.username);
    expect(names).toContain(bob.username);
  });

  it('the owner sweeps, and the new member can read what was said before', async () => {
    // Said BEFORE they had the key: the room key is not rotated on join, so
    // history stays readable - which is the whole reason a gap is filled with
    // the existing key rather than a new one.
    const earlier = await alice.sandbox.encryptMessageForRoom(roomId, 'сказано до прихода');

    const swept = await alice.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test' });
    expect(swept.ran).toBe(true);
    expect(swept.shared).toBeGreaterThanOrEqual(1);

    const loaded = await bob.sandbox.loadRoomKey(roomId);
    expect(loaded.ok).toBe(true);
    expect(await bob.manager.decryptMessage(roomId, JSON.parse(earlier)))
      .toBe('сказано до прихода');
  });

  it('a second sweep finds nothing left to do', async () => {
    // The endpoint derives gaps from what is missing, so a filled one stops
    // being reported. A sweep that kept re-sharing would be an infinite loop
    // between two clients that both think they are helping.
    const again = await alice.sandbox.sweepRoomKeyGaps({ roomId, reason: 'test-2' });
    expect(again.shared).toBe(0);

    const gaps = await http(ISLAND, `/crypto/rooms/key-gaps?room_id=${roomId}`, {
      token: alice.token,
    });
    expect((gaps.data.gaps || []).map((g) => g.username)).not.toContain(bob.username);
  });

  it('a removed member keeps nothing, and the room moves on without them', async () => {
    // Rotation on kick is the only thing standing between "removed" and "still
    // reading everything". The rotated key must reach the members who stayed,
    // and must not reach the one who left.
    const kicked = await http(ISLAND, `/rooms/${roomId}/kick`, {
      method: 'POST', token: alice.token, body: { username: bob.username },
    });
    expect(kicked.ok).toBe(true);

    const rotated = await alice.sandbox.rotateRoomKey(roomId, { kickedUsername: bob.username });
    expect(rotated.ok).toBe(true);

    const afterKick = await alice.sandbox.encryptMessageForRoom(roomId, 'уже без них');
    const theirKey = await http(ISLAND, `/crypto/room-key/${roomId}`, { token: bob.token });
    expect(theirKey.ok).toBe(false);

    // And the owner still reads both sides of the rotation.
    expect(await alice.manager.decryptMessage(roomId, JSON.parse(afterKick))).toBe('уже без них');
  });
});
