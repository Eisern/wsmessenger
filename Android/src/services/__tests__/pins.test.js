// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// TOFU pins decide whether the user is shown "this key changed" — the warning
// that means somebody may be intercepting them. Two things can go wrong
// silently here, and both are tested: two islands sharing one pin slot, and a
// pin that the island-scoping migration failed to bring along, which reads as
// "no pin" and therefore as a first contact.

const { Keychain, _kc, _mem } = require('./integration/helpers/rnStubs');
const StorageService = require('../StorageService').default || require('../StorageService');

const A = 'alpha.example';
const B = 'beta.example';

// StorageService namespaces every Keychain service; legacy rows have to be
// seeded the way the old build wrote them, not through today's API.
const service = (key) => `com.wsmessenger.${key}`;

async function seedLegacyPin(key, value) {
  await Keychain.setGenericPassword('ws', JSON.stringify(value), { service: service(key) });
}

async function rawPin(key) {
  const creds = await Keychain.getGenericPassword({ service: service(key) });
  if (!creds) return null;
  try { return JSON.parse(creds.password); } catch (_e) { return creds.password; }
}

beforeEach(() => {
  _kc.clear();
  _mem.clear();
});

describe('pins are addressed by island as well as by name', () => {
  it('keeps two islands\' "bob" apart', async () => {
    await StorageService.setKnownFingerprint(A, 'me', 'bob', 'fp-from-alpha');

    // The same name on another island is a different person, so there is
    // nothing pinned for them yet. Answering with alpha's fingerprint here is
    // the bug: beta's bob would either look like an impostor or inherit trust.
    expect(await StorageService.getKnownFingerprint(B, 'me', 'bob')).toBeNull();

    await StorageService.setKnownFingerprint(B, 'me', 'bob', 'fp-from-beta');
    expect(await StorageService.getKnownFingerprint(A, 'me', 'bob')).toBe('fp-from-alpha');
    expect(await StorageService.getKnownFingerprint(B, 'me', 'bob')).toBe('fp-from-beta');
  });

  it('scopes the verified and changed flags too', async () => {
    await StorageService.setKeyVerified(A, 'me', 'bob');
    await StorageService.setKeyChanged(A, 'me', 'bob');

    expect(await StorageService.isKeyVerified(A, 'me', 'bob')).toBe(true);
    expect(await StorageService.isKeyVerified(B, 'me', 'bob')).toBe(false);
    expect(await StorageService.getKeyChanged(A, 'me', 'bob')).toBe(true);
    expect(await StorageService.getKeyChanged(B, 'me', 'bob')).toBe(false);
  });

  it('is case-insensitive in all three parts of the address', async () => {
    await StorageService.setKnownFingerprint('Alpha.Example', 'Me', 'Bob', 'fp');
    expect(await StorageService.getKnownFingerprint(A, 'me', 'bob')).toBe('fp');
  });
});

describe('migrating pins written before the address carried an island', () => {
  async function seedV1() {
    await seedLegacyPin('fp_me_bob', 'fp-v1');
    await seedLegacyPin('fp_me_bob_verified', { ts: 111 });
    await seedLegacyPin('fp_me_bob_changed', true);
    await seedLegacyPin('_fp_index', ['fp_me_bob']);
  }

  it('brings the fingerprint and both flags onto the island', async () => {
    await seedV1();
    expect(await StorageService.migrateFingerprintPins(A)).toBe(1);

    expect(await StorageService.getKnownFingerprint(A, 'me', 'bob')).toBe('fp-v1');
    expect(await StorageService.isKeyVerified(A, 'me', 'bob')).toBe(true);
    expect(await StorageService.getKeyChanged(A, 'me', 'bob')).toBe(true);
  });

  // The whole reason the migration runs before the first read. A pin that did
  // not move reads as "no pin", "no pin" means first contact, and first contact
  // records whatever key is on offer as trusted — the silent downgrade.
  it('leaves nothing behind that would read as a first contact', async () => {
    await seedV1();
    await StorageService.migrateFingerprintPins(A);

    expect(await rawPin('fp_me_bob')).toBeNull();
    expect(await rawPin('fp_me_bob_verified')).toBeNull();
    expect(await rawPin('fp_me_bob_changed')).toBeNull();
  });

  it('rewrites the index so logout still finds the pins', async () => {
    await seedV1();
    await StorageService.migrateFingerprintPins(A);

    expect(await rawPin('_fp_index')).toEqual([`fp2_${A}_me_bob`]);
  });

  it('does not move a pin twice or move one that is already scoped', async () => {
    await seedV1();
    await StorageService.migrateFingerprintPins(A);

    // A second run has nothing to do, and must not re-attribute the pin to
    // whatever island happens to be active now.
    expect(await StorageService.migrateFingerprintPins(B)).toBe(0);
    expect(await StorageService.getKnownFingerprint(A, 'me', 'bob')).toBe('fp-v1');
    expect(await StorageService.getKnownFingerprint(B, 'me', 'bob')).toBeNull();
  });

  it('is a no-op when there is nothing to move', async () => {
    expect(await StorageService.migrateFingerprintPins(A)).toBe(0);
  });
});
