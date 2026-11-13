// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Attachments, end to end (file-crypt.js - one file, byte-identical in both
 * clients).
 *
 * A file used to reach the island as it was. What is held here: the blob says
 * nothing about the file, opens only whole and only under its own key, and the
 * marker that carries the key reads back exactly - on the other client too,
 * which is why the format is pinned by a vector and the copies by a comparison.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');

const FC = require('../file-crypt');

const ANDROID_PATH = path.join(__dirname, '..', 'file-crypt.js');
const EXTENSION_PATH = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension', 'file-crypt.js');
const normalized = (file) => fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');

const C = { subtle: nodeCrypto.webcrypto.subtle, getRandomValues: (a) => nodeCrypto.webcrypto.getRandomValues(a) };
const M = FC.FORMAT.CHUNK;
const HEADER = FC.FORMAT.HEADER_LEN;
const TAG = FC.FORMAT.TAG_LEN;

const bytes = (n) => new Uint8Array(nodeCrypto.randomBytes(n));
const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

/** A source that hands out at most `step` bytes a time, as a phone's file API may. */
const source = (u8, step) => async (offset, length) =>
  u8.subarray(offset, Math.min(u8.length, offset + Math.min(length, step || length)));

async function seal(data, opts = {}) {
  const parts = [];
  const out = await FC.seal({
    read: source(data, opts.step),
    write: async (p) => { parts.push(Uint8Array.from(p)); },
    crypto: opts.crypto || C,
    maxSealedBytes: opts.maxSealedBytes,
  });
  return { ...out, blob: new Uint8Array(Buffer.concat(parts)) };
}

async function open(blob, key, size) {
  const parts = [];
  await FC.open({
    key, size, sealedSize: blob.length,
    read: source(blob),
    write: async (p) => { parts.push(Uint8Array.from(p)); },
    crypto: C,
  });
  return new Uint8Array(Buffer.concat(parts));
}

describe('file-crypt.js parity between the two clients', () => {
  it('both copies exist and are identical', () => {
    expect(fs.existsSync(ANDROID_PATH)).toBe(true);
    expect(fs.existsSync(EXTENSION_PATH)).toBe(true);
    expect(normalized(ANDROID_PATH)).toBe(normalized(EXTENSION_PATH));
  });

  it('the extension copy, loaded as the browser loads it, reads what this one wrote', async () => {
    const sandbox = { console, JSON, Date, Math, Uint8Array, Int8Array, String, Number, Error, Object };
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(fs.readFileSync(EXTENSION_PATH, 'utf8'), sandbox, { filename: 'file-crypt.js' });
    const ext = sandbox.WSFileCrypt;
    expect(Object.keys(ext).sort()).toEqual(Object.keys(FC).sort());

    const marker = FC.makeMarker({ token: 'tok_1', key: bytes(32), name: 'отчёт.pdf', mime: 'application/pdf', size: 12345 });
    const theirs = ext.parseMarker(marker);
    expect(theirs.filename).toBe('отчёт.pdf');
    expect(theirs.sizeBytes).toBe(12345);
    expect(same(theirs.key, FC.parseMarker(marker).key)).toBe(true);
    for (const n of [0, 4096, 4097, M, 50 * M, 100 * M]) expect(ext.sealedLength(n)).toBe(FC.sealedLength(n));
  });
});

describe('a file goes in and comes out', () => {
  // Either side of every boundary: the padding floor, one chunk, several.
  const sizes = [0, 1, 4095, 4096, 4097, 70000, M - 1, M, M + 1, 2 * M, 3 * M + 12345];

  test.each(sizes)('%d bytes', async (n) => {
    const data = bytes(n);
    const s = await seal(data, { step: n % 2 ? 7777 : undefined });
    expect(s.size).toBe(n);
    expect(s.blob.length).toBe(FC.sealedLength(n));
    expect(s.sealedSize).toBe(s.blob.length);
    expect(same(await open(s.blob, s.key, n), data)).toBe(true);
  });

  test('every file gets a key and a nonce prefix of its own', async () => {
    const data = bytes(5000);
    const a = await seal(data);
    const b = await seal(data);
    expect(same(a.key, b.key)).toBe(false);
    expect(same(a.blob.subarray(4, HEADER), b.blob.subarray(4, HEADER))).toBe(false);
    expect(same(a.blob, b.blob)).toBe(false);
  });

  test('a file too big for the island is given up on, not uploaded', async () => {
    await expect(seal(bytes(3 * M), { maxSealedBytes: 2 * M })).rejects.toMatchObject({ code: 'TOO_BIG' });
  });
});

describe('what the island can see', () => {
  test('none of the file', async () => {
    const line = Buffer.from('the quarterly figures, as they are: 4 815 162 342\n');
    const data = new Uint8Array(Buffer.concat(Array(400).fill(line)));
    const s = await seal(data);
    expect(Buffer.from(s.blob).includes(line.subarray(0, 16))).toBe(false);
    // Nor the key that opens it.
    expect(Buffer.from(s.blob).includes(Buffer.from(s.key))).toBe(false);
    expect(Buffer.from(s.blob.subarray(0, 4)).toString('latin1')).toBe('WSF3');
  });

  test('a size class, not a size', async () => {
    // Everything small looks alike...
    for (const n of [0, 1, 40, 400, 4096]) expect(FC.sealedLength(n)).toBe(HEADER + 4096 + TAG);
    // ...and above that, neighbours share a length.
    expect(FC.sealedLength(1000001)).toBe(FC.sealedLength(1000200));
    expect((await seal(bytes(70001))).blob.length).toBe((await seal(bytes(70100))).blob.length);
  });

  test('padding costs at most about an eighth, and never shrinks a file', () => {
    let worst = 0;
    for (let n = 4096; n < 200 * M; n = Math.floor(n * 1.37) + 1) {
      const p = FC.paddedLength(n);
      expect(p).toBeGreaterThanOrEqual(n);
      worst = Math.max(worst, p / n - 1);
    }
    expect(worst).toBeLessThan(0.125);
    // The largest file the clients send still fits what the server takes.
    expect(FC.sealedLength(100 * M)).toBeLessThanOrEqual(100 * M + 64 * 1024);
  });
});

describe('a blob that is not the one that was sent', () => {
  let data;
  let s;
  beforeAll(async () => {
    data = bytes(2 * M + 5);
    s = await seal(data);
  });
  const refused = (blob, key = s.key, size = data.length) => expect(open(blob, key, size)).rejects.toThrow();
  const chunk = M + TAG;

  test('one bit changed', async () => {
    for (const at of [HEADER, HEADER + 5000, s.blob.length - 1]) {
      const b = Uint8Array.from(s.blob);
      b[at] ^= 1;
      await refused(b);
    }
  });

  test('a changed nonce prefix or a foreign header', async () => {
    const b = Uint8Array.from(s.blob);
    b[6] ^= 1;
    await refused(b);
    const c = Uint8Array.from(s.blob);
    c[0] = 0x25;
    await expect(open(c, s.key, data.length)).rejects.toThrow('Not an encrypted file');
  });

  test('cut short, or longer than it should be', async () => {
    await refused(s.blob.subarray(0, s.blob.length - 1));
    await refused(s.blob.subarray(0, HEADER + 2 * chunk));           // its last chunk dropped
    await refused(new Uint8Array(Buffer.concat([s.blob, Buffer.alloc(16)])));
  });

  test('chunks in another order, or one repeated', async () => {
    const swapped = Uint8Array.from(s.blob);
    swapped.set(s.blob.subarray(HEADER + chunk, HEADER + 2 * chunk), HEADER);
    swapped.set(s.blob.subarray(HEADER, HEADER + chunk), HEADER + chunk);
    await refused(swapped);
    const repeated = Uint8Array.from(s.blob);
    repeated.set(s.blob.subarray(HEADER, HEADER + chunk), HEADER + chunk);
    await refused(repeated);
  });

  test('a last chunk passed off as a middle one', async () => {
    // A two-chunk file whose first chunk is offered as a whole one-chunk file:
    // the lengths can be made to agree, the "last" flag in the nonce cannot.
    const two = await seal(bytes(M + 5));
    const first = two.blob.subarray(0, HEADER + chunk);
    expect(first.length).toBe(FC.sealedLength(M));
    await expect(open(first, two.key, M)).rejects.toThrow('damaged or was altered');
  });

  test('another file\'s key, or another file under this one\'s key', async () => {
    const other = await seal(bytes(2 * M + 5));
    await refused(s.blob, other.key);
    await refused(other.blob, s.key);
  });

  test('nothing is written from a blob of the wrong length', async () => {
    let written = 0;
    await expect(FC.open({
      key: s.key, size: data.length, sealedSize: s.blob.length - 1,
      read: source(s.blob.subarray(0, s.blob.length - 1)),
      write: async () => { written += 1; },
      crypto: C,
    })).rejects.toThrow('not the one that was sent');
    expect(written).toBe(0);
  });
});

describe('the marker', () => {
  const key = bytes(32);
  const make = (over = {}) => FC.makeMarker({ token: 'Abc_123-xyz', key, name: 'notes.txt', mime: 'text/plain', size: 77, ...over });

  test('reads back what was written', () => {
    const m = FC.parseMarker(make({ name: 'Фото из отпуска 🏖.jpg', mime: 'image/jpeg', size: 3 * M }));
    expect(m).toMatchObject({ v: 3, token: 'Abc_123-xyz', filename: 'Фото из отпуска 🏖.jpg', mime: 'image/jpeg', sizeBytes: 3 * M });
    expect(same(m.key, key)).toBe(true);
  });

  test('is plain ASCII, whatever the name', () => {
    expect(make({ name: 'Фото 🏖.jpg' })).toMatch(/^FILE3::[A-Za-z0-9_-]+$/);
  });

  test('refuses to be made without a real key, token or size', () => {
    expect(() => make({ key: bytes(16) })).toThrow();
    expect(() => make({ key: Array.from(key) })).toThrow();
    expect(() => make({ token: '../etc/passwd' })).toThrow();
    expect(() => make({ token: '' })).toThrow();
    expect(() => make({ size: -1 })).toThrow();
    expect(() => make({ size: 1.5 })).toThrow();
  });

  test('a name is the sender\'s word and is treated as such', () => {
    const name = (n) => FC.parseMarker(make({ name: n })).filename;
    expect(name('../../etc/passwd')).not.toMatch(/[/\\]|\.\./);
    expect(name('C:\\Users\\me\\secret.txt')).not.toMatch(/[/\\:]/);
    expect(name('photo\u202Egnp.exe')).not.toMatch(/\u202e/);      // no right-to-left override
    expect(name('a\nb\tc\u0000d')).toBe('a b c d');
    expect(name('')).toBe('file');
    expect(name('x'.repeat(500)).length).toBe(FC.FORMAT.NAME_MAX);
    expect(FC.parseMarker(make({ mime: 'text/html; charset=utf-8' })).mime).toBe('');
  });

  test('what is not a marker is not a file', () => {
    const forge = (obj, prefix = 'FILE3::') => prefix + Buffer.from(JSON.stringify(obj)).toString('base64url');
    const good = { v: 3, t: 'tok', k: Buffer.from(key).toString('base64url'), n: 'a', m: '', s: 5 };
    expect(FC.parseMarker(forge(good))).toMatchObject({ v: 3, token: 'tok', sizeBytes: 5 });

    expect(FC.parseMarker('hello')).toBeNull();
    expect(FC.parseMarker(null)).toBeNull();
    expect(FC.parseMarker('FILE3::')).toBeNull();
    expect(FC.parseMarker('FILE3::%%%')).toBeNull();
    expect(FC.parseMarker(forge({ ...good, k: 'AAAA' }))).toBeNull();             // not a key
    expect(FC.parseMarker(forge({ ...good, k: undefined }))).toBeNull();
    expect(FC.parseMarker(forge({ ...good, s: '5' }))).toBeNull();                // size must be a number
    expect(FC.parseMarker(forge({ ...good, s: -5 }))).toBeNull();
    expect(FC.parseMarker(forge({ ...good, t: 'a/b' }))).toBeNull();
    expect(FC.parseMarker(forge({ ...good, v: 2 }))).toBeNull();
    expect(FC.parseMarker(forge([1, 2, 3]))).toBeNull();
  });

  test('a file sent before files were encrypted is still read, and says it has no key', () => {
    // As the extension wrote it (UTF-8 JSON) ...
    const legacy = 'FILE2::' + Buffer.from(JSON.stringify({ v: 2, t: 'tok', n: 'фото.png', s: 12, ts: 1 })).toString('base64url');
    expect(FC.parseMarker(legacy)).toEqual({ v: 2, token: 'tok', key: null, filename: 'фото.png', mime: '', sizeBytes: 12 });
    // ... and a FILE2 that claims a key gets none: only FILE3 is opened with one.
    const sly = 'FILE2::' + Buffer.from(JSON.stringify({ v: 2, t: 'tok', n: 'x', s: 1, k: Buffer.from(key).toString('base64url') })).toString('base64url');
    expect(FC.parseMarker(sly).key).toBeNull();
  });
});

describe('base64 for the file API', () => {
  test('agrees with the platform, both ways, at every remainder', () => {
    for (const n of [0, 1, 2, 3, 4, 5, 255, 8191, 8192, 8193, 100001]) {
      const data = bytes(n);
      const text = Buffer.from(data).toString('base64');
      expect(FC.bytesToB64(data)).toBe(text);
      expect(same(FC.b64ToBytes(text), data)).toBe(true);
      expect(same(FC.b64ToBytes(Buffer.from(data).toString('base64url')), data)).toBe(true);
    }
    expect(() => FC.b64ToBytes('abc$')).toThrow();
  });
});

describe('the format, pinned', () => {
  // Both clients run this same file, but each brings its own AES-GCM. A fixed
  // key, prefix and file must give this exact blob wherever it is made; if this
  // changes, every file already sent stops opening.
  test('a known file under a known key gives a known blob', async () => {
    const fixed = {
      subtle: C.subtle,
      getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = (i * 7 + 3) & 255; return a; },
    };
    const data = new Uint8Array(5000);
    for (let i = 0; i < data.length; i++) data[i] = i % 251;

    const s = await seal(data, { crypto: fixed });
    expect(s.blob.length).toBe(5147);
    expect(Buffer.from(s.blob.subarray(0, HEADER)).toString('hex')).toBe('5753463303' + '0a11181f262d');
    expect(nodeCrypto.createHash('sha256').update(s.blob).digest('hex')).toBe(PINNED_BLOB_SHA256);
    expect(same(await open(s.blob, s.key, data.length), data)).toBe(true);
  });
});

const PINNED_BLOB_SHA256 = 'f4b1d536049a6df79c9f0247201d39b7685dcd482d538f42ef7dcf001cf64365';
