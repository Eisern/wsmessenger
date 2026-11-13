// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Sending and fetching a file on Android (FileTransferService over
 * file-crypt.js), against a file system and an island held in memory.
 *
 * The app used to hand the picked file's uri straight to the upload: the
 * island got the bytes, the name and the type. What is held here is what
 * leaves the phone now - one opaque blob - and that nothing readable is left
 * behind in the cache, whether the transfer worked or not.
 *
 * The file system stands in for react-native-fs with its two habits that the
 * service has to live with: a read may return fewer bytes than asked, and a
 * read at the end of a file rejects.
 */

const nodeCrypto = require('crypto');

if (!globalThis.crypto?.subtle) globalThis.crypto = nodeCrypto.webcrypto;

const mockFs = {
  files: new Map(),          // path or uri -> Buffer
  island: new Map(),         // token -> Buffer
  readCap: 300000,           // most bytes one read returns
  statSize: null,            // a size to claim instead of the real one
  downloads: [],
};
const mockNorm = (p) => String(p).replace(/^file:\/\//, '');

jest.mock('react-native-fs', () => ({
  CachesDirectoryPath: '/cache',
  DownloadDirectoryPath: '/downloads',
  async copyFile(from, to) {
    const src = mockFs.files.get(mockNorm(from));
    if (!src) throw new Error('ENOENT: ' + from);
    mockFs.files.set(mockNorm(to), Buffer.from(src));
  },
  async stat(p) {
    const f = mockFs.files.get(mockNorm(p));
    if (!f) throw new Error('File does not exist');
    return { size: mockFs.statSize != null ? mockFs.statSize : f.length };
  },
  async read(p, length, position, encoding) {
    if (encoding !== 'base64') throw new Error('test fs reads base64 only');
    const f = mockFs.files.get(mockNorm(p));
    if (!f) throw new Error('ENOENT: ' + p);
    if (position >= f.length) throw new Error('read at the end of the file');   // as the native module does
    return f.subarray(position, Math.min(f.length, position + Math.min(length, mockFs.readCap))).toString('base64');
  },
  async appendFile(p, contents, encoding) {
    if (encoding !== 'base64') throw new Error('test fs appends base64 only');
    const prev = mockFs.files.get(mockNorm(p)) || Buffer.alloc(0);
    mockFs.files.set(mockNorm(p), Buffer.concat([prev, Buffer.from(contents, 'base64')]));
  },
  async writeFile(p, contents) {
    mockFs.files.set(mockNorm(p), Buffer.from(contents, 'utf8'));
  },
  async unlink(p) {
    if (!mockFs.files.delete(mockNorm(p))) throw new Error('File does not exist');
  },
  async moveFile(from, to) {
    const src = mockFs.files.get(mockNorm(from));
    if (!src) throw new Error('ENOENT: ' + from);
    mockFs.files.set(mockNorm(to), src);
    mockFs.files.delete(mockNorm(from));
  },
  async exists(p) { return mockFs.files.has(mockNorm(p)); },
  downloadFile({ fromUrl, toFile, headers }) {
    mockFs.downloads.push({ fromUrl, headers });
    const token = String(fromUrl).split('/files/')[1];
    const bytes = mockFs.island.get(token);
    // The native module writes whatever came back, an error page included.
    mockFs.files.set(mockNorm(toFile), bytes || Buffer.from('{"detail":"File not found"}'));
    return { promise: Promise.resolve({ statusCode: bytes ? 200 : 404 }) };
  },
}));

jest.mock('../NetworkService', () => ({
  __esModule: true,
  default: {
    getFileUrl: (token) => `https://island.test/files/${token}`,
    getFileHeaders: () => ({ Authorization: 'Bearer tok' }),
  },
}));

const FC = require('../file-crypt');
const { sendEncryptedFile, fetchFileTo, MAX_FILE_BYTES } = require('../FileTransferService');
const { parseFileMarker } = require('../../utils/fileMarker');

const PICKED = 'content://com.android.providers.downloads.documents/document/17';
const NAME = 'квартальный отчёт.pdf';
const LINE = Buffer.from('the quarterly figures, as they are: 4 815 162 342\n');
const CONTENT = Buffer.concat(Array(300).fill(LINE));

/** Everything in the cache: what a transfer may use, and must not leave. */
const cached = () => [...mockFs.files.keys()].filter((p) => p.startsWith('/cache/'));

/** An upload that keeps what it was given, the way the island would. */
function islandUpload(seen = {}) {
  return async (uri) => {
    seen.uri = uri;
    seen.bytes = Buffer.from(mockFs.files.get(mockNorm(uri)));
    seen.cacheDuring = cached();
    const token = `tok${mockFs.island.size + 1}`;
    mockFs.island.set(token, seen.bytes);
    return { token, filename: 'blob', size_bytes: seen.bytes.length };
  };
}

beforeEach(() => {
  mockFs.files.clear();
  mockFs.island.clear();
  mockFs.downloads.length = 0;
  mockFs.statSize = null;
  mockFs.readCap = 300000;
  mockFs.files.set(PICKED, CONTENT);
});

describe('what leaves the phone when a file is sent', () => {
  test('one opaque blob - none of the file, and no readable copy left while it uploads', async () => {
    const seen = {};
    const marker = await sendEncryptedFile({ uri: PICKED, name: NAME, mime: 'application/pdf', upload: islandUpload(seen) });

    expect(seen.uri).toMatch(/^file:\/\/\/cache\/ws_up_[0-9a-f]{16}\.blob$/);
    expect(seen.bytes.subarray(0, 4).toString('latin1')).toBe('WSF3');
    expect(seen.bytes.length).toBe(FC.sealedLength(CONTENT.length));
    expect(seen.bytes.includes(LINE.subarray(0, 16))).toBe(false);
    // The plaintext copy made for reading is gone before the upload begins.
    expect(seen.cacheDuring).toEqual([mockNorm(seen.uri)]);

    const info = parseFileMarker(marker);
    expect(info).toMatchObject({ v: 3, token: 'tok1', filename: NAME, mime: 'application/pdf', sizeBytes: CONTENT.length });
    expect(seen.bytes.includes(Buffer.from(info.key))).toBe(false);
  });

  test('nothing is left in the cache afterwards', async () => {
    await sendEncryptedFile({ uri: PICKED, name: NAME, upload: islandUpload() });
    expect(cached()).toEqual([]);
    expect(mockFs.files.get(PICKED).equals(CONTENT)).toBe(true);   // the user's own file is untouched
  });

  test('nor when the upload fails', async () => {
    const upload = async () => { throw new Error('Request timed out'); };
    await expect(sendEncryptedFile({ uri: PICKED, name: NAME, upload })).rejects.toThrow('timed out');
    expect(cached()).toEqual([]);
  });

  test('an upload that returns no token is a failure, not a file', async () => {
    await expect(sendEncryptedFile({ uri: PICKED, name: NAME, upload: async () => ({}) })).rejects.toThrow('no token');
    expect(cached()).toEqual([]);
  });

  test('a file over the limit is refused before anything is encrypted or sent', async () => {
    mockFs.statSize = MAX_FILE_BYTES + 1;
    const upload = jest.fn();
    await expect(sendEncryptedFile({ uri: PICKED, name: NAME, upload })).rejects.toThrow('too large');
    expect(upload).not.toHaveBeenCalled();
    expect(cached()).toEqual([]);
  });

  test('a file that cannot be read is an error, not an empty upload', async () => {
    const upload = jest.fn();
    await expect(sendEncryptedFile({ uri: 'content://gone/1', name: NAME, upload })).rejects.toThrow();
    expect(upload).not.toHaveBeenCalled();
    expect(cached()).toEqual([]);
  });

  test('a photo from the camera (a file:// uri) goes the same way', async () => {
    mockFs.files.set('/cache/rn_image_picker_lib_temp_1.jpg', CONTENT);
    const seen = {};
    const marker = await sendEncryptedFile({
      uri: 'file:///cache/rn_image_picker_lib_temp_1.jpg', name: 'photo_1.jpg', mime: 'image/jpeg', upload: islandUpload(seen),
    });
    expect(seen.bytes.subarray(0, 4).toString('latin1')).toBe('WSF3');
    expect(parseFileMarker(marker)).toMatchObject({ filename: 'photo_1.jpg', mime: 'image/jpeg', sizeBytes: CONTENT.length });
  });
});

describe('fetching a file', () => {
  async function sent(content = CONTENT, name = NAME) {
    mockFs.files.set(PICKED, content);
    const marker = await sendEncryptedFile({ uri: PICKED, name, upload: islandUpload() });
    return parseFileMarker(marker);
  }

  test('what was sent comes back, and the cache is clean', async () => {
    const info = await sent();
    await fetchFileTo(info, '/downloads/out.pdf');
    expect(mockFs.files.get('/downloads/out.pdf').equals(CONTENT)).toBe(true);
    expect(cached()).toEqual([]);
    expect(mockFs.downloads).toEqual([{ fromUrl: 'https://island.test/files/tok1', headers: { Authorization: 'Bearer tok' } }]);
  });

  test.each([
    ['an empty file', Buffer.alloc(0)],
    ['one byte', Buffer.from([7])],
    ['several chunks, read a little at a time', nodeCrypto.randomBytes(2 * 1024 * 1024 + 7)],
  ])('%s', async (_what, content) => {
    const info = await sent(content, 'x.bin');
    expect(info.sizeBytes).toBe(content.length);
    await fetchFileTo(info, '/downloads/x.bin');
    expect(mockFs.files.get('/downloads/x.bin').equals(content)).toBe(true);
    expect(cached()).toEqual([]);
  });

  test('a blob the island altered leaves nothing where the file should be', async () => {
    const info = await sent();
    const tampered = Buffer.from(mockFs.island.get('tok1'));
    tampered[2000] ^= 1;
    mockFs.island.set('tok1', tampered);
    await expect(fetchFileTo(info, '/downloads/out.pdf')).rejects.toThrow('damaged or was altered');
    expect(mockFs.files.has('/downloads/out.pdf')).toBe(false);
    expect(cached()).toEqual([]);
  });

  test('nor one it cut short, or the readable file in its place', async () => {
    const info = await sent();
    const whole = mockFs.island.get('tok1');
    mockFs.island.set('tok1', whole.subarray(0, whole.length - 300));
    await expect(fetchFileTo(info, '/downloads/out.pdf')).rejects.toThrow('not the one that was sent');
    mockFs.island.set('tok1', CONTENT);
    await expect(fetchFileTo(info, '/downloads/out.pdf')).rejects.toThrow();
    expect(mockFs.files.has('/downloads/out.pdf')).toBe(false);
    expect(cached()).toEqual([]);
  });

  test('the island saying no is an error, and its answer is not saved as the file', async () => {
    const info = await sent();
    mockFs.island.clear();
    await expect(fetchFileTo(info, '/downloads/out.pdf')).rejects.toMatchObject({ status: 404 });
    expect(mockFs.files.has('/downloads/out.pdf')).toBe(false);
    expect(cached()).toEqual([]);
  });

  test('a file sent before files were encrypted is fetched as it is', async () => {
    mockFs.island.set('old1', CONTENT);
    const legacy = 'FILE2::' + Buffer.from(JSON.stringify({ v: 2, t: 'old1', n: NAME, s: CONTENT.length, ts: 1 })).toString('base64url');
    const info = parseFileMarker(legacy);
    expect(info).toMatchObject({ v: 2, key: null, filename: NAME });
    await fetchFileTo(info, '/downloads/old.pdf');
    expect(mockFs.files.get('/downloads/old.pdf').equals(CONTENT)).toBe(true);
    expect(cached()).toEqual([]);
  });

  test('what the extension sent opens here, and the other way round', async () => {
    // The same module on both sides; the proof that the two halves around it
    // agree is a blob made without FileTransferService opening through it.
    const parts = [];
    const sealed = await FC.seal({
      read: async (o, l) => new Uint8Array(CONTENT.subarray(o, o + l)),
      write: async (b) => { parts.push(Buffer.from(b)); },
      crypto: globalThis.crypto,
    });
    mockFs.island.set('ext1', Buffer.concat(parts));
    const info = parseFileMarker(FC.makeMarker({ token: 'ext1', key: sealed.key, name: NAME, mime: '', size: sealed.size }));
    await fetchFileTo(info, '/downloads/from-extension.pdf');
    expect(mockFs.files.get('/downloads/from-extension.pdf').equals(CONTENT)).toBe(true);
  });
});
