// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Sending and fetching a file, in the extension (chrome_extension/panel.js
 * uploadEncryptedFile + downloadFile, over file-crypt.js and the real
 * panel-crypto.js).
 *
 * The extension used to post the file itself - bytes, name and type - and, in
 * a room, to announce it with a marker sent as plain text. What is held here
 * is what the island is handed now: one opaque blob called "blob", and an
 * encrypted message. The island is a fetch stub that keeps everything it was
 * given, so "it never saw the name" is checked against all of it.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { makePanel, unlockRealManager, PASS } = require('./integration/helpers/panelHarness');
const FC = require('../file-crypt');

const EXT = path.join(__dirname, '..', '..', '..', '..', 'chrome_extension');
const source = (f) => fs.readFileSync(path.join(EXT, f), 'utf8').split('\r\n').join('\n');
function block(src, head, close = '}') {
  const start = src.indexOf(head);
  if (start < 0) throw new Error(`${head} not found`);
  const end = src.indexOf('\n' + close + '\n', start);
  return src.slice(start, end + close.length + 2);
}

const ROOM = 42;
const THREAD = 77;
const NAME = 'квартальный отчёт.pdf';
const LINE = Buffer.from('the quarterly figures, as they are: 4 815 162 342\n');
const CONTENT = Buffer.concat(Array(300).fill(LINE));   // ~15 KB, recognisable anywhere

async function setUp() {
  const P = makePanel({ apiBase: 'http://island.test', islandId: 'island.test', username: 'alice', token: 'tok' });
  await unlockRealManager(P.sandbox, { username: 'alice', password: PASS });
  const s = P.sandbox;
  const CU = P.CU;

  // The island: keeps every request it was sent, and every blob.
  const island = { requests: [], files: new Map(), refuse: null, n: 0 };
  s.fetch = async (url, opts = {}) => {
    const u = String(url);
    const req = { url: u, method: opts.method || 'GET', headers: opts.headers || {}, parts: [] };
    island.requests.push(req);
    const upload = /\/(rooms|dm)\/\d+\/files$/.test(u) && req.method === 'POST';
    if (upload) {
      for (const [field, value] of opts.body.entries()) {
        req.parts.push({
          field, name: value.name, type: value.type,
          bytes: Buffer.from(await value.arrayBuffer()),
        });
      }
      if (island.refuse) {
        return { ok: false, status: island.refuse.status, json: async () => ({ detail: island.refuse.detail }) };
      }
      const token = `tok${++island.n}`;
      island.files.set(token, req.parts[0].bytes);
      return { ok: true, status: 201, json: async () => ({ token, filename: 'blob', size_bytes: req.parts[0].bytes.length }) };
    }
    const m = u.match(/\/files\/([^/]+)$/);
    if (m) {
      const bytes = island.files.get(m[1]);
      if (!bytes) return { ok: false, status: 404, json: async () => ({ detail: 'File not found' }) };
      return { ok: true, status: 200, blob: async () => new Blob([bytes]) };
    }
    return { ok: true, status: 200, json: async () => ({}) };
  };

  // What the browser would do with a finished download.
  const saved = [];
  const U = class extends URL {};
  U.createObjectURL = (b) => { saved.push({ blob: b }); return `blob:test/${saved.length}`; };
  U.revokeObjectURL = () => {};
  s.URL = U;
  s.Blob = Blob;
  s.FormData = FormData;
  s.setTimeout = () => 0;
  s.document.body = { appendChild() {} };
  s.document.createElement = () => ({
    click() { saved[saved.length - 1].as = this.download; },
    remove() {},
  });
  const alerts = [];
  s.__ui.alert = async (m) => { alerts.push(String(m)); };

  // Keys for one room and one conversation.
  await P.manager.loadRoomKey(ROOM, await CU.exportRoomKey(await CU.generateRoomKey(true)));
  s.ensureDmKeyReady = async () => {};
  s._foreignForThread = async () => null;
  const dmRid = vm.runInContext(`dmRid(${THREAD})`, s);
  await P.manager.loadRoomKey(dmRid, await CU.exportRoomKey(await CU.generateRoomKey(true)));

  // The code under test, from panel.js itself.
  const panel = source('panel.js');
  vm.runInContext(fs.readFileSync(path.join(EXT, 'file-crypt.js'), 'utf8'), s, { filename: 'file-crypt.js' });
  vm.runInContext([
    'var __markDmSeen = () => {};',
    panel.match(/^const MAX_UPLOAD_BYTES = .*;$/m)[0],
    block(panel, 'async function uploadEncryptedFile(f, dest) {'),
    block(panel, 'function parseFileMarker(text) {'),
    block(panel, 'async function downloadFile(file) {'),
  ].join('\n'), s, { filename: 'panel.js#files' });

  s.__a = null;
  const call = (expr, ...args) => { s.__a = args; return vm.runInContext(expr, s); };
  return {
    P, s, island, saved, alerts,
    send: (file, dest) => call('uploadEncryptedFile(__a[0], __a[1])', file, dest),
    fetchFile: (info) => call('downloadFile(__a[0])', info),
    parse: (text) => call('parseFileMarker(__a[0])', text),
    openRoom: (text) => call(`decryptMessageFromRoom(${ROOM}, __a[0], 'alice')`, text),
    openDm: (text) => call(`decryptDm(${THREAD}, __a[0], 'bob', __a[1])`, text, Date.now()),
    uploads: () => island.requests.filter((r) => r.parts.length),
    // What the panel asked the worker to send into a conversation (it posts
    // other things too - its own housekeeping).
    posts: () => P.posted.filter((m) => m.type === 'send' || m.type === 'dm_send'),
  };
}

const theFile = () => new File([CONTENT], NAME, { type: 'application/pdf' });
/** Everything the island was told, as one buffer to search. */
function everythingSent(T) {
  return Buffer.concat(T.island.requests.map((r) => Buffer.concat([
    Buffer.from(r.url + JSON.stringify(r.headers)),
    ...r.parts.flatMap((p) => [Buffer.from(`${p.field}|${p.name}|${p.type}`), p.bytes]),
  ])));
}

describe('what the island is handed when a file is sent', () => {
  test('to a room: one opaque blob, and nothing that says what it is', async () => {
    const T = await setUp();
    await T.send(theFile(), { roomId: ROOM });

    const ups = T.uploads();
    expect(ups).toHaveLength(1);
    expect(ups[0].url).toBe(`http://island.test/rooms/${ROOM}/files`);
    expect(ups[0].parts).toHaveLength(1);
    const part = ups[0].parts[0];
    expect(part).toMatchObject({ field: 'file', name: 'blob', type: 'application/octet-stream' });
    expect(part.bytes.subarray(0, 4).toString('latin1')).toBe('WSF3');
    expect(part.bytes.length).toBe(FC.sealedLength(CONTENT.length));

    const sent = everythingSent(T);
    expect(sent.includes(LINE.subarray(0, 16))).toBe(false);          // none of the file
    expect(sent.includes(Buffer.from('отчёт'))).toBe(false);          // none of its name
    expect(sent.includes(Buffer.from('.pdf'))).toBe(false);
    expect(sent.includes(Buffer.from('application/pdf'))).toBe(false);
  });

  test('to a room: the marker goes out encrypted, and opens to the file\'s name and key', async () => {
    const T = await setUp();
    await T.send(theFile(), { roomId: ROOM });

    expect(T.posts()).toHaveLength(1);
    const post = T.posts()[0];
    expect(post).toMatchObject({ type: 'send', room_id: ROOM });
    // It used to be the marker itself, in the clear.
    expect(post.text).not.toContain('FILE');
    expect(post.text).not.toContain('tok1');
    expect(JSON.parse(post.text)).toMatchObject({ encrypted: true });

    const opened = await T.openRoom(post.text);
    expect(opened).toMatchObject({ from: 'alice', sigValid: true });
    const info = T.parse(opened.text);
    expect(info).toMatchObject({ v: 3, token: 'tok1', filename: NAME, mime: 'application/pdf', sizeBytes: CONTENT.length });
    expect(info.key).toHaveLength(32);
    // The key is in the message and nowhere the island can read.
    expect(everythingSent(T).includes(Buffer.from(info.key))).toBe(false);
    expect(post.text).not.toContain(Buffer.from(info.key).toString('base64url'));
  });

  test('to a conversation: the same, through the sealed direct message', async () => {
    const T = await setUp();
    await T.send(theFile(), { threadId: THREAD, peer: 'bob' });

    expect(T.uploads()[0].url).toBe(`http://island.test/dm/${THREAD}/files`);
    expect(T.uploads()[0].parts[0]).toMatchObject({ name: 'blob', type: 'application/octet-stream' });
    expect(everythingSent(T).includes(Buffer.from('отчёт'))).toBe(false);

    expect(T.posts()).toHaveLength(1);
    const post = T.posts()[0];
    expect(post).toMatchObject({ type: 'dm_send', thread_id: THREAD });
    expect(post.text).not.toContain('FILE');
    const opened = await T.openDm(post.text);
    expect(T.parse(opened.text)).toMatchObject({ v: 3, token: 'tok1', filename: NAME, sizeBytes: CONTENT.length });
  });

  test('a file goes where it was picked for, whatever is on screen by the time it is up', async () => {
    const T = await setUp();
    // The panel's idea of "the active room" plays no part: only `dest` does.
    vm.runInContext('var activeRoomId = 999, activeDmThreadId = 998, dmMode = true;', T.s);
    await T.send(theFile(), { roomId: ROOM });
    expect(T.uploads()[0].url).toContain(`/rooms/${ROOM}/files`);
    expect(T.posts()[0]).toMatchObject({ type: 'send', room_id: ROOM });
  });

  test('a file the island refuses announces nothing', async () => {
    const T = await setUp();
    T.island.refuse = { status: 413, detail: 'File too large (max 100MB)' };
    await expect(T.send(theFile(), { roomId: ROOM })).rejects.toThrow('File too large');
    expect(T.posts()).toHaveLength(0);
  });

  test('a file over the limit is not read, encrypted or uploaded', async () => {
    const T = await setUp();
    const huge = { size: 100 * 1024 * 1024 + 1, name: 'x.bin', type: '', slice() { throw new Error('read'); } };
    await T.send(huge, { roomId: ROOM });
    expect(T.alerts.join(' ')).toMatch(/too big/i);
    expect(T.island.requests).toHaveLength(0);
    expect(T.posts()).toHaveLength(0);
  });

  test('an empty file and one of several chunks both make the trip', async () => {
    const T = await setUp();
    const big = Buffer.alloc(2 * 1024 * 1024 + 7, 0x61);
    for (const [content, name] of [[Buffer.alloc(0), 'empty.txt'], [big, 'big.bin']]) {
      T.saved.length = 0;
      await T.send(new File([content], name), { roomId: ROOM });
      const info = T.parse((await T.openRoom(T.posts().pop().text)).text);
      await T.fetchFile(info);
      expect(Buffer.from(await T.saved[0].blob.arrayBuffer()).equals(content)).toBe(true);
      expect(T.saved[0].as).toBe(name);
    }
  });
});

describe('fetching a file', () => {
  async function sent() {
    const T = await setUp();
    await T.send(theFile(), { roomId: ROOM });
    const info = T.parse((await T.openRoom(T.posts()[0].text)).text);
    return { T, info };
  }

  test('what was sent comes back, under its own name', async () => {
    const { T, info } = await sent();
    await T.fetchFile(info);
    expect(T.saved).toHaveLength(1);
    expect(Buffer.from(await T.saved[0].blob.arrayBuffer()).equals(CONTENT)).toBe(true);
    expect(T.saved[0].as).toBe(NAME);
    // The island was asked for a token, with the session, and nothing more.
    const get = T.island.requests[T.island.requests.length - 1];
    expect(get.url).toBe('http://island.test/files/tok1');
    expect(get.headers).toEqual({ Authorization: 'Bearer tok' });
  });

  test('a blob the island altered saves nothing', async () => {
    const { T, info } = await sent();
    const tampered = Buffer.from(T.island.files.get('tok1'));
    tampered[2000] ^= 1;
    T.island.files.set('tok1', tampered);
    await expect(T.fetchFile(info)).rejects.toThrow('damaged or was altered');
    expect(T.saved).toHaveLength(0);
  });

  test('a blob the island cut short, or swapped for another file, saves nothing', async () => {
    const { T, info } = await sent();
    const whole = T.island.files.get('tok1');

    T.island.files.set('tok1', whole.subarray(0, whole.length - 300));
    await expect(T.fetchFile(info)).rejects.toThrow('not the one that was sent');

    // Another file of the same size class, encrypted by the same person.
    await T.send(new File([Buffer.alloc(CONTENT.length, 0x62)], 'other.bin'), { roomId: ROOM });
    T.island.files.set('tok1', T.island.files.get('tok2'));
    await expect(T.fetchFile(info)).rejects.toThrow('damaged or was altered');

    // The original file, readable, where the encrypted one should be.
    T.island.files.set('tok1', CONTENT);
    await expect(T.fetchFile(info)).rejects.toThrow();
    expect(T.saved).toHaveLength(0);
  });

  test('a file sent before files were encrypted is still fetched, as it is', async () => {
    const T = await setUp();
    T.island.files.set('old1', CONTENT);
    const legacy = 'FILE2::' + Buffer.from(JSON.stringify({ v: 2, t: 'old1', n: NAME, s: CONTENT.length, ts: 1 })).toString('base64url');
    const info = T.parse(legacy);
    expect(info).toMatchObject({ v: 2, token: 'old1', key: null, filename: NAME });
    await T.fetchFile(info);
    expect(Buffer.from(await T.saved[0].blob.arrayBuffer()).equals(CONTENT)).toBe(true);
    expect(T.saved[0].as).toBe(NAME);
  });

  test('the island\'s refusal is reported as the island put it', async () => {
    const { T, info } = await sent();
    T.island.files.clear();
    await expect(T.fetchFile(info)).rejects.toThrow('File not found');
    expect(T.saved).toHaveLength(0);
  });
});

describe('around the transfer: where a file goes, and what of it can be copied', () => {
  test('a file picked for one conversation goes there, whatever is open by the time it is chosen', async () => {
    const T = await setUp();
    // The file dialog: opened by click(), answered later through onchange.
    const inp = { value: '', files: [theFile()], click() {} };
    T.s.__inp = inp;
    vm.runInContext([
      `var dmMode = false, activeRoomId = ${ROOM}, activeDmThreadId = null, activeDmPeer = '';`,
      'var __syncCryptoUiLockFromRuntime = () => false, isReadOnlyRoomForMember = () => false;',
      'var ensureFileInput = () => __inp;',
      block(source('panel.js'), 'async function pickAndUploadFile() {'),
    ].join('\n'), T.s, { filename: 'panel.js#pick' });

    await vm.runInContext('pickAndUploadFile()', T.s);
    // The dialog is still open, and the user has wandered into a direct
    // conversation. The file - and its key - must not follow them there.
    vm.runInContext(`dmMode = true; activeRoomId = 999; activeDmThreadId = ${THREAD}; activeDmPeer = 'bob';`, T.s);
    await inp.onchange();

    expect(T.alerts).toEqual([]);
    expect(T.uploads()).toHaveLength(1);
    expect(T.uploads()[0].url).toBe(`http://island.test/rooms/${ROOM}/files`);
    expect(T.posts()).toHaveLength(1);
    expect(T.posts()[0]).toMatchObject({ type: 'send', room_id: ROOM });
  });

  test('right-clicking a file offers its name to quote or copy - never the marker, which holds the key', async () => {
    const T = await setUp();
    const shown = [];
    const menus = [];
    T.s.document.createElement = () => ({ style: {}, appendChild() {} });
    T.s.chat = { appendChild: (el) => { shown.push(el); }, scrollTop: 0, scrollHeight: 0 };
    T.s.__showMsgCtxMenu = (_e, user, text) => { menus.push({ user, text }); };
    const panel = source('panel.js');
    vm.runInContext([
      'var lastMsgAuthor = null, dmMode = false;',
      'var colorForUsername = () => "#000", openProfile = () => {}, humanSize = (n) => n + " B";',
      'var formatMsgTime = () => "", __appendTextWithLinks = (el, t) => { el.textContent = t; };',
      block(panel, 'function buildFileCard(file, me) {'),
      block(panel, 'function addMsg(user, text, me = false, ts = null, reply = null) {'),
    ].join('\n'), T.s, { filename: 'panel.js#addMsg' });

    const key = new Uint8Array(32).fill(7);
    const marker = FC.makeMarker({ token: 'tok9', key, name: NAME, mime: 'application/pdf', size: 5 });
    const rightClick = (el) => el.oncontextmenu({ preventDefault() {} });

    vm.runInContext('addMsg("bob", __a[0])', Object.assign(T.s, { __a: [marker] }));
    rightClick(shown[shown.length - 1]);
    expect(menus).toEqual([{ user: 'bob', text: NAME }]);
    expect(JSON.stringify(menus)).not.toContain('FILE3');
    expect(JSON.stringify(menus)).not.toContain(Buffer.from(key).toString('base64url'));

    // An ordinary message is still offered as it was written.
    vm.runInContext('addMsg("bob", __a[0])', Object.assign(T.s, { __a: ['see you at five'] }));
    rightClick(shown[shown.length - 1]);
    expect(menus[1]).toEqual({ user: 'bob', text: 'see you at five' });
  });
});

describe('the panel loads what it needs', () => {
  test('panel.html loads file-crypt.js before panel.js', () => {
    const html = source('panel.html');
    const at = (f) => html.indexOf(`<script src="${f}"></script>`);
    expect(at('file-crypt.js')).toBeGreaterThan(0);
    expect(at('file-crypt.js')).toBeLessThan(at('panel.js'));
  });

  test('nothing in the extension uploads a file any other way', () => {
    // The worker had a second upload path that posted the file as it was.
    expect(source('background.js')).not.toMatch(/file_upload|\/files`/);
    const uploads = source('panel.js').match(/\/files`\)/g) || [];
    expect(uploads).toHaveLength(2);   // the two URLs inside uploadEncryptedFile
    expect(source('panel.js')).not.toMatch(/form\.append\("file", f\b/);
  });
});
