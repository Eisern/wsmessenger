// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// Attachments, end to end.
//
// A file used to go to the island as it was: its bytes, its name and its type,
// readable by whoever runs the server and sitting in every backup. Now the
// island is handed one opaque blob and nothing else:
//
//   - the file is encrypted with a key made for that file alone, which never
//     leaves the clients except inside an encrypted message;
//   - the name, the type and the true size travel in that message too (the
//     FILE3 marker), not in the upload;
//   - the blob is padded, so its length gives a size class, not a size.
//
// Blob:    "WSF3" ‖ nonce prefix(7) ‖ chunk ‖ chunk ‖ …
// Chunk:   AES-256-GCM over up to 1 MiB of plaintext, tag appended.
//          nonce = prefix(7) ‖ chunk index (uint32 BE) ‖ last(1)
//          AAD   = "ws-file-v3" ‖ the 11 header bytes
// Plain:   the file, then zeros up to paddedLength(size).
//
// The chunk index and the "last" flag are in the nonce, so chunks cannot be
// dropped, repeated, reordered or cut off the end without a tag failing; and
// the blob's length must be exactly what the marker's size predicts.
//
// Marker:  "FILE3::" ‖ base64url(JSON {v:3, t:token, k:key, n:name, m:type,
//          s:size, ts}) - the plaintext of an ordinary room or direct message.
//          It holds the key, so it must never be sent unencrypted.
//
// Both clients must produce and read exactly this, so it lives here once, with
// the cipher and the file access injected (as foreign-dm.js, guest-rooms.js).

(function (root) {
  "use strict";

  const FORMAT = {
    MARKER: "FILE3::",
    LEGACY_MARKER: "FILE2::",
    MAGIC: [0x57, 0x53, 0x46, 0x33],   // "WSF3"
    PREFIX_LEN: 7,
    HEADER_LEN: 11,
    CHUNK: 1024 * 1024,
    TAG_LEN: 16,
    KEY_LEN: 32,
    MIN_PADDED: 4096,
    AAD: "ws-file-v3",
    NAME_MAX: 220,
    MAX_SIZE: 1024 * 1024 * 1024 * 1024,
  };

  // ---- bytes and text, with nothing borrowed from the platform ----

  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const B64_CODES = new Uint8Array(64);
  const B64_VALUES = new Int8Array(128).fill(-1);
  for (let i = 0; i < 64; i++) {
    B64_CODES[i] = B64.charCodeAt(i);
    B64_VALUES[B64.charCodeAt(i)] = i;
  }
  B64_VALUES[45] = 62;   // "-"  the URL-safe alphabet reads the same
  B64_VALUES[95] = 63;   // "_"

  function codesToString(codes) {
    let s = "";
    for (let i = 0; i < codes.length; i += 8192) {
      s += String.fromCharCode.apply(null, codes.subarray(i, Math.min(codes.length, i + 8192)));
    }
    return s;
  }

  /** Standard base64 with padding - the form a file API takes and gives. */
  function bytesToB64(u8) {
    const n = u8.length;
    const out = new Uint8Array(Math.ceil(n / 3) * 4);
    let o = 0;
    let i = 0;
    for (; i + 2 < n; i += 3) {
      const x = (u8[i] << 16) | (u8[i + 1] << 8) | u8[i + 2];
      out[o++] = B64_CODES[x >> 18];
      out[o++] = B64_CODES[(x >> 12) & 63];
      out[o++] = B64_CODES[(x >> 6) & 63];
      out[o++] = B64_CODES[x & 63];
    }
    if (i < n) {
      const two = i + 1 < n;
      const x = (u8[i] << 16) | (two ? u8[i + 1] << 8 : 0);
      out[o++] = B64_CODES[x >> 18];
      out[o++] = B64_CODES[(x >> 12) & 63];
      out[o++] = two ? B64_CODES[(x >> 6) & 63] : 61;
      out[o++] = 61;
    }
    return codesToString(out);
  }

  /** Either alphabet, padded or not; whitespace is skipped, anything else throws. */
  function b64ToBytes(text) {
    const s = String(text == null ? "" : text);
    const out = new Uint8Array(Math.floor((s.length * 3) / 4));
    let o = 0;
    let acc = 0;
    let bits = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 61 || c === 10 || c === 13 || c === 32 || c === 9) continue;
      const v = c < 128 ? B64_VALUES[c] : -1;
      if (v < 0) throw new Error("not base64");
      acc = ((acc << 6) | v) & 0xffff;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out[o++] = (acc >> bits) & 255;
      }
    }
    return o === out.length ? out : out.slice(0, o);
  }

  function bytesToB64Url(u8) {
    return bytesToB64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/[=]+$/, "");
  }

  function utf8Decode(u8) {
    let s = "";
    for (let i = 0; i < u8.length;) {
      const b = u8[i++];
      let cp = b;
      let more = 0;
      if (b >= 0xf0) { cp = b & 7; more = 3; }
      else if (b >= 0xe0) { cp = b & 15; more = 2; }
      else if (b >= 0xc0) { cp = b & 31; more = 1; }
      else if (b >= 0x80) { cp = 0xfffd; }
      for (; more > 0; more--) {
        const next = i < u8.length ? u8[i] : 0;
        if ((next & 0xc0) !== 0x80) { cp = 0xfffd; break; }
        cp = (cp << 6) | (next & 63);
        i++;
      }
      if (cp > 0x10ffff) cp = 0xfffd;
      if (cp >= 0x10000) {
        cp -= 0x10000;
        s += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
      } else {
        s += String.fromCharCode(cp);
      }
    }
    return s;
  }

  function asciiBytes(s) {
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 127;
    return out;
  }

  // ---- what a file is called ----

  /**
   * A name fit to show and to save under. It is written by whoever sent the
   * file, so it is treated as theirs: no path, no traversal, no control
   * characters, and none of the direction overrides (U+202E and its kin) that
   * make a name ending in "gnp.exe" read as one ending in "exe.png".
   */
  function sanitizeName(name) {
    const raw = String(name == null ? "" : name);
    let shown = "";
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      const hidden = c < 0x20 || c === 0x7f || c === 0x200e || c === 0x200f ||
        (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
      shown += hidden ? " " : raw[i];
    }
    const s = shown
      .replace(/\.\./g, "_")
      .replace(/[/\\:*?"<>|]/g, "_")
      .trim()
      .slice(0, FORMAT.NAME_MAX)
      .trim();
    return s || "file";
  }

  function sanitizeMime(mime) {
    const s = String(mime == null ? "" : mime).trim().toLowerCase();
    return /^[a-z0-9][a-z0-9.+-]{0,60}\/[a-z0-9][a-z0-9.+-]{0,60}$/.test(s) ? s : "";
  }

  function validToken(token) {
    return typeof token === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(token);
  }

  function validSize(n) {
    return typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= FORMAT.MAX_SIZE;
  }

  // ---- how long things are ----

  function bitLength(n) {
    let bits = 0;
    for (let x = n; x >= 1; x = Math.floor(x / 2)) bits++;
    return bits;
  }

  /**
   * The length a file of `size` bytes is padded to before encryption (Padme:
   * at most ~12% over, and the length says only which size class a file is
   * in). Nothing is shorter than MIN_PADDED - a note of forty bytes and one of
   * four hundred look the same.
   */
  function paddedLength(size) {
    const len = Math.max(size, FORMAT.MIN_PADDED);
    const e = bitLength(len) - 1;          // floor(log2(len))
    const s = bitLength(e);                // floor(log2(e)) + 1
    const unit = Math.pow(2, e - s);
    return Math.ceil(len / unit) * unit;
  }

  /** The exact length of the blob a file of `size` bytes becomes. */
  function sealedLength(size) {
    const padded = paddedLength(size);
    return FORMAT.HEADER_LEN + padded + FORMAT.TAG_LEN * Math.ceil(padded / FORMAT.CHUNK);
  }

  // ---- the marker ----

  /**
   * @param {object} f
   * @param {string} f.token       what the island called the blob
   * @param {Uint8Array} f.key     the file's key
   * @param {string} f.name
   * @param {string} [f.mime]
   * @param {number} f.size        of the file itself, in bytes
   * @returns {string}  to be ENCRYPTED and sent as a message - it holds the key
   */
  function makeMarker(f) {
    if (!validToken(f && f.token)) throw new Error("Bad file token");
    if (!(f.key instanceof Uint8Array) || f.key.length !== FORMAT.KEY_LEN) throw new Error("Bad file key");
    if (!validSize(f.size)) throw new Error("Bad file size");
    const payload = {
      v: 3,
      t: f.token,
      k: bytesToB64Url(f.key),
      n: sanitizeName(f.name),
      m: sanitizeMime(f.mime),
      s: f.size,
      ts: Date.now(),
    };
    // Escaped down to ASCII, so reading it back needs no text codec at all.
    const raw = JSON.stringify(payload);
    let json = "";
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      json += c < 128 ? raw[i] : "\\u" + ("000" + c.toString(16)).slice(-4);
    }
    return FORMAT.MARKER + bytesToB64Url(asciiBytes(json));
  }

  /**
   * @returns {null | {v:3, token:string, key:Uint8Array, filename:string, mime:string, sizeBytes:number}
   *                | {v:2, token:string, key:null, filename:string, mime:"", sizeBytes:number|null}}
   *   v 2 is a file sent before files were encrypted: the blob is the file.
   */
  function parseMarker(text) {
    if (typeof text !== "string") return null;
    const v3 = text.startsWith(FORMAT.MARKER);
    if (!v3 && !text.startsWith(FORMAT.LEGACY_MARKER)) return null;
    const body = text.slice(v3 ? FORMAT.MARKER.length : FORMAT.LEGACY_MARKER.length).trim();
    if (!body) return null;

    let p;
    try {
      p = JSON.parse(utf8Decode(b64ToBytes(body)));
    } catch (_e) {
      return null;
    }
    if (!p || typeof p !== "object") return null;

    const token = String(p.t == null ? "" : p.t).trim();
    if (!validToken(token)) return null;
    const filename = sanitizeName(p.n);

    if (!v3) {
      if (Number(p.v) !== 2) return null;
      const n = p.s == null ? null : Number(p.s);
      return {
        v: 2, token: token, key: null, filename: filename, mime: "",
        sizeBytes: (n != null && Number.isFinite(n) && n >= 0) ? n : null,
      };
    }

    if (p.v !== 3 || !validSize(p.s) || typeof p.k !== "string") return null;
    let key;
    try {
      key = b64ToBytes(p.k);
    } catch (_e) {
      return null;
    }
    if (key.length !== FORMAT.KEY_LEN) return null;
    return { v: 3, token: token, key: key, filename: filename, mime: sanitizeMime(p.m), sizeBytes: p.s };
  }

  // ---- the blob ----

  function nonceFor(header, index, last) {
    const nonce = new Uint8Array(12);
    nonce.set(header.subarray(FORMAT.MAGIC.length, FORMAT.HEADER_LEN), 0);
    nonce[7] = (index >>> 24) & 255;
    nonce[8] = (index >>> 16) & 255;
    nonce[9] = (index >>> 8) & 255;
    nonce[10] = index & 255;
    nonce[11] = last ? 1 : 0;
    return nonce;
  }

  function aadFor(header) {
    const domain = asciiBytes(FORMAT.AAD);
    const aad = new Uint8Array(domain.length + header.length);
    aad.set(domain, 0);
    aad.set(header, domain.length);
    return aad;
  }

  function importKey(C, key, usage) {
    return C.subtle.importKey("raw", key, { name: "AES-GCM", length: 256 }, false, [usage]);
  }

  /** Up to `want` bytes from `offset`; fewer only when the source has ended. */
  async function readFull(read, offset, want) {
    let buf = null;
    let have = 0;
    while (have < want) {
      const got = await read(offset + have, want - have);
      const piece = got instanceof Uint8Array ? got : new Uint8Array(got || 0);
      if (!piece.length) break;
      if (piece.length > want - have) throw new Error("File source returned more than was asked for");
      if (have === 0 && piece.length === want) return piece;
      if (!buf) buf = new Uint8Array(want);
      buf.set(piece, have);
      have += piece.length;
    }
    if (!buf) return new Uint8Array(0);
    return have === want ? buf : buf.subarray(0, have);
  }

  /**
   * Encrypt a file into a blob, under a key made here for it alone.
   *
   * The size need not be known beforehand - some sources (a document picked
   * on a phone) cannot say. One full chunk is therefore held back at a time:
   * whether it is the last is known only when the read after it comes back
   * empty.
   *
   * @param {object} d
   * @param {function} d.read    async (offset, length) => Uint8Array - up to
   *                             `length` bytes at `offset`; none means the end
   * @param {function} d.write   async (Uint8Array) => void - the blob, in order
   * @param {object}   d.crypto  { subtle, getRandomValues }
   * @param {number}   [d.maxSealedBytes]  give up (throwing .code "TOO_BIG")
   *                             once the blob would be longer than this
   * @param {function} [d.onProgress]  (bytes of the file done so far)
   * @returns {Promise<{key: Uint8Array, size: number, sealedSize: number}>}
   */
  async function seal(d) {
    const C = d.crypto;
    const CHUNK = FORMAT.CHUNK;
    const key = C.getRandomValues(new Uint8Array(FORMAT.KEY_LEN));
    const header = new Uint8Array(FORMAT.HEADER_LEN);
    header.set(FORMAT.MAGIC, 0);
    header.set(C.getRandomValues(new Uint8Array(FORMAT.PREFIX_LEN)), FORMAT.MAGIC.length);
    const aes = await importKey(C, key, "encrypt");
    const aad = aadFor(header);

    let index = 0;
    let sealedSize = header.length;
    async function emit(plain, last) {
      const sealed = new Uint8Array(await C.subtle.encrypt(
        { name: "AES-GCM", iv: nonceFor(header, index, last), additionalData: aad, tagLength: 128 },
        aes, plain,
      ));
      index += 1;
      sealedSize += sealed.length;
      await d.write(sealed);
    }

    await d.write(header);
    let size = 0;
    let held = null;
    let tail;
    for (;;) {
      const buf = await readFull(d.read, size, CHUNK);
      size += buf.length;
      if (d.maxSealedBytes && sealedLength(size) > d.maxSealedBytes) {
        const err = new Error("File is too big");
        err.code = "TOO_BIG";
        throw err;
      }
      if (buf.length < CHUNK) { tail = buf; break; }
      if (held) await emit(held, false);
      held = buf;
      if (d.onProgress) d.onProgress(size);
    }

    const padded = paddedLength(size);
    let done = index * CHUNK;
    if (held) {
      done += CHUNK;
      await emit(held, done === padded);
    }
    // What is left of the file, then zeros, in chunks, up to the padded length.
    while (done < padded) {
      const n = Math.min(CHUNK, padded - done);
      const piece = new Uint8Array(n);
      piece.set(tail, 0);
      tail = new Uint8Array(0);
      done += n;
      await emit(piece, done === padded);
    }
    if (d.onProgress) d.onProgress(size);
    return { key: key, size: size, sealedSize: sealedSize };
  }

  /**
   * Decrypt a blob back into the file.
   *
   * NOTHING WRITTEN IS TO BE TRUSTED UNTIL THIS RESOLVES. Every chunk is
   * authenticated before it is written, but that the blob is whole is known
   * only at the end - write to somewhere that can be thrown away, and throw it
   * away if this throws.
   *
   * @param {object} d
   * @param {Uint8Array} d.key
   * @param {number}   d.size        the file's own size, from the marker
   * @param {number}   d.sealedSize  the length of the blob that arrived
   * @param {function} d.read        async (offset, length) => Uint8Array
   * @param {function} d.write       async (Uint8Array) => void - the file, in order
   * @param {object}   d.crypto      { subtle }
   * @param {function} [d.onProgress]
   */
  async function open(d) {
    const C = d.crypto;
    const CHUNK = FORMAT.CHUNK;
    const TAG = FORMAT.TAG_LEN;
    if (!(d.key instanceof Uint8Array) || d.key.length !== FORMAT.KEY_LEN) throw new Error("Bad file key");
    if (!validSize(d.size)) throw new Error("Bad file size");
    // Before a byte is decrypted: a blob of any other length is not this file.
    if (d.sealedSize !== sealedLength(d.size)) {
      throw new Error("The file on the server is not the one that was sent");
    }

    const header = await readFull(d.read, 0, FORMAT.HEADER_LEN);
    if (header.length !== FORMAT.HEADER_LEN || FORMAT.MAGIC.some(function (b, i) { return header[i] !== b; })) {
      throw new Error("Not an encrypted file");
    }
    const aes = await importKey(C, d.key, "decrypt");
    const aad = aadFor(header);
    const padded = paddedLength(d.size);

    let offset = FORMAT.HEADER_LEN;
    let done = 0;
    let index = 0;
    while (done < padded) {
      const n = Math.min(CHUNK, padded - done);
      const sealed = await readFull(d.read, offset, n + TAG);
      if (sealed.length !== n + TAG) throw new Error("The file is cut short");
      let plain;
      try {
        plain = new Uint8Array(await C.subtle.decrypt(
          { name: "AES-GCM", iv: nonceFor(header, index, done + n === padded), additionalData: aad, tagLength: 128 },
          aes, sealed,
        ));
      } catch (_e) {
        throw new Error("The file is damaged or was altered");
      }
      if (plain.length !== n) throw new Error("The file is damaged or was altered");
      // Only the file goes out; the padding after it is checked and dropped.
      if (done < d.size) await d.write(plain.subarray(0, Math.min(n, d.size - done)));
      done += n;
      offset += n + TAG;
      index += 1;
      if (d.onProgress) d.onProgress(Math.min(done, d.size));
    }
  }

  const API = {
    FORMAT: FORMAT,
    paddedLength: paddedLength,
    sealedLength: sealedLength,
    sanitizeName: sanitizeName,
    makeMarker: makeMarker,
    parseMarker: parseMarker,
    seal: seal,
    open: open,
    bytesToB64: bytesToB64,
    b64ToBytes: b64ToBytes,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = API;
  else if (root) root.WSFileCrypt = API;
})(this);
