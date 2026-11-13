// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * FileTransferService.js — attachments, encrypted on the phone.
 *
 * A file used to be uploaded as it was: the island got its bytes, its name and
 * its type. Now it is encrypted here under a key made for that file alone, the
 * island is handed an opaque padded blob called "blob", and the key, the name
 * and the type travel only inside the encrypted message that announces the
 * file (the FILE3 marker).
 *
 * The format and the cipher are file-crypt.js, shared with the extension byte
 * for byte. This file supplies the Android half: where the bytes come from and
 * go to. Everything is done a chunk at a time through files in the app's own
 * cache, so a 50 MB file never has to fit in the JS heap.
 */

import NetworkService from './NetworkService';
import FC from './file-crypt';

// Lazy: react-native-quick-crypto is installed after module evaluation.
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

const fs = () => require('react-native-fs');

export const MAX_FILE_BYTES = 50 * 1024 * 1024;

function tmpPath(kind, ext) {
  let hex = '';
  for (const b of crypto.getRandomValues(new Uint8Array(8))) hex += b.toString(16).padStart(2, '0');
  return `${fs().CachesDirectoryPath}/ws_${kind}_${hex}.${ext}`;
}

async function drop(path) {
  try { await fs().unlink(path); } catch (_e) { /* was never written, or is already gone */ }
}

// RNFS.read rejects when asked to read at the end of a file, and may return
// fewer bytes than asked for. So it is never asked past the known size, and
// file-crypt.js keeps asking until it has what it wants.
function reader(path, size) {
  return async (offset, length) => {
    if (offset >= size) return new Uint8Array(0);
    return FC.b64ToBytes(await fs().read(path, Math.min(length, size - offset), offset, 'base64'));
  };
}

function appender(path) {
  return async (bytes) => { await fs().appendFile(path, FC.bytesToB64(bytes), 'base64'); };
}

/**
 * Encrypt a picked file, upload the blob, and return the marker to send.
 *
 * @param {object} p
 * @param {string} p.uri      content:// or file:// - a picked document, a photo
 * @param {string} p.name
 * @param {string} [p.mime]
 * @param {function} p.upload async (sealedFileUri) => { token } - one of
 *                            NetworkService.uploadFile / uploadDmFile
 * @returns {Promise<string>} the FILE3 marker. It holds the file's key: it is
 *   to be ENCRYPTED (CryptoService.encryptMessage / encryptDm) and sent as a
 *   message, never anything else.
 */
export async function sendEncryptedFile({ uri, name, mime, upload }) {
  const RNFS = fs();
  const plain = tmpPath('up', 'plain');
  const sealed = tmpPath('up', 'blob');
  try {
    // First a copy in the app's own cache: a picked document is a content://
    // stream that often cannot say how long it is, and its size has to be
    // known before the first read (see reader).
    await RNFS.copyFile(uri, plain);
    const size = Number((await RNFS.stat(plain)).size);
    if (!Number.isInteger(size) || size < 0) throw new Error('Could not read the file');
    if (size > MAX_FILE_BYTES) {
      throw new Error(`File too large (${Math.round(size / 1024 / 1024)}MB). Maximum: ${MAX_FILE_BYTES / 1024 / 1024}MB`);
    }

    const out = await FC.seal({ read: reader(plain, size), write: appender(sealed), crypto });
    if (out.size !== size) throw new Error('Could not read the whole file');
    await drop(plain);

    const res = await upload(`file://${sealed}`);
    if (!res?.token) throw new Error('Upload failed — no token');
    return FC.makeMarker({ token: String(res.token), key: out.key, name, mime, size });
  } finally {
    await drop(plain);
    await drop(sealed);
  }
}

/**
 * Fetch a file to destPath, decrypting an encrypted one.
 *
 * Nothing appears at destPath unless the whole file checked out: a blob the
 * island cut short, swapped or altered throws, and what was written so far is
 * deleted with the rest of the temporary files.
 *
 * @param {object} file      parseFileMarker's result; `key` null means a file
 *                           sent before files were encrypted (the blob is it)
 * @param {string} destPath
 */
export async function fetchFileTo(file, destPath) {
  const RNFS = fs();
  const sealed = tmpPath('dl', 'blob');
  const plain = tmpPath('dl', 'plain');
  try {
    const res = await RNFS.downloadFile({
      fromUrl: NetworkService.getFileUrl(file.token),
      toFile: sealed,
      headers: NetworkService.getFileHeaders(),
    }).promise;
    if (res.statusCode !== 200) {
      const err = new Error(`Server returned status ${res.statusCode}`);
      err.status = res.statusCode;
      throw err;
    }
    if (!file.key) {
      await RNFS.moveFile(sealed, destPath);
      return;
    }

    const sealedSize = Number((await RNFS.stat(sealed)).size);
    await RNFS.writeFile(plain, '', 'utf8');   // an empty file is still a file
    await FC.open({
      key: file.key,
      size: file.sizeBytes,
      sealedSize,
      read: reader(sealed, sealedSize),
      write: appender(plain),
      crypto,
    });
    await RNFS.moveFile(plain, destPath);
  } finally {
    await drop(sealed);
    await drop(plain);
  }
}
