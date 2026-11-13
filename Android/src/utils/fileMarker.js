// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * fileMarker.js — how a file shows up in a conversation.
 *
 * The marker format is services/file-crypt.js, shared with the extension byte
 * for byte: FILE3 (an encrypted file - the marker holds its key, name, type
 * and size) and FILE2 (a file sent before files were encrypted). Markers are
 * written by FileTransferService.sendEncryptedFile; this file only reads them.
 */

import FC from '../services/file-crypt';

/**
 * @param {string} text  a decrypted message
 * @returns {null | {v:number, token:string, key:Uint8Array|null, filename:string,
 *   mime:string, sizeBytes:number|null}}  `key` null: sent unencrypted (FILE2)
 */
export function parseFileMarker(text) {
  return FC.parseMarker(text);
}

/**
 * Returns true if the filename has an image extension that can be rendered inline.
 */
export function isImageFile(filename) {
  return /\.(jpg|jpeg|png|webp|gif)$/i.test(filename || '');
}

/**
 * Format file size for display.
 */
export function formatFileSize(bytes) {
  if (bytes == null || !Number.isFinite(bytes)) return '';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
