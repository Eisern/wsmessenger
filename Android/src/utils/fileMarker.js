// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * fileMarker.js — FILE2:: marker encoding/decoding
 *
 * Format: FILE2::<base64url(JSON{v:2, t:token, n:filename, s:sizeBytes, ts:Date.now()})>
 * Matches the Chrome Extension's panel.js makeFileMarker / parseFileMarker.
 */

/**
 * Sanitize filename: strip path separators, traversal sequences, null bytes, and
 * other dangerous characters. Returns basename only (no directory components).
 */
function _sanitizeFilename(name) {
  let s = String(name || 'file')
    .replace(/\0/g, '')               // null bytes
    .replace(/\.\./g, '_')            // traversal sequences
    .replace(/[\/\\]/g, '_')          // path separators
    .replace(/[:*?"<>|]/g, '_')       // Windows-invalid chars
    .replace(/\n/g, ' ')
    .trim()
    .slice(0, 220);
  return s || 'file';
}

/**
 * Create a FILE2:: marker string from upload response data.
 * @param {string} token  File download token from server
 * @param {string} filename  Original filename
 * @param {number|null} sizeBytes  File size in bytes (or null)
 * @returns {string}
 */
export function makeFileMarker(token, filename, sizeBytes) {
  const safeName = _sanitizeFilename(filename);
  const safeSize = Number.isFinite(sizeBytes) ? Number(sizeBytes) : null;
  const payload = {
    v: 2,
    t: String(token || '').trim(),
    n: safeName || 'file',
    s: (safeSize != null && safeSize >= 0) ? safeSize : null,
    ts: Date.now(),
  };
  const json = JSON.stringify(payload);
  // base64url encode
  const b64 = btoa(json).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `FILE2::${b64}`;
}

/**
 * Parse a FILE2:: marker string back to {token, filename, sizeBytes} or null.
 * @param {string} text
 * @returns {{token: string, filename: string, sizeBytes: number|null}|null}
 */
export function parseFileMarker(text) {
  if (typeof text !== 'string') return null;
  if (!text.startsWith('FILE2::')) return null;

  const b64url = String(text.slice('FILE2::'.length) || '').trim();
  if (!b64url) return null;

  try {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    b64 += '='.repeat((4 - (b64.length % 4)) % 4);
    const raw = atob(b64);
    const p = JSON.parse(raw);

    if (Number(p?.v) !== 2) return null;
    const token = String(p?.t || '').trim();
    const filename = _sanitizeFilename(p?.n);
    const sizeNum = (p?.s == null) ? null : Number(p.s);
    const sizeBytes = Number.isFinite(sizeNum) && sizeNum >= 0 ? sizeNum : null;

    if (!token || token.length > 256 || /[^A-Za-z0-9_\-]/.test(token)) return null;

    return { token, filename: filename || 'file', sizeBytes };
  } catch (_e) {
    return null;
  }
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
