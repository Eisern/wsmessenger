// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

/**
 * Client side of the relay envelope — prototype.
 *
 * Wire format (must stay byte-compatible with server/relay_ingress.py):
 *
 *   request  = 0x03 || kid(4) || eph_pub(32) || iv(12) || AES-GCM(ct||tag)
 *              AAD = 0x03 || kid || eph_pub
 *   response = 0x03 || iv(12) || AES-GCM(ct||tag)
 *              AAD = 0x03
 *
 *   shared   = X25519(eph_priv, island_transport_pub)
 *   key_req  = HKDF-SHA256(shared, salt=eph_pub, info="ws-relay-seal-v1:req")
 *   key_resp = HKDF-SHA256(shared, salt=eph_pub, info="ws-relay-seal-v1:resp")
 *
 * Request and response use DIFFERENT keys from the same exchange on purpose:
 * one key in both directions would reuse the AES-GCM IV space.
 *
 * This lives in the test helpers, not in the clients, because shipping it
 * means writing it twice (WebCrypto in the extension, @noble on Android) and
 * that must not happen before there are cross-client pinned vectors — see
 * docs/internal/message-relay-assessment.md §9.
 */

const crypto = require('crypto');
const { x25519 } = require('@noble/curves/ed25519');
const { hkdf } = require('@noble/hashes/hkdf');
const { sha256 } = require('@noble/hashes/sha2');

const VERSION = 0x03;
const INFO_REQ = Buffer.from('ws-relay-seal-v1:req', 'utf8');
const INFO_RESP = Buffer.from('ws-relay-seal-v1:resp', 'utf8');

function kidOf(islandPub) {
  return crypto.createHash('sha256').update(islandPub).digest().subarray(0, 4);
}

/**
 * @param {string} islandPubB64 island transport public key (32 bytes, base64)
 * @param {object} inner the ordinary /ud/dm/send body plus env_ts / env_nonce_b64
 * @returns {{ envelope: Buffer, keyResp: Buffer, envNonceB64: string }}
 */
function sealEnvelope(islandPubB64, inner) {
  const islandPub = Buffer.from(islandPubB64, 'base64');
  if (islandPub.length !== 32) throw new Error('island transport key must be 32 bytes');

  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = Buffer.from(x25519.getPublicKey(ephPriv));
  const shared = Buffer.from(x25519.getSharedSecret(ephPriv, islandPub));

  const keyReq = Buffer.from(hkdf(sha256, shared, ephPub, INFO_REQ, 32));
  const keyResp = Buffer.from(hkdf(sha256, shared, ephPub, INFO_RESP, 32));

  const header = Buffer.concat([Buffer.from([VERSION]), kidOf(islandPub), ephPub]);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyReq, iv);
  cipher.setAAD(header);
  const ct = Buffer.concat([cipher.update(JSON.stringify(inner), 'utf8'), cipher.final()]);

  return {
    envelope: Buffer.concat([header, iv, ct, cipher.getAuthTag()]),
    keyResp,
    envNonceB64: inner.env_nonce_b64,
  };
}

/** Open the island's sealed answer. A relay cannot fake one. */
function openResponse(keyResp, bytes) {
  const buf = Buffer.from(bytes);
  if (buf.length < 1 + 12 + 16 || buf[0] !== VERSION) throw new Error('bad sealed response');
  const iv = buf.subarray(1, 13);
  const body = buf.subarray(13);
  const ct = body.subarray(0, body.length - 16);
  const tag = body.subarray(body.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyResp, iv);
  decipher.setAAD(Buffer.from([VERSION]));
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
}

/** Everything a client must add to a /ud/dm/send body before sealing it. */
function envelopeFields() {
  return {
    env_ts: Date.now(),
    env_nonce_b64: crypto.randomBytes(16).toString('base64'),
  };
}

module.exports = { sealEnvelope, openResponse, envelopeFields, kidOf, VERSION };
