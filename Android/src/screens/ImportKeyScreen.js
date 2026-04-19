// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ImportKeyScreen.js — Import existing account from Chrome Extension via BIP39 recovery phrase.
 *
 * Flow:
 *   1. Login with username + password → get JWT
 *   2. Decode 24-word BIP39 phrase → raw private key bytes
 *   3. Derive expected public key from private key via x25519.getPublicKey()
 *   4. Fetch actual public key from server, compare — abort if mismatch
 *   5. Encrypt private key with password (PBKDF2 + AES-GCM) → EPK
 *   6. Save EPK to StorageService.setIdentity()
 *   7. Unlock CryptoService immediately (no extra password prompt needed after import)
 *   8. Dispatch SET_AUTH → navigate to AppTabs
 */

import React, { useState, useRef } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator,
  ScrollView, Alert,
} from 'react-native';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';
import { useApp } from '../contexts/AppContext';
import { CryptoUtils } from '../crypto';
import { Colors, Spacing, Radii, Typography } from '../theme';

const { x25519 } = require('@noble/curves/ed25519');

// Lazy proxy for Web Crypto
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

export default function ImportKeyScreen({ navigation }) {
  const { dispatch } = useApp();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [phrase, setPhrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // 2FA state
  const [show2fa, setShow2fa] = useState(false);
  const [tempToken, setTempToken] = useState('');
  const [code2fa, setCode2fa] = useState('');

  const passwordRef = useRef(null);
  const phraseRef = useRef(null);
  const codeRef = useRef(null);

  async function _rollbackImportAuth() {
    try {
      await NetworkService.logout();
    } catch (_e) {
      try { await StorageService.removeAuth(); } catch (__e) { /* ignore */ }
    }
  }

  function _pubKeysMatch(aB64, bB64) {
    try {
      const a = new Uint8Array(CryptoUtils.base64ToArrayBuffer(String(aB64 || '')));
      const b = new Uint8Array(CryptoUtils.base64ToArrayBuffer(String(bB64 || '')));
      if (a.length !== 32 || b.length !== 32) return false; // X25519 keys must be exactly 32 bytes
      // Constant-time comparison to prevent timing side-channels
      let diff = 0;
      for (let i = 0; i < 32; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    } catch (_e) {
      return false;
    }
  }

  async function handleImport() {
    const u = username.trim();
    const p = password;
    const ph = phrase.trim();

    if (!u || !p || !ph) {
      setError('Fill in all fields');
      return;
    }

    const wordCount = ph.split(/\s+/).filter(Boolean).length;
    if (wordCount !== 24) {
      setError(`Recovery phrase must be exactly 24 words (got ${wordCount})`);
      return;
    }

    setLoading(true);
    setError('');

    try {
      // Step 1: Login
      const loginResult = await NetworkService.login(u, p);
      if (loginResult.requires_2fa) {
        setTempToken(loginResult.temp_token);
        setShow2fa(true);
        setLoading(false);
        return;
      }
      if (!loginResult.ok) {
        setError(loginResult.error || 'Login failed');
        setLoading(false);
        return;
      }

      await _finishImport(u, p, ph, loginResult.token, loginResult.refreshToken || null);
    } catch (e) {
      setError(e?.message || 'Import failed');
    } finally {
      setLoading(false);
    }
  }

  async function handle2fa() {
    if (code2fa.length !== 6) { setError('Enter the 6-digit code'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await NetworkService.verify2fa(tempToken, code2fa);
      if (!result.ok) {
        setError(result.error || 'Invalid code');
        setCode2fa('');
        setLoading(false);
        return;
      }
      await _finishImport(
        username.trim(),
        password,
        phrase.trim(),
        result.token,
        result.refreshToken || null,
      );
    } catch (e) {
      setError(e?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }

  async function _finishImport(u, p, ph, token, refreshToken = null) {
    async function fail(message) {
      setError(message);
      await _rollbackImportAuth();
      return false;
    }

    // Step 2: Decode BIP39 phrase -> raw private key bytes
    let privRaw;
    try {
      privRaw = CryptoUtils.bip39Decode(ph);
    } catch (e) {
      return fail('Invalid recovery phrase: ' + (e?.message || 'checksum mismatch'));
    }

    // Step 3: Derive public key from private key
    const pubRaw = x25519.getPublicKey(privRaw);
    const derivedPubB64 = CryptoUtils.arrayBufferToBase64(pubRaw);

    // Step 4: Fetch server public key and compare
    let serverPubB64 = null;
    try {
      const keyData = await NetworkService.fetchPeerKey(u);
      serverPubB64 = keyData?.public_key;
    } catch (fetchErr) {
      console.warn('[ImportKey] fetchPeerKey error:', fetchErr?.message, fetchErr?.status);
    }

    if (!serverPubB64) {
      return fail('Could not fetch public key from server. Check your connection.');
    }

    if (!_pubKeysMatch(derivedPubB64, serverPubB64)) {
      return fail('Recovery phrase does not match this account. Double-check the 24 words.');
    }

    try {
      // Step 5: Encrypt private key with password -> EPK
      const uLower = String(u || '').trim().toLowerCase();
      const privB64 = CryptoUtils.arrayBufferToBase64(privRaw);
      const epk = await _encryptPrivateKey(privB64, p, uLower);

      // Step 6: Save identity locally (per-user slot)
      await StorageService.setIdentity(uLower, {
        encrypted_private_key: epk,
        public_key: serverPubB64,
        username: uLower,
        updated_at: Date.now(),
      });
      await StorageService.setActiveUsername(uLower);

      // Step 7: Save auth and dispatch
      await StorageService.setAuth({ username: u, token, refreshToken });
      // Unlock directly from the raw key already in memory — no PBKDF2 round-trip needed
      const unlocked = await CryptoService.unlockWithRawKey(privRaw, serverPubB64);
      privRaw.fill(0); // wipe raw private key from memory
      if (!unlocked) {
        return fail('Failed to unlock encryption after import. Please try again.');
      }
      dispatch({ type: 'SET_AUTH', username: u, token });
      return true;
    } catch (e) {
      try { privRaw.fill(0); } catch (_) {} // wipe on error too
      return fail(e?.message || 'Import failed');
    }
  }
  // ---- 2FA screen ----
  if (show2fa) {
    return (
      <View style={styles.root}>
        <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
          <View style={styles.card}>
            <Text style={styles.title}>Two-Factor Auth</Text>
            <Text style={styles.subtitle}>Enter the 6-digit code from your authenticator app</Text>
            {!!error && <Text style={styles.errorText}>{error}</Text>}
            <TextInput
              ref={codeRef}
              style={styles.input}
              placeholder="000000"
              placeholderTextColor={Colors.textMuted}
              value={code2fa}
              onChangeText={v => setCode2fa(v.replace(/\D/g, '').slice(0, 6))}
              keyboardType="numeric"
              maxLength={6}
              onSubmitEditing={handle2fa}
              autoFocus
            />
            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={handle2fa}
              disabled={loading}
            >
              {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Verify</Text>}
            </TouchableOpacity>
            <TouchableOpacity onPress={() => { setShow2fa(false); setCode2fa(''); setError(''); }}>
              <Text style={styles.linkText}>← Back</Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </View>
    );
  }

  // ---- Main screen ----
  return (
    <View style={styles.root}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.card}>
          <Text style={styles.title}>Import Account</Text>
          <Text style={styles.subtitle}>
            Enter your credentials and the 24-word recovery phrase from{'\n'}
            Chrome Extension → Security settings
          </Text>

          {!!error && <Text style={styles.errorText}>{error}</Text>}

          <TextInput
            style={styles.input}
            placeholder="Username"
            placeholderTextColor={Colors.textMuted}
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            autoCorrect={false}
            returnKeyType="next"
            onSubmitEditing={() => passwordRef.current?.focus()}
          />
          <TextInput
            ref={passwordRef}
            style={styles.input}
            placeholder="Password"
            placeholderTextColor={Colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            returnKeyType="next"
            onSubmitEditing={() => phraseRef.current?.focus()}
          />
          <TextInput
            ref={phraseRef}
            style={[styles.input, styles.phraseInput]}
            placeholder="word1 word2 word3 … (24 words)"
            placeholderTextColor={Colors.textMuted}
            value={phrase}
            onChangeText={setPhrase}
            autoCapitalize="none"
            autoCorrect={false}
            multiline
            returnKeyType="go"
            onSubmitEditing={handleImport}
          />

          <TouchableOpacity
            style={[styles.btn, loading && styles.btnDisabled]}
            onPress={handleImport}
            disabled={loading}
          >
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Import</Text>}
          </TouchableOpacity>

          <TouchableOpacity onPress={() => navigation.goBack()}>
            <Text style={styles.linkText}>← Back to login</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </View>
  );
}

// ---- Helpers ----

async function _encryptPrivateKey(privB64, password, username = '') {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = CryptoUtils.arrayBufferToBase64(salt);

  // Derive AES-256 encryption key — Argon2id preferred, PBKDF2 fallback
  const { raw, kdf: kdfObj } = await CryptoUtils.deriveRawKeyFromPassword(password, saltB64, {
    preferArgon2: true,
  });
  const aesKey = await crypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt'],
  );
  raw.fill(0); // wipe intermediate key material

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const container = {
    v: 3,
    alg: 'AES-256-GCM',
    kdf: kdfObj,
    salt: saltB64,
    iv: CryptoUtils.arrayBufferToBase64(iv),
    created_at: Date.now(),
    username: String(username).trim().toLowerCase(),
    ext_version: '0',
  };
  const aad = new TextEncoder().encode(CryptoUtils.buildPrivateKeyContainerAAD(container));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad }, aesKey, new TextEncoder().encode(privB64),
  );
  return {
    ...container,
    data: CryptoUtils.arrayBufferToBase64(ct),
  };
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: Colors.bgMain },
  scroll: { flexGrow: 1, justifyContent: 'center', padding: Spacing.xl },
  card: {
    backgroundColor: Colors.bgPanel,
    borderRadius: 14,
    padding: Spacing.xxl,
    borderWidth: 1,
    borderColor: Colors.border,
    gap: Spacing.md,
    elevation: 8,
  },
  title: {
    fontSize: Typography.xxl,
    fontWeight: '700',
    color: Colors.textMain,
    textAlign: 'center',
    marginBottom: Spacing.xs,
  },
  subtitle: {
    fontSize: Typography.sm,
    color: Colors.textMuted,
    textAlign: 'center',
    marginBottom: Spacing.sm,
    lineHeight: 18,
  },
  input: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  phraseInput: {
    minHeight: 80,
    textAlignVertical: 'top',
  },
  btn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.lg,
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: '#fff', fontSize: Typography.lg, fontWeight: '600' },
  linkText: {
    color: Colors.accent,
    fontSize: Typography.md,
    textAlign: 'center',
    marginTop: Spacing.sm,
  },
  errorText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    textAlign: 'center',
  },
});

