// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * RegisterScreen.js — Account registration with E2EE key generation
 * Ported from login.js (register flow)
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
import MnemonicModal from '../components/MnemonicModal';

// Lazy proxy — reads globalThis.crypto at call time, not at module init time.
const crypto = {
  get subtle() { return globalThis.crypto.subtle; },
  getRandomValues: (arr) => globalThis.crypto.getRandomValues(arr),
};

// Mirrors server-side RegisterRequest validation (main.py: ^[a-zA-Z][a-zA-Z0-9_]*$, 3-32).
// Validating client-side prevents wasting Argon2id derivation (~0.5–2s) on
// names the server will reject with an opaque pydantic 422 error.
const USERNAME_RE = /^[a-zA-Z][a-zA-Z0-9_]*$/;
const USERNAME_MIN = 3;
const USERNAME_MAX = 32;

function validateUsername(raw) {
  const u = String(raw || '').trim();
  if (!u) return 'Username is required';
  if (u.length < USERNAME_MIN) return `Username must be at least ${USERNAME_MIN} characters`;
  if (u.length > USERNAME_MAX) return `Username must be at most ${USERNAME_MAX} characters`;
  if (!USERNAME_RE.test(u)) return 'Username must start with a letter and contain only letters, digits, or underscores';
  return null;
}

export default function RegisterScreen({ navigation }) {
  const { dispatch } = useApp();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [loading, setLoading] = useState('');  // '' | 'keys' | 'register'
  const [error, setError] = useState('');

  // Mnemonic modal state
  const [mnemonicWords, setMnemonicWords] = useState(null); // string[] | null
  const mnemonicCallbackRef = useRef(null);

  const passwordRef = useRef(null);
  const password2Ref = useRef(null);

  async function handleRegister() {
    const usernameErr = validateUsername(username);
    if (usernameErr) {
      setError(usernameErr);
      return;
    }
    if (!password || !password2) {
      setError('Fill in all fields');
      return;
    }
    if (password !== password2) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    // Server normalises to lowercase ([main.py /auth/register]); use the same
    // form everywhere downstream (EPK AAD, identity slot, active-user pointer)
    // so case-insensitive matches are explicit, not accidental.
    const uTrim = username.trim();
    const uLower = uTrim.toLowerCase();

    setError('');
    setLoading('keys');

    let rawKey = null;
    let privB64 = null;
    try {
      // Generate X25519 identity keypair
      const kp = await CryptoUtils.generateIdentityKeyPair();
      const pubB64 = await CryptoUtils.exportPublicKey(kp.publicKey);
      privB64 = await CryptoUtils.exportPrivateKey(kp.privateKey);

      // Raw private key bytes (Android CryptoUtils returns raw 32-byte keys)
      rawKey = kp.privateKey.priv;

      // Derive recovery_key_hash and BIP39 mnemonic (matches extension login.js:852-857)
      const recoveryAuth = CryptoUtils.deriveRecoveryAuth(rawKey);
      const recoveryKeyHash = CryptoUtils.sha256Hex(recoveryAuth);
      const mnemonic = CryptoUtils.bip39Encode(rawKey);

      // Encrypt private key (Argon2id preferred, PBKDF2 fallback). AAD pins the
      // lowercase username — must match what the server stores.
      const encryptedPrivKey = await _encryptPrivateKey(privB64, password, uLower);

      setLoading('register');

      // Register with server — send recovery_key_hash (extension parity)
      const result = await NetworkService.register(
        uLower,
        password,
        pubB64,
        encryptedPrivKey,
        recoveryKeyHash,
      );

      if (result.ok) {
        // Save identity locally AFTER successful server registration
        // (extension: login.js:894-900 — must NOT save before server confirms)
        await StorageService.setIdentity(uLower, {
          encrypted_private_key: encryptedPrivKey,
          public_key: pubB64,
          username: uLower,
          updated_at: Date.now(),
        });
        await StorageService.setActiveUsername(uLower);
        // Pending-ack flag — cleared only on user confirmation. If the app
        // crashes between here and ack, the next unlock re-surfaces the
        // mnemonic modal (App.tsx pendingMnemonic effect).
        await StorageService.setPendingMnemonicAck(uLower);

        setLoading('');

        // Show mnemonic before proceeding to login (extension parity: login.js:905)
        const words = mnemonic.split(' ');
        setMnemonicWords(words);

        // Store callback for after user acknowledges
        mnemonicCallbackRef.current = async () => {
          // Clear pending FIRST so App.tsx pendingMnemonic effect is a no-op.
          await StorageService.clearPendingMnemonicAck().catch(() => {});
          try {
            const loginResult = await NetworkService.login(uLower, password);
            if (loginResult.ok) {
              const resolvedUsername = loginResult.username || uLower;
              await CryptoService.unlockWithPassword(password);
              dispatch({ type: 'SET_AUTH', username: resolvedUsername, token: loginResult.token });
            } else {
              Alert.alert('Registered!', 'Account created. Please sign in.');
              navigation.navigate('Login');
            }
          } catch (e) {
            Alert.alert('Registered!', 'Account created. Please sign in.');
            navigation.navigate('Login');
          }
        };
      } else {
        setError(result.error || 'Registration failed');
      }
    } catch (e) {
      setError(e?.message || 'Error during registration');
    } finally {
      // Wipe key material regardless of success/failure path.
      try { if (rawKey) rawKey.fill(0); } catch (_e) { /* best-effort */ }
      privB64 = null;
      if (!mnemonicWords) setLoading('');
    }
  }

  function handleMnemonicDone() {
    // Overwrite word array elements before clearing state to reduce memory exposure
    if (Array.isArray(mnemonicWords)) {
      for (let i = 0; i < mnemonicWords.length; i++) mnemonicWords[i] = '';
    }
    setMnemonicWords(null);
    const cb = mnemonicCallbackRef.current;
    mnemonicCallbackRef.current = null;
    if (cb) cb();
  }

  return (
    <View style={styles.root}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.card}>
          <Text style={styles.title}>Create Account</Text>
          <Text style={styles.subtitle}>Your identity key will be generated locally</Text>
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
            placeholder="Password (min 8 chars)"
            placeholderTextColor={Colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            returnKeyType="next"
            onSubmitEditing={() => password2Ref.current?.focus()}
          />
          <TextInput
            ref={password2Ref}
            style={styles.input}
            placeholder="Repeat password"
            placeholderTextColor={Colors.textMuted}
            value={password2}
            onChangeText={setPassword2}
            secureTextEntry
            returnKeyType="go"
            onSubmitEditing={handleRegister}
          />
          {loading === 'keys' && (
            <Text style={styles.hint}>Generating encryption keys…</Text>
          )}
          {loading === 'register' && (
            <Text style={styles.hint}>Creating account…</Text>
          )}
          <TouchableOpacity
            style={[styles.btn, !!loading && styles.btnDisabled]}
            onPress={handleRegister}
            disabled={!!loading}
          >
            {loading
              ? <ActivityIndicator color="#fff" />
              : <Text style={styles.btnText}>Register</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={() => navigation.navigate('Login')}>
            <Text style={styles.linkText}>← Back to sign in</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>

      <MnemonicModal
        visible={!!mnemonicWords}
        words={mnemonicWords || []}
        onAck={handleMnemonicDone}
      />
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
  root: {
    flex: 1,
    backgroundColor: Colors.bgMain,
  },
  scroll: {
    flexGrow: 1,
    justifyContent: 'center',
    padding: Spacing.xl,
  },
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
    fontSize: Typography.md,
    color: Colors.textMuted,
    textAlign: 'center',
    marginBottom: Spacing.sm,
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
  btn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.lg,
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  btnDisabled: {
    opacity: 0.6,
  },
  btnText: {
    color: '#fff',
    fontSize: Typography.lg,
    fontWeight: '600',
  },
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
  hint: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
    textAlign: 'center',
  },
});
