// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * RecoveryScreen.js — Reset password using 24-word BIP39 recovery phrase.
 *
 * Mirrors the Chrome Extension's forgot-password form in login.js:
 *   1. Decode phrase client-side (checksum verified).
 *   2. Derive recovery_auth token via HKDF and new EPK container with new password.
 *   3. POST /auth/recover-start → nonce.
 *   4. POST /auth/recover → server updates password_hash, returns ok.
 *   5. Save new EPK to Keychain device-only.
 *   6. Return to LoginScreen.
 *
 * Does NOT log the user in — they sign in with the new password afterward.
 */

import React, { useState, useRef } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator, ScrollView,
} from 'react-native';
import CryptoService from '../services/CryptoService';
import { Colors, Spacing, Radii, Typography } from '../theme';

export default function RecoveryScreen({ navigation }) {
  const [username, setUsername] = useState('');
  const [phrase, setPhrase] = useState('');
  const [newPass, setNewPass] = useState('');
  const [newPass2, setNewPass2] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const phraseRef = useRef(null);
  const passRef = useRef(null);
  const pass2Ref = useRef(null);

  async function handleRecover() {
    setError('');
    if (!username.trim()) return setError('Username is required');
    if (!phrase.trim()) return setError('Recovery phrase is required');
    if (!newPass) return setError('New password is required');
    if (newPass !== newPass2) return setError('Passwords do not match');

    setLoading(true);
    try {
      await CryptoService.recoverFromBip39(username.trim(), phrase, newPass);
      setSuccess(true);
      setTimeout(() => navigation.goBack(), 1800);
    } catch (e) {
      setError(e?.message || 'Recovery failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <View style={styles.root}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.card}>
          <Text style={styles.title}>Reset Password</Text>
          <Text style={styles.subtitle}>
            Enter your 24-word recovery phrase to set a new password.{'\n'}
            Your encryption key stays the same.
          </Text>

          {!!error && <Text style={styles.errorText}>{error}</Text>}
          {success && <Text style={styles.successText}>Password reset. Please sign in.</Text>}

          <TextInput
            style={styles.input}
            placeholder="Username"
            placeholderTextColor={Colors.textMuted}
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            autoCorrect={false}
            editable={!loading && !success}
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
            editable={!loading && !success}
            multiline
            returnKeyType="next"
            onSubmitEditing={() => passRef.current?.focus()}
          />
          <TextInput
            ref={passRef}
            style={styles.input}
            placeholder="New password"
            placeholderTextColor={Colors.textMuted}
            value={newPass}
            onChangeText={setNewPass}
            secureTextEntry
            editable={!loading && !success}
            returnKeyType="next"
            onSubmitEditing={() => pass2Ref.current?.focus()}
          />
          <TextInput
            ref={pass2Ref}
            style={styles.input}
            placeholder="Confirm new password"
            placeholderTextColor={Colors.textMuted}
            value={newPass2}
            onChangeText={setNewPass2}
            secureTextEntry
            editable={!loading && !success}
            returnKeyType="go"
            onSubmitEditing={handleRecover}
          />

          <TouchableOpacity
            style={[styles.btn, (loading || success) && styles.btnDisabled]}
            onPress={handleRecover}
            disabled={loading || success}
          >
            {loading ? <ActivityIndicator color="#fff" /> : <Text style={styles.btnText}>Recover Account</Text>}
          </TouchableOpacity>

          <TouchableOpacity onPress={() => navigation.goBack()} disabled={loading}>
            <Text style={styles.linkText}>← Back to login</Text>
          </TouchableOpacity>
        </View>
      </ScrollView>
    </View>
  );
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
  successText: {
    color: '#28a745',
    fontSize: Typography.sm,
    textAlign: 'center',
  },
});
