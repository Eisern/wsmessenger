// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * PasswordModal.js — Reusable password prompt modal
 * Used by ChatScreen and DMChatScreen for crypto unlocking
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Modal, View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator,
} from 'react-native';
import { Colors, Spacing, Radii, Typography } from '../theme';

export default function PasswordModal({ visible, reason, onSubmit, onCancel }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);

  // Auto-focus on open
  useEffect(() => {
    if (visible) {
      setPassword('');
      setBusy(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [visible]);

  async function handleSubmit() {
    if (!password) return;
    setBusy(true);
    try {
      // Pass password back; parent resolves the promise
      await onSubmit(password);
    } catch (_e) {
      // Reset busy state so user can retry
      setBusy(false);
    }
    // Don't clear until modal closes to avoid flash
  }

  function handleCancel() {
    setPassword(''); // Clear password from memory on cancel
    onCancel();
  }

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={handleCancel}
    >
      <View
        style={styles.overlay}
      >
        <View style={styles.card}>
          <Text style={styles.title}>Unlock Encryption</Text>
          {!!reason && <Text style={styles.reason}>{reason}</Text>}
          <Text style={styles.label}>Enter your password:</Text>
          <TextInput
            ref={inputRef}
            style={styles.input}
            placeholder="Password"
            placeholderTextColor={Colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
            returnKeyType="go"
            onSubmitEditing={handleSubmit}
          />
          <View style={styles.btns}>
            <TouchableOpacity style={styles.cancelBtn} onPress={handleCancel} disabled={busy}>
              <Text style={styles.cancelText}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.submitBtn, (!password || busy) && styles.submitBtnDisabled]}
              onPress={handleSubmit}
              disabled={!password || busy}
            >
              {busy
                ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.submitText}>Unlock</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: Colors.overlay,
    justifyContent: 'center',
    alignItems: 'center',
    padding: Spacing.xl,
  },
  card: {
    width: '100%',
    backgroundColor: Colors.bgPanel,
    borderRadius: 14,
    padding: Spacing.xxl,
    gap: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.border,
    elevation: 8,
  },
  title: {
    fontSize: Typography.xl,
    fontWeight: '700',
    color: Colors.textMain,
  },
  reason: {
    fontSize: Typography.md,
    color: Colors.textMuted,
    marginTop: -Spacing.xs,
  },
  label: {
    fontSize: Typography.sm,
    color: Colors.textMuted,
  },
  input: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.md,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  btns: {
    flexDirection: 'row',
    gap: Spacing.md,
    justifyContent: 'flex-end',
    marginTop: Spacing.sm,
  },
  cancelBtn: {
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    borderRadius: Radii.md,
    backgroundColor: Colors.btnBg,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  cancelText: {
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  submitBtn: {
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    borderRadius: Radii.md,
    backgroundColor: '#238636',
    minWidth: 80,
    alignItems: 'center',
  },
  submitBtnDisabled: { opacity: 0.5 },
  submitText: {
    color: '#fff',
    fontSize: Typography.md,
    fontWeight: '600',
  },
});
