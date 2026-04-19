// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * MnemonicModal — shared 24-word recovery phrase display + acknowledgement.
 *
 * Used in two flows:
 *   1. RegisterScreen (post-register, before auto-login).
 *   2. App.tsx pending-ack recovery (when the user crashed before
 *      acknowledging — re-derived from the in-memory raw private key).
 *
 * Once mounted, the modal cannot be dismissed by back button or outside tap —
 * the only exit is the "I have saved my phrase" confirmation. This is
 * intentional: the recovery phrase is the only way to recover an account if
 * the password is lost.
 */

import React, { useState } from 'react';
import { View, Text, TouchableOpacity, StyleSheet, Modal } from 'react-native';
import { Colors, Spacing, Radii, Typography } from '../theme';

export default function MnemonicModal({ visible, words, onAck }) {
  const [ack, setAck] = useState(false);

  // Reset acknowledgement state when the modal is reopened.
  React.useEffect(() => {
    if (visible) setAck(false);
  }, [visible]);

  if (!visible || !Array.isArray(words) || words.length === 0) return null;

  return (
    <Modal
      visible={visible}
      transparent
      animationType="fade"
      onRequestClose={() => { /* block back-button dismissal */ }}
    >
      <View style={styles.modalOverlay}>
        <View style={styles.mnemonicCard}>
          <Text style={styles.mnemonicTitle}>Recovery Phrase</Text>
          <Text style={styles.mnemonicWarning}>
            Write these 24 words down in order. They are the only way to recover your account if you forget your password.
          </Text>

          <View style={styles.wordGrid}>
            {words.map((word, i) => (
              <View key={i} style={styles.wordCell}>
                <Text style={styles.wordIndex}>{i + 1}.</Text>
                <Text style={styles.wordText}>{word}</Text>
              </View>
            ))}
          </View>

          <TouchableOpacity
            style={styles.ackRow}
            onPress={() => setAck(!ack)}
            activeOpacity={0.7}
          >
            <View style={[styles.checkbox, ack && styles.checkboxChecked]}>
              {ack && <Text style={styles.checkmark}>✓</Text>}
            </View>
            <Text style={styles.ackText}>I have saved my recovery phrase</Text>
          </TouchableOpacity>

          <TouchableOpacity
            style={[styles.btn, !ack && styles.btnDisabled]}
            onPress={() => { if (ack) onAck?.(); }}
            disabled={!ack}
          >
            <Text style={styles.btnText}>Continue</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.85)',
    justifyContent: 'center',
    padding: Spacing.lg,
  },
  mnemonicCard: {
    backgroundColor: Colors.bgPanel,
    borderRadius: 14,
    padding: Spacing.xxl,
    borderWidth: 1,
    borderColor: Colors.border,
    elevation: 8,
  },
  mnemonicTitle: {
    fontSize: Typography.xxl,
    fontWeight: '700',
    color: Colors.textMain,
    textAlign: 'center',
    marginBottom: Spacing.md,
  },
  mnemonicWarning: {
    fontSize: Typography.md,
    color: Colors.warning || '#f0ad4e',
    textAlign: 'center',
    marginBottom: Spacing.lg,
    lineHeight: 22,
  },
  wordGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
    marginBottom: Spacing.lg,
  },
  wordCell: {
    flexDirection: 'row',
    alignItems: 'center',
    width: '30%',
    marginBottom: Spacing.sm,
    backgroundColor: Colors.inputBg,
    borderRadius: Radii.sm,
    paddingHorizontal: Spacing.sm,
    paddingVertical: Spacing.xs,
  },
  wordIndex: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
    width: 24,
  },
  wordText: {
    color: Colors.textMain,
    fontSize: Typography.md,
    fontWeight: '600',
  },
  ackRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: Spacing.md,
    paddingVertical: Spacing.sm,
  },
  checkbox: {
    width: 22,
    height: 22,
    borderRadius: 4,
    borderWidth: 2,
    borderColor: Colors.textMuted,
    marginRight: Spacing.sm,
    alignItems: 'center',
    justifyContent: 'center',
  },
  checkboxChecked: {
    borderColor: '#238636',
    backgroundColor: '#238636',
  },
  checkmark: {
    color: '#fff',
    fontSize: 14,
    fontWeight: '700',
  },
  ackText: {
    color: Colors.textMain,
    fontSize: Typography.md,
    flex: 1,
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
});
