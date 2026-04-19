// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ProfileScreen.js — User profile, privacy settings, 2FA, safety numbers
 * Ported from panel-ui.js profile drawer + 2FA settings
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ScrollView, Switch, Alert,
  ActivityIndicator, Modal, Linking,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';

const FONT_SCALES = [
  { value: 0.85, label: 'XS' },
  { value: 0.92, label: 'S' },
  { value: 1.0,  label: 'M' },
  { value: 1.15, label: 'L' },
  { value: 1.3,  label: 'XL' },
];

export default function ProfileScreen() {
  const { state, dispatch, logout, loadMyProfile, setFontScale } = useApp();
  const insets = useSafeAreaInsets();

  const [loading, setLoading] = useState(false);
  const [about, setAbout] = useState('');
  const [allowInvites, setAllowInvites] = useState(true);
  const [allowDm, setAllowDm] = useState(true);

  // 2FA
  const [twoFaEnabled, setTwoFaEnabled] = useState(false);
  const [showTwoFaSetup, setShowTwoFaSetup] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [totpQr, setTotpQr] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [setupLoading, setSetupLoading] = useState(false);
  const [showDisable2fa, setShowDisable2fa] = useState(false);
  const [disable2faCode, setDisable2faCode] = useState('');

  // Crypto
  const [myFingerprint, setMyFingerprint] = useState('');
  const [cryptoReady, setCryptoReady] = useState(false);
  const [idleLockMs, setIdleLockMs] = useState(CryptoService.getCryptoIdleLockMs());

  // Feedback
  const [feedbackText, setFeedbackText] = useState('');
  const [feedbackSending, setFeedbackSending] = useState(false);

  // Account deletion
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState('');
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  // Change password
  const [showChangePassModal, setShowChangePassModal] = useState(false);
  const [changePassOld, setChangePassOld] = useState('');
  const [changePassNew, setChangePassNew] = useState('');
  const [changePassConfirm, setChangePassConfirm] = useState('');
  const [changePassLoading, setChangePassLoading] = useState(false);
  const [changePassError, setChangePassError] = useState('');
  const [changePassDone, setChangePassDone] = useState(false);

  // Recovery phrase
  const [showRecoveryModal, setShowRecoveryModal] = useState(false);
  const [recoveryPassword, setRecoveryPassword] = useState('');
  const [recoveryWords, setRecoveryWords] = useState(null); // string[] | null
  const [recoveryLoading, setRecoveryLoading] = useState(false);
  const [recoveryError, setRecoveryError] = useState('');

  // Server config
  const [showServerSetup, setShowServerSetup] = useState(false);
  const [setupApiBase, setSetupApiBase] = useState('');
  const [setupWsBase, setSetupWsBase] = useState('');
  const [setupStatus, setSetupStatus] = useState('');
  const [setupTestLoading, setSetupTestLoading] = useState(false);
  const [setupSaveLoading, setSetupSaveLoading] = useState(false);

  const myUsername = state.username;
  const profile = state.myProfile;

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      await loadMyProfile();
      // Load 2FA status
      const status = await NetworkService.get2faStatus();
      if (status) setTwoFaEnabled(status.enabled || false);
      // Load fingerprint
      const ready = await CryptoService.ensureReady({ interactive: false });
      setCryptoReady(ready);
      if (ready) {
        const fp = await CryptoService.getMyFingerprint();
        if (fp) setMyFingerprint(fp);
      }
    } catch (_e) { /* ignore */ }
    setLoading(false);
  }

  useEffect(() => {
    if (profile) {
      setAbout(profile.about || '');
      setAllowInvites(profile.privacy?.allow_group_invites_from_non_friends ?? true);
      setAllowDm(profile.privacy?.allow_dm_from_non_friends ?? true);
    }
  }, [profile]);

  // Load current server config into server setup fields
  useEffect(() => {
    const cfg = NetworkService.getServerConfig();
    if (!cfg.isDefault) {
      setSetupApiBase(cfg.apiBase);
      setSetupWsBase(cfg.wsBase);
    }
  }, []);

  async function handleSaveProfile() {
    setLoading(true);
    try {
      await NetworkService.updateProfile({
        about: about.trim(),
        privacy: { allow_group_invites_from_non_friends: allowInvites, allow_dm_from_non_friends: allowDm },
      });
      Alert.alert('Saved', 'Profile updated');
      await loadMyProfile();
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not save profile');
    } finally {
      setLoading(false);
    }
  }

  function _deriveWsBase(api) {
    return api.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://');
  }

  async function handleTestServer() {
    const api = setupApiBase.trim().replace(/\/$/, '');
    if (!api) { setSetupStatus('Enter API base URL first'); return; }
    setSetupTestLoading(true);
    setSetupStatus('Testing…');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const r = await fetch(api + '/health', { cache: 'no-store', signal: controller.signal });
      setSetupStatus(r.ok ? 'Connected ✓' : `Server returned HTTP ${r.status}`);
    } catch (e) {
      setSetupStatus(e.name === 'AbortError' ? 'Connection timed out' : 'Connection failed: ' + e.message);
    } finally {
      clearTimeout(timer);
      setSetupTestLoading(false);
    }
  }

  async function handleSaveServer() {
    const api = setupApiBase.trim().replace(/\/$/, '');
    if (!api) {
      await NetworkService.clearServerConfig();
      setSetupStatus('Reverted to default server');
      setShowServerSetup(false);
      return;
    }
    let parsed;
    try { parsed = new URL(api); } catch {
      setSetupStatus('Invalid URL'); return;
    }
    if (!['https:', 'http:'].includes(parsed.protocol)) {
      setSetupStatus('URL must start with https://'); return;
    }
    if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(parsed.hostname)) {
      setSetupStatus('HTTP only allowed for localhost'); return;
    }
    const cleanApi = parsed.origin;
    const ws = (setupWsBase.trim().replace(/\/$/, '')) || _deriveWsBase(cleanApi);
    setSetupSaveLoading(true);
    setSetupStatus('Saving…');
    try {
      await NetworkService.saveServerConfig(cleanApi, ws);
      setSetupWsBase(ws);
      setSetupStatus('Saved ✓ — sign out and log in on the new server');
    } catch (e) {
      setSetupStatus('Save failed: ' + e.message);
    } finally {
      setSetupSaveLoading(false);
    }
  }

  async function handleClearServer() {
    await NetworkService.clearServerConfig();
    setSetupApiBase('');
    setSetupWsBase('');
    setSetupStatus('Using default server');
    setTimeout(() => setShowServerSetup(false), 800);
  }

  async function handleLogout() {
    Alert.alert('Sign Out', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Sign Out', style: 'destructive', onPress: async () => {
        CryptoService.lockSession();
        await logout();
      }},
    ]);
  }

  function handleDeleteAccount() {
    setDeletePassword('');
    setDeleteError('');
    setShowDeleteModal(true);
  }

  async function confirmDeleteAccount() {
    if (!deletePassword.trim()) { setDeleteError('Password is required'); return; }
    setDeleteLoading(true);
    setDeleteError('');
    try {
      // Re-authenticate before deletion
      const authResult = await NetworkService.login(myUsername, deletePassword.trim());
      if (!authResult?.ok && !authResult?.token) {
        setDeleteError('Incorrect password');
        return;
      }
      await NetworkService.deleteAccount();
      setDeletePassword('');
      setShowDeleteModal(false);
      CryptoService.lockSession();
      await logout();
    } catch (e) {
      setDeleteError(e?.message || 'Could not delete account');
    } finally {
      setDeleteLoading(false);
    }
  }

  // ---- 2FA Setup ----

  async function handleEnable2fa() {
    setSetupLoading(true);
    try {
      const data = await NetworkService.setup2fa();
      if (data) {
        setTotpSecret(data.secret || '');
        setTotpQr(data.otpauth_url || data.qr_url || '');
        setShowTwoFaSetup(true);
      }
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not start 2FA setup');
    } finally {
      setSetupLoading(false);
    }
  }

  async function handleConfirm2fa() {
    if (totpCode.length !== 6) { Alert.alert('Error', 'Enter the 6-digit code'); return; }
    setSetupLoading(true);
    try {
      await NetworkService.confirm2fa(totpCode);
      setTwoFaEnabled(true);
      setShowTwoFaSetup(false);
      setTotpCode('');
      setTotpSecret('');
      setTotpQr('');
      Alert.alert('2FA Enabled', 'Two-factor authentication is now active.');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Invalid code');
    } finally {
      setSetupLoading(false);
    }
  }

  function handleDisable2fa() {
    setDisable2faCode('');
    setShowDisable2fa(true);
  }

  async function handleConfirmDisable2fa() {
    if (disable2faCode.length !== 6) { Alert.alert('Error', 'Enter the 6-digit code'); return; }
    setSetupLoading(true);
    try {
      await NetworkService.disable2fa(disable2faCode);
      setTwoFaEnabled(false);
      setShowDisable2fa(false);
      setDisable2faCode('');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Invalid code');
    } finally {
      setSetupLoading(false);
    }
  }

  function _wipeRecoveryWords() {
    if (Array.isArray(recoveryWords)) {
      for (let i = 0; i < recoveryWords.length; i++) recoveryWords[i] = '';
    }
    setRecoveryWords(null);
    setRecoveryPassword('');
  }

  function handleShowChangePass() {
    setChangePassOld('');
    setChangePassNew('');
    setChangePassConfirm('');
    setChangePassError('');
    setChangePassDone(false);
    setShowChangePassModal(true);
  }

  async function handleChangePassword() {
    if (!changePassOld) { setChangePassError('Enter your current password'); return; }
    if (changePassNew.length < 8) { setChangePassError('New password must be at least 8 characters'); return; }
    if (changePassNew !== changePassConfirm) { setChangePassError('New passwords do not match'); return; }
    setChangePassLoading(true);
    setChangePassError('');
    try {
      await CryptoService.changePassword(changePassOld, changePassNew);
      setChangePassDone(true);
    } catch (e) {
      setChangePassError(e?.message || 'Failed to change password');
    } finally {
      setChangePassLoading(false);
    }
  }

  function handleShowRecovery() {
    setRecoveryPassword('');
    setRecoveryWords(null);
    setRecoveryError('');
    setShowRecoveryModal(true);
  }

  async function handleDecryptRecovery() {
    if (!recoveryPassword) { setRecoveryError('Enter your password'); return; }
    setRecoveryLoading(true);
    setRecoveryError('');
    try {
      const mnemonic = await CryptoService.getRecoveryPhrase(recoveryPassword);
      setRecoveryWords(mnemonic.split(' '));
    } catch (e) {
      setRecoveryError(e?.message || 'Failed to decrypt');
    } finally {
      setRecoveryLoading(false);
    }
  }

  async function handleSendFeedback() {
    const msg = feedbackText.trim();
    if (!msg) return;
    setFeedbackSending(true);
    try {
      await NetworkService.sendFeedback(msg, { username: myUsername });
      setFeedbackText('');
      Alert.alert('Sent', 'Thank you for your feedback!');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not send feedback');
    } finally {
      setFeedbackSending(false);
    }
  }

  async function handleUnlockCrypto() {
    const ok = await CryptoService.ensureReady({ interactive: true, reason: 'View identity key' });
    if (ok) {
      setCryptoReady(true);
      const fp = await CryptoService.getMyFingerprint();
      if (fp) setMyFingerprint(fp);
    }
  }

  return (
    <ScrollView style={styles.root} contentContainerStyle={[styles.scroll, { paddingBottom: insets.bottom + Spacing.xxl }]}>
      {/* Header */}
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <Text style={styles.title}>Profile</Text>
      </View>

      {/* User info */}
      <View style={styles.section}>
        <View style={styles.avatarRow}>
          <View style={styles.avatar}>
            <Text style={styles.avatarText}>{(myUsername || '?')[0].toUpperCase()}</Text>
          </View>
          <Text style={styles.username}>{myUsername}</Text>
        </View>
      </View>

      {/* About */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About</Text>
        <TextInput
          style={[styles.input, { height: 80, textAlignVertical: 'top' }]}
          placeholder="Write something about yourself…"
          placeholderTextColor={Colors.textMuted}
          value={about}
          onChangeText={setAbout}
          multiline
          maxLength={300}
        />
      </View>

      {/* Privacy */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Privacy</Text>
        <View style={styles.switchRow}>
          <Text style={styles.switchLabel}>Allow group invites from non-friends</Text>
          <Switch
            value={allowInvites}
            onValueChange={setAllowInvites}
            trackColor={{ true: Colors.success, false: Colors.border }}
            thumbColor="#fff"
          />
        </View>
        <View style={styles.switchRow}>
          <Text style={styles.switchLabel}>Allow DMs from non-friends</Text>
          <Switch
            value={allowDm}
            onValueChange={setAllowDm}
            trackColor={{ true: Colors.success, false: Colors.border }}
            thumbColor="#fff"
          />
        </View>
        <Text style={styles.privacyHint}>Privacy settings are visible only to you.</Text>
        <TouchableOpacity
          style={[styles.btn, loading && styles.btnDisabled]}
          onPress={handleSaveProfile}
          disabled={loading}
        >
          {loading
            ? <ActivityIndicator color="#fff" />
            : <Text style={styles.btnText}>Save Profile</Text>}
        </TouchableOpacity>
      </View>

      {/* Text Size */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Text Size</Text>
        <View style={styles.previewBubble}>
          <Text style={styles.previewAuthor}>Alice</Text>
          <Text style={[styles.previewMsg, {
            fontSize: Math.round(Typography.md * (state.fontScale || 1.0)),
            lineHeight: Math.round(20 * (state.fontScale || 1.0)),
          }]}>
            Hey! This is how messages will look in chats.
          </Text>
          <Text style={styles.previewTs}>12:34</Text>
        </View>
        <View style={styles.fontChipRow}>
          {FONT_SCALES.map(s => {
            const active = Math.abs((state.fontScale || 1.0) - s.value) < 0.01;
            return (
              <TouchableOpacity
                key={s.value}
                style={[styles.fontChip, active && styles.fontChipActive]}
                onPress={() => setFontScale(s.value)}
              >
                <Text style={{ fontSize: Math.round(Typography.md * s.value), color: active ? Colors.accent : Colors.textMuted, fontWeight: '700' }}>
                  Aa
                </Text>
                <Text style={[styles.timeoutChipText, active && styles.timeoutChipTextActive]}>
                  {s.label}
                </Text>
              </TouchableOpacity>
            );
          })}
        </View>
      </View>

      {/* 2FA */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Two-Factor Authentication</Text>
        <View style={styles.statusRow}>
          <Text style={styles.switchLabel}>Status: </Text>
          <Text style={[styles.statusValue, twoFaEnabled ? styles.statusOn : styles.statusOff]}>
            {twoFaEnabled ? 'Enabled' : 'Not enabled'}
          </Text>
        </View>
        {twoFaEnabled ? (
          <TouchableOpacity style={styles.dangerBtn} onPress={handleDisable2fa}>
            <Text style={styles.dangerBtnText}>Disable 2FA</Text>
          </TouchableOpacity>
        ) : (
          <TouchableOpacity
            style={[styles.btn, setupLoading && styles.btnDisabled]}
            onPress={handleEnable2fa}
            disabled={setupLoading}
          >
            {setupLoading
              ? <ActivityIndicator color="#fff" />
              : <Text style={styles.btnText}>Enable 2FA</Text>}
          </TouchableOpacity>
        )}
      </View>

      {/* Encryption identity */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Encryption Identity</Text>
        {!cryptoReady ? (
          <TouchableOpacity style={styles.outlineBtn} onPress={handleUnlockCrypto}>
            <Text style={styles.outlineBtnText}>Unlock to view key fingerprint</Text>
          </TouchableOpacity>
        ) : (
          <View style={{ gap: Spacing.md }}>
            <Text style={styles.label}>Public key fingerprint:</Text>
            <Text style={styles.fingerprint}>{myFingerprint || 'Loading…'}</Text>
            <TouchableOpacity style={styles.outlineBtn} onPress={handleShowChangePass}>
              <Text style={styles.outlineBtnText}>Change Password</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.outlineBtn} onPress={handleShowRecovery}>
              <Text style={styles.outlineBtnText}>Show Recovery Phrase</Text>
            </TouchableOpacity>
          </View>
        )}

        <Text style={[styles.sectionTitle, { marginTop: Spacing.lg }]}>Auto-Lock Timeout</Text>
        <Text style={styles.privacyHint}>
          Crypto will auto-relock after this idle period. Keychain re-unlock is attempted first.
        </Text>
        <View style={styles.timeoutRow}>
          {CryptoService.CRYPTO_IDLE_LOCK_OPTIONS.map(opt => (
            <TouchableOpacity
              key={opt.value}
              style={[styles.timeoutChip, idleLockMs === opt.value && styles.timeoutChipActive]}
              onPress={() => {
                setIdleLockMs(opt.value);
                CryptoService.setCryptoIdleLockMs(opt.value);
              }}
            >
              <Text style={[styles.timeoutChipText, idleLockMs === opt.value && styles.timeoutChipTextActive]}>
                {opt.label}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
      </View>

      {/* Feedback */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Feedback</Text>
        <Text style={styles.privacyHint}>Have a suggestion or found a bug? Let us know.</Text>
        <TextInput
          style={[styles.input, { height: 80, textAlignVertical: 'top' }]}
          placeholder="Your feedback…"
          placeholderTextColor={Colors.textMuted}
          value={feedbackText}
          onChangeText={setFeedbackText}
          multiline
          maxLength={2000}
        />
        <TouchableOpacity
          style={[styles.btn, (feedbackSending || !feedbackText.trim()) && styles.btnDisabled]}
          onPress={handleSendFeedback}
          disabled={feedbackSending || !feedbackText.trim()}
        >
          {feedbackSending
            ? <ActivityIndicator color="#fff" />
            : <Text style={styles.btnText}>Send Feedback</Text>}
        </TouchableOpacity>
      </View>

      {/* Server Config */}
      <View style={styles.section}>
        <TouchableOpacity style={styles.serverToggle} onPress={() => setShowServerSetup(v => !v)}>
          <View style={{ flex: 1 }}>
            <Text style={styles.sectionTitle}>Server</Text>
            <Text style={styles.privacyHint}>
              {NetworkService.getServerConfig().isDefault
                ? 'Default server (imagine-1-ws.xyz)'
                : NetworkService.getServerConfig().apiBase.replace(/^https?:\/\//, '')}
            </Text>
          </View>
          <Text style={styles.serverChevron}>{showServerSetup ? '▴' : '▾'}</Text>
        </TouchableOpacity>
        {showServerSetup && (
          <View style={{ gap: Spacing.sm }}>
            <TextInput
              style={styles.input}
              placeholder="API base (e.g. https://your-server.example)"
              placeholderTextColor={Colors.textMuted}
              value={setupApiBase}
              onChangeText={v => { setSetupApiBase(v); if (v.trim()) setSetupWsBase(_deriveWsBase(v.trim())); }}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
            <TextInput
              style={styles.input}
              placeholder="WS base (auto-derived if empty)"
              placeholderTextColor={Colors.textMuted}
              value={setupWsBase}
              onChangeText={setSetupWsBase}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
            />
            {!!setupStatus && (
              <Text style={[
                styles.privacyHint,
                setupStatus.includes('✓') && { color: Colors.success || '#28a745' },
                (setupStatus.includes('failed') || setupStatus.includes('Invalid') || setupStatus.includes('timed out')) && { color: Colors.danger },
              ]}>
                {setupStatus}
              </Text>
            )}
            <View style={styles.serverBtns}>
              <TouchableOpacity
                style={[styles.serverBtn, setupTestLoading && styles.btnDisabled]}
                onPress={handleTestServer}
                disabled={setupTestLoading || setupSaveLoading}
              >
                {setupTestLoading
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.serverBtnText}>Test</Text>}
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.serverBtn, styles.serverBtnSave, setupSaveLoading && styles.btnDisabled]}
                onPress={handleSaveServer}
                disabled={setupTestLoading || setupSaveLoading}
              >
                {setupSaveLoading
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.serverBtnText}>Save</Text>}
              </TouchableOpacity>
              {!NetworkService.getServerConfig().isDefault && (
                <TouchableOpacity
                  style={[styles.serverBtn, styles.serverBtnClear]}
                  onPress={handleClearServer}
                >
                  <Text style={styles.serverBtnText}>Reset</Text>
                </TouchableOpacity>
              )}
            </View>
          </View>
        )}
      </View>

      {/* Danger zone */}
      <View style={[styles.section, styles.dangerZone]}>
        <Text style={styles.sectionTitle}>Danger Zone</Text>
        <TouchableOpacity style={styles.outlineBtn} onPress={handleLogout}>
          <Text style={styles.outlineBtnText}>Sign Out</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.dangerBtn, { marginTop: Spacing.sm }]} onPress={handleDeleteAccount}>
          <Text style={styles.dangerBtnText}>Delete Account</Text>
        </TouchableOpacity>
      </View>

      {/* About & License */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>About & License</Text>
        <Text style={{ color: Colors.textMain, marginBottom: Spacing.xs }}>
          WS Messenger
        </Text>
        <Text style={{ color: Colors.textMuted, fontSize: 12, marginBottom: Spacing.sm }}>
          Copyright © 2026 Yevgeniy Kropochev
        </Text>
        <Text style={{ color: Colors.textMuted, fontSize: 12, marginBottom: Spacing.sm }}>
          Licensed under the GNU AGPL-3.0-or-later.{' '}
          <Text
            style={{ color: '#8ab4ff', textDecorationLine: 'underline' }}
            onPress={() => Linking.openURL('https://www.gnu.org/licenses/agpl-3.0.html')}>
            View license
          </Text>
          .
        </Text>
        <Text style={{ color: Colors.textMuted, fontSize: 12, marginBottom: Spacing.sm }}>
          Source code (AGPL §13):{'\n'}
          <Text
            style={{ color: '#8ab4ff', textDecorationLine: 'underline' }}
            onPress={() => Linking.openURL('https://github.com/Eisern/wsmessenger')}>
            https://github.com/Eisern/wsmessenger
          </Text>
        </Text>
        <Text style={{ color: Colors.textMuted, fontSize: 11 }}>
          This program comes with ABSOLUTELY NO WARRANTY.
        </Text>
      </View>

      {/* Disable 2FA Modal */}
      <Modal visible={showDisable2fa} transparent animationType="slide" onRequestClose={() => setShowDisable2fa(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Disable 2FA</Text>
            <Text style={styles.modalSub}>Enter your current authenticator code to confirm.</Text>
            <TextInput
              style={styles.input}
              placeholder="6-digit code"
              placeholderTextColor={Colors.textMuted}
              value={disable2faCode}
              onChangeText={v => setDisable2faCode(v.replace(/\D/g, '').slice(0, 6))}
              keyboardType="numeric"
              maxLength={6}
              autoFocus
              onSubmitEditing={handleConfirmDisable2fa}
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => setShowDisable2fa(false)}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.dangerBtn, setupLoading && styles.btnDisabled]}
                onPress={handleConfirmDisable2fa}
                disabled={setupLoading}
              >
                {setupLoading ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.dangerBtnText}>Disable</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* Change Password Modal */}
      <Modal visible={showChangePassModal} transparent animationType="fade"
        onRequestClose={() => { if (!changePassLoading) setShowChangePassModal(false); }}>
        <View style={styles.recoveryOverlay}>
          <View style={styles.recoveryCard}>
            <Text style={styles.modalTitle}>Change Password</Text>
            {changePassDone ? (
              <>
                <Text style={[styles.modalSub, { color: Colors.success || '#28a745' }]}>
                  Password changed. You have been signed out — please log in again with your new password.
                </Text>
                <TouchableOpacity style={styles.btn} onPress={() => {
                  setShowChangePassModal(false);
                  NetworkService.logout().catch(() => {});
                }}>
                  <Text style={styles.btnText}>OK</Text>
                </TouchableOpacity>
              </>
            ) : (
              <>
                <Text style={styles.changePassWarning}>
                  All other sessions will be signed out on all devices.
                </Text>
                {!!changePassError && <Text style={styles.errorText}>{changePassError}</Text>}
                <TextInput
                  style={styles.input}
                  placeholder="Current password"
                  placeholderTextColor={Colors.textMuted}
                  value={changePassOld}
                  onChangeText={setChangePassOld}
                  secureTextEntry
                  autoFocus
                />
                <TextInput
                  style={styles.input}
                  placeholder="New password (min 8 characters)"
                  placeholderTextColor={Colors.textMuted}
                  value={changePassNew}
                  onChangeText={setChangePassNew}
                  secureTextEntry
                />
                <TextInput
                  style={styles.input}
                  placeholder="Confirm new password"
                  placeholderTextColor={Colors.textMuted}
                  value={changePassConfirm}
                  onChangeText={setChangePassConfirm}
                  secureTextEntry
                  onSubmitEditing={handleChangePassword}
                />
                <View style={styles.modalBtns}>
                  <TouchableOpacity style={styles.cancelBtn}
                    onPress={() => setShowChangePassModal(false)} disabled={changePassLoading}>
                    <Text style={styles.cancelBtnText}>Cancel</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.btn, changePassLoading && styles.btnDisabled]}
                    onPress={handleChangePassword}
                    disabled={changePassLoading}
                  >
                    {changePassLoading
                      ? <ActivityIndicator color="#fff" size="small" />
                      : <Text style={styles.btnText}>Change</Text>}
                  </TouchableOpacity>
                </View>
              </>
            )}
          </View>
        </View>
      </Modal>

      {/* Recovery Phrase Modal */}
      <Modal visible={showRecoveryModal} transparent animationType="fade"
        onRequestClose={() => { setShowRecoveryModal(false); _wipeRecoveryWords(); }}>
        <View style={styles.recoveryOverlay}>
          <View style={styles.recoveryCard}>
            <Text style={styles.modalTitle}>Recovery Phrase</Text>
            {!recoveryWords ? (
              <>
                <Text style={styles.modalSub}>Enter your password to view your 24-word recovery phrase.</Text>
                {!!recoveryError && <Text style={styles.errorText}>{recoveryError}</Text>}
                <TextInput
                  style={styles.input}
                  placeholder="Password"
                  placeholderTextColor={Colors.textMuted}
                  value={recoveryPassword}
                  onChangeText={setRecoveryPassword}
                  secureTextEntry
                  autoFocus
                  onSubmitEditing={handleDecryptRecovery}
                />
                <View style={styles.modalBtns}>
                  <TouchableOpacity style={styles.cancelBtn} onPress={() => setShowRecoveryModal(false)}>
                    <Text style={styles.cancelBtnText}>Cancel</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.btn, recoveryLoading && styles.btnDisabled]}
                    onPress={handleDecryptRecovery}
                    disabled={recoveryLoading}
                  >
                    {recoveryLoading ? <ActivityIndicator color="#fff" size="small" />
                      : <Text style={styles.btnText}>Decrypt</Text>}
                  </TouchableOpacity>
                </View>
              </>
            ) : (
              <>
                <Text style={styles.recoveryWarning}>
                  Write these words down and keep them safe. Anyone with this phrase can access your account.
                </Text>
                <View style={styles.wordGrid}>
                  {recoveryWords.map((word, i) => (
                    <View key={i} style={styles.wordCell}>
                      <Text style={styles.wordIndex}>{i + 1}.</Text>
                      <Text style={styles.wordText}>{word}</Text>
                    </View>
                  ))}
                </View>
                <TouchableOpacity style={styles.btn} onPress={() => { setShowRecoveryModal(false); _wipeRecoveryWords(); }}>
                  <Text style={styles.btnText}>Done</Text>
                </TouchableOpacity>
              </>
            )}
          </View>
        </View>
      </Modal>

      {/* 2FA Setup Modal */}
      <Modal visible={showTwoFaSetup} transparent animationType="slide" onRequestClose={() => setShowTwoFaSetup(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Set Up 2FA</Text>
            <Text style={styles.modalSub}>
              Scan the QR code with your authenticator app, or manually enter the secret.
            </Text>
            {!!totpQr && (
              <TouchableOpacity onPress={() => Linking.openURL(totpQr)}>
                <Text style={styles.linkText}>Open in Authenticator App</Text>
              </TouchableOpacity>
            )}
            {!!totpSecret && (
              <View style={styles.secretBox}>
                <Text style={styles.secretLabel}>Manual key:</Text>
                <Text style={styles.secretValue} selectable>{totpSecret}</Text>
              </View>
            )}
            <TextInput
              style={styles.input}
              placeholder="6-digit code"
              placeholderTextColor={Colors.textMuted}
              value={totpCode}
              onChangeText={v => setTotpCode(v.replace(/\D/g, '').slice(0, 6))}
              keyboardType="numeric"
              maxLength={6}
              onSubmitEditing={handleConfirm2fa}
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => { setShowTwoFaSetup(false); setTotpCode(''); setTotpSecret(''); setTotpQr(''); }}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.btn, setupLoading && styles.btnDisabled]}
                onPress={handleConfirm2fa}
                disabled={setupLoading}
              >
                {setupLoading ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.btnText}>Confirm</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>

      {/* Delete account re-auth modal */}
      <Modal visible={showDeleteModal} transparent animationType="fade" onRequestClose={() => { setShowDeleteModal(false); setDeletePassword(''); }}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Delete Account</Text>
            <Text style={styles.modalHint}>This action is irreversible. Enter your password to confirm.</Text>
            {!!deleteError && <Text style={styles.errorText}>{deleteError}</Text>}
            <TextInput
              style={styles.modalInput}
              placeholder="Password"
              placeholderTextColor={Colors.textMuted}
              value={deletePassword}
              onChangeText={setDeletePassword}
              secureTextEntry
              autoFocus
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => { setShowDeleteModal(false); setDeletePassword(''); }}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.dangerBtn, deleteLoading && { opacity: 0.6 }]}
                onPress={confirmDeleteAccount}
                disabled={deleteLoading}
              >
                {deleteLoading ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.dangerBtnText}>Delete Forever</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: Colors.bgMain },
  scroll: { paddingBottom: Spacing.xxl },
  header: {
    paddingHorizontal: Spacing.lg,
    paddingBottom: Spacing.md,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle,
    elevation: 4,
  },
  title: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain },
  section: {
    backgroundColor: Colors.bgPane,
    marginTop: Spacing.md,
    marginHorizontal: Spacing.md,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.lg,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.08)',
    borderRadius: 14,
    gap: Spacing.md,
  },
  dangerZone: {
    borderColor: 'rgba(248,81,73,0.3)',
    marginTop: Spacing.lg,
  },
  sectionTitle: {
    fontSize: Typography.sm,
    fontWeight: '600',
    color: Colors.textMuted,
    textTransform: 'uppercase',
    letterSpacing: 0.8,
    marginBottom: Spacing.xs,
  },
  avatarRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.lg,
  },
  avatar: {
    width: 52,
    height: 52,
    borderRadius: 26,
    backgroundColor: 'rgba(88,166,255,0.2)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  avatarText: { fontSize: Typography.xxl, fontWeight: '700', color: Colors.accent },
  username: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain },
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
  switchRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  switchLabel: { fontSize: Typography.md, color: Colors.textMain, flex: 1 },
  privacyHint: { fontSize: Typography.xs, color: Colors.textMuted, marginTop: Spacing.xs },
  statusRow: { flexDirection: 'row', alignItems: 'center' },
  statusValue: { fontSize: Typography.md, fontWeight: '600' },
  statusOn: { color: Colors.success },
  statusOff: { color: Colors.textMuted },
  btn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    alignItems: 'center',
  },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: '#fff', fontSize: Typography.md, fontWeight: '600' },
  outlineBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: Colors.border,
  },
  outlineBtnText: { color: Colors.textMain, fontSize: Typography.md },
  dangerBtn: {
    backgroundColor: '#dc3545',
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    alignItems: 'center',
  },
  dangerBtnText: { color: '#fff', fontSize: Typography.md, fontWeight: '600' },
  label: { fontSize: Typography.sm, color: Colors.textMuted },
  fingerprint: {
    fontSize: Typography.sm,
    color: Colors.success,
    fontFamily: 'monospace',
    letterSpacing: 1,
  },
  linkText: { color: Colors.accent, fontSize: Typography.md, textDecorationLine: 'underline' },
  secretBox: {
    backgroundColor: Colors.inputBg,
    borderRadius: Radii.md,
    padding: Spacing.md,
    gap: Spacing.xs,
  },
  secretLabel: { fontSize: Typography.sm, color: Colors.textMuted },
  secretValue: {
    fontSize: Typography.md,
    color: Colors.textMain,
    fontFamily: 'monospace',
    letterSpacing: 1,
  },
  // Modal
  modalOverlay: { flex: 1, backgroundColor: Colors.overlay, justifyContent: 'flex-end' },
  modalCard: {
    backgroundColor: Colors.bgPanel,
    borderTopLeftRadius: 14,
    borderTopRightRadius: 14,
    padding: Spacing.xxl,
    gap: Spacing.md,
    borderTopWidth: 1,
    borderColor: Colors.border,
    elevation: 8,
  },
  modalTitle: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain },
  modalHint: { fontSize: Typography.md, color: Colors.textMuted },
  modalInput: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.md,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  modalSub: { fontSize: Typography.md, color: Colors.textMuted },
  modalBtns: { flexDirection: 'row', gap: Spacing.md, justifyContent: 'flex-end', marginTop: Spacing.sm },
  cancelBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  cancelBtnText: { color: Colors.textMain, fontSize: Typography.md },
  errorText: { color: Colors.danger, fontSize: Typography.sm, textAlign: 'center' },
  changePassWarning: { color: Colors.textMuted, fontSize: Typography.sm, textAlign: 'center', marginBottom: 8 },
  // Font size picker
  previewBubble: {
    backgroundColor: Colors.bgCard,
    borderRadius: Radii.lg,
    padding: Spacing.lg,
    borderWidth: 1,
    borderColor: Colors.borderSubtle,
  },
  previewAuthor: {
    fontSize: Typography.sm,
    color: Colors.authorName,
    fontWeight: '600',
    marginBottom: 4,
  },
  previewMsg: { color: Colors.textMain },
  previewTs: { fontSize: Typography.xs, color: Colors.textDim, textAlign: 'right', marginTop: 4 },
  fontChipRow: { flexDirection: 'row', gap: Spacing.sm },
  fontChip: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: Spacing.md,
    borderRadius: Radii.md,
    borderWidth: 1,
    borderColor: Colors.border,
    backgroundColor: Colors.inputBg,
    gap: 2,
  },
  fontChipActive: {
    borderColor: Colors.accent,
    backgroundColor: 'rgba(88,166,255,0.15)',
  },
  timeoutRow: { flexDirection: 'row', flexWrap: 'wrap', gap: Spacing.sm },
  timeoutChip: {
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderRadius: Radii.md,
    borderWidth: 1,
    borderColor: Colors.border,
    backgroundColor: Colors.inputBg,
  },
  timeoutChipActive: {
    borderColor: Colors.accent,
    backgroundColor: 'rgba(88,166,255,0.15)',
  },
  timeoutChipText: { color: Colors.textMuted, fontSize: Typography.sm },
  timeoutChipTextActive: { color: Colors.accent, fontWeight: '600' },
  // Recovery phrase modal
  recoveryOverlay: { flex: 1, backgroundColor: 'rgba(0,0,0,0.85)', justifyContent: 'center', padding: Spacing.lg },
  recoveryCard: {
    backgroundColor: Colors.bgPanel,
    borderRadius: 14,
    padding: Spacing.xxl,
    gap: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.border,
    elevation: 8,
  },
  recoveryWarning: {
    fontSize: Typography.md,
    color: Colors.warning || '#f0ad4e',
    textAlign: 'center',
    lineHeight: 22,
  },
  wordGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  wordCell: {
    flexDirection: 'row',
    alignItems: 'center',
    width: '30%',
    marginBottom: Spacing.sm,
    backgroundColor: Colors.inputBg,
    borderRadius: Radii.sm || 4,
    paddingHorizontal: Spacing.sm,
    paddingVertical: Spacing.xs,
  },
  wordIndex: { color: Colors.textMuted, fontSize: Typography.sm, width: 24 },
  wordText: { color: Colors.textMain, fontSize: Typography.md, fontWeight: '600' },
  // Server config
  serverToggle: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  serverChevron: { color: Colors.textMuted, fontSize: Typography.sm, marginLeft: Spacing.sm },
  serverBtns: { flexDirection: 'row', gap: Spacing.sm },
  serverBtn: {
    flex: 1,
    paddingVertical: Spacing.sm,
    borderRadius: Radii.md,
    alignItems: 'center',
    backgroundColor: 'rgba(255,255,255,0.07)',
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.1)',
  },
  serverBtnSave: {
    backgroundColor: '#1a7a3a',
    borderColor: '#28a745',
  },
  serverBtnClear: {
    backgroundColor: 'rgba(248,81,73,0.15)',
    borderColor: Colors.danger,
  },
  serverBtnText: { color: Colors.textMain, fontSize: Typography.sm, fontWeight: '600' },
});
