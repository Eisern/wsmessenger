// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * LoginScreen.js — Login + 2FA flow
 * Ported from login.html / login.js
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  View, Text, TextInput, TouchableOpacity,
  StyleSheet, ActivityIndicator,
  ScrollView, Alert,
} from 'react-native';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';
import ServerSetup from '../components/ServerSetup';
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';

export default function LoginScreen({ navigation }) {
  const { dispatch } = useApp();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // 2FA state
  const [show2fa, setShow2fa] = useState(false);
  const [tempToken, setTempToken] = useState('');
  const [code2fa, setCode2fa] = useState('');

  const passwordRef = useRef(null);
  const codeRef = useRef(null);

  // Server setup — the whole form lives in <ServerSetup/>, shared with ProfileScreen
  const [showServerSetup, setShowServerSetup] = useState(false);
  const [serverCfg, setServerCfg] = useState(() => NetworkService.getServerConfig());

  useEffect(() => {
    const onChanged = () => setServerCfg(NetworkService.getServerConfig());
    NetworkService.on('endpoint_changed', onChanged);
    return () => NetworkService.off('endpoint_changed', onChanged);
  }, []);

  async function handleLogin() {
    if (!username.trim() || !password.trim()) {
      setError('Enter username and password');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const result = await NetworkService.login(username.trim(), password);
      if (result.ok) {
        const resolvedUsername = result.username || username.trim();
        const uLower = resolvedUsername.toLowerCase();
        // StorageService.setAuth() is already called inside NetworkService._setSession()
        // Check if we have local identity (EPK) — required for E2EE
        const identity = await StorageService.getIdentity(uLower);
        if (!identity) {
          // No local identity — user must import key first
          setLoading(false);
          Alert.alert(
            'Encryption key not found',
            'No encryption key on this device. Use your 24-word recovery phrase to set up E2EE.',
            [
              { text: 'Import Key', onPress: () => navigation.navigate('ImportKey', { username: resolvedUsername, token: result.token }) },
            ],
          );
          return;
        }
        const unlocked = await CryptoService.unlockWithPassword(password);
        if (!unlocked) {
          setError('Failed to unlock encryption. Your local key may be corrupted — try importing your recovery phrase.');
          return;
        }
        await StorageService.setActiveUsername(uLower).catch(() => {});
        dispatch({ type: 'SET_AUTH', username: resolvedUsername, token: result.token });
      } else if (result.requires_2fa) {
        setTempToken(result.temp_token);
        setShow2fa(true);
      } else if (result.banned) {
        setError('Account is banned.');
      } else {
        setError(result.error || 'Login failed');
      }
    } catch (e) {
      setError(e?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }

  async function handle2fa() {
    if (code2fa.length !== 6) {
      setError('Enter the 6-digit code');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const result = await NetworkService.verify2fa(tempToken, code2fa);
      if (result.ok) {
        const resolvedUsername = result.username || username.trim();
        const uLower = resolvedUsername.toLowerCase();
        const resolvedToken = result.token;
        // StorageService.setAuth() is already called inside NetworkService._setSession()
        const identity = await StorageService.getIdentity(uLower);
        if (!identity) {
          setLoading(false);
          Alert.alert(
            'Encryption key not found',
            'No encryption key on this device. Use your 24-word recovery phrase to set up E2EE.',
            [
              { text: 'Import Key', onPress: () => navigation.navigate('ImportKey', { username: resolvedUsername, token: resolvedToken }) },
            ],
          );
          return;
        }
        const unlocked = await CryptoService.unlockWithPassword(password);
        if (!unlocked) {
          setError('Failed to unlock encryption. Your local key may be corrupted — try importing your recovery phrase.');
          return;
        }
        await StorageService.setActiveUsername(uLower).catch(() => {});
        dispatch({ type: 'SET_AUTH', username: resolvedUsername, token: resolvedToken });
      } else {
        setError(result.error || 'Invalid code');
        setCode2fa('');
      }
    } catch (e) {
      setError(e?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }

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
              <Text style={styles.linkText}>← Back to login</Text>
            </TouchableOpacity>
          </View>
        </ScrollView>
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.card}>
          <Text style={styles.title}>WS Messenger</Text>
          <Text style={styles.subtitle}>Sign in to your account</Text>
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
            returnKeyType="go"
            onSubmitEditing={handleLogin}
          />
          <TouchableOpacity
            style={[styles.btn, loading && styles.btnDisabled]}
            onPress={handleLogin}
            disabled={loading}
          >
            {loading
              ? <ActivityIndicator color="#fff" />
              : <Text style={styles.btnText}>Sign In</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={() => navigation.navigate('Register')}>
            <Text style={styles.linkText}>Create an account →</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => navigation.navigate('ImportKey')}>
            <Text style={styles.linkText}>Import existing account →</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={() => navigation.navigate('Recovery')}>
            <Text style={styles.linkText}>Forgot password?</Text>
          </TouchableOpacity>

          {/* Server setup */}
          <View style={styles.serverDivider} />
          <TouchableOpacity
            style={styles.serverToggle}
            onPress={() => setShowServerSetup(v => !v)}
          >
            <Text style={styles.serverToggleText}>
              {serverCfg.isDefault
                ? 'Connect to another server'
                : `Server: ${serverCfg.apiBase.replace(/^https?:\/\//, '')}` +
                  (serverCfg.endpoints.length > 1 ? ` (+${serverCfg.endpoints.length - 1})` : '')}
            </Text>
            <Text style={styles.serverToggleChevron}>{showServerSetup ? '▴' : '▾'}</Text>
          </TouchableOpacity>

          {showServerSetup && (
            <View style={styles.serverSetupBox}>
              <ServerSetup onSaved={() => setServerCfg(NetworkService.getServerConfig())} />
            </View>
          )}
        </View>
      </ScrollView>
    </View>
  );
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
  serverDivider: {
    height: 1,
    backgroundColor: 'rgba(255,255,255,0.07)',
    marginTop: Spacing.md,
  },
  serverToggle: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: Spacing.sm,
  },
  serverToggleText: {
    flex: 1,
    color: Colors.textMuted,
    fontSize: Typography.sm,
  },
  serverToggleChevron: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
  },
  serverSetupBox: {
    gap: Spacing.sm,
    paddingTop: Spacing.xs,
  },
  // The form itself (inputs, buttons, status) now lives in ServerSetup.js,
  // which carries its own styles.
});
