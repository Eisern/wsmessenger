// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ServerSetup.js — the island's entry points, edited in one place.
 *
 * An island is one backend with one database; it may be reachable through
 * several entry points (several of its own domains, volunteer bridges later).
 * The client tries them in order and fails over without touching the session,
 * so this form edits a LIST, not a single address.
 *
 * LoginScreen and ProfileScreen used to carry two byte-identical copies of this
 * form, its URL validation and its /health probe.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { View, Text, TextInput, TouchableOpacity, StyleSheet, ActivityIndicator } from 'react-native';
import { useFocusEffect } from '@react-navigation/native';
import NetworkService from '../services/NetworkService';
import EP from '../services/endpoints';
import { Colors, Spacing, Radii, Typography } from '../theme';

const PROBE_TIMEOUT_MS = 5000;

/** Same rule as the extension's login page: https only, http for localhost. */
function validateApiBase(raw) {
  const api = String(raw || '').trim().replace(/\/$/, '');
  if (!api) return { error: 'Enter a server address' };
  let parsed;
  try { parsed = new URL(api); } catch { return { error: 'Invalid URL' }; }
  if (!['https:', 'http:'].includes(parsed.protocol)) return { error: 'URL must start with https://' };
  if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1'].includes(parsed.hostname)) {
    return { error: 'HTTP is only allowed for localhost' };
  }
  return { apiBase: parsed.origin, wsBase: EP.deriveWsBase(parsed.origin) };
}

async function probe(apiBase) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    const r = await fetch(apiBase + '/health', { cache: 'no-store', signal: ctrl.signal });
    return r.ok ? 'ok' : `HTTP ${r.status}`;
  } catch (e) {
    return e?.name === 'AbortError' ? 'timed out' : 'unreachable';
  } finally {
    clearTimeout(timer);
  }
}

export default function ServerSetup({ onSaved, savedHint }) {
  const [cfg, setCfg] = useState(() => NetworkService.getServerConfig());
  const [endpoints, setEndpoints] = useState(() => NetworkService.getServerConfig().endpoints.map(e => e.apiBase));
  const [draft, setDraft] = useState('');
  const [status, setStatus] = useState('');
  const [probes, setProbes] = useState({});   // apiBase -> 'ok' | reason | 'testing'
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);

  const reload = useCallback(() => {
    const next = NetworkService.getServerConfig();
    setCfg(next);
    setEndpoints(next.endpoints.map(e => e.apiBase));
  }, []);

  // The active entry point changes underneath us on failover, and the list can
  // be edited from the other screen — never render from a stale snapshot.
  useEffect(() => {
    const onChanged = () => reload();
    NetworkService.on('endpoint_changed', onChanged);
    return () => NetworkService.off('endpoint_changed', onChanged);
  }, [reload]);

  useFocusEffect(useCallback(() => { reload(); }, [reload]));

  function addEndpoint() {
    const v = validateApiBase(draft);
    if (v.error) { setStatus(v.error); return; }
    if (endpoints.includes(v.apiBase)) { setStatus('Already in the list'); return; }
    if (endpoints.length >= EP.MAX_ENDPOINTS) { setStatus(`At most ${EP.MAX_ENDPOINTS} entry points`); return; }
    setEndpoints([...endpoints, v.apiBase]);
    setDraft('');
    setStatus('');
  }

  function removeEndpoint(apiBase) {
    setEndpoints(endpoints.filter(e => e !== apiBase));
    setStatus('');
  }

  function promote(apiBase) {
    const i = endpoints.indexOf(apiBase);
    if (i <= 0) return;
    const next = endpoints.slice();
    next.splice(i, 1);
    next.splice(i - 1, 0, apiBase);
    setEndpoints(next);
  }

  async function testAll() {
    const list = endpoints.length ? endpoints : [validateApiBase(draft).apiBase].filter(Boolean);
    if (!list.length) { setStatus('Add a server address first'); return; }
    setTesting(true);
    setStatus('Testing...');
    const results = {};
    for (const apiBase of list) {
      setProbes(p => ({ ...p, [apiBase]: 'testing' }));
      // Sequential on purpose: probing every domain of an island at once lights
      // them all up in one burst, which is the opposite of what a client whose
      // reason to exist is surviving blocks should do.
      results[apiBase] = await probe(apiBase);
      setProbes(p => ({ ...p, [apiBase]: results[apiBase] }));
    }
    const okCount = Object.values(results).filter(r => r === 'ok').length;
    setStatus(okCount ? `${okCount} of ${list.length} reachable OK` : 'None reachable');
    setTesting(false);
  }

  async function save() {
    let list = endpoints;
    if (draft.trim()) {
      const v = validateApiBase(draft);
      if (v.error) { setStatus(v.error); return; }
      if (!list.includes(v.apiBase)) list = [...list, v.apiBase];
    }
    if (!list.length) { setStatus('Add at least one entry point, or press Reset'); return; }

    // Keep using the entry point we are on, if it is still in the list.
    const activeIdx = Math.max(0, list.indexOf(cfg.apiBase));
    setSaving(true);
    setStatus('Saving...');
    try {
      const change = await NetworkService.saveIsland({
        schema: 2,
        endpoints: list.map(apiBase => ({ apiBase })),
        activeIdx,
      });
      setDraft('');
      reload();
      setStatus(
        change === 'island'
          ? (savedHint || 'Saved OK - this is a different server, sign in again')
          : 'Saved OK - session kept',
      );
      if (onSaved) onSaved(change);
    } catch (e) {
      setStatus('Save failed: ' + (e?.message || 'unknown error'));
    } finally {
      setSaving(false);
    }
  }

  async function reset() {
    setSaving(true);
    try {
      await NetworkService.clearServerConfig();
      reload();
      setProbes({});
      setDraft('');
      setStatus('Using the default server');
      if (onSaved) onSaved('island');
    } finally {
      setSaving(false);
    }
  }

  const busy = testing || saving;
  const statusColor =
    status.includes('OK') ? Colors.success
      : (status.includes('failed') || status.includes('Invalid') || status.includes('None') || status.includes('At most')) ? Colors.danger
        : Colors.textMuted;

  return (
    <View style={styles.box}>
      <Text style={styles.hint}>
        Several addresses for the same server. If one is blocked, the app moves to the next one
        without losing your session.
      </Text>

      {endpoints.map((apiBase, i) => {
        const isActive = apiBase === cfg.apiBase;
        const p = probes[apiBase];
        return (
          <View key={apiBase} style={styles.row}>
            <Text style={[styles.rowIdx, isActive && styles.rowIdxActive]}>{isActive ? '●' : i + 1}</Text>
            <View style={styles.rowMain}>
              <Text style={styles.rowHost} numberOfLines={1}>{apiBase.replace(/^https?:\/\//, '')}</Text>
              {!!p && (
                <Text style={[
                  styles.rowProbe,
                  p === 'ok' && { color: Colors.success },
                  p !== 'ok' && p !== 'testing' && { color: Colors.danger },
                ]}>
                  {p === 'testing' ? 'testing...' : p}
                </Text>
              )}
            </View>
            {i > 0 && (
              <TouchableOpacity style={styles.rowBtn} onPress={() => promote(apiBase)} disabled={busy}>
                <Text style={styles.rowBtnText}>{'↑'}</Text>
              </TouchableOpacity>
            )}
            <TouchableOpacity style={styles.rowBtn} onPress={() => removeEndpoint(apiBase)} disabled={busy}>
              <Text style={[styles.rowBtnText, { color: Colors.danger }]}>{'×'}</Text>
            </TouchableOpacity>
          </View>
        );
      })}

      <View style={styles.addRow}>
        <TextInput
          style={styles.input}
          placeholder="https://your-server.example"
          placeholderTextColor={Colors.textMuted}
          value={draft}
          onChangeText={setDraft}
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          onSubmitEditing={addEndpoint}
        />
        <TouchableOpacity style={styles.addBtn} onPress={addEndpoint} disabled={busy}>
          <Text style={styles.addBtnText}>+</Text>
        </TouchableOpacity>
      </View>

      {!!status && <Text style={[styles.status, { color: statusColor }]}>{status}</Text>}

      <View style={styles.btns}>
        <TouchableOpacity style={[styles.btn, busy && styles.btnDisabled]} onPress={testAll} disabled={busy}>
          {testing ? <ActivityIndicator color="#fff" size="small" /> : <Text style={styles.btnText}>Test all</Text>}
        </TouchableOpacity>
        <TouchableOpacity style={[styles.btn, styles.btnSave, busy && styles.btnDisabled]} onPress={save} disabled={busy}>
          {saving ? <ActivityIndicator color="#fff" size="small" /> : <Text style={styles.btnText}>Save</Text>}
        </TouchableOpacity>
        {!cfg.isDefault && (
          <TouchableOpacity style={[styles.btn, styles.btnClear, busy && styles.btnDisabled]} onPress={reset} disabled={busy}>
            <Text style={styles.btnText}>Reset</Text>
          </TouchableOpacity>
        )}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  box: { gap: Spacing.sm },
  hint: { fontSize: Typography.sm, color: Colors.textMuted, marginBottom: Spacing.xs },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
    backgroundColor: Colors.bgCard,
    borderWidth: 1,
    borderColor: Colors.borderSubtle,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
  },
  rowIdx: { width: 16, textAlign: 'center', color: Colors.textMuted, fontSize: Typography.sm },
  rowIdxActive: { color: Colors.accent },
  rowMain: { flex: 1 },
  rowHost: { color: Colors.textMain, fontSize: Typography.md },
  rowProbe: { fontSize: Typography.xs, color: Colors.textMuted },
  rowBtn: { paddingHorizontal: Spacing.md, paddingVertical: 2 },
  rowBtnText: { color: Colors.textMuted, fontSize: Typography.xxl },
  addRow: { flexDirection: 'row', alignItems: 'center', gap: Spacing.sm },
  input: {
    flex: 1,
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  addBtn: {
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    borderRadius: Radii.md,
    backgroundColor: Colors.btnBg,
  },
  addBtnText: { color: Colors.textMain, fontSize: Typography.xl },
  status: { fontSize: Typography.sm },
  btns: { flexDirection: 'row', gap: Spacing.sm },
  btn: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: Spacing.md,
    borderRadius: Radii.md,
    backgroundColor: Colors.btnBg,
  },
  btnSave: { backgroundColor: Colors.accent },
  btnClear: { backgroundColor: Colors.danger },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: '#fff', fontSize: Typography.md, fontWeight: '600' },
});
