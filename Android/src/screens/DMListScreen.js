// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * DMListScreen.js — Direct message threads list
 * Ported from panel-ui.js DM section
 */

import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, TextInput, RefreshControl, Modal, Alert, ActivityIndicator,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';

const DM_PINNED_KEY = 'dm_pinned_threads_v1';
const MAX_PINNED = 50;

// Deterministic color for username
function colorForUsername(name) {
  const COLORS = ['#58a6ff','#79c0ff','#d2a8ff','#f78166','#56d364','#e3b341','#3aa0ff','#4ac26b'];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (Math.imul(31, h) + name.charCodeAt(i)) | 0;
  return COLORS[Math.abs(h) % COLORS.length];
}

export default function DMListScreen({ navigation }) {
  const { state, dispatch, loadDmThreads, openDmThread } = useApp();
  const insets = useSafeAreaInsets();
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState('');
  const [showNewDM, setShowNewDM] = useState(false);
  const [pinnedIds, setPinnedIds] = useState([]); // string[]

  // Load pinned IDs from storage on mount
  useEffect(() => {
    AsyncStorage.getItem(DM_PINNED_KEY).then(raw => {
      try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) setPinnedIds(arr.map(String));
      } catch {}
    });
  }, []);

  function savePins(ids) {
    setPinnedIds(ids);
    AsyncStorage.setItem(DM_PINNED_KEY, JSON.stringify(ids)).catch(() => {});
  }

  function togglePin(threadId) {
    const tid = String(threadId);
    setPinnedIds(prev => {
      const newList = prev.includes(tid)
        ? prev.filter(x => x !== tid)                  // unpin
        : [tid, ...prev].slice(0, MAX_PINNED);         // pin to front
      AsyncStorage.setItem(DM_PINNED_KEY, JSON.stringify(newList)).catch(() => {});
      return newList;
    });
  }

  useEffect(() => {
    loadDmThreads();
  }, []);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    await loadDmThreads();
    setRefreshing(false);
  }, [loadDmThreads]);

  const threads = useMemo(() => {
    const filtered = (state.dmThreads || []).filter(t => {
      if (!search) return true;
      return (t.peer_username || '').toLowerCase().includes(search.toLowerCase());
    });
    // Sort: pinned first (in pin order), then the rest
    return [...filtered].sort((a, b) => {
      const aTid = String(a.thread_id || a.id);
      const bTid = String(b.thread_id || b.id);
      const aPin = pinnedIds.indexOf(aTid);
      const bPin = pinnedIds.indexOf(bTid);
      if (aPin !== -1 && bPin !== -1) return aPin - bPin;
      if (aPin !== -1) return -1;
      if (bPin !== -1) return 1;
      return 0; // preserve server order for unpinned
    });
  }, [state.dmThreads, search, pinnedIds]);

  function handleThreadPress(thread) {
    const tid = thread.thread_id || thread.id;
    const peer = thread.peer_username || thread.peer;
    dispatch({ type: 'CLEAR_UNREAD_DM', threadId: tid });
    // openDmThread: creates delivery secret (POST /dm/open) + connects WS
    openDmThread(tid, peer);
    navigation.navigate('DMChat', { threadId: tid, peer });
  }

  function handleThreadLongPress(thread) {
    const tid = thread.thread_id || thread.id;
    const peer = thread.peer_username || thread.peer;
    const isPinned = pinnedIds.includes(String(tid));

    Alert.alert(
      `Conversation with ${peer}`,
      'Choose an action:',
      [
        {
          text: isPinned ? 'Unpin' : 'Pin',
          onPress: () => togglePin(tid),
        },
        {
          text: 'Delete for me',
          onPress: () => confirmDelete(tid, 'self'),
        },
        {
          text: 'Delete for both',
          style: 'destructive',
          onPress: () => confirmDelete(tid, 'both'),
        },
        { text: 'Cancel', style: 'cancel' },
      ]
    );
  }

  async function confirmDelete(threadId, scope) {
    try {
      const res = await NetworkService.deleteDmThread(threadId, scope);
      if (res?.pending_confirmation) {
        Alert.alert(
          'Pending',
          `Deletion request sent to your peer. It will be confirmed automatically within ${res.confirm_ttl_sec || 60} seconds if they agree.`
        );
      }
      dispatch({ type: 'REMOVE_DM_THREAD', threadId });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not delete conversation');
    }
  }

  function renderThread({ item }) {
    const tid = item.thread_id || item.id;
    const peer = item.peer_username || item.peer;
    const unread = state.unreadDms[tid] || item.unread_count || 0;
    const lastMsg = item.last_message || item.last_body || '';
    const rawTs = item.last_ts || item.updated_at;
    const ts = rawTs != null && rawTs < 1e12 ? rawTs * 1000 : rawTs;
    const color = colorForUsername(peer || '');
    const isPinned = pinnedIds.includes(String(tid));

    return (
      <TouchableOpacity
        style={[styles.threadRow, isPinned && styles.threadRowPinned]}
        onPress={() => handleThreadPress(item)}
        onLongPress={() => handleThreadLongPress(item)}
        delayLongPress={500}
        activeOpacity={0.7}
      >
        {/* Avatar */}
        <View style={[styles.avatar, { backgroundColor: color + '33' }]}>
          <Text style={[styles.avatarText, { color }]}>{(peer || '?')[0].toUpperCase()}</Text>
        </View>
        <View style={styles.threadInfo}>
          <View style={styles.threadTopRow}>
            <Text style={[styles.peerName, { color }]}>
              {isPinned ? '\ud83d\udccc ' : ''}{peer}
            </Text>
            {ts ? <Text style={styles.tsText}>{new Date(ts).toLocaleDateString()}</Text> : null}
          </View>
          {!!lastMsg && <Text style={styles.preview} numberOfLines={1}>{lastMsg}</Text>}
        </View>
        {unread > 0 && (
          <View style={styles.badge}>
            <Text style={styles.badgeText}>{unread > 99 ? '99+' : unread}</Text>
          </View>
        )}
      </TouchableOpacity>
    );
  }

  return (
    <View style={styles.root}>
      {/* Header */}
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <Text style={styles.title}>Messages</Text>
        <TouchableOpacity style={styles.newBtn} onPress={() => setShowNewDM(true)}>
          <Text style={styles.newBtnText}>+ New</Text>
        </TouchableOpacity>
      </View>

      {/* Search */}
      <View style={styles.searchRow}>
        <TextInput
          style={styles.searchInput}
          placeholder="Search conversations…"
          placeholderTextColor={Colors.textMuted}
          value={search}
          onChangeText={setSearch}
        />
      </View>

      {/* Status */}
      <View style={styles.statusRow}>
        <View style={[styles.statusDot, state.dmWsOnline ? styles.online : styles.offline]} />
        <Text style={styles.statusText}>{state.dmWsOnline ? 'DM Connected' : 'DM Offline'}</Text>
      </View>

      <FlatList
        data={threads}
        keyExtractor={(t) => String(t.thread_id || t.id)}
        renderItem={renderThread}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={handleRefresh} tintColor={Colors.textMuted} />}
        ListEmptyComponent={
          <Text style={styles.emptyText}>No conversations yet</Text>
        }
      />

      <NewDMModal
        visible={showNewDM}
        onClose={() => setShowNewDM(false)}
        onCreated={(thread) => {
          setShowNewDM(false);
          handleThreadPress(thread);
        }}
      />
    </View>
  );
}

// ---- New DM modal ----

function NewDMModal({ visible, onClose, onCreated }) {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleStart() {
    if (!username.trim()) { setError('Enter a username'); return; }
    setLoading(true);
    setError('');
    try {
      const thread = await NetworkService.startDmThread(username.trim());
      setUsername('');
      onCreated(thread);
    } catch (e) {
      setError(e?.message || 'Could not start conversation');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.modalCard}>
          <Text style={styles.modalTitle}>New Message</Text>
          {!!error && <Text style={styles.errorText}>{error}</Text>}
          <TextInput
            style={styles.input}
            placeholder="Username"
            placeholderTextColor={Colors.textMuted}
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            autoFocus
            onSubmitEditing={handleStart}
            returnKeyType="go"
          />
          <View style={styles.modalBtns}>
            <TouchableOpacity style={styles.cancelBtn} onPress={onClose}>
              <Text style={styles.cancelBtnText}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={handleStart}
              disabled={loading}
            >
              {loading ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.btnText}>Start</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: Colors.bgMain },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: Spacing.lg,
    paddingBottom: Spacing.md,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle,
    elevation: 4,
  },
  title: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain },
  newBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.sm,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  newBtnText: { color: Colors.textMain, fontSize: Typography.sm },
  searchRow: {
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle,
  },
  searchInput: {
    backgroundColor: Colors.inputBg,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.xs,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  statusDot: { width: 8, height: 8, borderRadius: 4, marginRight: Spacing.sm },
  online: { backgroundColor: Colors.success },
  offline: { backgroundColor: Colors.danger },
  statusText: { fontSize: Typography.xs, color: Colors.textMuted },
  threadRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: Spacing.md,
    marginVertical: 3,
    padding: Spacing.md,
    paddingHorizontal: Spacing.lg,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.12)',
    borderRadius: Radii.md,
    backgroundColor: 'rgba(255,255,255,0.06)',
    gap: Spacing.md,
  },
  threadRowPinned: {
    borderColor: 'rgba(88,166,255,0.3)',
    backgroundColor: 'rgba(88,166,255,0.08)',
  },
  avatar: {
    width: 36,
    height: 36,
    borderRadius: Radii.md,
    alignItems: 'center',
    justifyContent: 'center',
  },
  avatarText: { fontSize: Typography.lg, fontWeight: '700' },
  threadInfo: { flex: 1 },
  threadTopRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  peerName: { fontSize: Typography.md, fontWeight: '600', color: Colors.textMain },
  tsText: { fontSize: Typography.xs, color: Colors.textMuted },
  preview: { fontSize: Typography.sm, color: Colors.textMuted, marginTop: 2 },
  badge: {
    backgroundColor: Colors.accentDm,
    borderRadius: Radii.round,
    minWidth: 20,
    height: 20,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: Spacing.xs,
  },
  badgeText: { color: '#fff', fontSize: Typography.xs, fontWeight: '700' },
  emptyText: { textAlign: 'center', color: Colors.textMuted, marginTop: Spacing.xxl },
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
  modalBtns: { flexDirection: 'row', gap: Spacing.md, justifyContent: 'flex-end' },
  btn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    alignItems: 'center',
  },
  btnDisabled: { opacity: 0.6 },
  btnText: { color: '#fff', fontSize: Typography.md, fontWeight: '600' },
  cancelBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  cancelBtnText: { color: Colors.textMain, fontSize: Typography.md },
  errorText: { color: Colors.danger, fontSize: Typography.sm },
});
