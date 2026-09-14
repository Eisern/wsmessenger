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
import Clipboard from '@react-native-clipboard/clipboard';
import { useFocusEffect } from '@react-navigation/native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import CryptoService from '../services/CryptoService';
import ForeignService from '../services/ForeignService';
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

  // Contacts on other islands. They are kept apart from local conversations
  // because they are a different kind of thing: reached by a key rather than by
  // a name, and living half on another server. Opening one lands in the
  // ordinary chat screen — the mailbox is an ordinary thread here.
  const [foreign, setForeign] = useState([]);
  const [showCard, setShowCard] = useState(false);
  const [cardText, setCardText] = useState('');
  const [showAdd, setShowAdd] = useState(false);

  const loadForeign = useCallback(async () => {
    try {
      setForeign(await ForeignService.listContacts());
    } catch (e) {
      console.warn('[DMList] foreign contacts:', e?.message || e);
    }
  }, []);

  // Re-read on focus: a contact may have been added, removed or claimed while
  // the chat screen was open, and the one line each row shows is exactly the
  // state that changes there.
  useFocusEffect(useCallback(() => { loadForeign(); }, [loadForeign]));

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

  // ---- Cross-island contacts ----

  async function openForeign(contact) {
    try {
      if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: false });
      let c = contact;
      if (!c.outbox?.keyB64) {
        // Still one-way until they add us; the conversation opens either way,
        // because their messages to us arrive regardless.
        try { c = await ForeignService.claimOutbox(c); } catch (_e) { /* keep going */ }
      }
      await ForeignService.ensureKeysReady(c);
      // Opening the conversation is the moment the user cares whether anything
      // is still waiting, and usually the moment connectivity came back.
      ForeignService.drainOutbox().catch(() => {});
      // Cheap and throttled: better to learn their island moved while the old
      // address still answers than the first time it does not.
      ForeignService.refreshIsland(c).catch(() => {});

      const tid = ForeignService.threadIdOf(c);
      dispatch({ type: 'CLEAR_UNREAD_DM', threadId: tid });
      dispatch({ type: 'SET_CURRENT_DM', threadId: tid, peer: c.displayName });
      // Not openDmThread(): POST /dm/open names a local user, and this peer has
      // no account here. The socket is all that is needed — we are the only
      // member of this thread.
      NetworkService.connectDm(tid, '');
      loadForeign();
      navigation.navigate('DMChat', { threadId: tid, peer: c.displayName, foreignKid: c.kid });
    } catch (e) {
      Alert.alert('Could not open', e?.message || String(e));
    }
  }

  function foreignActions(contact) {
    const name = contact.displayName || contact.kid.slice(0, 8);
    const via = !!contact.useRelay;
    Alert.alert(
      `${name} on ${contact.island?.islandId || 'another server'}`,
      'Choose an action:',
      [
        { text: 'Safety number', onPress: () => showForeignSafetyNumber(contact) },
        {
          // Deliberately a per-contact choice the user makes, not a default:
          // sending directly hands the sender's address to a server they do not
          // trust, and sending through a relay depends on a third party being
          // up. The trade must be visible rather than decided for them.
          text: via ? 'Send directly instead' : 'Send through a relay',
          onPress: () => toggleRelay(contact, !via),
        },
        { text: 'Remove contact', style: 'destructive', onPress: () => confirmRemoveForeign(contact) },
        { text: 'Cancel', style: 'cancel' },
      ],
    );
  }

  async function showForeignSafetyNumber(contact) {
    try {
      const sn = await ForeignService.safetyNumber(contact);
      Alert.alert(
        'Safety number',
        `Read this to ${contact.displayName} over a channel you both already trust. ` +
        `If you both see the same number, nobody is in the middle:\n\n${sn.safetyNumber}`,
        [
          { text: 'Copy', onPress: () => Clipboard.setString(sn.safetyNumber) },
          { text: 'Close', style: 'cancel' },
        ],
      );
    } catch (e) {
      Alert.alert('Could not compute it', e?.message || String(e));
    }
  }

  async function toggleRelay(contact, on) {
    try {
      await ForeignService.setUseRelay(contact, on);
      await loadForeign();
      Alert.alert(
        on ? 'Going through a relay' : 'Going directly',
        on
          ? `Messages to ${contact.displayName} will go through a relay, which cannot read them ` +
            'and does not know who you are. Their server will no longer see your address.'
          : `Messages to ${contact.displayName} will go straight to their server, which will see your address.`,
      );
    } catch (e) {
      Alert.alert('Could not change that', e?.message || String(e));
    }
  }

  function confirmRemoveForeign(contact) {
    Alert.alert(
      `Remove ${contact.displayName}?`,
      'Their mailbox on this server is closed with them. They will no longer be able to ' +
      'deliver to you, and the conversation stored here goes with it.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Remove',
          style: 'destructive',
          onPress: async () => {
            try {
              await ForeignService.removeContact(contact.kid);
              await loadForeign();
            } catch (e) {
              Alert.alert('Could not remove', e?.message || String(e));
            }
          },
        },
      ],
    );
  }

  async function openMyCard() {
    try {
      if (!CryptoService.isReady()) await CryptoService.ensureReady({ interactive: false });
      setCardText(await ForeignService.buildMyCard());
      setShowCard(true);
    } catch (e) {
      Alert.alert('Could not build the card', e?.message || String(e));
    }
  }

  function renderForeignSection() {
    if (!foreign.length) return null;
    return (
      <View style={styles.foreignSection}>
        <Text style={styles.sectionTitle}>Other servers</Text>
        {foreign.map((contact) => {
          const name = contact.displayName || contact.kid.slice(0, 8);
          const color = colorForUsername(name);
          // Whether we can write yet is the one piece of state worth showing —
          // and WHY not, because the two reasons need different things from the
          // user: wait for the other person, or go and fix the address.
          const meta = contact.outbox?.keyB64
            ? (contact.island?.islandId || 'another server') + (contact.useRelay ? ' · via relay' : '')
            : contact.lastClaim?.kind === 'unreachable'
              ? 'their server did not answer'
              : 'waiting for them to add you';
          return (
            <TouchableOpacity
              key={contact.kid}
              style={[styles.threadRow, styles.foreignRow]}
              onPress={() => openForeign(contact)}
              onLongPress={() => foreignActions(contact)}
              delayLongPress={500}
              activeOpacity={0.7}
            >
              <View style={[styles.avatar, { backgroundColor: color + '33' }]}>
                <Text style={[styles.avatarText, { color }]}>{(name || '?')[0].toUpperCase()}</Text>
              </View>
              <View style={styles.threadInfo}>
                <Text style={[styles.peerName, { color }]}>{name}</Text>
                <Text style={styles.preview} numberOfLines={1}>{meta}</Text>
              </View>
            </TouchableOpacity>
          );
        })}
      </View>
    );
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
        <View style={styles.headerBtns}>
          <TouchableOpacity style={styles.newBtn} onPress={openMyCard}>
            <Text style={styles.newBtnText}>My card</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.newBtn} onPress={() => setShowAdd(true)}>
            <Text style={styles.newBtnText}>+ Card</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.newBtn} onPress={() => setShowNewDM(true)}>
            <Text style={styles.newBtnText}>+ New</Text>
          </TouchableOpacity>
        </View>
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
        ListHeaderComponent={renderForeignSection()}
        refreshControl={<RefreshControl refreshing={refreshing} onRefresh={handleRefresh} tintColor={Colors.textMuted} />}
        ListEmptyComponent={
          foreign.length ? null : <Text style={styles.emptyText}>No conversations yet</Text>
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

      <MyCardModal
        visible={showCard}
        card={cardText}
        onClose={() => setShowCard(false)}
      />

      <AddForeignModal
        visible={showAdd}
        onClose={() => setShowAdd(false)}
        onAdded={async (contact) => {
          setShowAdd(false);
          await loadForeign();
          Alert.alert(
            'Added',
            contact?.outbox?.keyB64
              ? `${contact.displayName} added. You can write to each other now.`
              : `${contact?.displayName || 'Contact'} added. They need to add your card before you ` +
                'can write to them; their messages to you will arrive as soon as they do.',
          );
        }}
      />
    </View>
  );
}

// ---- Cross-island contact cards ----

/**
 * The card this user hands over, shown rather than copied silently: it is the
 * thing the other person's trust rests on, so it should be visible and
 * deliberately handed over.
 */
function MyCardModal({ visible, card, onClose }) {
  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.modalCard}>
          <Text style={styles.modalTitle}>My contact card</Text>
          <Text style={styles.modalHint}>
            Send this to the person you want to write to, over a channel you both trust.
          </Text>
          <TextInput
            style={[styles.input, styles.cardBox]}
            value={card}
            multiline
            editable={false}
            selectTextOnFocus
          />
          <View style={styles.modalBtns}>
            <TouchableOpacity style={styles.cancelBtn} onPress={onClose}>
              <Text style={styles.cancelBtnText}>Close</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btn} onPress={() => Clipboard.setString(card)}>
              <Text style={styles.btnText}>Copy</Text>
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

function AddForeignModal({ visible, onClose, onAdded }) {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleAdd() {
    if (!text.trim()) { setError('Paste their card first'); return; }
    setLoading(true);
    setError('');
    try {
      const contact = await ForeignService.addContact(text);
      setText('');
      onAdded(contact);
    } catch (e) {
      setError(e?.message || 'Could not add');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.modalCard}>
          <Text style={styles.modalTitle}>Add someone from another server</Text>
          <Text style={styles.modalHint}>
            Pasting their card opens a mailbox on this server for their key — nobody can write
            to you here until you do.
          </Text>
          {!!error && <Text style={styles.errorText}>{error}</Text>}
          <TextInput
            style={[styles.input, styles.cardBox]}
            placeholder={'{"payload":…'}
            placeholderTextColor={Colors.textMuted}
            value={text}
            onChangeText={setText}
            multiline
            autoCapitalize="none"
            autoCorrect={false}
          />
          <View style={styles.modalBtns}>
            <TouchableOpacity style={styles.cancelBtn} onPress={onClose}>
              <Text style={styles.cancelBtnText}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={handleAdd}
              disabled={loading}
            >
              {loading ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.btnText}>Add</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
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
  headerBtns: { flexDirection: 'row', gap: Spacing.sm },
  foreignSection: { paddingTop: Spacing.sm },
  sectionTitle: {
    fontSize: Typography.xs,
    color: Colors.textMuted,
    textTransform: 'uppercase',
    letterSpacing: 1,
    paddingHorizontal: Spacing.lg,
    paddingBottom: Spacing.xs,
  },
  foreignRow: {
    borderColor: 'rgba(210,168,255,0.35)',
    backgroundColor: 'rgba(210,168,255,0.08)',
  },
  modalHint: { fontSize: Typography.sm, color: Colors.textMuted },
  cardBox: { minHeight: 110, maxHeight: 220, textAlignVertical: 'top', fontSize: Typography.sm },
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
