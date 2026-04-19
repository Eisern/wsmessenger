// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * InvitesScreen.js — Room invites + join requests management
 * Ported from panel-ui.js invite/join-request sections
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, RefreshControl, Alert, SectionList, ActivityIndicator,
  TextInput, Modal,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import CryptoService from '../services/CryptoService';
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';

export default function InvitesScreen({ navigation }) {
  const { state, dispatch, loadInvites, openDmThread } = useApp();
  const insets = useSafeAreaInsets();
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState({});  // id -> bool
  const [friends, setFriends] = useState([]);
  const [showAddFriend, setShowAddFriend] = useState(false);
  const [addFriendUsername, setAddFriendUsername] = useState('');
  const [addingFriend, setAddingFriend] = useState(false);
  const friendRequests = state.friendRequests || [];

  useEffect(() => {
    handleRefresh();
  }, []);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await loadInvites();
      const [jrs, frs, fl] = await Promise.all([
        NetworkService.getJoinRequestsAll().catch(() => []),
        NetworkService.getIncomingFriendRequests().catch(() => []),
        NetworkService.getFriends().catch(() => []),
      ]);
      if (jrs) dispatch({ type: 'SET_JOIN_REQUESTS', requests: jrs });
      if (Array.isArray(frs)) dispatch({ type: 'SET_FRIEND_REQUESTS', requests: frs });
      if (Array.isArray(fl)) setFriends(fl);
    } catch (_e) { /* ignore */ }
    setRefreshing(false);
  }, [loadInvites, dispatch]);

  // ---- Invite actions ----

  async function handleAccept(invite) {
    const key = `invite_${invite.room_id}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.acceptRoomInvite(invite.room_id);
      dispatch({ type: 'REMOVE_INVITE', roomId: invite.room_id });
      Alert.alert('Joined!', `You joined "${invite.room_name || invite.room_id}"`);
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not accept invite');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  async function handleDecline(invite) {
    const key = `invite_${invite.room_id}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.declineRoomInvite(invite.room_id);
      dispatch({ type: 'REMOVE_INVITE', roomId: invite.room_id });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not decline invite');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  // ---- Friend request actions ----

  async function handleAcceptFriend(req) {
    const key = `fr_${req.from_username}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.acceptFriendRequest(req.from_username);
      dispatch({ type: 'REMOVE_FRIEND_REQUEST', username: req.from_username });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not accept friend request');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  async function handleDeclineFriend(req) {
    const key = `fr_${req.from_username}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.declineFriendRequest(req.from_username);
      dispatch({ type: 'REMOVE_FRIEND_REQUEST', username: req.from_username });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not decline friend request');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  // ---- Join request actions (for room owners) ----

  async function handleApproveRequest(req) {
    const key = `req_${req.room_id}_${req.username}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.approveJoinRequest(req.room_id, req.username);
      dispatch({ type: 'REMOVE_JOIN_REQUEST', roomId: req.room_id, username: req.username });
      // Share room key to the newly approved member so they can decrypt messages.
      // Fire-and-forget — user already joined; key sharing failure is non-fatal.
      CryptoService.shareRoomKeyToUser(req.room_id, req.username).catch(err => {
        console.warn('[InvitesScreen] shareRoomKeyToUser failed:', err?.message);
      });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not approve request');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  async function handleDenyRequest(req) {
    const key = `req_${req.room_id}_${req.username}`;
    setLoading(l => ({ ...l, [key]: true }));
    try {
      await NetworkService.rejectJoinRequest(req.room_id, req.username);
      dispatch({ type: 'REMOVE_JOIN_REQUEST', roomId: req.room_id, username: req.username });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not deny request');
    } finally {
      setLoading(l => ({ ...l, [key]: false }));
    }
  }

  // ---- Friend list actions ----

  async function handleAddFriend() {
    const target = addFriendUsername.trim();
    if (!target) return;
    setAddingFriend(true);
    try {
      await NetworkService.sendFriendRequest(target);
      Alert.alert('Done', `Friend request sent to ${target}`);
      setAddFriendUsername('');
      setShowAddFriend(false);
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not send friend request');
    } finally {
      setAddingFriend(false);
    }
  }

  async function handleRemoveFriend(username) {
    Alert.alert('Remove friend', `Remove ${username} from friends?`, [
      { text: 'Cancel', style: 'cancel' },
      { text: 'Remove', style: 'destructive', onPress: async () => {
        try {
          await NetworkService.removeFriend(username);
          setFriends(f => f.filter(fr => (fr.username || fr) !== username));
        } catch (e) {
          Alert.alert('Error', e?.message || 'Could not remove friend');
        }
      }},
    ]);
  }

  async function handleMessageFriend(username) {
    try {
      const thread = await NetworkService.openDmThread(username);
      if (thread?.thread_id) {
        openDmThread(thread.thread_id, username);
        navigation.navigate('DMs', { screen: 'DMChat', params: { threadId: thread.thread_id, peer: username } });
      }
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not open DM');
    }
  }

  const invites = state.receivedInvites || [];
  const joinRequests = state.joinRequests || [];

  const sections = [];
  if (friendRequests.length > 0) {
    sections.push({ title: `Friend Requests (${friendRequests.length})`, data: friendRequests, type: 'friend' });
  }
  if (invites.length > 0) {
    sections.push({ title: `Room Invites (${invites.length})`, data: invites, type: 'invite' });
  }
  if (joinRequests.length > 0) {
    sections.push({ title: `Join Requests (${joinRequests.length})`, data: joinRequests, type: 'request' });
  }
  // Always show friends section
  sections.push({ title: `Friends (${friends.length})`, data: friends.length > 0 ? friends : [{ _empty: true }], type: 'friends_list' });

  function renderItem({ item, section }) {
    if (section.type === 'friends_list') {
      if (item._empty) {
        return <Text style={styles.emptyFriends}>No friends yet</Text>;
      }
      const username = item.username || item;
      return (
        <View style={styles.itemRow}>
          <View style={styles.itemInfo}>
            <Text style={styles.itemTitle}>{username}</Text>
          </View>
          <View style={styles.itemActions}>
            <TouchableOpacity style={styles.acceptBtn} onPress={() => handleMessageFriend(username)}>
              <Text style={styles.acceptBtnText}>Message</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.declineBtn} onPress={() => handleRemoveFriend(username)}>
              <Text style={styles.declineBtnText}>Remove</Text>
            </TouchableOpacity>
          </View>
        </View>
      );
    }
    if (section.type === 'friend') {
      const key = `fr_${item.from_username}`;
      const busy = loading[key];
      return (
        <View style={styles.itemRow}>
          <View style={styles.itemInfo}>
            <Text style={styles.itemTitle}>{item.from_username}</Text>
            <Text style={styles.itemSub}>wants to be your friend</Text>
          </View>
          <View style={styles.itemActions}>
            <TouchableOpacity
              style={[styles.acceptBtn, busy && styles.btnDisabled]}
              onPress={() => handleAcceptFriend(item)}
              disabled={busy}
            >
              {busy ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.acceptBtnText}>Accept</Text>}
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.declineBtn, busy && styles.btnDisabled]}
              onPress={() => handleDeclineFriend(item)}
              disabled={busy}
            >
              <Text style={styles.declineBtnText}>Decline</Text>
            </TouchableOpacity>
          </View>
        </View>
      );
    }
    if (section.type === 'invite') {
      const key = `invite_${item.room_id}`;
      const busy = loading[key];
      return (
        <View style={styles.itemRow}>
          <View style={styles.itemInfo}>
            <Text style={styles.itemTitle}>{item.room_name || item.room_alias || `Room #${item.room_id}`}</Text>
            <Text style={styles.itemSub}>from {item.from_username || item.invited_by}</Text>
          </View>
          <View style={styles.itemActions}>
            <TouchableOpacity
              style={[styles.acceptBtn, busy && styles.btnDisabled]}
              onPress={() => handleAccept(item)}
              disabled={busy}
            >
              {busy ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.acceptBtnText}>Join</Text>}
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.declineBtn, busy && styles.btnDisabled]}
              onPress={() => handleDecline(item)}
              disabled={busy}
            >
              <Text style={styles.declineBtnText}>Decline</Text>
            </TouchableOpacity>
          </View>
        </View>
      );
    }
    // join request
    const key = `req_${item.room_id}_${item.username}`;
    const busy = loading[key];
    return (
      <View style={styles.itemRow}>
        <View style={styles.itemInfo}>
          <Text style={styles.itemTitle}>{item.username}</Text>
          <Text style={styles.itemSub}>wants to join {item.room_name || `#${item.room_id}`}</Text>
        </View>
        <View style={styles.itemActions}>
          <TouchableOpacity
            style={[styles.acceptBtn, busy && styles.btnDisabled]}
            onPress={() => handleApproveRequest(item)}
            disabled={busy}
          >
            {busy ? <ActivityIndicator color="#fff" size="small" />
              : <Text style={styles.acceptBtnText}>Approve</Text>}
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.declineBtn, busy && styles.btnDisabled]}
            onPress={() => handleDenyRequest(item)}
            disabled={busy}
          >
            <Text style={styles.declineBtnText}>Deny</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <View style={styles.root}>
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <Text style={styles.title}>Friends & Invites</Text>
        <TouchableOpacity style={styles.addFriendBtn} onPress={() => { setShowAddFriend(true); setAddFriendUsername(''); }}>
          <Text style={styles.addFriendBtnText}>+ Add Friend</Text>
        </TouchableOpacity>
      </View>
      {sections.length === 0 ? (
        <View style={styles.emptyContainer}>
          <Text style={styles.emptyText}>No pending invites or requests</Text>
          <TouchableOpacity onPress={handleRefresh} style={styles.refreshBtn}>
            <Text style={styles.refreshBtnText}>Refresh</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <SectionList
          sections={sections}
          keyExtractor={(item, idx) => item._empty ? 'empty_friends' : item.from_username ? `fr_${item.from_username}` : (item.username || item.room_id) ? `${item.room_id || ''}_${item.username || item}` : `item_${idx}`}
          renderItem={renderItem}
          renderSectionHeader={({ section }) => (
            <View style={styles.sectionHeader}>
              <Text style={styles.sectionTitle}>{section.title}</Text>
            </View>
          )}
          refreshControl={
            <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} tintColor={Colors.textMuted} />
          }
          stickySectionHeadersEnabled={false}
        />
      )}

      {/* Add friend modal */}
      <Modal visible={showAddFriend} transparent animationType="fade" onRequestClose={() => setShowAddFriend(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Add Friend</Text>
            <TextInput
              style={styles.modalInput}
              placeholder="Username…"
              placeholderTextColor={Colors.textMuted}
              value={addFriendUsername}
              onChangeText={setAddFriendUsername}
              autoCapitalize="none"
              autoCorrect={false}
              autoFocus
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.declineBtn} onPress={() => setShowAddFriend(false)}>
                <Text style={styles.declineBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.acceptBtn, (!addFriendUsername.trim() || addingFriend) && styles.btnDisabled]}
                onPress={handleAddFriend}
                disabled={!addFriendUsername.trim() || addingFriend}
              >
                {addingFriend
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.acceptBtnText}>Send Request</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: Colors.bgMain },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: Spacing.lg,
    paddingBottom: Spacing.md,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle,
    elevation: 4,
  },
  title: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain, flex: 1 },
  addFriendBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.xs,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  addFriendBtnText: { color: Colors.accent, fontSize: Typography.sm, fontWeight: '600' },
  sectionHeader: {
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
    backgroundColor: Colors.bgMain,
  },
  sectionTitle: {
    fontSize: Typography.sm,
    fontWeight: '600',
    color: Colors.textMuted,
    textTransform: 'uppercase',
    letterSpacing: 0.8,
  },
  itemRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: Spacing.md,
    marginVertical: 3,
    padding: Spacing.md,
    paddingHorizontal: Spacing.lg,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.10)',
    borderRadius: Radii.md,
    backgroundColor: 'rgba(255,255,255,0.04)',
    gap: Spacing.md,
  },
  itemInfo: { flex: 1 },
  itemTitle: { fontSize: Typography.md, fontWeight: '600', color: Colors.textMain },
  itemSub: { fontSize: Typography.sm, color: Colors.textMuted, marginTop: 2 },
  itemActions: { flexDirection: 'row', gap: Spacing.sm },
  acceptBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    minWidth: 60,
    alignItems: 'center',
  },
  acceptBtnText: { color: '#fff', fontSize: Typography.sm, fontWeight: '600' },
  declineBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderWidth: 1,
    borderColor: Colors.border,
    minWidth: 60,
    alignItems: 'center',
  },
  declineBtnText: { color: Colors.textMuted, fontSize: Typography.sm },
  btnDisabled: { opacity: 0.6 },
  emptyContainer: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: Spacing.xl,
  },
  emptyText: { color: Colors.textMuted, fontSize: Typography.md },
  refreshBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  refreshBtnText: { color: Colors.textMain, fontSize: Typography.md },
  emptyFriends: { color: Colors.textMuted, fontSize: Typography.sm, paddingHorizontal: Spacing.lg, paddingVertical: Spacing.sm },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.6)',
    justifyContent: 'center',
    alignItems: 'center',
  },
  modalCard: {
    backgroundColor: Colors.bgPanel,
    borderRadius: Radii.lg,
    padding: Spacing.lg,
    width: '85%',
    borderWidth: 1,
    borderColor: Colors.border,
  },
  modalTitle: { fontSize: Typography.lg, fontWeight: '700', color: Colors.textMain, marginBottom: Spacing.md },
  modalInput: {
    backgroundColor: Colors.bgMain,
    color: Colors.textMain,
    borderRadius: Radii.sm,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: Spacing.sm,
    fontSize: Typography.md,
    marginBottom: Spacing.md,
  },
  modalBtns: { flexDirection: 'row', justifyContent: 'flex-end', gap: Spacing.sm },
});
