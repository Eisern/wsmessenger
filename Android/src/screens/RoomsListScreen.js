// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * RoomsListScreen.js — Room browser (private + public rooms)
 * Ported from panel-ui.js room list rendering
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  View, Text, FlatList, TouchableOpacity,
  StyleSheet, TextInput, RefreshControl, ActivityIndicator,
  SectionList, Alert, Modal, ScrollView,
} from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';
import RoomLogo from '../components/RoomLogo';

export default function RoomsListScreen({ navigation }) {
  const { state, dispatch, loadMyRooms, loadPublicRooms, connectRoom } = useApp();
  const insets = useSafeAreaInsets();
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [showCreate, setShowCreate] = useState(false);

  // Room password prompt state
  const [passwordRoom, setPasswordRoom] = useState(null); // room object needing password
  const [roomPassword, setRoomPassword] = useState('');
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordError, setPasswordError] = useState('');

  useEffect(() => {
    handleRefresh();
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, []);

  // Load join requests across all owned rooms on login
  useEffect(() => {
    if (state.isLoggedIn) {
      NetworkService.getJoinRequestsAll().then(r => {
        if (Array.isArray(r)) dispatch({ type: 'SET_JOIN_REQUESTS', requests: r });
      }).catch(() => {});
    }
  }, [state.isLoggedIn]);

  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    await Promise.all([loadMyRooms(), loadPublicRooms(searchQuery)]);
    setRefreshing(false);
  }, [searchQuery, loadMyRooms, loadPublicRooms]);

  const searchTimerRef = useRef(null);
  const handleSearchChange = useCallback((q) => {
    setSearchQuery(q);
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => loadPublicRooms(q), 350);
  }, [loadPublicRooms]);

  const handleRoomPress = useCallback(async (room) => {
    const roomId = room.id || room.room_id;
    const roomName = room.name || room.room_name || room.room_alias;
    const roomAlias = room.alias || room.room_alias;
    await connectRoom(roomId, roomName, roomAlias);
    navigation.navigate('Chat', { roomId, roomName, roomAlias });
  }, [connectRoom, navigation]);

  const handleJoinPublic = useCallback(async (room, password) => {
    try {
      const result = await NetworkService.joinPublicRoom(room.id || room.room_id, password || undefined);
      // Server returns status='requested' for public rooms needing owner approval.
      // Only navigate to chat if the user is actually accepted.
      if (result?.status === 'requested') {
        await loadPublicRooms();
        Alert.alert('Request sent', 'Your join request has been sent. Waiting for room owner approval.');
        return true;
      }
      await loadMyRooms();
      handleRoomPress(room);
      return true; // success
    } catch (e) {
      const msg = String(e?.message || '');
      // Server returns 403 "Bad room password" for password-protected rooms
      if (/password|403|forbidden/i.test(msg)) {
        setPasswordRoom(room);
        setRoomPassword('');
        setPasswordError(password ? 'Invalid room password' : '');
        return false; // stay in password modal
      }
      Alert.alert('Error', msg || 'Could not join room');
      return false;
    }
  }, [loadMyRooms, loadPublicRooms, handleRoomPress]);

  const handlePasswordSubmit = useCallback(async () => {
    if (!roomPassword.trim() || !passwordRoom) return;
    setPasswordLoading(true);
    setPasswordError('');
    try {
      const ok = await handleJoinPublic(passwordRoom, roomPassword.trim());
      if (ok) {
        // Only close modal on successful join
        setPasswordRoom(null);
        setRoomPassword('');
      }
    } catch (_e) {
      // Error is handled inside handleJoinPublic
    } finally {
      setPasswordLoading(false);
    }
  }, [roomPassword, passwordRoom, handleJoinPublic]);

  const handleRequestJoin = useCallback(async (room) => {
    try {
      await NetworkService.requestJoinRoom(room.id || room.room_id);
      Alert.alert('Request sent', 'Your request to join has been sent.');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not send request');
    }
  }, []);

  const myRooms = state.myRooms || [];
  const publicRooms = (state.publicRooms || []).filter(r => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (r.name || '').toLowerCase().includes(q) ||
           (r.alias || '').toLowerCase().includes(q);
  });

  const joinRequestCount = (state.joinRequests || []).length;

  const sections = [
    { title: `My Rooms (${myRooms.length})`, data: myRooms, type: 'mine' },
    { title: `Public Rooms (${publicRooms.length})`, data: publicRooms, type: 'public' },
  ];

  const handleLeaveRoom = useCallback(async (room) => {
    const roomId = room.id || room.room_id;
    const roomName = room.name || room.room_name || room.alias || room.room_alias;

    if (room.is_owner) {
      Alert.alert('Cannot leave', 'You are the room owner. You cannot leave — you can only delete the room from room settings.');
      return;
    }

    Alert.alert(
      'Leave room',
      `Leave "${roomName}"? You will no longer see it in the list.`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Leave', style: 'destructive', onPress: async () => {
          try {
            await NetworkService.leaveRoom(roomId);
            await loadMyRooms();
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to leave room');
          }
        }},
      ],
    );
  }, [loadMyRooms]);

  function renderRoom({ item, section }) {
    const roomId = item.id || item.room_id;
    const roomName = item.name || item.room_name || item.alias || item.room_alias;
    const unread = state.unreadRooms[roomId] || 0;
    const isPublic = section.type === 'public';
    const isReadonly = !!item.is_readonly;
    const isMine = section.type === 'mine';
    return (
      <TouchableOpacity
        style={[styles.roomRow, isPublic && styles.roomRowPublic]}
        onPress={() => isPublic ? handleJoinOrChat(item, isPublic) : handleRoomPress(item)}
        activeOpacity={0.7}
      >
        <RoomLogo logoUrl={item.logo_url} roomName={roomName} size={40} />
        <View style={styles.roomInfo}>
          <View style={styles.roomNameRow}>
            <Text style={styles.roomName} numberOfLines={1}>{roomName}</Text>
            {isReadonly && (
              <View style={styles.readonlyBadge}>
                <Text style={styles.readonlyBadgeText}>read-only</Text>
              </View>
            )}
          </View>
          {item.alias || item.room_alias ? (
            <Text style={styles.roomAlias}>#{item.alias || item.room_alias}</Text>
          ) : null}
        </View>
        <View style={styles.roomRight}>
          {unread > 0 && (
            <View style={styles.badge}>
              <Text style={styles.badgeText}>{unread > 99 ? '99+' : unread}</Text>
            </View>
          )}
          {isMine && (
            <TouchableOpacity style={styles.leaveBtn} onPress={() => handleLeaveRoom(item)}>
              <Text style={styles.leaveBtnText}>Leave</Text>
            </TouchableOpacity>
          )}
          {isPublic && (
            <TouchableOpacity style={styles.joinBtn} onPress={() => handleJoinPublic(item)}>
              <Text style={styles.joinBtnText}>Join</Text>
            </TouchableOpacity>
          )}
        </View>
      </TouchableOpacity>
    );
  }

  function handleJoinOrChat(item, isPublic) {
    const isMember = myRooms.some(r => (r.id || r.room_id) === (item.id || item.room_id));
    if (isMember) {
      handleRoomPress(item);
    } else {
      const isPrivate = item.is_private;
      if (isPrivate) {
        handleRequestJoin(item);
      } else {
        handleJoinPublic(item);
      }
    }
  }

  return (
    <View style={styles.root}>
      {/* Header */}
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <Text style={styles.headerTitle}>Rooms</Text>
        <View style={styles.headerRight}>
          {joinRequestCount > 0 && (
            <TouchableOpacity
              onPress={() => navigation.navigate('Invites')}
              style={{ marginRight: Spacing.sm }}
            >
              <View style={styles.badge}>
                <Text style={styles.badgeText}>{joinRequestCount}</Text>
              </View>
            </TouchableOpacity>
          )}
          <TouchableOpacity style={styles.createBtn} onPress={() => setShowCreate(true)}>
            <Text style={styles.createBtnText}>+ New</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Search */}
      <View style={styles.searchRow}>
        <TextInput
          style={styles.searchInput}
          placeholder="Search public rooms…"
          placeholderTextColor={Colors.textMuted}
          value={searchQuery}
          onChangeText={handleSearchChange}
          returnKeyType="search"
        />
      </View>

      {/* Status bar */}
      <View style={styles.statusRow}>
        <View style={[styles.statusDot, state.wsOnline ? styles.online : styles.offline]} />
        <Text style={styles.statusText}>{state.wsOnline ? 'Connected' : 'Offline'}</Text>
      </View>

      {/* Sections */}
      <SectionList
        sections={sections}
        keyExtractor={(item, idx) => String(item.id || item.room_id || idx)}
        renderItem={renderRoom}
        renderSectionHeader={({ section }) => (
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionTitle}>{section.title}</Text>
          </View>
        )}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={handleRefresh} tintColor={Colors.textMuted} />
        }
        ListEmptyComponent={
          <Text style={styles.emptyText}>No rooms found</Text>
        }
        stickySectionHeadersEnabled={false}
      />

      {/* Create room modal */}
      <CreateRoomModal
        visible={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={() => { setShowCreate(false); loadMyRooms(); }}
      />

      {/* Room password modal */}
      <Modal visible={!!passwordRoom} transparent animationType="fade" onRequestClose={() => setPasswordRoom(null)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Room Password</Text>
            <Text style={styles.passwordHint}>
              "{passwordRoom?.name || passwordRoom?.alias || 'Room'}" requires a password.
            </Text>
            {!!passwordError && <Text style={styles.errorText}>{passwordError}</Text>}
            <TextInput
              style={styles.input}
              placeholder="Enter room password"
              placeholderTextColor={Colors.textMuted}
              value={roomPassword}
              onChangeText={setRoomPassword}
              secureTextEntry
              autoFocus
              onSubmitEditing={handlePasswordSubmit}
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => { setPasswordRoom(null); setRoomPassword(''); }}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.btn, passwordLoading && styles.btnDisabled]}
                onPress={handlePasswordSubmit}
                disabled={passwordLoading}
              >
                {passwordLoading ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.btnText}>Join</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
}

// ---- Create room modal ----

function CreateRoomModal({ visible, onClose, onCreated }) {
  const [name, setName] = useState('');
  const [alias, setAlias] = useState('');
  const [password, setPassword] = useState('');
  const [isPrivate, setIsPrivate] = useState(true);
  const [isReadonly, setIsReadonly] = useState(false);
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleCreate() {
    if (!name.trim()) { setError('Room name is required'); return; }
    setLoading(true);
    setError('');
    try {
      // Ensure crypto is ready before creating room (E2EE required)
      if (!CryptoService.isReady()) {
        await CryptoService.ensureReady({ interactive: false });
      }

      // Generate room key and encrypt for owner
      const keyData = await CryptoService.generateRoomKeyForCreation();
      if (!keyData) {
        setError('Failed to generate room key. Crypto may not be ready.');
        setLoading(false);
        return;
      }

      const room = await NetworkService.createRoom({
        name: name.trim(),
        alias: alias.trim() || undefined,
        description: description.trim() || undefined,
        is_private: isPrivate,
        is_readonly: isReadonly,
        password: password.trim() || undefined,
        encrypted_room_key: keyData.encrypted_room_key,
      });

      // Load the generated room key locally so we can encrypt/decrypt in this room
      const roomId = room?.id || room?.room_id;
      if (roomId && keyData.rawB64) {
        await CryptoService.loadRoomKey(roomId, keyData.rawB64);
      }

      setName(''); setAlias(''); setDescription(''); setPassword(''); setIsPrivate(true); setIsReadonly(false);
      onCreated();
    } catch (e) {
      setError(e?.message || 'Failed to create room');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.modalCard}>
          <Text style={styles.modalTitle}>Create Room</Text>
          {!!error && <Text style={styles.errorText}>{error}</Text>}
          <TextInput
            style={styles.input}
            placeholder="Room name"
            placeholderTextColor={Colors.textMuted}
            value={name}
            onChangeText={setName}
          />
          <TextInput
            style={styles.input}
            placeholder="Alias (optional, lowercase)"
            placeholderTextColor={Colors.textMuted}
            value={alias}
            onChangeText={v => setAlias(v.toLowerCase().replace(/[^a-z0-9_-]/g, ''))}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="Password (optional)"
            placeholderTextColor={Colors.textMuted}
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />
          <TextInput
            style={[styles.input, { height: 72, textAlignVertical: 'top' }]}
            placeholder="Description (optional)"
            placeholderTextColor={Colors.textMuted}
            value={description}
            onChangeText={setDescription}
            multiline
          />
          <TouchableOpacity style={styles.toggleRow} onPress={() => setIsPrivate(p => !p)}>
            <View style={[styles.checkbox, isPrivate && styles.checkboxOn]} />
            <Text style={styles.toggleLabel}>Private room (invite only)</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.toggleRow} onPress={() => setIsReadonly(p => !p)}>
            <View style={[styles.checkbox, isReadonly && styles.checkboxOn]} />
            <Text style={styles.toggleLabel}>Read-only channel (members cannot send)</Text>
          </TouchableOpacity>
          <View style={styles.modalBtns}>
            <TouchableOpacity style={styles.cancelBtn} onPress={onClose}>
              <Text style={styles.cancelBtnText}>Cancel</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={[styles.btn, loading && styles.btnDisabled]}
              onPress={handleCreate}
              disabled={loading}
            >
              {loading ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.btnText}>Create</Text>}
            </TouchableOpacity>
          </View>
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: Colors.bgMain,
  },
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
  headerTitle: {
    fontSize: Typography.xl,
    fontWeight: '700',
    color: Colors.textMain,
  },
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  createBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.xs,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  createBtnText: {
    color: Colors.textMain,
    fontSize: Typography.sm,
  },
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
  statusDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginRight: Spacing.sm,
  },
  online: { backgroundColor: Colors.success },
  offline: { backgroundColor: Colors.danger },
  statusText: { fontSize: Typography.xs, color: Colors.textMuted },
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
  roomRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginHorizontal: Spacing.md,
    marginVertical: 3,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    backgroundColor: Colors.bgCard,
  },
  roomRowPublic: {
    borderColor: Colors.public,
    backgroundColor: Colors.publicBg,
  },
  roomInfo: { flex: 1, marginLeft: Spacing.md },
  roomNameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
    flexWrap: 'wrap',
  },
  roomName: {
    fontSize: Typography.md,
    color: Colors.textMain,
    fontWeight: '500',
  },
  readonlyBadge: {
    backgroundColor: 'rgba(248,209,55,0.15)',
    borderRadius: Radii.xs,
    paddingHorizontal: 5,
    paddingVertical: 1,
    borderWidth: 1,
    borderColor: 'rgba(248,209,55,0.4)',
  },
  readonlyBadgeText: {
    color: '#f8d137',
    fontSize: Typography.xs,
    fontWeight: '500',
  },
  roomAlias: {
    fontSize: Typography.sm,
    color: Colors.textMuted,
    marginTop: 2,
  },
  roomRight: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
  },
  badge: {
    backgroundColor: Colors.badgeBlue,
    borderRadius: Radii.round,
    minWidth: 18,
    height: 18,
    alignItems: 'center',
    justifyContent: 'center',
    paddingHorizontal: Spacing.xs,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.18)',
  },
  badgeText: {
    color: '#071018',
    fontSize: Typography.xs,
    fontWeight: '700',
  },
  leaveBtn: {
    backgroundColor: Colors.danger + '18',
    borderRadius: Radii.xs,
    paddingHorizontal: Spacing.sm,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: Colors.danger + '44',
    marginRight: Spacing.xs,
  },
  leaveBtnText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    fontWeight: '600',
  },
  joinBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.xs,
    paddingHorizontal: Spacing.sm,
    paddingVertical: 3,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  joinBtnText: {
    color: Colors.accent,
    fontSize: Typography.sm,
  },
  emptyText: {
    textAlign: 'center',
    color: Colors.textMuted,
    marginTop: Spacing.xxl,
    fontSize: Typography.md,
  },
  // Modal
  modalOverlay: {
    flex: 1,
    backgroundColor: Colors.overlay,
    justifyContent: 'flex-end',
  },
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
  modalTitle: {
    fontSize: Typography.xl,
    fontWeight: '700',
    color: Colors.textMain,
    marginBottom: Spacing.sm,
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
  toggleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.md,
  },
  checkbox: {
    width: 18,
    height: 18,
    borderRadius: Radii.xs,
    borderWidth: 2,
    borderColor: Colors.border,
  },
  checkboxOn: {
    backgroundColor: Colors.success,
    borderColor: Colors.success,
  },
  toggleLabel: {
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  modalBtns: {
    flexDirection: 'row',
    gap: Spacing.md,
    justifyContent: 'flex-end',
    marginTop: Spacing.sm,
  },
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
  errorText: {
    color: Colors.danger,
    fontSize: Typography.sm,
  },
  passwordHint: {
    color: Colors.textMuted,
    fontSize: Typography.md,
    marginBottom: Spacing.sm,
  },
});
