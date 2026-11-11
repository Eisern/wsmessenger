// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * GuestRoomScreen.js — a room on another island, taken part in as a guest.
 *
 * Nothing here goes through this island: the app talks to the room's island
 * directly, with a session signed by the identity key (GuestRoomService). What
 * is shown and in what order is guest-room-feed.js's business - shared with
 * the extension - and this screen only draws it, with the room chat's own
 * bubble, so a room looks like a room wherever it lives.
 *
 * Deliberately smaller than ChatScreen: no files (they live on the island they
 * were uploaded to, fetched with an account there), no members panel, no
 * moderation - a guest cannot moderate.
 */

import React, { useState, useRef, useCallback, useMemo } from 'react';
import { useFocusEffect } from '@react-navigation/native';
import { View, Text, FlatList, TextInput, TouchableOpacity, Alert, StyleSheet } from 'react-native';
import { KeyboardAvoidingView } from 'react-native-keyboard-controller';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import CryptoService from '../services/CryptoService';
import GuestRoomService from '../services/GuestRoomService';
import RoomLogo from '../components/RoomLogo';
import { MessageBubble, chatStyles as styles } from './ChatScreen';
import { roomSigVerdict } from '../utils/roomSig';
import { parseFileMarker } from '../utils/fileMarker';
import { Colors, Spacing, Typography } from '../theme';

const FILE_ELSEWHERE = '[A file. Files in rooms on other servers cannot be opened from here yet.]';

// Seconds from the socket, an ISO string from the history: both to what the
// bubble expects.
function msOf(ts) {
  if (ts == null) return null;
  if (typeof ts === 'number') return ts < 1e12 ? ts * 1000 : ts;
  const n = Date.parse(String(ts));
  return Number.isFinite(n) ? n : null;
}

// A room message may be a reply envelope ({v:2, t, reply}), as in ChatScreen.
function bodyOf(text) {
  if (typeof text === 'string' && text.startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.v === 2 && parsed.t !== undefined) {
        return { text: String(parsed.t), reply: parsed.reply || null };
      }
    } catch (_e) { /* plain text that starts with a brace */ }
  }
  return { text: String(text == null ? '' : text), reply: null };
}

function toBubble(it) {
  const { text, reply } = bodyOf(it.text);
  return {
    key: it.key,
    author: it.user,
    username: it.user,
    _decrypted: parseFileMarker(text) ? FILE_ELSEWHERE : text,
    ...(reply ? { _reply: reply } : {}),
    ts: msOf(it.ts),
    ...roomSigVerdict(it),
  };
}

let _noticeN = 0;
function noticeBubble(text) {
  _noticeN += 1;
  return { key: `notice-${_noticeN}`, author: 'System', username: 'System', _decrypted: text, ts: Date.now() };
}

export default function GuestRoomScreen({ navigation, route }) {
  const room = route?.params?.room || null;
  const insets = useSafeAreaInsets();
  const [items, setItems] = useState([]);   // oldest first
  const [online, setOnline] = useState(false);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const feedRef = useRef(null);

  // One feed per visit: opened when the screen is shown, closed when it is
  // not, so a room in a background tab holds no socket open to its island.
  useFocusEffect(useCallback(() => {
    if (!room) return undefined;
    const feed = GuestRoomService.createFeed(room, {
      onReset: (list) => setItems(list.map(toBubble)),
      onAppend: (it) => setItems((prev) => [...prev, toBubble(it)]),
      onNotice: (n) => setItems((prev) => [...prev, noticeBubble(n.text)]),
      onStatus: (s) => setOnline(!!s?.online),
    });
    feedRef.current = feed;
    feed.start();
    // What arrived while locked could not be read; read the page again.
    const offUnlocked = CryptoService.on('unlocked', () => feed.refresh());
    return () => {
      offUnlocked();
      feed.stop();
      if (feedRef.current === feed) feedRef.current = null;
      setOnline(false);
    };
  }, [room?.islandId, room?.roomId]));   // eslint-disable-line react-hooks/exhaustive-deps

  const shown = useMemo(() => [...items].reverse(), [items]);

  async function handleSend() {
    const text = input.trim();
    if (!text || sending || !room) return;
    setSending(true);
    try {
      const enc = await GuestRoomService.encrypt(room, text);
      if (!feedRef.current) throw new Error('The room was closed');
      feedRef.current.send(enc);
      setInput('');
    } catch (e) {
      Alert.alert('Not sent', e?.message || 'Could not send to their server');
    } finally {
      setSending(false);
    }
  }

  function handleMenu() {
    Alert.alert(
      room.roomName || `#${room.roomId}`,
      `On ${room.islandId}, where you are ${room.guestName}. Your own server is not told about this room.`,
      [
        { text: 'Close', style: 'cancel' },
        {
          text: 'Leave room',
          style: 'destructive',
          onPress: () => Alert.alert(
            'Leave room',
            'To come back you need a new invitation.',
            [
              { text: 'Cancel', style: 'cancel' },
              {
                text: 'Leave',
                style: 'destructive',
                onPress: async () => {
                  try {
                    await GuestRoomService.leave(room);
                    navigation.goBack();
                  } catch (e) {
                    Alert.alert('Error', e?.message || 'Could not leave');
                  }
                },
              },
            ],
          ),
        },
      ],
    );
  }

  if (!room) {
    return <View style={{ flex: 1, backgroundColor: Colors.bgMain }} />;
  }

  const name = room.roomName || `#${room.roomId}`;
  return (
    <KeyboardAvoidingView style={styles.root} behavior="padding">
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.backBtn}>←</Text>
        </TouchableOpacity>
        <RoomLogo logoUrl={null} roomName={name} size={34} />
        <View style={styles.headerCenter}>
          <Text style={styles.roomName} numberOfLines={1}>{name}</Text>
          <Text style={[local.sub, online && local.subOnline]} numberOfLines={1}>
            {online ? '● ' : '○ '}{room.islandId}
          </Text>
        </View>
        <TouchableOpacity onPress={handleMenu}>
          <Text style={styles.membersBtn}>⋯</Text>
        </TouchableOpacity>
      </View>

      <FlatList
        data={shown}
        inverted
        keyExtractor={(m) => m.key}
        renderItem={({ item }) => <MessageBubble msg={item} myUsername={room.guestName} />}
        contentContainerStyle={{ padding: Spacing.md }}
      />

      <View style={[styles.inputRow, { paddingBottom: Math.max(insets.bottom, Spacing.sm) }]}>
        <TextInput
          style={styles.input}
          value={input}
          onChangeText={setInput}
          placeholder={`Message as ${room.guestName}`}
          placeholderTextColor={Colors.textMuted}
          multiline
        />
        <TouchableOpacity
          style={[styles.sendBtn, (!input.trim() || sending || !online) && styles.sendBtnDisabled]}
          disabled={!input.trim() || sending || !online}
          onPress={handleSend}
        >
          <Text style={styles.sendBtnText}>↑</Text>
        </TouchableOpacity>
      </View>
    </KeyboardAvoidingView>
  );
}

const local = StyleSheet.create({
  sub: { fontSize: Typography.xs, color: Colors.textMuted },
  subOnline: { color: Colors.success },
});
