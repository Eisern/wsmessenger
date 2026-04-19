// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ChatScreen.js — Room chat with E2EE
 * Ported from panel.js + panel-ui.js (addMsg, renderHistory, etc.)
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useFocusEffect } from '@react-navigation/native';
import {
  View, Text, FlatList, TextInput, TouchableOpacity, ScrollView,
  StyleSheet, Platform, Modal,
  Alert, ActivityIndicator, Linking, Keyboard,
} from 'react-native';
import { KeyboardAvoidingView } from 'react-native-keyboard-controller';
import Clipboard from '@react-native-clipboard/clipboard';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';

// Auto-clear clipboard 60s after copying a message (plaintext is sensitive).
let _clipClearTimer = null;
function _copyMessage(text) {
  Clipboard.setString(text);
  if (_clipClearTimer) clearTimeout(_clipClearTimer);
  _clipClearTimer = setTimeout(() => { Clipboard.setString(''); _clipClearTimer = null; }, 60_000);
}
import { useApp } from '../contexts/AppContext';
import { Colors, Spacing, Radii, Typography } from '../theme';
import FileCard from '../components/FileCard';
import RoomLogo from '../components/RoomLogo';
import { parseFileMarker, makeFileMarker } from '../utils/fileMarker';
import { pick as pickDocument, types as pickerTypes } from '@react-native-documents/picker';

// Deterministic username color (ported from panel.js colorForUsername)
function colorForUsername(name) {
  const COLORS = [
    '#58a6ff', '#79c0ff', '#d2a8ff', '#f78166',
    '#56d364', '#e3b341', '#db6d28', '#ff7b72',
    '#3aa0ff', '#4ac26b', '#f47067', '#ffa657',
  ];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (Math.imul(31, h) + name.charCodeAt(i)) | 0;
  return COLORS[Math.abs(h) % COLORS.length];
}

// ---- Suspicious link detection (ported from panel.js) ----

const LINKIFY_MAX_URL_LEN = 2048;
const TRAIL_RE = /[)\]}",.!?:;]+$/;
const URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"']{2,2048})/gi;

function splitTrailingPunct(s) {
  const m = TRAIL_RE.exec(s);
  if (!m) return { core: s, tail: '' };
  return { core: s.slice(0, m.index), tail: m[0] };
}

function isMixedScriptHostname(hostname) {
  const h = String(hostname || '');
  const hasLatin = /[a-zA-Z]/.test(h);
  const hasCyr = /[\u0400-\u04FF]/.test(h); // Cyrillic block
  return hasLatin && hasCyr;
}

function isSuspiciousHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return false;
  if (h.includes('xn--')) return true; // Punycode
  if (isMixedScriptHostname(h)) return true; // Mixed script
  return false;
}

function safeHttpUrl(token) {
  let s = String(token || '').trim();
  if (!s) return null;
  const { core } = splitTrailingPunct(s);
  s = core.trim();
  if (!s) return null;
  if (/^www\./i.test(s)) s = 'https://' + s;
  if (s.length > LINKIFY_MAX_URL_LEN) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.username || u.password) return null; // block auth-in-URL
  if (!u.hostname) return null;
  return u.toString();
}

// Parse URLs from text for clickable links (with suspicious detection)
function parseMessageText(text) {
  const parts = [];
  let last = 0;
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    const start = m.index;
    const rawToken = m[1];
    if (start > last) parts.push({ type: 'text', value: text.slice(last, start) });

    const { core, tail } = splitTrailingPunct(rawToken);
    const href = safeHttpUrl(core);

    if (!href) {
      parts.push({ type: 'text', value: rawToken });
      last = start + rawToken.length;
      continue;
    }

    let suspicious = false;
    try { suspicious = isSuspiciousHostname(new URL(href).hostname); } catch {}

    parts.push({ type: 'url', value: core, href, suspicious });
    if (tail) parts.push({ type: 'text', value: tail });
    last = start + rawToken.length;
  }
  if (last < text.length) parts.push({ type: 'text', value: text.slice(last) });
  return parts;
}

function MessageText({ text, isMe }) {
  const { state } = useApp();
  const fontScale = state.fontScale || 1.0;
  const parts = useMemo(() => parseMessageText(text || ''), [text]);
  return (
    <Text style={[styles.msgText, { fontSize: Math.round(Typography.md * fontScale), lineHeight: Math.round(20 * fontScale) }, isMe && styles.msgTextMe]}>
      {parts.map((p, i) =>
        p.type === 'url' ? (
          <Text
            key={i}
            style={[styles.linkText, p.suspicious && styles.suspiciousLink]}
            onPress={() => {
              const title = p.suspicious ? 'Suspicious link!' : 'Open link?';
              const msg = p.suspicious
                ? `This link may be deceptive (Punycode or mixed-script hostname).\n\n${p.href}`
                : p.href;
              Alert.alert(title, msg, [
                { text: 'Cancel', style: 'cancel' },
                { text: 'Open', onPress: () => Linking.openURL(p.href) },
              ]);
            }}
          >
            {p.suspicious ? '\u26a0 ' : ''}{p.value}
          </Text>
        ) : (
          <Text key={i}>{p.value}</Text>
        )
      )}
    </Text>
  );
}

// Normalize server message: ts seconds→ms, 'from' field → 'author'/'username'
const normMsg = m => {
  if (!m) return m;
  const ts = m.ts != null && m.ts < 1e12 ? m.ts * 1000 : m.ts;
  const author = m.author || m.from || m.username;
  return { ...m, ts, ...(author ? { author, username: m.username || author } : {}) };
};

function MessageBubble({ msg, myUsername, isSearchHit, isSearchActive, onReply }) {
  const meLower = (myUsername || '').toLowerCase();
  const isMe = (msg.author || '').toLowerCase() === meLower || (msg.username || '').toLowerCase() === meLower;
  const author = msg.author || msg.username || 'unknown';
  const decryptFailed = msg._decryptFailed;
  const text = decryptFailed ? '' : (msg._decrypted ?? msg.text ?? msg.body ?? '');
  const ts = msg.ts || msg.created_at;
  const timeStr = ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
  const color = colorForUsername(author);

  const fileInfo = useMemo(() => parseFileMarker(text), [text]);

  const handleLongPress = useCallback(() => {
    const actions = [];
    if (onReply && text) actions.push({ text: 'Reply', onPress: () => onReply(msg) });
    if (text) actions.push({ text: 'Copy', onPress: () => _copyMessage(text) });
    actions.push({ text: 'Cancel', style: 'cancel' });
    Alert.alert('Message', null, actions);
  }, [text, msg, onReply]);

  return (
    <TouchableOpacity
      activeOpacity={0.8}
      onLongPress={handleLongPress}
      delayLongPress={400}
    >
      <View style={[
        styles.bubble,
        isMe && styles.bubbleMe,
        isSearchHit && styles.bubbleSearchHit,
        isSearchActive && styles.bubbleSearchActive,
      ]}>
        {!isMe && <Text style={[styles.author, { color }]}>{author}</Text>}
        {msg._reply && (
          <View style={styles.replyQuote}>
            <View style={styles.replyQuoteBar} />
            <View style={styles.replyQuoteBody}>
              <Text style={[styles.replyQuoteAuthor, isMe && styles.replyQuoteTextMe]}>{msg._reply.author}</Text>
              <Text style={[styles.replyQuoteText, isMe && styles.replyQuoteTextMe]} numberOfLines={1}>{msg._reply.text}</Text>
            </View>
          </View>
        )}
        {decryptFailed ? (
          <Text style={styles.decryptFailedText}>Could not decrypt this message</Text>
        ) : fileInfo ? (
          <FileCard token={fileInfo.token} filename={fileInfo.filename} sizeBytes={fileInfo.sizeBytes} />
        ) : (
          <MessageText text={text} isMe={isMe} />
        )}
        {msg._decrypted === undefined && !decryptFailed && msg.encrypted && (
          <Text style={styles.encNote}>encrypted</Text>
        )}
        {timeStr ? <Text style={styles.timeText}>{timeStr}</Text> : null}
      </View>
    </TouchableOpacity>
  );
}

export default function ChatScreen({ navigation, route }) {
  const { state, dispatch, disconnectRoom } = useApp();
  const insets = useSafeAreaInsets();
  const { roomId, roomName } = route?.params || {};
  const screenReady = !!state.isLoggedIn && !!roomId;

  const [inputText, setInputText] = useState('');
  const [sending, setSending] = useState(false);
  const [showMembers, setShowMembers] = useState(false);
  const [cryptoReady, setCryptoReady] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [pinnedContext, setPinnedContext] = useState(null);
  const [pinnedCollapsed, setPinnedCollapsed] = useState(false);
  const [showPinEdit, setShowPinEdit] = useState(false);
  const [pinEditText, setPinEditText] = useState('');
  const [pinEditUrl, setPinEditUrl] = useState('');
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [replyTo, setReplyTo] = useState(null); // { id, author, text }
  const _isNearBottomRef = useRef(true); // track if user is scrolled near the bottom
  const _initialScrollDoneRef = useRef(false); // initial scroll-to-bottom done for this room
  const _kbScrollNeededRef = useRef(false); // captured at onFocus, before keyboard animation starts

  // Search
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchIdx, setSearchIdx] = useState(0);
  const searchInputRef = useRef(null);
  const searchFocusTimerRef = useRef(null);

  const flatRef = useRef(null);
  const messages = state.currentRoomMessages || [];
  const myUsername = state.username;

  const messagesRef = useRef(messages);
  messagesRef.current = messages;
  const _pendingSentRef = useRef(new Set());
  // Track echo-suppression cleanup timers so we can clear them on unmount
  const _echoTimersRef = useRef(new Set());
  useEffect(() => () => { _echoTimersRef.current.forEach(t => clearTimeout(t)); }, []);

  // Stable handler refs — registered once, delegate to current closure via ref
  const _handleIncomingMsgRef = useRef(null);
  const _handleMembersChangedRef = useRef(null);

  // Pagination state (mirrors extension panel.js)
  const HISTORY_PAGE_SIZE = 50;
  const _hasMoreRef = useRef(false);
  const _oldestIdRef = useRef(null);

  // Room key readiness gate — prevents race between WS listener and init effect
  const _roomKeyReadyRef = useRef(false);
  const _pendingIncomingRef = useRef([]);
  // Guard against stale async init when roomId changes quickly (mirrors DMChatScreen._initActiveRef)
  const _initActiveRef = useRef(false);

  // Derive read-only status and role from room list
  const currentRoom = useMemo(() => {
    const id = String(roomId);
    return (state.myRooms || []).find(r => String(r.id || r.room_id) === id) || null;
  }, [state.myRooms, roomId]);
  const myRole = state.roomRoles?.[roomId] ||
    (currentRoom?.role) ||
    (currentRoom?.is_owner ? 'owner' : 'member');
  const isOwnerOrAdmin = myRole === 'owner' || myRole === 'admin';
  const isReadonly = !!(currentRoom?.is_readonly);
  const composerLocked = isReadonly && !isOwnerOrAdmin;

  // No interactive password prompts — crypto auto-unlocks from Keychain

  // Set current room on enter, clear on leave (keeps unread counters accurate)
  // useFocusEffect fires on tab switch too, ensuring currentRoomId resets to null when leaving.
  useFocusEffect(useCallback(() => {
    if (!screenReady) {
      return () => {
        if (searchFocusTimerRef.current) clearTimeout(searchFocusTimerRef.current);
      };
    }
    if (roomId) dispatch({ type: 'CLEAR_UNREAD_ROOM', roomId });
    return () => {
      // Just un-mark the active room; preserve currentRoomMessages for when user returns
      dispatch({ type: 'LEAVE_ROOM_VIEW' });
      if (searchFocusTimerRef.current) clearTimeout(searchFocusTimerRef.current);
    };
  }, [screenReady, roomId]));

  // Check crypto status on mount (actual unlock happens in the history load effect below)
  useEffect(() => {
    setCryptoReady(CryptoService.isReady());
  }, []);

  // Set up NetworkService listeners for incoming messages.
  // Use ref-based stable handler: registered ONCE on mount, removed ONCE on unmount.
  // Delegates to the latest handleIncomingMsg via ref — prevents listener accumulation
  // that caused message duplication when navigating between tabs/screens.
  _handleIncomingMsgRef.current = handleIncomingMsg;
  useEffect(() => {
    const stableHandler = (msg) => _handleIncomingMsgRef.current?.(msg);
    NetworkService.on('message', stableHandler);
    return () => NetworkService.off('message', stableHandler);
  }, []); // empty deps — register once

  // Auto-share room key when an invitee accepts (owner only)
  _handleMembersChangedRef.current = (msg) => {
    if (!screenReady) return;
    if (msg.type !== 'members_changed') return;
    if (String(msg.room_id) !== String(roomId)) return;
    if (msg.action !== 'invite_accepted') return;
    if (myRole !== 'owner') return;
    const username = msg.username;
    if (!username) return;
    CryptoService.shareRoomKeyToUser(roomId, username).catch(err => {
      if (String(err?.message || '').includes('re-verification')) {
        Alert.alert('Key Verification Required', err.message);
      } else if (__DEV__) {
        console.warn('[ChatScreen] auto key share after accept failed:', err?.message);
      }
    });
    refreshMembers();
  };
  useEffect(() => {
    const stableHandler = (msg) => _handleMembersChangedRef.current?.(msg);
    NetworkService.on('message', stableHandler);
    return () => NetworkService.off('message', stableHandler);
  }, []); // empty deps — register once

  // Scroll to bottom when new messages arrive — skip if search is open or user scrolled up
  const _scrollTimerRef = useRef(null);
  useEffect(() => {
    if (messages.length > 0 && !searchOpen && _isNearBottomRef.current) {
      clearTimeout(_scrollTimerRef.current);
      if (!_initialScrollDoneRef.current) {
        // First load for this room — jump instantly without animation
        _initialScrollDoneRef.current = true;
        _scrollTimerRef.current = setTimeout(() => flatRef.current?.scrollToEnd({ animated: false }), 50);
      } else {
        _scrollTimerRef.current = setTimeout(() => flatRef.current?.scrollToEnd({ animated: true }), 100);
      }
    }
    return () => clearTimeout(_scrollTimerRef.current);
  }, [messages.length, searchOpen]);

  // When keyboard fully appears, scroll to end if user was at the bottom when they tapped the input.
  // onFocus captures the pre-animation state (before KAV padding shrinks the FlatList).
  // Without this, adjustNothing + Reanimated leaves the scroll offset unchanged while the
  // visible area shrinks — the last message scrolls out of view.
  useEffect(() => {
    const sub = Keyboard.addListener('keyboardDidShow', () => {
      if (_kbScrollNeededRef.current) {
        flatRef.current?.scrollToEnd({ animated: false });
        _kbScrollNeededRef.current = false;
      }
    });
    return () => sub.remove();
  }, []);

  // Persist messages to storage (debounced) — single writer avoids race conditions
  const _persistTimerRef = useRef(null);
  useEffect(() => {
    if (!screenReady || !messages.length) return;
    clearTimeout(_persistTimerRef.current);
    _persistTimerRef.current = setTimeout(() => {
      StorageService.setRoomHistory(roomId, messages.slice(-200)).catch(() => {});
    }, 300);
    return () => clearTimeout(_persistTimerRef.current);
  }, [screenReady, roomId, messages]);

  // Ensure WS is connected to this room on mount (handles kick + re-invite scenario)
  useEffect(() => {
    if (!screenReady) return;
    if (!NetworkService.isConnectedToRoom(roomId)) {
      console.log('[ChatScreen] WS not connected to room', roomId, '— reconnecting');
      NetworkService.connectRoom(roomId);
    }
  }, [screenReady, roomId]);

  // Load room history from server + room key on enter (mirrors extension panel.js)
  useEffect(() => {
    if (!screenReady) {
      _roomKeyReadyRef.current = false;
      _pendingIncomingRef.current = [];
      _initActiveRef.current = false;
      return;
    }
    _hasMoreRef.current = false;
    _oldestIdRef.current = null;

    _roomKeyReadyRef.current = false;
    _pendingIncomingRef.current = [];
    _initActiveRef.current = true;
    _isNearBottomRef.current = true;
    _initialScrollDoneRef.current = false;

    (async () => {
      // Ensure crypto is unlocked before loading room keys
      if (!CryptoService.isReady()) {
        const ok = await CryptoService.ensureReady({ interactive: false });
        if (!_initActiveRef.current) return;
        if (ok) setCryptoReady(true);
      }

      await CryptoService.restoreRoomKeyArchive(roomId);
      if (!_initActiveRef.current) return;
      const ownerFlag = myRole === 'owner';
      await CryptoService.ensureRoomKeyReady(roomId, { isOwner: ownerFlag }).catch(() => {});
      if (!_initActiveRef.current) return;
      // NOTE: _roomKeyReadyRef stays false here — WS messages queue in _pendingIncomingRef.
      // Gate opens AFTER SET_CURRENT_ROOM_MESSAGES to prevent WS messages being wiped by SET.

      // Fetch history from server (like extension)
      try {
        const data = await NetworkService.getRoomHistory(roomId, { limit: HISTORY_PAGE_SIZE });
        if (!_initActiveRef.current) return;
        const serverMsgs = data?.messages || (Array.isArray(data) ? data : []);
        _hasMoreRef.current = !!data?.has_more;
        _oldestIdRef.current = data?.oldest_id || null;

        if (serverMsgs.length) {
          const decrypted = await decryptBatch(serverMsgs);
          if (!_initActiveRef.current) return;
          dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: decrypted.map(normMsg) });
        }
      } catch (_e) {
        if (!_initActiveRef.current) return;
        // Server fetch failed — fall back to local storage
        const history = await StorageService.getRoomHistory(roomId);
        if (history && history.length) {
          const decrypted = await decryptBatch(history);
          if (!_initActiveRef.current) return;
          dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: decrypted.map(normMsg) });
        }
      }

      if (!_initActiveRef.current) return;

      // Only open the gate if the room key actually loaded. If ensureRoomKeyReady
      // silently failed (server 500 / network blip), keep the gate closed so queued
      // WS messages don't get permanently marked _decryptFailed. The 'room_key_loaded'
      // listener below will flush the queue once the key arrives.
      if (CryptoService.isRoomKeyLoaded(roomId)) {
        _roomKeyReadyRef.current = true;

        // Flush any WS messages that arrived while we were loading room key + history
        if (_pendingIncomingRef.current.length) {
          const queued = _pendingIncomingRef.current.splice(0);
          for (const qMsg of queued) {
            if (!_initActiveRef.current) return;
            const dec = normMsg(await tryDecrypt(qMsg));
            dispatch({ type: 'APPEND_ROOM_MESSAGE', message: dec });
          }
        }
      } else {
        console.warn('[ChatScreen] Room key not loaded after ensureRoomKeyReady — gate stays closed, waiting for room_key_loaded event');
      }

      // Load room members into state + TOFU batch-check for key changes
      CryptoService.resetKeyChangeAlerts();
      try {
        const memberList = await NetworkService.getRoomMembers(roomId);
        if (!_initActiveRef.current) return;
        if (Array.isArray(memberList)) {
          dispatch({ type: 'SET_ROOM_MEMBERS', roomId, members: memberList });
          const names = memberList.map(m => m.username || m.name).filter(Boolean);
          CryptoService.checkRoomPeersKeyChanges(names).catch(() => {});
        }
      } catch (_e) { /* ignore */ }
    })().catch(e => console.warn('[ChatScreen] init error:', e?.message));

    return () => { _initActiveRef.current = false; };
  }, [screenReady, roomId]);

  // Fetch pinned context for this room
  useEffect(() => {
    if (!screenReady) {
      setPinnedContext(null);
      return;
    }
    (async () => {
      try {
        const pin = await NetworkService.fetchRoomPin(roomId);
        if (pin && (pin.url || pin.text)) {
          setPinnedContext(pin);
        } else {
          setPinnedContext(null);
        }
      } catch (_) { setPinnedContext(null); }
    })();
  }, [screenReady, roomId]);

  // Load older messages on scroll to top (infinite scroll, mirrors extension)
  async function loadOlderMessages() {
    if (!screenReady) return;
    if (loadingOlder || !_hasMoreRef.current || !_oldestIdRef.current) return;
    setLoadingOlder(true);
    try {
      const data = await NetworkService.getRoomHistory(roomId, {
        limit: HISTORY_PAGE_SIZE,
        before_id: _oldestIdRef.current,
      });
      const serverMsgs = data?.messages || (Array.isArray(data) ? data : []);
      _hasMoreRef.current = !!data?.has_more;
      _oldestIdRef.current = data?.oldest_id || _oldestIdRef.current;

      if (serverMsgs.length) {
        const decrypted = await decryptBatch(serverMsgs);
        const older = decrypted.map(normMsg);
        const current = messagesRef.current || [];
        // Deduplicate by id
        const existingIds = new Set(current.filter(m => m.id).map(m => String(m.id)));
        const newMsgs = older.filter(m => !existingIds.has(String(m.id)));
        if (newMsgs.length) {
          dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: [...newMsgs, ...current] });
        }
      }
    } catch (_e) { /* ignore */ }
    setLoadingOlder(false);
  }

  // Re-decrypt when crypto unlocks (e.g. user enters password after seeing ciphertext).
  // On idle lock, reset the key gate so incoming WS messages queue properly until
  // the Keychain auto-unlock completes.
  useEffect(() => {
    if (!screenReady) return;
    const lockedHandler = () => {
      _roomKeyReadyRef.current = false;
    };
    CryptoService.on('locked', lockedHandler);

    const handler = async () => {
      const ownerFlag = myRole === 'owner';
      await CryptoService.ensureRoomKeyReady(roomId, { isOwner: ownerFlag }).catch(() => {});
      // If init effect is still running, it will open the gate itself after SET_CURRENT_ROOM_MESSAGES.
      // Opening the gate here would let APPEND_ROOM_MESSAGE interleave before SET, causing those
      // messages to be wiped when SET fires. Loading the key above is still useful — it makes
      // init's decryptBatch succeed even though ensureRoomKeyReady already ran (and failed).
      if (_initActiveRef.current) return;
      _roomKeyReadyRef.current = true;

      // Flush queued WS messages that arrived before room key was ready
      if (_pendingIncomingRef.current.length) {
        const queued = _pendingIncomingRef.current.splice(0);
        for (const qMsg of queued) {
          const dec = normMsg(await tryDecrypt(qMsg));
          dispatch({ type: 'APPEND_ROOM_MESSAGE', message: dec });
        }
      }

      // Re-decrypt existing messages that failed on load
      const snapshot = messagesRef.current || [];
      const need = snapshot.filter(m => !m._decrypted && (m.text || m.body || '').includes('"encrypted"'));
      if (!need.length) return;
      const redone = await decryptBatch(need);
      const current = messagesRef.current || [];
      const updated = current.map(m => {
        if (m._decrypted) return m;
        return redone.find(r => String(r.id || r.ts) === String(m.id || m.ts)) || m;
      });
      dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: updated });
    };
    CryptoService.on('unlocked', handler);

    // Room-key-specific retry: fires when _loadRoomKey / createAndShareRoomKey /
    // _loadRoomKeyArchiveFromServer succeed. Covers the case where crypto is unlocked
    // but the room key failed to load on first entry (server 500, transient network).
    const roomKeyHandler = async (data) => {
      if (data?.roomId != null && String(data.roomId) !== String(roomId)) return;
      if (_initActiveRef.current) return;
      if (_roomKeyReadyRef.current) {
        // Gate already open — just re-run the decryptBatch redecrypt path for
        // messages that were marked failed/undecrypted.
        const snapshot = messagesRef.current || [];
        const need = snapshot.filter(m => !m._decrypted && (m.text || m.body || '').includes('"encrypted"'));
        if (!need.length) return;
        const redone = await decryptBatch(need);
        const current = messagesRef.current || [];
        const updated = current.map(m => {
          if (m._decrypted) return m;
          return redone.find(r => String(r.id || r.ts) === String(m.id || m.ts)) || m;
        });
        dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: updated });
        return;
      }
      // Gate was closed (ensureRoomKeyReady failed earlier) — open it now and flush queue.
      _roomKeyReadyRef.current = true;
      if (_pendingIncomingRef.current.length) {
        const queued = _pendingIncomingRef.current.splice(0);
        for (const qMsg of queued) {
          const dec = normMsg(await tryDecrypt(qMsg));
          dispatch({ type: 'APPEND_ROOM_MESSAGE', message: dec });
        }
      }
      const snapshot = messagesRef.current || [];
      const need = snapshot.filter(m => !m._decrypted && (m.text || m.body || '').includes('"encrypted"'));
      if (need.length) {
        const redone = await decryptBatch(need);
        const current = messagesRef.current || [];
        const updated = current.map(m => {
          if (m._decrypted) return m;
          return redone.find(r => String(r.id || r.ts) === String(m.id || m.ts)) || m;
        });
        dispatch({ type: 'SET_CURRENT_ROOM_MESSAGES', messages: updated });
      }
    };
    CryptoService.on('room_key_loaded', roomKeyHandler);

    return () => {
      CryptoService.off('locked', lockedHandler);
      CryptoService.off('unlocked', handler);
      CryptoService.off('room_key_loaded', roomKeyHandler);
    };
  }, [screenReady, roomId]);

  function handleIncomingMsg(msg) {
    if (!screenReady) return;
    if (!msg || msg.type !== 'message') return;
    // Room_id check: skip if message belongs to a different room
    if (msg.room_id && String(msg.room_id) !== String(roomId)) return;

    // Echo suppression: skip messages we just sent
    const rawBody = msg.body || msg.text || '';
    if (rawBody && _pendingSentRef.current.has(rawBody)) {
      _pendingSentRef.current.delete(rawBody);
      return;
    }

    // If room key isn't loaded yet, queue message for later decryption
    if (!_roomKeyReadyRef.current) {
      _pendingIncomingRef.current.push(msg);
      return;
    }

    (async () => {
      const dec = normMsg(await tryDecrypt(msg));
      dispatch({ type: 'APPEND_ROOM_MESSAGE', message: dec });
      // TOFU: check sender's key on each incoming message (extension parity)
      const sender = msg.author || msg.username;
      if (sender) CryptoService.checkAndAlertKeyChange(sender).catch(() => {});
    })();
  }

  async function tryDecrypt(msg) {
    const body = msg.body || msg.text || msg.content || '';
    if (!body || !body.includes('"encrypted"')) return msg;
    try {
      const text = await CryptoService.decryptMessage(roomId, body);
      if (text !== null) {
        // Strip stale failure/needs-decrypt flags — render logic hides text if _decryptFailed
        // is set, so a successful re-decryption must clear it.
        const { _decryptFailed: _f, _needsDecrypt: _n, ...rest } = msg;
        if (text.startsWith('{')) {
          try {
            const parsed = JSON.parse(text);
            if (parsed.v === 2 && parsed.t !== undefined) {
              return { ...rest, _decrypted: parsed.t, ...(parsed.reply ? { _reply: parsed.reply } : {}) };
            }
          } catch (_pe) {}
        }
        return { ...rest, _decrypted: text };
      }
    } catch (_e) {
      console.warn('[ChatScreen] decryptMessage failed:', _e?.message);
    }
    // Mark as failed so UI can show indicator instead of raw ciphertext
    return { ...msg, _decryptFailed: true };
  }

  async function decryptBatch(msgs) {
    return Promise.all(msgs.map(m => tryDecrypt(m)));
  }

  function handleReply(msg) {
    const text = (msg._decrypted || '').slice(0, 120);
    setReplyTo({ id: msg.id ?? null, author: msg.author || msg.username || 'Unknown', text });
  }

  async function handleSend() {
    if (!screenReady) return;
    if (!inputText.trim() || sending) return;
    const text = inputText.trim();
    setInputText('');
    setSending(true);

    try {
      // Encrypt message — never send plaintext (matches extension behavior)
      if (!CryptoService.isReady()) {
        const ok = await CryptoService.ensureReady({ interactive: false });
        if (ok) setCryptoReady(true);
      }
      if (!CryptoService.isReady()) {
        Alert.alert('Encryption required', 'Please restart the app and enter your password to send messages.');
        setInputText(text);
        return;
      }
      const payload = replyTo
        ? JSON.stringify({ v: 2, t: text, reply: { id: replyTo.id, author: replyTo.author, text: replyTo.text } })
        : text;
      const body = await CryptoService.encryptMessage(roomId, payload);
      if (!body) {
        Alert.alert('Encryption failed', 'Unable to encrypt the message. Room key may not be loaded yet — please try again.');
        setInputText(text);
        return;
      }

      // Track body for echo suppression before sending
      _pendingSentRef.current.add(body);
      const _t1 = setTimeout(() => { _pendingSentRef.current.delete(body); _echoTimersRef.current.delete(_t1); }, 30000);
      _echoTimersRef.current.add(_t1);

      // Auto-reconnect WS if not connected (e.g. after kick + re-invite)
      if (!NetworkService.isConnectedToRoom(roomId)) {
        NetworkService.connectRoom(roomId);
        // Wait for WS to open (up to 5s)
        const _wsReady = await new Promise(resolve => {
          let _timer = null;
          const _onStatus = (msg) => {
            if (msg.online) {
              clearTimeout(_timer);
              NetworkService.off('status', _onStatus);
              resolve(true);
            }
          };
          NetworkService.on('status', _onStatus);
          _timer = setTimeout(() => { NetworkService.off('status', _onStatus); resolve(false); }, 5000);
        });
        if (!_wsReady) {
          Alert.alert('Connection error', 'Unable to connect to the room. Please try again.');
          setInputText(text);
          _pendingSentRef.current.delete(body);
          return;
        }
      }

      await NetworkService.sendMessage(body);
      setReplyTo(null);
      // Optimistic UI: add message locally
      const optimistic = {
        id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        author: myUsername,
        username: myUsername,
        body: text,
        text,
        _decrypted: text,
        ts: Date.now(),
        ...(replyTo ? { _reply: { id: replyTo.id, author: replyTo.author, text: replyTo.text } } : {}),
      };
      dispatch({ type: 'APPEND_ROOM_MESSAGE', message: optimistic });
      // Storage is handled by the debounced useEffect
    } catch (e) {
      Alert.alert('Error', e?.message || 'Send failed');
      setInputText(text); // restore
    } finally {
      setSending(false);
    }
  }

  async function handleAttachFile() {
    if (!screenReady) return;
    try {
      const [res] = await pickDocument({ type: [pickerTypes.allFiles] });
      if (!res?.uri) return;

      if (!CryptoService.isReady()) {
        const ok = await CryptoService.ensureReady({ interactive: true, reason: 'Attach encrypted file' });
        if (!ok) { Alert.alert('Encryption required', 'Unlock encryption to send files.'); return; }
        setCryptoReady(true);
      }

      setSending(true);
      const upload = await NetworkService.uploadFile(roomId, {
        filename: res.name || 'file',
        mimeType: res.type || 'application/octet-stream',
        fileBlob: res.uri,
      });

      if (!upload?.token) throw new Error('Upload failed — no token');

      const marker = makeFileMarker(upload.token, upload.filename || res.name, upload.size_bytes || 0);
      const body = await CryptoService.encryptMessage(roomId, marker);
      if (!body) {
        Alert.alert('Encryption failed', 'Unable to encrypt file marker. Please try again.');
        setSending(false);
        return;
      }

      _pendingSentRef.current.add(body);
      const _t2 = setTimeout(() => { _pendingSentRef.current.delete(body); _echoTimersRef.current.delete(_t2); }, 30000);
      _echoTimersRef.current.add(_t2);

      await NetworkService.sendMessage(body);

      const optimistic = {
        id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        author: myUsername,
        username: myUsername,
        body: marker,
        text: marker,
        _decrypted: marker,
        ts: Date.now(),
      };
      dispatch({ type: 'APPEND_ROOM_MESSAGE', message: optimistic });
    } catch (e) {
      if (e?.code !== 'OPERATION_CANCELED') {
        Alert.alert('File upload failed', e?.message || 'Unknown error');
      }
    } finally {
      setSending(false);
    }
  }

  // Search: compute matching indices from decrypted text + author
  const searchHits = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q || !searchOpen) return [];
    const hits = [];
    messages.forEach((m, i) => {
      const text = (m._decrypted ?? m.text ?? m.body ?? '').toLowerCase();
      const author = (m.author || m.username || '').toLowerCase();
      if (text.includes(q) || author.includes(q)) hits.push(i);
    });
    return hits;
  }, [searchQuery, searchOpen, messages]);

  // Reset active index when query changes
  useEffect(() => { setSearchIdx(0); }, [searchQuery]);

  // Scroll to active search hit
  useEffect(() => {
    if (!searchHits.length) return;
    const idx = searchHits[searchIdx % searchHits.length];
    if (idx == null) return;
    try {
      flatRef.current?.scrollToIndex({ index: idx, animated: true, viewPosition: 0.4 });
    } catch (_e) {
      flatRef.current?.scrollToOffset({ offset: idx * 80, animated: true });
    }
  }, [searchIdx, searchHits]);

  function openSearch() {
    setSearchOpen(true);
    setSearchQuery('');
    if (searchFocusTimerRef.current) clearTimeout(searchFocusTimerRef.current);
    searchFocusTimerRef.current = setTimeout(() => searchInputRef.current?.focus(), 100);
  }

  function closeSearch() {
    setSearchOpen(false);
    setSearchQuery('');
    Keyboard.dismiss();
  }

  function stepSearch(dir) {
    if (!searchHits.length) return;
    setSearchIdx(i => (i + dir + searchHits.length) % searchHits.length);
  }

  const members = state.roomMembers[roomId] || [];
  const onlineUsers = state.onlineByRoom[roomId] || [];

  const refreshMembers = useCallback(async () => {
    if (!screenReady) return;
    try {
      const list = await NetworkService.getRoomMembers(roomId);
      if (Array.isArray(list)) dispatch({ type: 'SET_ROOM_MEMBERS', roomId, members: list });
    } catch (_e) { /* ignore */ }
  }, [screenReady, roomId]);

  if (!screenReady) {
    return <View style={{ flex: 1, backgroundColor: Colors.bgMain }} />;
  }

  return (
    <KeyboardAvoidingView style={styles.root} behavior="padding">
      {/* Header */}
      <View style={[styles.header, { paddingTop: (insets.top || Spacing.lg) + Spacing.md }]}>
        <TouchableOpacity onPress={() => navigation.goBack()}>
          <Text style={styles.backBtn}>←</Text>
        </TouchableOpacity>
        <RoomLogo logoUrl={currentRoom?.logo_url} roomName={currentRoom?.name || roomName || 'Chat'} size={34} />
        <View style={styles.headerCenter}>
          <View style={styles.roomNameRow}>
            <Text style={styles.roomName} numberOfLines={1}>{currentRoom?.name || roomName || 'Chat'}</Text>
            {isReadonly && <View style={styles.readonlyBadge}><Text style={styles.readonlyBadgeText}>read-only</Text></View>}
          </View>
          {onlineUsers.length > 0 && (
            <Text style={styles.onlineCount}>{onlineUsers.length} online</Text>
          )}
        </View>
        {isOwnerOrAdmin && (
          <TouchableOpacity onPress={() => setShowSettings(true)} style={styles.settingsBtn}>
            <Text style={styles.settingsBtnText}>⚙</Text>
          </TouchableOpacity>
        )}
        <TouchableOpacity onPress={openSearch} style={styles.searchBtn}>
          <Text style={styles.searchBtnText}>🔍</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => setShowMembers(true)}>
          <Text style={styles.membersBtn}>⋯</Text>
        </TouchableOpacity>
      </View>

      {/* Search bar */}
      {searchOpen && (
        <View style={styles.searchBar}>
          <TextInput
            ref={searchInputRef}
            style={styles.searchInput}
            placeholder="Search messages…"
            placeholderTextColor={Colors.textMuted}
            value={searchQuery}
            onChangeText={setSearchQuery}
            returnKeyType="search"
            onSubmitEditing={() => stepSearch(1)}
            autoCapitalize="none"
          />
          {searchQuery.trim().length > 0 && (
            <Text style={styles.searchMeta}>
              {searchHits.length
                ? `${(searchIdx % searchHits.length) + 1}/${searchHits.length}`
                : '0/0'}
            </Text>
          )}
          <TouchableOpacity
            style={[styles.searchNavBtn, !searchHits.length && styles.searchNavDisabled]}
            onPress={() => stepSearch(-1)}
            disabled={!searchHits.length}
          >
            <Text style={styles.searchNavText}>↑</Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.searchNavBtn, !searchHits.length && styles.searchNavDisabled]}
            onPress={() => stepSearch(1)}
            disabled={!searchHits.length}
          >
            <Text style={styles.searchNavText}>↓</Text>
          </TouchableOpacity>
          <TouchableOpacity onPress={closeSearch} style={styles.searchCloseBtn}>
            <Text style={styles.searchCloseBtnText}>✕</Text>
          </TouchableOpacity>
        </View>
      )}

      {/* Pinned context bar */}
      {pinnedContext && (pinnedContext.url || pinnedContext.text) && (
        <TouchableOpacity
          style={styles.pinnedBar}
          onPress={() => setPinnedCollapsed(!pinnedCollapsed)}
          onLongPress={myRole === 'owner' ? () => {
            setPinEditUrl(pinnedContext.url || '');
            setPinEditText(pinnedContext.text || '');
            setShowPinEdit(true);
          } : undefined}
        >
          <View style={styles.pinnedHeader}>
            <Text style={styles.pinnedTitle}>📌 Pinned context</Text>
            <Text style={styles.pinnedToggle}>{pinnedCollapsed ? '▼' : '▲'}</Text>
          </View>
          {!pinnedCollapsed && (
            <>
              {pinnedContext.url ? (
                <Text
                  style={styles.pinnedUrl}
                  numberOfLines={1}
                  onPress={() => Linking.openURL(pinnedContext.url)}
                >
                  {pinnedContext.url}
                </Text>
              ) : null}
              {pinnedContext.text ? (
                <Text style={styles.pinnedText} numberOfLines={4}>
                  {pinnedContext.text.slice(0, 180)}{pinnedContext.text.length > 180 ? '…' : ''}
                </Text>
              ) : null}
            </>
          )}
        </TouchableOpacity>
      )}

      {/* Messages */}
      <FlatList
        ref={flatRef}
        data={messages}
        keyExtractor={(item, idx) => `${item.id ?? 'msg'}_${idx}`}
        renderItem={({ item, index }) => {
          const hitPos = searchHits.indexOf(index);
          const isHit = hitPos !== -1;
          const isActive = isHit && hitPos === searchIdx % searchHits.length;
          return (
            <MessageBubble
              msg={item}
              myUsername={myUsername}
              isSearchHit={isHit}
              isSearchActive={isActive}
              onReply={handleReply}
            />
          );
        }}
        contentContainerStyle={styles.messageList}
        ListHeaderComponent={
          loadingOlder ? (
            <ActivityIndicator size="small" color={Colors.textMuted} style={{ marginVertical: Spacing.sm }} />
          ) : _hasMoreRef.current ? (
            <TouchableOpacity onPress={loadOlderMessages} style={styles.loadMoreBtn}>
              <Text style={styles.loadMoreText}>Load older messages</Text>
            </TouchableOpacity>
          ) : null
        }
        ListEmptyComponent={
          <Text style={styles.emptyText}>No messages yet</Text>
        }
        onContentSizeChange={() => !searchOpen && _isNearBottomRef.current && flatRef.current?.scrollToEnd({ animated: false })}
        onScrollToIndexFailed={({ index }) => {
          setTimeout(() => {
            flatRef.current?.scrollToIndex({ index, animated: true, viewPosition: 0.4 });
          }, 200);
        }}
        onScroll={({ nativeEvent }) => {
          // Track if user is near the bottom (within 150px) for auto-scroll
          const { contentOffset, layoutMeasurement, contentSize } = nativeEvent;
          _isNearBottomRef.current = contentOffset.y + layoutMeasurement.height >= contentSize.height - 150;
          // Load older messages when scrolled near top
          if (contentOffset.y < 40 && !searchOpen && _hasMoreRef.current && !loadingOlder) {
            loadOlderMessages();
          }
        }}
        scrollEventThrottle={200}
      />

      {/* Input */}
      {replyTo && !composerLocked && (
        <View style={styles.replyBar}>
          <View style={styles.replyBarContent}>
            <Text style={styles.replyBarAuthor}>{replyTo.author}</Text>
            <Text style={styles.replyBarText} numberOfLines={1}>{replyTo.text}</Text>
          </View>
          <TouchableOpacity onPress={() => setReplyTo(null)} hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}>
            <Text style={styles.replyBarClose}>✕</Text>
          </TouchableOpacity>
        </View>
      )}
      {composerLocked ? (
        <View style={[styles.readonlyBar, { paddingBottom: insets.bottom || Spacing.sm }]}>
          <Text style={styles.readonlyBarText}>🔇 Read-only channel — you cannot send messages</Text>
        </View>
      ) : (
        <View style={[styles.inputRow, { paddingBottom: insets.bottom || Spacing.sm }]}>
          <TouchableOpacity style={styles.attachBtn} onPress={handleAttachFile} disabled={sending}>
            <Text style={styles.attachBtnText}>+</Text>
          </TouchableOpacity>
          <TextInput
            style={styles.input}
            placeholder="Message…"
            placeholderTextColor={Colors.textMuted}
            value={inputText}
            onChangeText={setInputText}
            multiline
            maxLength={4096}
            returnKeyType="send"
            onSubmitEditing={handleSend}
            blurOnSubmit={false}
            onFocus={() => { _kbScrollNeededRef.current = _isNearBottomRef.current; }}
          />
          <TouchableOpacity
            style={[styles.sendBtn, (!inputText.trim() || sending) && styles.sendBtnDisabled]}
            onPress={handleSend}
            disabled={!inputText.trim() || sending}
          >
            {sending
              ? <ActivityIndicator color="#fff" size="small" />
              : <Text style={styles.sendBtnText}>↑</Text>}
          </TouchableOpacity>
        </View>
      )}

      {/* Members modal */}
      <MembersModal
        visible={showMembers}
        onClose={() => setShowMembers(false)}
        members={members}
        onlineUsers={onlineUsers}
        roomId={roomId}
        myUsername={myUsername}
        myRole={myRole}
        onMembersChanged={refreshMembers}
        onLeaveRoom={() => navigation.goBack()}
        onSystemMessage={(text) => dispatch({
          type: 'APPEND_ROOM_MESSAGE',
          message: normMsg({ id: `sys_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`, author: 'System', text, ts: Date.now(), _decrypted: text }),
        })}
      />

      {/* Room settings modal (owner/admin) */}
      <RoomSettingsModal
        visible={showSettings}
        onClose={() => setShowSettings(false)}
        roomId={roomId}
        currentRoom={currentRoom}
        myRole={myRole}
        dispatch={dispatch}
      />

      {/* Pin edit modal (owner only) */}
      <Modal visible={showPinEdit} transparent animationType="fade" onRequestClose={() => setShowPinEdit(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.renameCard}>
            <Text style={styles.modalTitle}>Edit Pinned Context</Text>
            <TextInput
              style={styles.settingsInput}
              value={pinEditUrl}
              onChangeText={setPinEditUrl}
              placeholder="URL (optional)"
              placeholderTextColor="rgba(255,255,255,0.35)"
              autoCapitalize="none"
            />
            <TextInput
              style={styles.settingsTextarea}
              value={pinEditText}
              onChangeText={setPinEditText}
              placeholder="Pinned text…"
              placeholderTextColor="rgba(255,255,255,0.35)"
              multiline
              numberOfLines={4}
              maxLength={4000}
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => setShowPinEdit(false)}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.btn} onPress={async () => {
                try {
                  await NetworkService.putRoomPin(roomId, { url: pinEditUrl.trim(), text: pinEditText.trim() });
                  const newPin = { url: pinEditUrl.trim(), text: pinEditText.trim() };
                  setPinnedContext(newPin.url || newPin.text ? newPin : null);
                  setShowPinEdit(false);
                } catch (e) {
                  Alert.alert('Error', e?.message || 'Failed to save pin');
                }
              }}>
                <Text style={styles.btnText}>Save</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </KeyboardAvoidingView>
  );
}

// ---- Room settings modal (owner/admin) ----

function RoomSettingsModal({ visible, onClose, roomId, currentRoom, myRole, dispatch }) {
  const isOwner = myRole === 'owner';
  const [roomNameInput, setRoomNameInput] = React.useState('');
  const [description, setDescription] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [saving, setSaving] = React.useState(false);
  const [renaming, setRenaming] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [logoUploading, setLogoUploading] = React.useState(false);
  const [logoUrl, setLogoUrl] = React.useState(null);
  const [hasPassword, setHasPassword] = React.useState(false);
  const [removingPassword, setRemovingPassword] = React.useState(false);

  // Load current meta when modal opens
  React.useEffect(() => {
    if (!visible || loaded) return;
    (async () => {
      try {
        const meta = await NetworkService.getRoomMeta(roomId);
        setDescription(meta?.description || '');
        setLogoUrl(meta?.logo_url || null);
        setHasPassword(!!meta?.has_password || !!currentRoom?.has_password);
        setRoomNameInput(currentRoom?.name || '');
        setLoaded(true);
      } catch (_) { setLoaded(true); }
    })();
  }, [visible]);

  // Reset when modal closes
  React.useEffect(() => {
    if (!visible) { setLoaded(false); setPassword(''); setRoomNameInput(''); }
  }, [visible]);

  async function handleRename() {
    const newName = roomNameInput.trim();
    if (!newName || newName === (currentRoom?.name || '')) return;
    setRenaming(true);
    try {
      await NetworkService.renameRoom(roomId, newName);
      dispatch({ type: 'UPDATE_ROOM_NAME', roomId, name: newName });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Could not rename room');
    } finally {
      setRenaming(false);
    }
  }

  async function handleSave() {
    setSaving(true);
    try {
      // Update description
      await NetworkService.setRoomMeta(roomId, { description: description.trim() });

      // Update password if changed
      if (password.trim()) {
        await NetworkService._fetch(`/rooms/${roomId}/password`, {
          method: 'PUT',
          body: { password: password.trim() },
        });
        setHasPassword(true);
      }

      Alert.alert('Done', 'Room settings updated');
      onClose();
    } catch (e) {
      Alert.alert('Error', e?.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  }

  async function handleRemovePassword() {
    Alert.alert(
      'Remove Password',
      'Anyone with the room link will be able to join without a password.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Remove', style: 'destructive', onPress: async () => {
          setRemovingPassword(true);
          try {
            await NetworkService._fetch(`/rooms/${roomId}/password`, {
              method: 'PUT',
              body: { password: '' },
            });
            setHasPassword(false);
            setPassword('');
            Alert.alert('Done', 'Room password removed');
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to remove password');
          } finally {
            setRemovingPassword(false);
          }
        }},
      ],
    );
  }

  async function handleUploadLogo() {
    try {
      const [res] = await pickDocument({ type: ['image/*'] });
      if (!res?.uri) return;
      setLogoUploading(true);
      const result = await NetworkService.uploadRoomLogo(roomId, {
        filename: res.name || 'logo.png',
        mimeType: res.type || 'image/png',
        fileBlob: res.uri,
      });
      if (result?.logo_token) {
        await NetworkService.setRoomMeta(roomId, { logo_token: result.logo_token });
        setLogoUrl(`/rooms/${roomId}/logo`);
      }
      Alert.alert('Done', 'Room logo updated');
    } catch (e) {
      if (e?.code === 'OPERATION_CANCELED') return;
      Alert.alert('Error', e?.message || 'Failed to upload logo');
    } finally {
      setLogoUploading(false);
    }
  }

  async function handleDelete() {
    Alert.alert(
      'Delete Room',
      'This cannot be undone. All messages will be lost.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Delete', style: 'destructive', onPress: async () => {
          try {
            await NetworkService.deleteRoom(roomId);
            Alert.alert('Done', 'Room deleted');
            onClose();
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to delete');
          }
        }},
      ],
    );
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.settingsCard}>
          <View style={styles.modalHeader}>
            <View>
              <Text style={styles.modalTitle}>Room Settings</Text>
              <Text style={styles.roomIdHint}>ID: {roomId}</Text>
            </View>
            <TouchableOpacity onPress={onClose}>
              <Text style={styles.closeBtn}>✕</Text>
            </TouchableOpacity>
          </View>

          <ScrollView style={{ maxHeight: 400 }}>
          <View style={styles.settingsBody}>
            {/* Rename (owner/admin) */}
            <Text style={styles.settingsLabel}>Room Name</Text>
            <View style={styles.renameRow}>
              <TextInput
                style={[styles.settingsInput, { flex: 1 }]}
                value={roomNameInput}
                onChangeText={setRoomNameInput}
                placeholder="Room name"
                placeholderTextColor="rgba(255,255,255,0.35)"
                maxLength={64}
              />
              <TouchableOpacity
                style={[styles.renameApplyBtn, (renaming || !roomNameInput.trim() || roomNameInput.trim() === (currentRoom?.name || '')) && styles.btnDisabled]}
                onPress={handleRename}
                disabled={renaming || !roomNameInput.trim() || roomNameInput.trim() === (currentRoom?.name || '')}
              >
                {renaming
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.saveBtnText}>Rename</Text>}
              </TouchableOpacity>
            </View>

            {/* Logo */}
            <Text style={styles.settingsLabel}>Room Logo</Text>
            <View style={styles.logoRow}>
              <RoomLogo logoUrl={logoUrl} roomName={currentRoom?.name || roomName || 'Room'} size={48} />
              {!logoUrl && (
                <Text style={[styles.noLogoText, { marginLeft: Spacing.sm }]}>No logo</Text>
              )}
              {isOwner && (
                <TouchableOpacity
                  style={[styles.logoUploadBtn, logoUploading && { opacity: 0.5 }]}
                  onPress={handleUploadLogo}
                  disabled={logoUploading}
                >
                  {logoUploading
                    ? <ActivityIndicator color="#fff" size="small" />
                    : <Text style={styles.saveBtnText}>Upload</Text>}
                </TouchableOpacity>
              )}
            </View>

            {/* Description */}
            <Text style={styles.settingsLabel}>Description</Text>
            <TextInput
              style={styles.settingsTextarea}
              value={description}
              onChangeText={setDescription}
              placeholder="Room description…"
              placeholderTextColor="rgba(255,255,255,0.35)"
              multiline
              numberOfLines={3}
              maxLength={2000}
            />

            {/* Password (owner only) */}
            {isOwner && (
              <>
                <Text style={styles.settingsLabel}>
                  {hasPassword ? 'Change Password' : 'Set Password'}
                </Text>
                <TextInput
                  style={styles.settingsInput}
                  value={password}
                  onChangeText={setPassword}
                  placeholder={hasPassword ? 'Leave empty to keep current' : 'Enter new password'}
                  placeholderTextColor="rgba(255,255,255,0.35)"
                  secureTextEntry
                />
                {hasPassword && (
                  <TouchableOpacity
                    style={[styles.removePassBtn, removingPassword && { opacity: 0.5 }]}
                    onPress={handleRemovePassword}
                    disabled={removingPassword}
                  >
                    {removingPassword
                      ? <ActivityIndicator color={Colors.danger} size="small" />
                      : <Text style={styles.removePassBtnText}>Remove Password</Text>}
                  </TouchableOpacity>
                )}
              </>
            )}

            {/* Save */}
            <TouchableOpacity
              style={[styles.saveBtn, saving && { opacity: 0.5 }]}
              onPress={handleSave}
              disabled={saving}
            >
              {saving
                ? <ActivityIndicator color="#fff" size="small" />
                : <Text style={styles.saveBtnText}>Save</Text>}
            </TouchableOpacity>

            {/* Delete (owner only) */}
            {isOwner && (
              <TouchableOpacity style={styles.deleteBtn} onPress={handleDelete}>
                <Text style={styles.deleteBtnText}>Delete Room</Text>
              </TouchableOpacity>
            )}
          </View>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

// ---- Members modal ----

function MembersModal({ visible, onClose, members, onlineUsers, roomId, myUsername, myRole, onMembersChanged, onLeaveRoom, onSystemMessage }) {
  const onlineSet = new Set(onlineUsers);
  const canModerate = myRole === 'owner' || myRole === 'admin';
  const isOwner = myRole === 'owner';

  const [inviteUsername, setInviteUsername] = React.useState('');
  const [inviting, setInviting] = React.useState(false);
  const [reRequestingKey, setReRequestingKey] = React.useState(false);
  const [reportTarget, setReportTarget] = React.useState(null);
  const [reportReason, setReportReason] = React.useState('spam');
  const [reportComment, setReportComment] = React.useState('');
  const [reporting, setReporting] = React.useState(false);

  const REPORT_REASONS = [
    { value: 'spam', label: 'Spam' },
    { value: 'harassment', label: 'Harassment / abuse' },
    { value: 'illegal_content', label: 'Illegal content' },
    { value: 'impersonation', label: 'Impersonation' },
    { value: 'other', label: 'Other' },
  ];

  async function handleReport() {
    if (!reportTarget) return;
    setReporting(true);
    try {
      await NetworkService.reportUser(reportTarget, reportReason, reportComment.trim());
      setReportTarget(null);
      setReportComment('');
      setReportReason('spam');
      Alert.alert('Done', 'Report submitted. Thank you.');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Failed to submit report');
    } finally {
      setReporting(false);
    }
  }

  async function handleInvite() {
    const target = inviteUsername.trim();
    if (!target) return;
    setInviting(true);
    try {
      await NetworkService.inviteToRoom(roomId, target);
      // Key will be shared automatically when the invitee accepts (via members_changed WS event)
      Alert.alert('Done', `${target} has been invited. Room key will be shared when they accept.`);
      setInviteUsername('');
      onMembersChanged?.();
    } catch (e) {
      Alert.alert('Error', e?.message || 'Failed to invite');
    } finally {
      setInviting(false);
    }
  }

  async function handleRoleChange(username, currentRole) {
    const newRole = currentRole === 'admin' ? 'member' : 'admin';
    Alert.alert(
      'Change role',
      `Change ${username}'s role to ${newRole}?`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Confirm', onPress: async () => {
          try {
            await NetworkService.setMemberRole(roomId, username, newRole);
            Alert.alert('Done', `${username} is now ${newRole}`);
            onMembersChanged?.();
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to change role');
          }
        }},
      ],
    );
  }

  async function handleKick(username) {
    Alert.alert(
      'Kick member',
      `Remove ${username} from this room?`,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Kick', style: 'destructive', onPress: async () => {
          try {
            await NetworkService.kickFromRoom(roomId, username);
            // Rotate room key so kicked user can't decrypt new messages
            const sysMsg = (text) => onSystemMessage?.(text);
            try {
              sysMsg(`Rotating room key after removing ${username}...`);
              const membersList = await NetworkService.getRoomMembers(roomId);
              const remaining = (membersList || []).filter(
                m => (m.username || '').toLowerCase() !== username.toLowerCase(),
              );
              // Fetch public keys for each remaining member
              const withKeys = await Promise.all(
                remaining.map(async m => {
                  try {
                    const peerData = await NetworkService.fetchPeerKey(m.username);
                    return { ...m, public_key: peerData?.public_key };
                  } catch (_) { return m; }
                }),
              );
              if (withKeys.length > 0) {
                const result = await CryptoService.rotateRoomKey(roomId, withKeys);
                if (result.ok) {
                  const failNote = result.failed.length
                    ? ` (${result.failed.length} member(s) failed: ${result.failed.join(', ')})`
                    : '';
                  sysMsg(`Room key rotated. New key distributed to ${result.shared} member(s).${failNote}`);
                } else {
                  sysMsg(`Room key rotation failed: ${result.error || 'unknown error'}. Old key is still in use.`);
                }
              }
            } catch (rotateErr) {
              console.warn('[MembersModal] key rotation after kick failed:', rotateErr?.message);
              sysMsg(`Room key rotation failed: ${rotateErr?.message || 'unknown error'}. Old key is still in use.`);
            }
            Alert.alert('Done', `${username} was removed`);
            onMembersChanged?.();
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to kick');
          }
        }},
      ],
    );
  }

  function handleLeaveRoom() {
    if (myRole === 'owner') {
      Alert.alert('Cannot leave', 'You are the room owner. You cannot leave — you can only delete the room from room settings.');
      return;
    }
    Alert.alert(
      'Leave room',
      'Leave this room? You will no longer see it in the list.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Leave', style: 'destructive', onPress: async () => {
          try {
            await NetworkService.leaveRoom(roomId);
            onClose();
            onLeaveRoom?.();
          } catch (e) {
            Alert.alert('Error', e?.message || 'Failed to leave room');
          }
        }},
      ],
    );
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <View style={styles.modalOverlay}>
        <View style={styles.modalCard}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Members ({members.length})</Text>
            <TouchableOpacity onPress={onClose}>
              <Text style={styles.closeBtn}>✕</Text>
            </TouchableOpacity>
          </View>
          {isOwner && (
            <View style={styles.inviteRow}>
              <TextInput
                style={styles.inviteInput}
                placeholder="Username to invite…"
                placeholderTextColor="rgba(255,255,255,0.35)"
                value={inviteUsername}
                onChangeText={setInviteUsername}
                autoCapitalize="none"
                autoCorrect={false}
                editable={!inviting}
              />
              <TouchableOpacity
                style={[styles.inviteBtn, (!inviteUsername.trim() || inviting) && { opacity: 0.4 }]}
                onPress={handleInvite}
                disabled={!inviteUsername.trim() || inviting}
              >
                {inviting
                  ? <ActivityIndicator size="small" color="#fff" />
                  : <Text style={styles.inviteBtnText}>Invite</Text>}
              </TouchableOpacity>
            </View>
          )}
          <FlatList
            data={members}
            keyExtractor={(m) => m.username}
            renderItem={({ item: m }) => {
              const memberRole = m.role || (m.is_owner ? 'owner' : 'member');
              const isMe = (m.username || '').toLowerCase() === (myUsername || '').toLowerCase();
              const isOwner = memberRole === 'owner';
              // Owner can change role of anyone except self; admin can change role of members only
              const canChangeRole = canModerate && !isMe && !isOwner &&
                (myRole === 'owner' || (myRole === 'admin' && memberRole === 'member'));
              // Owner can kick anyone except owner; admin can kick members only
              const canKick = canModerate && !isMe && !isOwner &&
                (myRole === 'owner' || (myRole === 'admin' && memberRole === 'member'));

              return (
                <View style={styles.memberRow}>
                  <View style={[styles.onlineDot, onlineSet.has(m.username) ? styles.dotOn : styles.dotOff]} />
                  <Text style={[styles.memberName, { color: colorForUsername(m.username) }]}>
                    {m.username}
                  </Text>
                  <Text style={styles.memberRole}>{memberRole}</Text>
                  {canChangeRole && (
                    <TouchableOpacity
                      style={styles.roleBtn}
                      onPress={() => handleRoleChange(m.username, memberRole)}
                    >
                      <Text style={styles.roleBtnText}>
                        {memberRole === 'admin' ? '↓' : '↑'}
                      </Text>
                    </TouchableOpacity>
                  )}
                  {canKick && (
                    <TouchableOpacity
                      style={styles.kickBtn}
                      onPress={() => handleKick(m.username)}
                    >
                      <Text style={styles.kickBtnText}>✕</Text>
                    </TouchableOpacity>
                  )}
                  {!isMe && (
                    <TouchableOpacity
                      style={styles.reportBtn}
                      onPress={() => { setReportTarget(m.username); setReportReason('spam'); setReportComment(''); }}
                    >
                      <Text style={styles.reportBtnText}>⚑</Text>
                    </TouchableOpacity>
                  )}
                </View>
              );
            }}
            style={{ maxHeight: 300 }}
          />
          {!isOwner && (
            <TouchableOpacity
              style={[styles.reRequestKeyBtn, reRequestingKey && styles.btnDisabled]}
              onPress={async () => {
                setReRequestingKey(true);
                try {
                  const ok = await CryptoService.ensureRoomKeyReady(roomId);
                  Alert.alert(ok ? 'Done' : 'Not available', ok ? 'Room key loaded successfully.' : 'Room key not available from server. Ask the room owner to re-share.');
                } catch (e) {
                  Alert.alert('Error', e?.message || 'Failed to request key');
                } finally {
                  setReRequestingKey(false);
                }
              }}
              disabled={reRequestingKey}
            >
              {reRequestingKey
                ? <ActivityIndicator color={Colors.accent} size="small" />
                : <Text style={styles.reRequestKeyBtnText}>Re-request my key</Text>}
            </TouchableOpacity>
          )}
          <TouchableOpacity style={styles.leaveRoomBtn} onPress={handleLeaveRoom}>
            <Text style={styles.leaveRoomBtnText}>Leave Room</Text>
          </TouchableOpacity>
        </View>
      </View>

      {/* Report user sub-modal */}
      <Modal visible={!!reportTarget} transparent animationType="fade" onRequestClose={() => setReportTarget(null)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalCard}>
            <Text style={styles.modalTitle}>Report {reportTarget}</Text>
            {REPORT_REASONS.map(r => (
              <TouchableOpacity
                key={r.value}
                style={[styles.reportReasonRow, reportReason === r.value && styles.reportReasonSelected]}
                onPress={() => setReportReason(r.value)}
              >
                <View style={[styles.reportRadio, reportReason === r.value && styles.reportRadioActive]} />
                <Text style={styles.reportReasonLabel}>{r.label}</Text>
              </TouchableOpacity>
            ))}
            <TextInput
              style={styles.reportCommentInput}
              placeholder="Additional details (optional)…"
              placeholderTextColor={Colors.textMuted}
              value={reportComment}
              onChangeText={setReportComment}
              multiline
              maxLength={500}
            />
            <View style={styles.modalBtns}>
              <TouchableOpacity style={styles.cancelBtn} onPress={() => setReportTarget(null)}>
                <Text style={styles.cancelBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.reportSubmitBtn, reporting && styles.btnDisabled]}
                onPress={handleReport}
                disabled={reporting}
              >
                {reporting
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.reportSubmitBtnText}>Submit Report</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
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
    paddingHorizontal: Spacing.lg,
    paddingBottom: Spacing.md,
    backgroundColor: Colors.bgPanel,
    borderBottomWidth: 1,
    borderBottomColor: Colors.borderSubtle,
    elevation: 4,
  },
  backBtn: {
    fontSize: 22,
    color: Colors.accent,
    paddingRight: Spacing.md,
  },
  headerCenter: { flex: 1, marginLeft: Spacing.sm },
  roomName: {
    fontSize: Typography.lg,
    fontWeight: '700',
    color: Colors.textMain,
  },
  onlineCount: {
    fontSize: Typography.xs,
    color: Colors.success,
  },
  membersBtn: {
    fontSize: 22,
    color: Colors.textMuted,
    paddingLeft: Spacing.md,
  },
  searchBtn: {
    paddingLeft: Spacing.sm,
  },
  searchBtnText: {
    fontSize: 18,
  },
  searchBar: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.md,
    backgroundColor: 'rgba(0,0,0,0.22)',
    borderTopWidth: 1,
    borderTopColor: 'rgba(255,255,255,0.08)',
    gap: Spacing.sm,
  },
  searchInput: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.18)',
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.12)',
    height: 32,
  },
  searchMeta: {
    color: Colors.textMuted,
    fontSize: Typography.xs,
    minWidth: 34,
    textAlign: 'center',
  },
  searchNavBtn: {
    borderRadius: Radii.md,
    backgroundColor: 'transparent',
    width: 30,
    height: 30,
    alignItems: 'center',
    justifyContent: 'center',
  },
  searchNavDisabled: { opacity: 0.35 },
  searchNavText: { color: 'rgba(255,255,255,0.85)', fontSize: 14, fontWeight: '600' },
  searchCloseBtn: {
    padding: Spacing.xs,
    width: 28,
    height: 28,
    alignItems: 'center',
    justifyContent: 'center',
  },
  searchCloseBtnText: { color: Colors.textMuted, fontSize: 16 },
  bubbleSearchHit: {
    borderColor: 'rgba(248,209,55,0.55)',
    borderWidth: 1.5,
  },
  bubbleSearchActive: {
    borderColor: '#f8d137',
    borderWidth: 2,
    backgroundColor: 'rgba(248,209,55,0.12)',
  },
  cryptoBanner: {
    backgroundColor: 'rgba(248,81,73,0.15)',
    padding: Spacing.sm,
    alignItems: 'center',
    borderBottomWidth: 1,
    borderBottomColor: Colors.danger,
  },
  cryptoBannerText: {
    color: Colors.danger,
    fontSize: Typography.sm,
  },
  messageList: {
    padding: Spacing.md,
    paddingBottom: Spacing.lg,
  },
  loadMoreBtn: {
    alignItems: 'center',
    paddingVertical: Spacing.sm,
    marginBottom: Spacing.xs,
  },
  loadMoreText: {
    color: Colors.accent,
    fontSize: Typography.sm,
  },
  emptyText: {
    textAlign: 'center',
    color: Colors.textMuted,
    marginTop: Spacing.xxl,
  },
  bubble: {
    paddingVertical: 2,
    paddingHorizontal: 0,
    marginBottom: 2,
    maxWidth: '85%',
    alignSelf: 'flex-start',
    borderLeftWidth: 2,
    borderLeftColor: 'rgba(255,255,255,0.25)',
    paddingLeft: Spacing.md,
  },
  bubbleMe: {
    alignSelf: 'flex-end',
    borderLeftWidth: 0,
    paddingLeft: 0,
    borderRightWidth: 2,
    borderRightColor: 'rgba(35,134,54,0.5)',
    paddingRight: Spacing.md,
  },
  author: {
    fontSize: Typography.lg,
    fontWeight: '600',
    marginTop: Spacing.md,
    marginBottom: 2,
  },
  // Reply quote (inside message bubble)
  replyQuote: {
    flexDirection: 'row',
    backgroundColor: 'rgba(255,255,255,0.06)',
    borderRadius: Radii.sm,
    marginBottom: Spacing.xs,
    overflow: 'hidden',
  },
  replyQuoteBar: { width: 3, backgroundColor: Colors.accent },
  replyQuoteBody: { paddingHorizontal: Spacing.sm, paddingVertical: Spacing.xs },
  replyQuoteAuthor: { fontSize: Typography.xs, color: Colors.accent, fontWeight: '600', marginBottom: 1 },
  replyQuoteText: { fontSize: Typography.xs, color: Colors.textMuted, lineHeight: 16 },
  replyQuoteTextMe: { textAlign: 'right' },
  msgTextMe: { textAlign: 'right' },
  // Reply bar (above input)
  replyBar: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.bgPanel,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
    gap: Spacing.sm,
  },
  replyBarContent: { flex: 1 },
  replyBarAuthor: { fontSize: Typography.xs, color: Colors.accent, fontWeight: '600', marginBottom: 1 },
  replyBarText: { fontSize: Typography.xs, color: Colors.textMuted },
  replyBarClose: { fontSize: Typography.md, color: Colors.textMuted, paddingLeft: Spacing.sm },
  msgText: {
    color: Colors.textMain,
    fontSize: Typography.md,
    lineHeight: 20,
  },
  linkText: {
    color: Colors.accent,
    textDecorationLine: 'underline',
  },
  suspiciousLink: {
    color: '#f87171',
    textDecorationLine: 'underline',
    textDecorationColor: '#f87171',
  },
  encNote: {
    fontSize: Typography.xs,
    color: Colors.textMuted,
    marginTop: 2,
  },
  decryptFailedText: {
    fontSize: Typography.sm,
    color: '#f87171',
    fontStyle: 'italic',
  },
  timeText: {
    fontSize: Typography.xs,
    color: Colors.textDim,
    marginTop: 2,
    alignSelf: 'flex-end',
  },
  inputRow: {
    flexDirection: 'row',
    alignItems: 'flex-end',
    padding: Spacing.sm,
    backgroundColor: Colors.bgPanel,
    borderTopWidth: 1,
    borderTopColor: Colors.border,
    gap: Spacing.sm,
  },
  input: {
    flex: 1,
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.lg,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
    maxHeight: 120,
  },
  sendBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.round,
    width: 36,
    height: 36,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sendBtnDisabled: { opacity: 0.45 },
  sendBtnText: { color: '#fff', fontSize: 18, fontWeight: '700' },
  attachBtn: {
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.round,
    width: 36,
    height: 36,
    alignItems: 'center',
    justifyContent: 'center',
  },
  attachBtnText: { color: Colors.textMuted, fontSize: 20, fontWeight: '600' },
  // Members modal
  modalOverlay: {
    flex: 1,
    backgroundColor: Colors.overlay,
    justifyContent: 'flex-end',
  },
  modalCard: {
    backgroundColor: Colors.bgPanel,
    borderTopLeftRadius: 14,
    borderTopRightRadius: 14,
    padding: Spacing.lg,
    borderTopWidth: 1,
    borderColor: Colors.border,
    maxHeight: '60%',
    elevation: 8,
  },
  modalHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: Spacing.md,
  },
  modalTitle: {
    fontSize: Typography.xl,
    fontWeight: '700',
    color: Colors.textMain,
  },
  closeBtn: {
    color: Colors.textMuted,
    fontSize: Typography.xl,
  },
  inviteRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
    marginBottom: Spacing.xs,
  },
  inviteInput: {
    flex: 1,
    backgroundColor: Colors.inputBg,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  inviteBtn: {
    backgroundColor: Colors.accent,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.lg,
    paddingVertical: Spacing.sm,
  },
  inviteBtnText: {
    color: '#fff',
    fontSize: Typography.md,
    fontWeight: '600',
  },
  memberRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: Spacing.sm,
    gap: Spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: Colors.border,
  },
  onlineDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
  },
  dotOn: { backgroundColor: Colors.success },
  dotOff: { backgroundColor: Colors.textMuted },
  memberName: {
    flex: 1,
    fontSize: Typography.md,
    fontWeight: '500',
  },
  memberRole: {
    fontSize: Typography.sm,
    color: Colors.textMuted,
  },
  roleBtn: {
    backgroundColor: Colors.btnBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.sm,
    paddingHorizontal: Spacing.sm,
    paddingVertical: 2,
  },
  roleBtnText: { color: Colors.accent, fontSize: Typography.sm, fontWeight: '600' },
  kickBtn: {
    backgroundColor: Colors.danger + '22',
    borderWidth: 1,
    borderColor: Colors.danger + '44',
    borderRadius: Radii.sm,
    paddingHorizontal: Spacing.sm,
    paddingVertical: 2,
  },
  kickBtnText: { color: Colors.danger, fontSize: Typography.sm, fontWeight: '700' },
  reportBtn: {
    paddingHorizontal: Spacing.xs,
    paddingVertical: 2,
    marginLeft: 2,
  },
  reportBtnText: { color: Colors.textMuted, fontSize: Typography.md },
  reRequestKeyBtn: {
    marginTop: Spacing.md,
    paddingVertical: Spacing.sm,
    borderRadius: Radii.sm,
    backgroundColor: Colors.accent + '18',
    borderWidth: 1,
    borderColor: Colors.accent + '44',
    alignItems: 'center',
  },
  reRequestKeyBtnText: {
    color: Colors.accent,
    fontSize: Typography.md,
    fontWeight: '600',
  },
  leaveRoomBtn: {
    marginTop: Spacing.md,
    paddingVertical: Spacing.sm,
    borderRadius: Radii.sm,
    backgroundColor: Colors.danger + '18',
    borderWidth: 1,
    borderColor: Colors.danger + '44',
    alignItems: 'center',
  },
  leaveRoomBtnText: {
    color: Colors.danger,
    fontSize: Typography.md,
    fontWeight: '600',
  },
  reportReasonRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 6,
    gap: Spacing.sm,
  },
  reportReasonSelected: {
    opacity: 1,
  },
  reportRadio: {
    width: 16,
    height: 16,
    borderRadius: 8,
    borderWidth: 2,
    borderColor: Colors.textMuted,
  },
  reportRadioActive: {
    borderColor: Colors.danger,
    backgroundColor: Colors.danger,
  },
  reportReasonLabel: {
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  reportCommentInput: {
    backgroundColor: Colors.bgMain,
    color: Colors.textMain,
    borderRadius: Radii.sm,
    borderWidth: 1,
    borderColor: Colors.border,
    padding: Spacing.sm,
    marginTop: Spacing.sm,
    marginBottom: Spacing.md,
    height: 70,
    textAlignVertical: 'top',
    fontSize: Typography.md,
  },
  reportSubmitBtn: {
    backgroundColor: Colors.danger,
    borderRadius: Radii.sm,
    paddingVertical: Spacing.sm,
    paddingHorizontal: Spacing.lg,
    alignItems: 'center',
  },
  reportSubmitBtnText: {
    color: '#fff',
    fontWeight: '700',
    fontSize: Typography.md,
  },
  // Read-only
  roomNameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
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
  readonlyBar: {
    backgroundColor: 'rgba(248,209,55,0.08)',
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.lg,
    alignItems: 'center',
    borderTopWidth: 1,
    borderTopColor: 'rgba(248,209,55,0.3)',
  },
  readonlyBarText: {
    color: '#f8d137',
    fontSize: Typography.sm,
  },
  // Rename (inline in settings)
  renameRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.sm,
  },
  renameApplyBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.sm,
    paddingHorizontal: Spacing.md,
    alignItems: 'center',
  },
  renameCard: {
    backgroundColor: Colors.bgPanel,
    margin: Spacing.xl,
    borderRadius: Radii.xl,
    padding: Spacing.xl,
    gap: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  renameInput: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.md,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  modalBtns: {
    flexDirection: 'row',
    gap: Spacing.md,
    justifyContent: 'flex-end',
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
  // Pinned context bar
  pinnedBar: {
    backgroundColor: 'rgba(42,171,238,0.08)',
    borderBottomWidth: 1,
    borderBottomColor: 'rgba(42,171,238,0.2)',
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
  },
  pinnedHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  pinnedTitle: {
    color: Colors.accent,
    fontSize: Typography.sm,
    fontWeight: '600',
  },
  pinnedToggle: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
  },
  pinnedUrl: {
    color: Colors.accent,
    fontSize: Typography.sm,
    marginTop: 2,
    textDecorationLine: 'underline',
  },
  pinnedText: {
    color: Colors.textMain,
    fontSize: Typography.sm,
    marginTop: 2,
    fontStyle: 'italic',
    opacity: 0.8,
  },
  // Settings button
  settingsBtn: {
    paddingLeft: Spacing.sm,
  },
  settingsBtnText: {
    fontSize: 18,
    color: Colors.textMuted,
  },
  // Room settings modal
  settingsCard: {
    backgroundColor: Colors.bgPanel,
    margin: Spacing.lg,
    borderRadius: 14,
    padding: Spacing.lg,
    borderWidth: 1,
    borderColor: Colors.border,
    elevation: 8,
    maxHeight: '80%',
  },
  settingsBody: {
    gap: Spacing.md,
  },
  settingsLabel: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
    fontWeight: '600',
    marginTop: Spacing.xs,
  },
  settingsInput: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
  },
  settingsTextarea: {
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    paddingHorizontal: Spacing.md,
    paddingVertical: Spacing.sm,
    color: Colors.textMain,
    fontSize: Typography.md,
    minHeight: 72,
    textAlignVertical: 'top',
  },
  roomIdHint: {
    color: Colors.textMuted,
    fontSize: Typography.xs,
    marginTop: 2,
  },
  logoRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: Spacing.md,
  },
  logoPreview: {
    width: 48,
    height: 48,
    borderRadius: Radii.sm,
    backgroundColor: 'rgba(255,255,255,0.08)',
    borderWidth: 1,
    borderColor: Colors.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  logoPreviewText: {
    color: Colors.textMuted,
    fontSize: Typography.xs,
    textAlign: 'center',
  },
  noLogoText: {
    color: Colors.textMuted,
    fontSize: Typography.sm,
    fontStyle: 'italic',
  },
  logoUploadBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.sm,
    paddingHorizontal: Spacing.md,
    alignItems: 'center',
  },
  removePassBtn: {
    borderWidth: 1,
    borderColor: Colors.danger,
    borderRadius: Radii.md,
    paddingVertical: Spacing.sm,
    alignItems: 'center',
    marginTop: Spacing.xs,
  },
  removePassBtnText: {
    color: Colors.danger,
    fontSize: Typography.sm,
    fontWeight: '600',
  },
  saveBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    alignItems: 'center',
    marginTop: Spacing.sm,
  },
  saveBtnText: {
    color: '#fff',
    fontSize: Typography.md,
    fontWeight: '600',
  },
  deleteBtn: {
    backgroundColor: '#dc3545',
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    alignItems: 'center',
  },
  deleteBtnText: {
    color: '#fff',
    fontSize: Typography.md,
    fontWeight: '600',
  },
});
