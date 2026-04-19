// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * DMChatScreen.js — Direct message conversation with E2EE
 * Ported from panel.js DM message handling
 */

import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useFocusEffect } from '@react-navigation/native';
import {
  View, Text, FlatList, TextInput, TouchableOpacity,
  StyleSheet, Platform, Alert,
  ActivityIndicator, Linking, Modal, Keyboard, PermissionsAndroid,
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
import ImageCard from '../components/ImageCard';
import { parseFileMarker, makeFileMarker, isImageFile } from '../utils/fileMarker';
import { pick as pickDocument, types as pickerTypes } from '@react-native-documents/picker';
import { launchCamera } from 'react-native-image-picker';

function colorForUsername(name) {
  const COLORS = ['#58a6ff','#79c0ff','#d2a8ff','#f78166','#56d364','#e3b341'];
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (Math.imul(31, h) + name.charCodeAt(i)) | 0;
  return COLORS[Math.abs(h) % COLORS.length];
}

// ---- Suspicious link detection (ported from panel.js) ----

const LINKIFY_MAX_URL_LEN = 2048;
const TRAIL_RE = /[)\]}",.!?:;]+$/;
const URL_RE_DM = /\b((?:https?:\/\/|www\.)[^\s<>"']{2,2048})/gi;

function splitTrailingPunct(s) {
  const m = TRAIL_RE.exec(s);
  if (!m) return { core: s, tail: '' };
  return { core: s.slice(0, m.index), tail: m[0] };
}

function isSuspiciousHostname(hostname) {
  const h = String(hostname || '').toLowerCase();
  if (!h) return false;
  if (h.includes('xn--')) return true;
  const hasLatin = /[a-zA-Z]/.test(h);
  const hasCyr = /[\u0400-\u04FF]/.test(h);
  if (hasLatin && hasCyr) return true;
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
  if (u.username || u.password) return null;
  if (!u.hostname) return null;
  return u.toString();
}

function parseMessageText(text) {
  const parts = [];
  let last = 0;
  URL_RE_DM.lastIndex = 0;
  let m;
  while ((m = URL_RE_DM.exec(text)) !== null) {
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

// Normalize server timestamps (seconds) to milliseconds for correct sort order
const normMsg = m => m?.ts != null && m.ts < 1e12 ? { ...m, ts: m.ts * 1000 } : m;

// Module-level set of thread IDs with an active DMChatScreen handler.
// Used by the global DM handler (App.tsx) to avoid double-processing.
export const activeScreenThreadIds = new Set();

// Module-level map: ciphertext_b64 → { author, username }
// Tracks messages sent by this user in the current session so tryDecrypt can restore
// authorship even for messages whose sealed envelope stored `from: ''` (race with NetworkService).
// Lives at module scope so it survives navigation between DM threads.
// Capped at 500 entries (oldest evicted first) to prevent unbounded growth in long sessions.
const _SENT_MAP_MAX = 500;
const _sentBySelfCiphertexts = new Map();

// Retry-cap for messages stuck in _needsDecrypt state (DM key missing / server 500).
// After MAX_DECRYPT_RETRIES passes through redecryptExisting without success, we mark
// the message as _decryptFailed so the UI stops re-attempting and shows an empty bubble.
const _retryCounts = new Map(); // key: "id:X" or "ts:X" → attempt count
const _MAX_DECRYPT_RETRIES = 5;
function _sentBySelfSet(key, value) {
  if (_sentBySelfCiphertexts.size >= _SENT_MAP_MAX) {
    // Evict the oldest entry (Maps iterate in insertion order)
    _sentBySelfCiphertexts.delete(_sentBySelfCiphertexts.keys().next().value);
  }
  _sentBySelfCiphertexts.set(key, value);
}

// Register ciphertext for echo suppression in both raw and base64url-encoded forms.
// Server broadcasts the base64url-encoded version — matching only the raw form misses the echo.
function _addEchoEntry(pendingSet, value) {
  if (!value) return;
  pendingSet.add(value);
  // Also store base64url-encoded version (server encodes plaintext ciphertext before WS broadcast)
  try {
    const b64 = btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    if (b64 !== value) pendingSet.add(b64);
  } catch (_e) { /* value may not be valid for btoa — skip */ }
}
function _deleteEchoEntry(pendingSet, value) {
  if (!value) return;
  pendingSet.delete(value);
  try {
    const b64 = btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    pendingSet.delete(b64);
  } catch (_e) {}
}

export default function DMChatScreen({ navigation, route }) {
  const { state, dispatch } = useApp();
  const insets = useSafeAreaInsets();
  const { threadId, peer } = route?.params || {};
  const screenReady = !!state.isLoggedIn && !!threadId;

  const [inputText, setInputText] = useState('');
  const [sending, setSending] = useState(false);
  const [cryptoReady, setCryptoReady] = useState(false);
  const [peerPubKey, setPeerPubKey] = useState(null); // used for safety numbers only
  const [safetyNumber, setSafetyNumber] = useState(null);
  const [showSafety, setShowSafety] = useState(false);
  const [peerKeyVerified, setPeerKeyVerified] = useState(false);
  const [peerKeyChanged, setPeerKeyChanged] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const [replyTo, setReplyTo] = useState(null); // { id, author, text }
  const _isNearBottomRef = useRef(true);
  const _initialScrollDoneRef = useRef(false); // initial scroll-to-bottom done for this thread
  const _scrollTimerRef = useRef(null);
  const _kbScrollNeededRef = useRef(false); // captured at onFocus, before keyboard animation starts

  // Report
  const [showReport, setShowReport] = useState(false);
  const [reportReason, setReportReason] = useState('spam');
  const [reportComment, setReportComment] = useState('');
  const [reporting, setReporting] = useState(false);

  const REPORT_REASONS = [
    { value: 'spam', label: 'Spam' },
    { value: 'harassment', label: 'Harassment / abuse' },
    { value: 'illegal_content', label: 'Illegal content' },
    { value: 'impersonation', label: 'Impersonation' },
    { value: 'other', label: 'Other' },
  ];

  async function handleReport() {
    if (!peer) return;
    setReporting(true);
    try {
      await NetworkService.reportUser(peer, reportReason, reportComment.trim());
      setShowReport(false);
      setReportComment('');
      setReportReason('spam');
      Alert.alert('Done', 'Report submitted. Thank you.');
    } catch (e) {
      Alert.alert('Error', e?.message || 'Failed to submit report');
    } finally {
      setReporting(false);
    }
  }

  // Search
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchIdx, setSearchIdx] = useState(0);
  const searchInputRef = useRef(null);
  const searchFocusTimerRef = useRef(null);

  const flatRef = useRef(null);
  // Track ciphertexts we just sent to suppress server echo (prevents duplicate bubbles)
  const _pendingSentRef = useRef(new Set());
  // Track echo-suppression cleanup timers so we can clear them on unmount
  const _echoTimersRef = useRef(new Set());
  useEffect(() => () => { _echoTimersRef.current.forEach(t => clearTimeout(t)); }, []);
  // Stable handler ref — registered once, delegate to current closure via ref
  const _handleIncomingRef = useRef(null);
  const messages = (state.dmMessages[threadId] || []);
  const myUsername = state.username;
  // Ref to always-current messages — avoids stale closures in event listeners
  const messagesRef = useRef(messages);
  messagesRef.current = messages;
  const peerColor = colorForUsername(peer || '');

  // Pagination state (mirrors extension panel.js)
  const HISTORY_PAGE_SIZE = 50;
  const _hasMoreRef = useRef(false);
  const _oldestIdRef = useRef(null);

  // DM key readiness gate — prevents race between WS listener and init effect
  const _dmKeyReadyRef = useRef(false);
  const _pendingIncomingRef = useRef([]);

  // Mark this thread as active and clear unread badge.
  // Also sets currentDmThreadId so AppContext won't increment unread for this thread
  // (handles navigation-via-notification where openDmThread isn't called first).
  // useFocusEffect tracks screen focus — fires on tab switch too (unlike useEffect unmount)
  useFocusEffect(useCallback(() => {
    if (!screenReady) {
      return () => {
        if (searchFocusTimerRef.current) clearTimeout(searchFocusTimerRef.current);
      };
    }
    if (threadId) {
      // Synchronous: tell global handler to skip this thread IMMEDIATELY
      activeScreenThreadIds.add(String(threadId));
      dispatch({ type: 'SET_CURRENT_DM', threadId, peer });
      dispatch({ type: 'CLEAR_UNREAD_DM', threadId });
    }
    return () => {
      activeScreenThreadIds.delete(String(threadId));
      dispatch({ type: 'SET_CURRENT_DM', threadId: null, peer: null });
      if (searchFocusTimerRef.current) clearTimeout(searchFocusTimerRef.current);
    };
  }, [screenReady, threadId, peer]));

  // No interactive password prompts — crypto auto-unlocks from Keychain

  // Load older DM messages on scroll to top (infinite scroll, mirrors extension)
  async function loadOlderMessages() {
    if (!screenReady) return;
    if (loadingOlder || !_hasMoreRef.current || !_oldestIdRef.current) return;
    setLoadingOlder(true);
    try {
      const data = await NetworkService.getDmHistory(threadId, {
        limit: HISTORY_PAGE_SIZE,
        before_id: _oldestIdRef.current,
      });
      const serverMsgs = data?.messages || (Array.isArray(data) ? data : []);
      _hasMoreRef.current = !!data?.has_more;
      _oldestIdRef.current = data?.oldest_id || _oldestIdRef.current;

      if (serverMsgs.length) {
        const dec = (await decryptBatch(serverMsgs)).map(normMsg);
        const current = messagesRef.current || [];
        const existingIds = new Set(current.filter(m => m.id).map(m => String(m.id)));
        const newMsgs = dec.filter(m => !existingIds.has(String(m.id)));
        if (newMsgs.length) {
          dispatch({ type: 'SET_DM_MESSAGES', threadId, messages: [...newMsgs, ...current] });
        }
      }
    } catch (_e) { /* ignore */ }
    setLoadingOlder(false);
  }

  // Re-decrypt messages that failed on load (crypto wasn't ready then).
  // Uses REDECRYPT_DM_MESSAGES reducer action for atomic update — avoids the race
  // where a concurrent APPEND_DM_MESSAGE is overwritten by a stale SET_DM_MESSAGES.
  async function redecryptExisting() {
    const snapshot = messagesRef.current || [];
    // Re-decrypt messages that either failed before (!_decrypted) or were
    // marked by the global handler as needing decryption (_needsDecrypt).
    const needsDecrypt = snapshot.filter(m => !m._decrypted && !m._decryptFailed);
    if (!needsDecrypt.length) return;
    const redecrypted = await decryptBatch(needsDecrypt);
    // Build update list — only include messages where decryption actually succeeded
    const updates = redecrypted
      .filter(r => r._decrypted)
      .map(r => ({
        id: r.id,
        ts: r.ts,
        _decrypted: r._decrypted,
        ...(r.author ? { author: r.author } : {}),
        ...(r.username ? { username: r.username } : {}),
      }));
    if (updates.length) {
      dispatch({ type: 'REDECRYPT_DM_MESSAGES', threadId, updates });
    }
    // Retry-cap: for messages still undecrypted after this pass, bump a session-level counter.
    // After MAX_RETRIES attempts, mark as _decryptFailed so the UI stops hoping forever.
    const stillFailing = redecrypted.filter(r => !r._decrypted && !r._decryptFailed);
    if (stillFailing.length) {
      const giveUp = [];
      for (const r of stillFailing) {
        const k = r.id != null ? `id:${r.id}` : `ts:${r.ts}`;
        const n = (_retryCounts.get(k) || 0) + 1;
        _retryCounts.set(k, n);
        if (n >= _MAX_DECRYPT_RETRIES) giveUp.push({ id: r.id, ts: r.ts });
      }
      if (giveUp.length) {
        dispatch({ type: 'MARK_DM_DECRYPT_FAILED', threadId, matchers: giveUp });
        for (const g of giveUp) {
          _retryCounts.delete(g.id != null ? `id:${g.id}` : `ts:${g.ts}`);
        }
      }
    }
  }

  // Init crypto and load history from server (mirrors extension)
  const _initActiveRef = useRef(false);
  useEffect(() => {
    if (!screenReady) {
      _dmKeyReadyRef.current = false;
      _pendingIncomingRef.current = [];
      _initActiveRef.current = false;
      return;
    }
    _hasMoreRef.current = false;
    _oldestIdRef.current = null;
    _dmKeyReadyRef.current = false;
    _pendingIncomingRef.current = [];
    _initActiveRef.current = true;
    _isNearBottomRef.current = true;
    _initialScrollDoneRef.current = false;

    (async () => {
      const ok = await CryptoService.ensureReady({ interactive: false });
      if (!_initActiveRef.current) return; // thread changed while awaiting
      if (ok) {
        setCryptoReady(true);
        // Load DM key BEFORE fetching history — otherwise decryptBatch fails silently
        await CryptoService.ensureDmKeyReady(threadId, peer).catch(e =>
          console.warn('[DMChat] ensureDmKeyReady failed:', e?.message));
        if (!_initActiveRef.current) return;
        // NOTE: _dmKeyReadyRef stays false here — WS messages queue in _pendingIncomingRef.
        // Gate opens AFTER SET_DM_MESSAGES to prevent WS messages being wiped by SET.
        // (mirrors ChatScreen._roomKeyReadyRef pattern)
        await loadPeerKeyForSafetyNumber();
        if (!_initActiveRef.current) return;
      }

      // Fetch history from server and merge with any WS messages already in state
      try {
        const data = await NetworkService.getDmHistory(threadId, { limit: HISTORY_PAGE_SIZE });
        if (!_initActiveRef.current) return;
        const serverMsgs = data?.messages || (Array.isArray(data) ? data : []);
        _hasMoreRef.current = !!data?.has_more;
        _oldestIdRef.current = data?.oldest_id || null;

        if (serverMsgs.length) {
          const dec = (await decryptBatch(serverMsgs)).map(normMsg);
          if (!_initActiveRef.current) return;
          const existing = messagesRef.current || [];

          // Strip local_ (optimistic) messages confirmed by server history.
          // Uses ciphertext fingerprint (_localCiphertextB64) for exact matching, or
          // server timestamp ±1s as a fallback for older optimistics without the field.
          //
          // serverTexts covers both m.text and m.ciphertext_b64 from server history.
          // This ensures id-less WS messages stored by globalDmHandler (which sets
          // text = ciphertext_b64 for dedup) are stripped when the server history
          // confirms the same message via its ciphertext_b64 field. Without this,
          // _needsDecrypt messages would survive the merge and show raw ciphertext.
          const serverTexts = new Set([
            ...dec.map(m => m.text || ''),
            ...dec.map(m => m.ciphertext_b64 || ''),
          ].filter(Boolean));
          const serverTsSecs = new Set(dec.map(m => Math.round((m.ts || 0) / 1000)));

          // Build ciphertext → author map from any in-state message that carries _localCiphertextB64
          // (covers both local_ optimistics and id-less echoes that had the field carried over by
          // the APPEND_DM_MESSAGE reducer). Used below to restore authorship on server history msgs.
          const confirmedLocalAuthorMap = {};
          existing.forEach(m => {
            const ciph = m._localCiphertextB64;
            if (ciph && serverTexts.has(ciph) && (m.author || m.username)) {
              confirmedLocalAuthorMap[ciph] = { author: m.author, username: m.username };
            }
          });

          const withoutConfirmedLocals = existing.filter(m => {
            if (String(m.id || '').startsWith('local_')) {
              if (m._localCiphertextB64 && serverTexts.has(m._localCiphertextB64)) return false;
              const localTsSec = Math.round((m.ts || 0) / 1000);
              if (serverTsSecs.has(localTsSec) || serverTsSecs.has(localTsSec - 1) || serverTsSecs.has(localTsSec + 1)) return false;
              return true;
            }
            // Strip id-less echo messages (from globalDmHandler) whose ciphertext is
            // confirmed in server history — match on text OR ciphertext_b64 field.
            // globalDmHandler stores _needsDecrypt messages with text = ciphertext_b64,
            // so checking ciphertext_b64 catches the case where server history uses that field.
            if (!m.id && (
              (m.text && serverTexts.has(m.text)) ||
              (m.ciphertext_b64 && serverTexts.has(m.ciphertext_b64))
            )) return false;
            return true;
          });

          // Deduplicate remaining messages against server history by real id.
          const existingIds = new Set(withoutConfirmedLocals.filter(m => m.id && !String(m.id).startsWith('local_')).map(m => String(m.id)));
          const fresh = dec
            .filter(m => !existingIds.has(String(m.id)))
            .map(m => {
              // Restore authorship for messages whose sealed envelope had `from: ''` (broken attribution).
              // Priority: confirmedLocalAuthorMap (in-state send history) > _sentBySelfCiphertexts (session map).
              if (!m.author && !m.username && m.text) {
                const fromLocal = confirmedLocalAuthorMap[m.text];
                const fromSession = _sentBySelfCiphertexts.get(m.text);
                const info = fromLocal || fromSession;
                if (info) return { ...m, author: info.author, username: info.username };
              }
              return m;
            });
          const merged = [...withoutConfirmedLocals, ...fresh].sort((a, b) => (a.ts || 0) - (b.ts || 0));
          dispatch({ type: 'SET_DM_MESSAGES', threadId, messages: merged });
        }
      } catch (_e) {
        if (!_initActiveRef.current) return;
        // Server fetch failed — fall back to local storage
        console.warn('[DMChat] getDmHistory failed:', _e?.message, 'status:', _e?.status);
        const history = await StorageService.getRoomHistory(`dm_${threadId}`);
        if (history && history.length) {
          const dec = (await decryptBatch(history)).map(normMsg);
          if (!_initActiveRef.current) return;
          dispatch({ type: 'SET_DM_MESSAGES', threadId, messages: dec });
        }
      }

      if (!_initActiveRef.current) return;

      // Open the gate AFTER history is set — all WS messages during fetch are in the queue
      // (mirrors ChatScreen._roomKeyReadyRef pattern). Only open if the key actually loaded;
      // otherwise keep the gate closed so queued messages don't get permanently marked
      // _decryptFailed. The 'dm_key_loaded' listener below will flush the queue once ready.
      if (CryptoService.isDmKeyLoaded(threadId)) {
        _dmKeyReadyRef.current = true;

        // Flush any WS messages that arrived while we were loading the DM key + history
        if (_pendingIncomingRef.current.length) {
          const queued = _pendingIncomingRef.current.splice(0);
          for (const qMsg of queued) {
            if (!_initActiveRef.current) return;
            const dec = normMsg(await tryDecrypt(qMsg));
            dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: dec });
          }
        }

        // Re-decrypt any messages that the global handler stored with _needsDecrypt
        // (failed to decrypt while user was on Rooms tab or crypto wasn't ready yet)
        await redecryptExisting();
      } else {
        console.warn('[DMChatScreen] DM key not loaded after ensureDmKeyReady — gate stays closed, waiting for dm_key_loaded event');
      }

      // TOFU: check DM peer's key on thread entry (extension parity)
      CryptoService.resetKeyChangeAlerts();
      if (peer) CryptoService.checkAndAlertKeyChange(peer).catch(() => {});
    })().catch(e => console.warn('[DMChatScreen] init error:', e?.message));

    return () => { _initActiveRef.current = false; };
  }, [screenReady, threadId]);

  // Scroll to bottom when new messages arrive — skip if search is open or user scrolled up
  useEffect(() => {
    if (messages.length > 0 && !searchOpen && _isNearBottomRef.current) {
      clearTimeout(_scrollTimerRef.current);
      if (!_initialScrollDoneRef.current) {
        // First load for this thread — jump instantly without animation
        _initialScrollDoneRef.current = true;
        _scrollTimerRef.current = setTimeout(() => flatRef.current?.scrollToEnd({ animated: false }), 50);
      } else {
        _scrollTimerRef.current = setTimeout(() => flatRef.current?.scrollToEnd({ animated: true }), 100);
      }
    }
    return () => clearTimeout(_scrollTimerRef.current);
  }, [messages.length, searchOpen]);

  // When keyboard fully appears, scroll to end if user was at the bottom when they tapped the input.
  // See ChatScreen for explanation of the adjustNothing + Reanimated mechanics.
  useEffect(() => {
    const sub = Keyboard.addListener('keyboardDidShow', () => {
      if (_kbScrollNeededRef.current) {
        flatRef.current?.scrollToEnd({ animated: false });
        _kbScrollNeededRef.current = false;
      }
    });
    return () => sub.remove();
  }, []);

  // When crypto unlocks (user entered password), re-decrypt messages that failed on load.
  // When crypto locks (idle timeout), reset the key gate so incoming WS messages queue
  // properly until the Keychain auto-unlock completes.
  useEffect(() => {
    if (!screenReady) return;
    const unsubLocked = CryptoService.on('locked', () => {
      _dmKeyReadyRef.current = false;
    });
    const unsub = CryptoService.on('unlocked', async () => {
      setCryptoReady(true);
      // Load DM key if it wasn't loaded during init (crypto wasn't ready then)
      if (!_dmKeyReadyRef.current) {
        await CryptoService.ensureDmKeyReady(threadId, peer).catch(() => {});
        // If init effect is still running, it will open the gate itself after SET_DM_MESSAGES.
        // Opening the gate here would let APPEND_DM_MESSAGE interleave before SET, causing those
        // messages to be wiped when SET fires. Loading the key above is still useful — it makes
        // init's decryptBatch succeed.
        if (_initActiveRef.current) return;
        // Only open the gate if the key actually loaded
        _dmKeyReadyRef.current = CryptoService.isDmKeyLoaded(threadId);
        // Flush queued WS messages only when the key is available
        if (_dmKeyReadyRef.current && _pendingIncomingRef.current.length) {
          const queued = _pendingIncomingRef.current.splice(0);
          for (const qMsg of queued) {
            const dec = normMsg(await tryDecrypt(qMsg));
            dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: dec });
          }
        }
      }
      await redecryptExisting();
    });

    // DM-key-specific retry: fires when _loadDmKey / _createAndShareDmKey succeed. Covers the
    // case where crypto is unlocked but the DM key failed to load on first entry (server 500,
    // transient network) — without this, queued WS messages and server history would be stuck
    // undecrypted after init completes with the gate closed.
    const dmKeyHandler = async (data) => {
      if (data?.threadId != null && String(data.threadId) !== String(threadId)) return;
      if (_initActiveRef.current) return;
      if (_dmKeyReadyRef.current) {
        await redecryptExisting();
        return;
      }
      _dmKeyReadyRef.current = true;
      if (_pendingIncomingRef.current.length) {
        const queued = _pendingIncomingRef.current.splice(0);
        for (const qMsg of queued) {
          const dec = normMsg(await tryDecrypt(qMsg));
          dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: dec });
        }
      }
      await redecryptExisting();
    };
    const unsubDmKey = CryptoService.on('dm_key_loaded', dmKeyHandler);

    return () => { unsubLocked(); unsub(); unsubDmKey(); };
  }, [screenReady, threadId]);

  async function loadPeerKeyForSafetyNumber() {
    if (!screenReady || !peer) return;
    try {
      const data = await NetworkService.fetchPeerKey(peer);
      if (data?.public_key) {
        setPeerPubKey(data.public_key);
        const sn = await CryptoService.getSafetyNumber(myUsername, peer, data.public_key);
        setSafetyNumber(sn);
        // Check verification and key-changed status
        const verified = await CryptoService.isPeerKeyVerified(myUsername, peer);
        setPeerKeyVerified(verified);
        const changed = await StorageService.getKeyChanged(myUsername, peer);
        setPeerKeyChanged(!!changed);
      }
    } catch (_e) { /* ignore */ }
  }

  // Persist DM messages to storage (debounced) — single writer avoids race conditions
  const _persistTimerRef = useRef(null);
  useEffect(() => {
    if (!screenReady || !messages.length) return;
    clearTimeout(_persistTimerRef.current);
    _persistTimerRef.current = setTimeout(() => {
      StorageService.setRoomHistory(`dm_${threadId}`, messages.slice(-200)).catch(() => {});
    }, 300);
    return () => clearTimeout(_persistTimerRef.current);
  }, [screenReady, threadId, messages]);

  // Incoming DM messages — ref-based stable handler to prevent listener accumulation
  _handleIncomingRef.current = handleIncoming;
  useEffect(() => {
    const stableHandler = (msg) => _handleIncomingRef.current?.(msg);
    NetworkService.on('dm_message', stableHandler);
    return () => NetworkService.off('dm_message', stableHandler);
  }, []); // empty deps — register once

  function handleIncoming(msg) {
    if (!screenReady) return;
    const p = msg?.payload || msg;
    if (!p || String(p.thread_id || p.id) !== String(threadId)) return;

    // Suppress echo of our own messages — server broadcasts back what we just sent.
    // Compare both raw and decoded forms to handle base64 normalization differences.
    if (_pendingSentRef.current.size > 0) {
      const rawCipher = p.ciphertext_b64 || p.body || p.text || '';
      if (rawCipher) {
        // Direct match (server echoes exact same string)
        if (_pendingSentRef.current.has(rawCipher)) {
          _pendingSentRef.current.delete(rawCipher);
          return; // skip echo
        }
        // Try decoded form (server may base64url-encode our ciphertext)
        try {
          const b64 = rawCipher.replace(/-/g, '+').replace(/_/g, '/');
          const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
          const decoded = atob(padded);
          if (_pendingSentRef.current.has(decoded)) {
            _pendingSentRef.current.delete(decoded);
            return; // skip echo
          }
        } catch (_e) { /* not base64 — not our echo */ }
      }
    }

    // If DM key isn't loaded yet, queue message for later decryption
    if (!_dmKeyReadyRef.current) {
      _pendingIncomingRef.current.push(p);
      return;
    }

    (async () => {
      const dec = normMsg(await tryDecrypt(p));
      dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: dec });
      // TOFU: check sender's key on each incoming DM (extension parity)
      const sender = dec.author || dec.username || dec.from;
      if (sender) CryptoService.checkAndAlertKeyChange(sender).catch(() => {});
    })();
  }

  async function tryDecrypt(msg) {
    // ciphertext_b64 is the canonical field used by server/Extension; fallback to text fields
    const raw = msg.ciphertext_b64 || msg.body || msg.text || msg.content || '';
    if (!raw) return msg;
    // Crypto not ready yet — mark for retry; do NOT expose raw ciphertext in the UI.
    // redecryptExisting() picks this up once the DM key is loaded.
    if (!CryptoService.isReady()) return { ...msg, _needsDecrypt: true };

    // The server stores ciphertext_b64 = base64url(utf8(encryptedJSON)) in the `text` field.
    // We must decode base64url → UTF-8 string first, then parse as JSON.
    let encryptedJson = null;

    // Attempt 1: decode base64url → check if result is valid encrypted JSON
    try {
      const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
      const decoded = atob(padded);
      const parsed = JSON.parse(decoded);
      if (parsed.encrypted && parsed.iv && parsed.data) encryptedJson = decoded;
    } catch (_e) { /* not base64url */ }

    // Attempt 2: raw value is already a JSON string (legacy / direct)
    if (!encryptedJson) {
      try {
        const parsed = JSON.parse(raw);
        if (parsed.encrypted && parsed.iv && parsed.data) encryptedJson = raw;
      } catch (_e) { /* not JSON */ }
    }

    if (!encryptedJson) {
      // Raw value is neither base64url-encoded encrypted JSON nor a direct encrypted JSON.
      // If it looks like ciphertext (long string of base64/base64url chars), mark as failed
      // so the UI renders an empty bubble instead of leaking raw bytes at line ~1062.
      // Plaintext system messages (short, with spaces/punctuation) pass through unchanged.
      const looksLikeCiphertext = typeof raw === 'string'
        && raw.length > 32
        && /^[A-Za-z0-9+/_=-]+$/.test(raw);
      if (looksLikeCiphertext) return { ...msg, _decryptFailed: true };
      return msg;
    }

    try {
      const result = await CryptoService.decryptDm(threadId, encryptedJson, peer);
      if (result !== null) {
        const rawText  = result?.text     ?? result;
        const from     = result?.from     ?? null;
        const sigValid = result?.sigValid ?? null; // true=OK, false=bad, null=not checked

        // Strip stale failure/needs-decrypt flags — render logic hides text if _decryptFailed
        // is set, so a successful re-decryption must clear it.
        const { _decryptFailed: _f, _needsDecrypt: _n, ...base } = msg;

        // Parse reply payload if body is a v2 JSON envelope
        let messageText = rawText;
        let replyData = null;
        if (typeof rawText === 'string' && rawText.startsWith('{')) {
          try {
            const parsed = JSON.parse(rawText);
            if (parsed.v === 2 && parsed.t !== undefined) {
              messageText = parsed.t;
              replyData = parsed.reply || null;
            }
          } catch (_pe) {}
        }

        const replyProp = replyData ? { _reply: replyData } : {};

        // Ed25519 signature failed — strong evidence of forgery by the peer.
        if (sigValid === false) {
          console.warn('[DMChat] Ed25519 signature INVALID — from:', from);
          const resolvedFrom = from || (msg.text && _sentBySelfCiphertexts.has(msg.text) ? _sentBySelfCiphertexts.get(msg.text).author : null);
          return { ...base, _decrypted: messageText, ...replyProp,
            ...(resolvedFrom ? { author: resolvedFrom, username: resolvedFrom } : {}),
            _sealedSenderSigFailed: true };
        }

        // Sealed sender: "from" should be either the peer or ourselves.
        const meLower = (myUsername || '').toLowerCase();
        if (from && peer && from.toLowerCase() !== String(peer).toLowerCase() && from.toLowerCase() !== meLower) {
          console.warn('[DMChat] sealed sender mismatch — from:', from, 'expected:', peer);
          return { ...base, _decrypted: messageText, ...replyProp, author: from, username: from, _sealedSenderMismatch: true };
        }
        const resolvedFrom = from || (msg.text && _sentBySelfCiphertexts.has(msg.text) ? _sentBySelfCiphertexts.get(msg.text).author : null);
        // sigValid===null with known sender means no Ed25519 sig (absent or unverifiable) — flag for UI.
        const sigUnverified = sigValid === null && from !== null && from.toLowerCase() !== meLower;
        return { ...base, _decrypted: messageText, ...replyProp,
          ...(resolvedFrom ? { author: resolvedFrom, username: resolvedFrom } : {}),
          ...(sigUnverified ? { _sealedSenderUnverified: true } : {}) };
      }
    } catch (_e) {
      console.warn('[DMChat] decryptDm failed:', _e?.message);
    }
    // Mark as failed so UI can show indicator instead of raw ciphertext
    return { ...msg, _decryptFailed: true };
  }

  async function decryptBatch(msgs) {
    return Promise.all(msgs.map(m => tryDecrypt(m)));
  }

  async function handleAttachFile() {
    if (!screenReady) return;
    try {
      const [res] = await pickDocument({ type: [pickerTypes.allFiles] });
      if (!res?.uri) return;

      if (!CryptoService.isReady()) {
        const ok = await CryptoService.ensureReady({ interactive: false });
        if (!ok) { Alert.alert('Encryption required', 'Restart the app and enter your password to send files.'); return; }
        setCryptoReady(true);
      }

      setSending(true);
      const upload = await NetworkService.uploadDmFile(threadId, {
        filename: res.name || 'file',
        mimeType: res.type || 'application/octet-stream',
        fileBlob: res.uri,
      });

      if (!upload?.token) throw new Error('Upload failed — no token');

      // Build file marker (FILE2:: format, matches extension)
      const marker = makeFileMarker(upload.token, upload.filename || res.name, upload.size_bytes || 0);
      const encrypted = await CryptoService.encryptDm(threadId, marker, peer, myUsername);
      if (!encrypted) throw new Error('Could not encrypt file marker');

      _addEchoEntry(_pendingSentRef.current, encrypted);
      const _t2 = setTimeout(() => { _deleteEchoEntry(_pendingSentRef.current, encrypted); _echoTimersRef.current.delete(_t2); }, 30000);
      _echoTimersRef.current.add(_t2);

      let deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
      try {
        await NetworkService.sendDmUd(threadId, encrypted, deliverySecret);
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
          await NetworkService.sendDmUd(threadId, encrypted, deliverySecret);
        } else {
          throw e;
        }
      }

      let _fileLocalCiphertextB64 = null;
      try {
        _fileLocalCiphertextB64 = btoa(encrypted).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      } catch (_e) {}

      if (_fileLocalCiphertextB64 && myUsername) {
        _sentBySelfSet(_fileLocalCiphertextB64, { author: myUsername, username: myUsername });
      }

      const optimistic = {
        id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        author: myUsername,
        username: myUsername,
        body: marker,
        text: marker,
        _decrypted: marker,
        ts: Date.now(),
        _localCiphertextB64: _fileLocalCiphertextB64,
      };
      dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: optimistic });
    } catch (e) {
      if (e?.code !== 'OPERATION_CANCELED') {
        Alert.alert('Error', e?.message || 'File upload failed');
      }
    } finally {
      setSending(false);
    }
  }

  async function handleTakePhoto() {
    if (!screenReady) return;
    // Security notes:
    // - launchCamera uses Android's ACTION_IMAGE_CAPTURE intent: the OS camera app
    //   handles the capture. This app has no direct camera hardware access.
    // - saveToPhotos: false — photo is NOT saved to the gallery; it lives only in
    //   the app's temp cache until the upload completes.
    // - The photo is encrypted with the DM key before leaving the device.
    // - CAMERA permission is a runtime "dangerous" permission — Android shows an
    //   explicit permission dialog before first use.

    // react-native-image-picker v8 requires explicit runtime permission request.
    const granted = await PermissionsAndroid.request(
      PermissionsAndroid.PERMISSIONS.CAMERA,
      {
        title: 'Camera permission',
        message: 'WS Messenger needs camera access to take a photo and send it encrypted in this conversation. The photo will not be saved to your gallery.',
        buttonPositive: 'Allow',
        buttonNegative: 'Deny',
      },
    );
    if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
      Alert.alert('Permission denied', 'Camera access is required to take a photo.');
      return;
    }

    const response = await launchCamera({
      mediaType: 'photo',
      saveToPhotos: false,
      maxWidth: 1920,
      maxHeight: 1920,
      quality: 0.85,
    });

    if (response.didCancel || response.errorCode) {
      if (response.errorCode === 'camera_unavailable') {
        Alert.alert('No camera', 'A camera is not available on this device.');
      } else if (response.errorCode) {
        Alert.alert('Camera error', response.errorMessage || 'Could not open camera.');
      }
      return;
    }

    const asset = response.assets?.[0];
    if (!asset?.uri) return;

    if (!CryptoService.isReady()) {
      const ok = await CryptoService.ensureReady({ interactive: false });
      if (!ok) {
        Alert.alert('Encryption required', 'Restart the app and enter your password to send photos.');
        return;
      }
      setCryptoReady(true);
    }

    setSending(true);
    try {
      const upload = await NetworkService.uploadDmFile(threadId, {
        filename: asset.fileName || `photo_${Date.now()}.jpg`,
        mimeType: asset.type || 'image/jpeg',
        fileBlob: asset.uri,
      });

      if (!upload?.token) throw new Error('Upload failed — no token');

      const marker = makeFileMarker(upload.token, upload.filename || asset.fileName, upload.size_bytes || 0);
      const encrypted = await CryptoService.encryptDm(threadId, marker, peer, myUsername);
      if (!encrypted) throw new Error('Could not encrypt photo');

      _addEchoEntry(_pendingSentRef.current, encrypted);
      const _t = setTimeout(() => { _deleteEchoEntry(_pendingSentRef.current, encrypted); _echoTimersRef.current.delete(_t); }, 30000);
      _echoTimersRef.current.add(_t);

      let deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
      try {
        await NetworkService.sendDmUd(threadId, encrypted, deliverySecret);
      } catch (e) {
        if (e?.status === 401 || e?.status === 403) {
          deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
          await NetworkService.sendDmUd(threadId, encrypted, deliverySecret);
        } else {
          throw e;
        }
      }

      let _localCiphertextB64 = null;
      try {
        _localCiphertextB64 = btoa(encrypted).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      } catch (_e) {}

      if (_localCiphertextB64 && myUsername) {
        _sentBySelfSet(_localCiphertextB64, { author: myUsername, username: myUsername });
      }

      dispatch({
        type: 'APPEND_DM_MESSAGE',
        threadId,
        message: {
          id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
          author: myUsername,
          username: myUsername,
          body: marker,
          text: marker,
          _decrypted: marker,
          ts: Date.now(),
          _localCiphertextB64,
        },
      });
    } catch (e) {
      Alert.alert('Error', e?.message || 'Photo upload failed');
    } finally {
      setSending(false);
    }
  }

  function showAttachMenu() {
    Alert.alert(
      'Attach',
      null,
      [
        { text: 'File from device', onPress: handleAttachFile },
        { text: 'Take photo', onPress: handleTakePhoto },
        { text: 'Cancel', style: 'cancel' },
      ],
    );
  }

  async function handleSend() {
    if (!screenReady) return;
    if (!inputText.trim() || sending) return;
    const text = inputText.trim();
    setInputText('');
    setSending(true); // Show spinner immediately — prevents double-send during password prompt

    try {
      // DMs require E2EE — auto-unlock from Keychain, never prompt for password.
      if (!CryptoService.isReady()) {
        const ok = await CryptoService.ensureReady({ interactive: false });
        if (ok) {
          setCryptoReady(true);
          loadPeerKeyForSafetyNumber();
        }
      }

      if (!CryptoService.isReady()) {
        Alert.alert('Encryption required', 'Please restart the app and enter your password to send messages.');
        setInputText(text);
        return;
      }

      // Encrypt message with the shared DM thread key.
      // Pass myUsername explicitly so the sealed envelope always has the correct `from` field,
      // even if NetworkService.username hasn't synced yet.
      const payload = replyTo
        ? JSON.stringify({ v: 2, t: text, reply: { id: replyTo.id, author: replyTo.author, text: replyTo.text } })
        : text;
      const encryptedBody = await CryptoService.encryptDm(threadId, payload, peer, myUsername);
      if (!encryptedBody) {
        Alert.alert('Encryption failed', 'Could not encrypt message. The DM key may not be established yet — please try again in a moment.');
        setInputText(text);
        return;
      }

      // Register ciphertext so handleIncoming can suppress the server echo
      _addEchoEntry(_pendingSentRef.current, encryptedBody);
      const _t1 = setTimeout(() => { _deleteEchoEntry(_pendingSentRef.current, encryptedBody); _echoTimersRef.current.delete(_t1); }, 30000);
      _echoTimersRef.current.add(_t1);

      // Send via UD (Unsealed Delivery — HMAC-authenticated, no auth header = sealed sender)
      let deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
      try {
        await NetworkService.sendDmUd(threadId, encryptedBody, deliverySecret);
      } catch (e) {
        // On 401 (expired TTL) or 403 bad-tag (rotation): cache already cleared in sendDmUd,
        // re-fetch with Bearer token and retry once.
        if (e?.status === 401 || e?.status === 403) {
          deliverySecret = await NetworkService.getDeliverySecret(threadId, peer);
          await NetworkService.sendDmUd(threadId, encryptedBody, deliverySecret);
        } else {
          throw e;
        }
      }

      // Compute the exact ciphertext_b64 the server will broadcast (base64url of encryptedBody).
      // Stored on the optimistic so the reducer can match the echo to this message by ciphertext —
      // which is unique per AES-GCM encryption and immune to timestamp/text collisions.
      let _localCiphertextB64 = null;
      try {
        _localCiphertextB64 = btoa(encryptedBody).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
      } catch (_e) {}

      // Record in session-level map so tryDecrypt can restore authorship on history reload
      if (_localCiphertextB64 && myUsername) {
        _sentBySelfSet(_localCiphertextB64, { author: myUsername, username: myUsername });
      }

      setReplyTo(null);
      // Optimistic local message (show decrypted text immediately)
      const optimistic = {
        id: `local_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
        author: myUsername,
        username: myUsername,
        body: text,
        text,
        _decrypted: text,
        ts: Date.now(),
        _localCiphertextB64,
        ...(replyTo ? { _reply: { id: replyTo.id, author: replyTo.author, text: replyTo.text } } : {}),
      };
      dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: optimistic });
      // Storage is handled by the debounced useEffect
    } catch (e) {
      Alert.alert('Error', e?.message || 'Send failed');
      setInputText(text);
    } finally {
      setSending(false);
    }
  }

  // Search: compute matching indices from decrypted text
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

  useEffect(() => { setSearchIdx(0); }, [searchQuery]);

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

  function renderMessage({ item, index }) {
    const meLower = (myUsername || '').toLowerCase();
    const isMe = (item.author || '').toLowerCase() === meLower || (item.username || '').toLowerCase() === meLower;
    const author = item.author || item.username || '';
    const hitPos = searchHits.indexOf(index);
    const isSearchHit = hitPos !== -1;
    const isSearchActive = isSearchHit && hitPos === searchIdx % searchHits.length;
    const decryptFailed = item._decryptFailed;
    const needsDecrypt = item._needsDecrypt && !item._decrypted;
    const sealedMismatch = item._sealedSenderMismatch;
    const sigFailed = item._sealedSenderSigFailed;
    const sigUnverified = item._sealedSenderUnverified;
    const text = (decryptFailed || needsDecrypt) ? '' : (item._decrypted ?? item.text ?? item.body ?? '');
    const ts = item.ts || item.created_at;
    const timeStr = ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';
    const fileInfo = (decryptFailed || needsDecrypt) ? null : parseFileMarker(text);

    return (
      <TouchableOpacity
        activeOpacity={0.8}
        onLongPress={() => {
          const actions = [];
          if (text) actions.push({ text: 'Reply', onPress: () => setReplyTo({ id: item.id ?? null, author: item.author || item.username || 'Unknown', text: text.slice(0, 120) }) });
          if (text) actions.push({ text: 'Copy', onPress: () => _copyMessage(text) });
          actions.push({ text: 'Cancel', style: 'cancel' });
          Alert.alert('Message', null, actions);
        }}
        delayLongPress={400}
      >
        <View style={[
          styles.bubble,
          isMe && styles.bubbleMe,
          isSearchHit && styles.bubbleSearchHit,
          isSearchActive && styles.bubbleSearchActive,
        ]}>
          {!isMe && <Text style={[styles.author, { color: peerColor }]}>{author}</Text>}
          {item._reply && (
            <View style={styles.replyQuote}>
              <View style={styles.replyQuoteBar} />
              <View style={styles.replyQuoteBody}>
                <Text style={[styles.replyQuoteAuthor, isMe && styles.replyQuoteTextMe]}>{item._reply.author}</Text>
                <Text style={[styles.replyQuoteText, isMe && styles.replyQuoteTextMe]} numberOfLines={1}>{item._reply.text}</Text>
              </View>
            </View>
          )}
          {decryptFailed ? (
            <Text style={styles.decryptFailedText}>Could not decrypt this message</Text>
          ) : needsDecrypt ? (
            <Text style={styles.decryptPendingText}>🔒 decrypting…</Text>
          ) : fileInfo ? (
            isImageFile(fileInfo.filename) ? (
              <ImageCard token={fileInfo.token} filename={fileInfo.filename} sizeBytes={fileInfo.sizeBytes} />
            ) : (
              <FileCard token={fileInfo.token} filename={fileInfo.filename} sizeBytes={fileInfo.sizeBytes} />
            )
          ) : (
            <MessageText text={text} isMe={isMe} />
          )}
          {sigFailed && (
            <Text style={styles.sealedWarnText}>⚠ Signature verification failed</Text>
          )}
          {!sigFailed && sealedMismatch && (
            <Text style={styles.sealedWarnText}>Sender identity could not be verified</Text>
          )}
          {!sigFailed && !sealedMismatch && sigUnverified && (
            <Text style={styles.sealedUnverifiedText}>(unverified)</Text>
          )}
          {timeStr ? <Text style={styles.timeText}>{timeStr}</Text> : null}
        </View>
      </TouchableOpacity>
    );
  }

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
        <TouchableOpacity style={styles.headerCenter} onPress={() => safetyNumber && setShowSafety(true)}>
          <Text style={[styles.peerName, { color: peerColor }]}>{peer}</Text>
          {safetyNumber && <Text style={styles.safetyHint}>🔐 verify keys</Text>}
        </TouchableOpacity>
        <TouchableOpacity onPress={() => { setShowReport(true); setReportReason('spam'); setReportComment(''); }} style={styles.reportHeaderBtn}>
          <Text style={styles.reportHeaderBtnText}>⚑</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={openSearch} style={styles.searchBtn}>
          <Text style={styles.searchBtnText}>🔍</Text>
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

      <FlatList
        ref={flatRef}
        data={messages}
        keyExtractor={(m, i) => `${m.id ?? 'dm'}_${i}`}
        renderItem={renderMessage}
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
        onContentSizeChange={() => !searchOpen && _isNearBottomRef.current && flatRef.current?.scrollToEnd({ animated: false })}
        ListEmptyComponent={<Text style={styles.emptyText}>No messages yet</Text>}
        onScrollToIndexFailed={({ index }) => {
          setTimeout(() => {
            flatRef.current?.scrollToIndex({ index, animated: true, viewPosition: 0.4 });
          }, 200);
        }}
        onScroll={({ nativeEvent }) => {
          const { contentOffset, layoutMeasurement, contentSize } = nativeEvent;
          _isNearBottomRef.current = contentOffset.y + layoutMeasurement.height >= contentSize.height - 150;
          if (contentOffset.y < 40 && !searchOpen && _hasMoreRef.current && !loadingOlder) {
            loadOlderMessages();
          }
        }}
        scrollEventThrottle={200}
      />

      {replyTo && (
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
      <View style={[styles.inputRow, { paddingBottom: insets.bottom || Spacing.sm }]}>
        <TouchableOpacity
          style={styles.attachBtn}
          onPress={showAttachMenu}
          disabled={sending}
        >
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
          onFocus={() => { _kbScrollNeededRef.current = _isNearBottomRef.current; }}
        />
        <TouchableOpacity
          style={[styles.sendBtn, (!inputText.trim() || sending) && styles.sendBtnDisabled]}
          onPress={handleSend}
          disabled={!inputText.trim() || sending}
        >
          {sending ? <ActivityIndicator color="#fff" size="small" />
            : <Text style={styles.sendBtnText}>↑</Text>}
        </TouchableOpacity>
      </View>

      {/* Safety number modal */}
      <Modal visible={showSafety} transparent animationType="fade" onRequestClose={() => setShowSafety(false)}>
        <View style={styles.safetyOverlay}>
          <View style={styles.safetyCard}>
            <Text style={styles.safetyTitle}>Safety Number</Text>
            <Text style={styles.safetySubtitle}>
              Compare this number with {peer} in person or via a trusted channel.
            </Text>

            {peerKeyChanged && (
              <View style={styles.keyWarning}>
                <Text style={styles.keyWarningText}>
                  WARNING: This user's encryption key has changed. Verify in person before sending sensitive messages.
                </Text>
              </View>
            )}

            <Text style={styles.safetyNumber} selectable>{safetyNumber}</Text>

            {/* Verification status */}
            <Text style={[styles.verifyStatus, peerKeyVerified && styles.verifyStatusOk]}>
              {peerKeyChanged ? '' : peerKeyVerified ? 'Verified' : 'Not yet verified'}
            </Text>

            {/* Action buttons */}
            <View style={styles.safetyActions}>
              {(!peerKeyVerified || peerKeyChanged) && (
                <TouchableOpacity
                  style={styles.verifyBtn}
                  onPress={async () => {
                    try {
                      const fp = peerPubKey ? await CryptoService.fingerprintPeerKey(peerPubKey) : null;
                      await CryptoService.verifyPeerKey(myUsername, peer, fp);
                      // Clear key changed flag
                      await StorageService.removeKeyChanged(myUsername, peer);
                      setPeerKeyVerified(true);
                      setPeerKeyChanged(false);
                    } catch (e) {
                      Alert.alert('Error', e?.message || 'Failed to verify');
                    }
                  }}
                >
                  <Text style={styles.verifyBtnText}>
                    {peerKeyChanged ? 'I verified the new key' : 'I verified this'}
                  </Text>
                </TouchableOpacity>
              )}
              <TouchableOpacity
                style={styles.copyBtn}
                onPress={() => {
                  if (safetyNumber) {
                    Clipboard.setString(safetyNumber);
                    Alert.alert('Copied', 'Safety number copied to clipboard.');
                  }
                }}
              >
                <Text style={styles.copyBtnText}>Copy number</Text>
              </TouchableOpacity>
            </View>

            <TouchableOpacity style={styles.closeBtn2} onPress={() => setShowSafety(false)}>
              <Text style={styles.closeBtnText}>Close</Text>
            </TouchableOpacity>
          </View>
        </View>
      </Modal>

      {/* Report user modal */}
      <Modal visible={showReport} transparent animationType="fade" onRequestClose={() => setShowReport(false)}>
        <View style={styles.safetyOverlay}>
          <View style={styles.safetyCard}>
            <Text style={styles.safetyTitle}>Report {peer}</Text>
            {REPORT_REASONS.map(r => (
              <TouchableOpacity
                key={r.value}
                style={styles.reportReasonRow}
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
            <View style={styles.reportBtns}>
              <TouchableOpacity style={styles.closeBtn2} onPress={() => setShowReport(false)}>
                <Text style={styles.closeBtnText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={[styles.reportSubmitBtn, reporting && { opacity: 0.5 }]}
                onPress={handleReport}
                disabled={reporting}
              >
                {reporting
                  ? <ActivityIndicator color="#fff" size="small" />
                  : <Text style={styles.reportSubmitBtnText}>Submit</Text>}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </KeyboardAvoidingView>
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
  backBtn: { fontSize: 22, color: Colors.accent, paddingRight: Spacing.md },
  headerCenter: { flex: 1 },
  peerName: { fontSize: Typography.lg, fontWeight: '700' },
  safetyHint: { fontSize: Typography.xs, color: Colors.textMuted },
  lockBtn: { fontSize: 20, paddingLeft: Spacing.md },
  reportHeaderBtn: { paddingLeft: Spacing.sm },
  reportHeaderBtnText: { fontSize: 18, color: Colors.textMuted },
  searchBtn: { paddingLeft: Spacing.sm },
  searchBtnText: { fontSize: 18 },
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
  messageList: { padding: Spacing.md, paddingBottom: Spacing.lg },
  loadMoreBtn: { alignItems: 'center', paddingVertical: Spacing.sm, marginBottom: Spacing.xs },
  loadMoreText: { color: Colors.accent, fontSize: Typography.sm },
  emptyText: { textAlign: 'center', color: Colors.textMuted, marginTop: Spacing.xxl },
  bubble: {
    paddingVertical: 2,
    paddingHorizontal: 0,
    marginBottom: 2,
    maxWidth: '85%',
    alignSelf: 'flex-start',
    borderLeftWidth: 2,
    borderLeftColor: 'rgba(139,92,246,0.5)',
    paddingLeft: Spacing.md,
  },
  bubbleMe: {
    alignSelf: 'flex-end',
    borderLeftWidth: 0,
    paddingLeft: 0,
    borderRightWidth: 2,
    borderRightColor: 'rgba(139,92,246,0.5)',
    paddingRight: Spacing.md,
  },
  author: { fontSize: Typography.lg, fontWeight: '600', marginTop: Spacing.md, marginBottom: 2 },
  // Reply quote (inside message bubble)
  replyQuote: { flexDirection: 'row', backgroundColor: 'rgba(255,255,255,0.06)', borderRadius: Radii.sm, marginBottom: Spacing.xs, overflow: 'hidden' },
  replyQuoteBar: { width: 3, backgroundColor: Colors.accentDm },
  replyQuoteBody: { paddingHorizontal: Spacing.sm, paddingVertical: Spacing.xs },
  replyQuoteAuthor: { fontSize: Typography.xs, color: Colors.accentDm, fontWeight: '600', marginBottom: 1 },
  replyQuoteText: { fontSize: Typography.xs, color: Colors.textMuted, lineHeight: 16 },
  replyQuoteTextMe: { textAlign: 'right' },
  msgTextMe: { textAlign: 'right' },
  // Reply bar (above input)
  replyBar: { flexDirection: 'row', alignItems: 'center', backgroundColor: Colors.bgPanel, borderTopWidth: 1, borderTopColor: Colors.border, paddingHorizontal: Spacing.lg, paddingVertical: Spacing.sm, gap: Spacing.sm },
  replyBarContent: { flex: 1 },
  replyBarAuthor: { fontSize: Typography.xs, color: Colors.accentDm, fontWeight: '600', marginBottom: 1 },
  replyBarText: { fontSize: Typography.xs, color: Colors.textMuted },
  replyBarClose: { fontSize: Typography.md, color: Colors.textMuted, paddingLeft: Spacing.sm },
  msgText: { color: Colors.textMain, fontSize: Typography.md, lineHeight: 20 },
  linkText: { color: Colors.accent, textDecorationLine: 'underline' },
  suspiciousLink: { color: '#f87171', textDecorationLine: 'underline', textDecorationColor: '#f87171' },
  timeText: { fontSize: Typography.xs, color: Colors.textDim, marginTop: 2, alignSelf: 'flex-end' },
  decryptFailedText: { fontSize: Typography.sm, color: '#f87171', fontStyle: 'italic' },
  decryptPendingText: { fontSize: Typography.sm, color: Colors.textMuted, fontStyle: 'italic' },
  sealedWarnText: { fontSize: Typography.xs, color: '#fbbf24', fontStyle: 'italic', marginTop: 2 },
  sealedUnverifiedText: { fontSize: Typography.xs, color: Colors.textMuted, fontStyle: 'italic', marginTop: 2 },
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
  attachBtn: {
    width: 36,
    height: 36,
    borderRadius: Radii.round,
    backgroundColor: 'transparent',
    borderWidth: 1,
    borderColor: Colors.border,
    alignItems: 'center',
    justifyContent: 'center',
  },
  attachBtnText: { color: Colors.textMuted, fontSize: 20, fontWeight: '600' },
  sendBtn: {
    backgroundColor: Colors.accentDm,
    borderRadius: Radii.round,
    width: 36,
    height: 36,
    alignItems: 'center',
    justifyContent: 'center',
  },
  sendBtnDisabled: { opacity: 0.45 },
  sendBtnText: { color: '#fff', fontSize: 18, fontWeight: '700' },
  // Safety number
  safetyOverlay: { flex: 1, backgroundColor: Colors.overlay, justifyContent: 'center', alignItems: 'center' },
  safetyCard: {
    backgroundColor: Colors.bgPanel,
    borderRadius: Radii.lg,
    padding: Spacing.xxl,
    width: '80%',
    alignItems: 'center',
    gap: Spacing.md,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  safetyTitle: { fontSize: Typography.xl, fontWeight: '700', color: Colors.textMain },
  safetySubtitle: { fontSize: Typography.sm, color: Colors.textMuted, textAlign: 'center' },
  safetyNumber: {
    fontSize: Typography.xl,
    color: Colors.success,
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    textAlign: 'center',
    letterSpacing: 2,
  },
  closeBtn2: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    marginTop: Spacing.sm,
  },
  closeBtnText: { color: Colors.textMain, fontSize: Typography.md },
  keyWarning: {
    backgroundColor: 'rgba(220,53,69,0.12)',
    borderWidth: 1,
    borderColor: '#dc3545',
    borderRadius: 6,
    padding: Spacing.sm,
    marginBottom: Spacing.sm,
  },
  keyWarningText: { color: '#dc3545', fontSize: Typography.sm, lineHeight: 18 },
  verifyStatus: { fontSize: Typography.sm, color: Colors.textMuted, textAlign: 'center', marginTop: Spacing.xs },
  verifyStatusOk: { color: Colors.success },
  safetyActions: { flexDirection: 'row', gap: Spacing.sm, marginTop: Spacing.md, justifyContent: 'center' },
  verifyBtn: {
    backgroundColor: '#238636',
    borderRadius: Radii.md,
    paddingVertical: Spacing.sm,
    paddingHorizontal: Spacing.lg,
  },
  verifyBtnText: { color: '#fff', fontSize: Typography.sm, fontWeight: '600' },
  copyBtn: {
    backgroundColor: Colors.btnBg,
    borderRadius: Radii.md,
    paddingVertical: Spacing.sm,
    paddingHorizontal: Spacing.lg,
    borderWidth: 1,
    borderColor: Colors.border,
  },
  copyBtnText: { color: Colors.textMain, fontSize: Typography.sm },
  reportReasonRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 6,
    gap: Spacing.sm,
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
  reportBtns: {
    flexDirection: 'row',
    justifyContent: 'flex-end',
    gap: Spacing.sm,
  },
  reportSubmitBtn: {
    backgroundColor: Colors.danger,
    borderRadius: Radii.md,
    paddingVertical: Spacing.md,
    paddingHorizontal: Spacing.xl,
    marginTop: Spacing.sm,
  },
  reportSubmitBtnText: {
    color: '#fff',
    fontWeight: '700',
    fontSize: Typography.md,
  },
});
