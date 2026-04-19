// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * AppContext.js — Central state management for WS Messenger
 * Replaces the global state from panel.js + chrome.runtime.connect messaging
 */

import React, { createContext, useContext, useReducer, useCallback, useRef, useEffect } from 'react';
import { Alert } from 'react-native';
import NetworkService from '../services/NetworkService';
import StorageService from '../services/StorageService';
import CryptoService from '../services/CryptoService';

// ==============================
// State shape
// ==============================

const initialState = {
  // Auth
  isLoggedIn: false,
  username: null,
  token: null,

  // Connection
  wsOnline: false,
  dmWsOnline: false,

  // Rooms
  myRooms: [],          // private rooms (member of)
  publicRooms: [],      // public rooms
  currentRoomId: null,
  currentRoomName: null,
  currentRoomAlias: null,
  currentRoomMessages: [],
  roomMembers: {},      // roomId -> [{username, role, is_owner}]
  roomRoles: {},        // roomId -> "owner"|"admin"|"member"
  roomOwners: {},       // roomId -> bool
  onlineByRoom: {},     // roomId -> [username, ...]
  roomMeta: {},         // roomId -> { description, logo_url, ... }
  joinRequests: [],     // [{room_id, room_name, username}, ...]
  roomPassByAlias: {},  // alias -> { room_id, room_name }

  // DMs
  dmThreads: [],        // [{thread_id, peer_username, unread_count}, ...]
  currentDmThreadId: null,
  currentDmPeer: null,
  dmMessages: {},       // threadId -> [msg, ...]
  dmOnline: {},         // peer -> bool

  // Invites
  receivedInvites: [],  // [{room_id, room_name, from_username}, ...]
  friendRequests: [],   // [{from_username, ...}, ...]

  // Crypto
  cryptoUnlocked: false,
  cryptoInitialized: false,
  userPublicKey: null,

  // Unread
  unreadRooms: {},      // roomId -> count
  unreadDms: {},        // threadId -> count

  // Profile
  myProfile: null,      // { username, about, privacy }

  // UI preferences
  fontScale: 1.0,       // message text scale factor (0.85 – 1.3)
};

// ==============================
// Reducer
// ==============================

function reducer(state, action) {
  switch (action.type) {
    case 'SET_AUTH':
      return { ...state, isLoggedIn: true, username: action.username, token: action.token || state.token };
    case 'CLEAR_AUTH':
      return { ...initialState, fontScale: state.fontScale };

    case 'SET_WS_ONLINE':
      return { ...state, wsOnline: action.online };
    case 'SET_DM_WS_ONLINE':
      return { ...state, dmWsOnline: action.online };

    case 'SET_MY_ROOMS':
      return { ...state, myRooms: action.rooms };
    case 'SET_PUBLIC_ROOMS':
      return { ...state, publicRooms: action.rooms };
    case 'SET_CURRENT_ROOM':
      return {
        ...state,
        currentRoomId: action.roomId,
        currentRoomName: action.roomName,
        currentRoomAlias: action.roomAlias,
        // Only clear messages when entering a NEW room (not when leaving to null)
        currentRoomMessages: action.roomId ? [] : state.currentRoomMessages,
      };
    // Used by ChatScreen blur: just un-marks the active room without wiping messages
    case 'LEAVE_ROOM_VIEW':
      return { ...state, currentRoomId: null };
    case 'UPDATE_ROOM_NAME': {
      // Update name in myRooms list and currentRoomName if it's the active room
      const updatedRooms = state.myRooms.map(r =>
        String(r.id || r.room_id) === String(action.roomId)
          ? { ...r, name: action.name }
          : r
      );
      const newCurrentName = String(state.currentRoomId) === String(action.roomId)
        ? action.name
        : state.currentRoomName;
      return { ...state, myRooms: updatedRooms, currentRoomName: newCurrentName };
    }
    case 'SET_CURRENT_ROOM_MESSAGES':
      return { ...state, currentRoomMessages: action.messages };
    case 'APPEND_ROOM_MESSAGE': {
      const msgs = state.currentRoomMessages;
      const nm = action.message;
      const mid = nm.id;
      // Deduplicate by id (REST history messages)
      if (mid != null && msgs.some(m => m.id === mid)) return state;
      // Deduplicate by ciphertext body — prevents double-append from listener accumulation
      const cipher = nm.body || nm.text;
      if (cipher && nm._decrypted && msgs.some(m => (m.body || m.text) === cipher)) return state;
      // Server echo confirmation: server message matches an optimistic local_ message
      // by decrypted text within ±2s — replace the local with the server version.
      const nmAuthor = (nm.author || nm.username || nm.from || '').toLowerCase();
      if (nm._decrypted && nm.ts != null) {
        const tsSec = Math.round(nm.ts / 1000);
        const localIdx = msgs.findIndex(m =>
          String(m.id || '').startsWith('local_') &&
          m._decrypted === nm._decrypted &&
          Math.abs(Math.round((m.ts || 0) / 1000) - tsSec) <= 5
        );
        if (localIdx !== -1) {
          // Replace optimistic with confirmed server message
          const updated = [...msgs];
          updated[localIdx] = nm;
          return { ...state, currentRoomMessages: updated };
        }
        // Deduplicate by decrypted text + author + timestamp (within 2s window)
        // Author check prevents dropping messages from different users with same text
        if (msgs.some(m => {
          const mAuthor = (m.author || m.username || m.from || '').toLowerCase();
          return m._decrypted === nm._decrypted &&
            mAuthor === nmAuthor &&
            Math.abs(Math.round((m.ts || 0) / 1000) - tsSec) <= 2;
        })) {
          return state;
        }
      }
      return { ...state, currentRoomMessages: [...msgs, nm] };
    }
    case 'SET_ROOM_MEMBERS':
      return { ...state, roomMembers: { ...state.roomMembers, [action.roomId]: action.members } };
    case 'SET_ROOM_ROLE':
      return { ...state, roomRoles: { ...state.roomRoles, [action.roomId]: action.role } };
    case 'SET_ROOM_OWNER':
      return { ...state, roomOwners: { ...state.roomOwners, [action.roomId]: action.isOwner } };
    case 'SET_ONLINE_IN_ROOM':
      return { ...state, onlineByRoom: { ...state.onlineByRoom, [action.roomId]: action.users } };
    case 'SET_ROOM_META':
      return { ...state, roomMeta: { ...state.roomMeta, [action.roomId]: action.meta } };
    case 'SET_JOIN_REQUESTS':
      return { ...state, joinRequests: action.requests };
    case 'SET_ROOM_PASS_BY_ALIAS':
      return { ...state, roomPassByAlias: { ...state.roomPassByAlias, [action.alias]: action.data } };

    case 'SET_DM_THREADS':
      return { ...state, dmThreads: action.threads };
    case 'REMOVE_DM_THREAD': {
      const filtered = state.dmThreads.filter(
        t => String(t.thread_id || t.id) !== String(action.threadId)
      );
      const newDmMessages = { ...state.dmMessages };
      delete newDmMessages[String(action.threadId)];
      return { ...state, dmThreads: filtered, dmMessages: newDmMessages };
    }
    case 'SET_CURRENT_DM': {
      const base = { ...state, currentDmThreadId: action.threadId, currentDmPeer: action.peer };
      if (action.threadId == null) return base;
      // Pre-create slot for this thread only when we have a real threadId
      const prev = state.dmMessages[action.threadId] || [];
      return { ...base, dmMessages: { ...state.dmMessages, [action.threadId]: prev } };
    }
    case 'SET_DM_MESSAGES':
      return { ...state, dmMessages: { ...state.dmMessages, [action.threadId]: action.messages } };
    // Atomic re-decryption: applies redecrypted results to current state inside the reducer,
    // avoiding the race where a concurrent APPEND_DM_MESSAGE is overwritten by a stale SET_DM_MESSAGES.
    // action.updates: Array<{ id?, ts?, _decrypted, author?, username? }>
    case 'REDECRYPT_DM_MESSAGES': {
      const tid = action.threadId;
      const current = state.dmMessages[tid] || [];
      if (!action.updates?.length) return state;
      const updateMap = new Map();
      for (const u of action.updates) {
        const key = u.id != null ? `id:${u.id}` : `ts:${u.ts}`;
        updateMap.set(key, u);
      }
      let changed = false;
      const updated = current.map(m => {
        if (m._decrypted && !m._needsDecrypt) return m;
        const key = m.id != null ? `id:${m.id}` : `ts:${m.ts}`;
        const fresh = updateMap.get(key);
        if (fresh && fresh._decrypted) {
          changed = true;
          const { _needsDecrypt, ...rest } = { ...m, ...fresh };
          return rest;
        }
        return m;
      });
      return changed ? { ...state, dmMessages: { ...state.dmMessages, [tid]: updated } } : state;
    }
    // Mark DM messages as permanently failed after too many retry attempts — prevents
    // users from seeing empty bubbles forever when a key is truly unrecoverable.
    // action.matchers: Array<{ id?, ts? }>
    case 'MARK_DM_DECRYPT_FAILED': {
      const tid = action.threadId;
      const current = state.dmMessages[tid] || [];
      if (!action.matchers?.length) return state;
      const matchSet = new Set(action.matchers.map(u =>
        u.id != null ? `id:${u.id}` : `ts:${u.ts}`));
      let changed = false;
      const updated = current.map(m => {
        if (m._decrypted || m._decryptFailed) return m;
        const key = m.id != null ? `id:${m.id}` : `ts:${m.ts}`;
        if (matchSet.has(key)) {
          changed = true;
          const { _needsDecrypt, ...rest } = m;
          return { ...rest, _decryptFailed: true };
        }
        return m;
      });
      return changed ? { ...state, dmMessages: { ...state.dmMessages, [tid]: updated } } : state;
    }
    case 'APPEND_DM_MESSAGE': {
      const tid = action.threadId;
      const prev = state.dmMessages[tid] || [];
      const nm = action.message;
      // Deduplicate by id (REST history messages)
      if (nm.id != null && prev.find(m => m.id === nm.id)) return state;
      // Deduplicate by ciphertext_b64 — prevents double-append when both global and screen handlers fire
      const cipher = nm.ciphertext_b64 || nm.body;
      if (cipher && prev.find(m => (m.ciphertext_b64 || m.body) === cipher)) return state;

      // Ciphertext-based echo ↔ optimistic matching.
      // Server broadcasts: text = base64url(encryptedBody). Optimistic stores _localCiphertextB64 = same value.
      // This is unique per AES-GCM send (randomized IV), so there are no false-positive collisions.
      const nmIsLocal = String(nm.id || '').startsWith('local_');

      // (A) Incoming server echo matching a pending optimistic:
      //     Replace the optimistic with the echo (merges author from optimistic if echo has none).
      if (!nmIsLocal && nm.text) {
        const localIdx = prev.findIndex(m =>
          String(m.id || '').startsWith('local_') &&
          m._localCiphertextB64 &&
          m._localCiphertextB64 === nm.text
        );
        if (localIdx !== -1) {
          const local = prev[localIdx];
          const merged = {
            ...nm,
            author: nm.author || local.author,
            username: nm.username || local.username,
            _decrypted: nm._decrypted || local._decrypted,
            // Carry forward ciphertext fingerprint so the init effect can restore authorship
            // even after the local_ is replaced by this id-less echo.
            _localCiphertextB64: local._localCiphertextB64 || nm._localCiphertextB64,
          };
          const updated = [...prev];
          updated[localIdx] = merged;
          return { ...state, dmMessages: { ...state.dmMessages, [tid]: updated } };
        }
      }

      // (B) Incoming optimistic matching an already-arrived echo:
      //     Echo landed first (activeDmScreens guard missed). Fix author if echo has none, then drop optimistic.
      if (nmIsLocal && nm._localCiphertextB64) {
        const echoIdx = prev.findIndex(m =>
          !String(m.id || '').startsWith('local_') &&
          m.text === nm._localCiphertextB64
        );
        if (echoIdx !== -1) {
          const existing = prev[echoIdx];
          if ((!existing.author || !existing.username) && (nm.author || nm.username)) {
            const updated = [...prev];
            updated[echoIdx] = { ...existing, author: nm.author || existing.author, username: nm.username || existing.username };
            return { ...state, dmMessages: { ...state.dmMessages, [tid]: updated } };
          }
          return state; // echo already in state with correct author — drop optimistic
        }
      }

      // Server echo confirmation: server message matches an optimistic local_ message
      // by decrypted text within ±5s — replace the local with the server version.
      if (nm._decrypted && nm.ts != null) {
        const tsSec = Math.round(nm.ts / 1000);
        const localIdx = prev.findIndex(m =>
          String(m.id || '').startsWith('local_') &&
          m._decrypted === nm._decrypted &&
          Math.abs(Math.round((m.ts || 0) / 1000) - tsSec) <= 5
        );
        if (localIdx !== -1) {
          const updated = [...prev];
          updated[localIdx] = nm;
          return { ...state, dmMessages: { ...state.dmMessages, [tid]: updated } };
        }
      }
      // Deduplicate WS messages (no id) by (ts_sec, text) — prevents double-append on reconnect
      if (nm.id == null && nm.text && nm.ts != null) {
        const tsSec = Math.round(nm.ts / 1000);
        if (prev.find(m => m.text === nm.text && Math.round((m.ts || 0) / 1000) === tsSec)) {
          return state;
        }
      }
      return { ...state, dmMessages: { ...state.dmMessages, [tid]: [...prev, nm] } };
    }

    case 'SET_INVITES':
      return { ...state, receivedInvites: action.invites };
    case 'REMOVE_INVITE':
      return { ...state, receivedInvites: state.receivedInvites.filter(i => String(i.room_id) !== String(action.roomId)) };

    case 'SET_FRIEND_REQUESTS':
      return { ...state, friendRequests: action.requests };
    case 'REMOVE_FRIEND_REQUEST':
      return { ...state, friendRequests: state.friendRequests.filter(r => r.from_username !== action.username) };
    case 'APPEND_JOIN_REQUEST': {
      // Deduplicate: ignore if we already have a request from the same user for the same room
      const already = state.joinRequests.some(
        r => String(r.room_id) === String(action.request.room_id) && r.username === action.request.username
      );
      if (already) return state;
      return { ...state, joinRequests: [...state.joinRequests, action.request] };
    }
    case 'REMOVE_JOIN_REQUEST':
      return { ...state, joinRequests: state.joinRequests.filter(r => !(String(r.room_id) === String(action.roomId) && r.username === action.username)) };

    case 'SET_CRYPTO_STATE':
      return {
        ...state,
        cryptoUnlocked: action.unlocked ?? state.cryptoUnlocked,
        cryptoInitialized: action.initialized ?? state.cryptoInitialized,
        userPublicKey: action.publicKey ?? state.userPublicKey,
      };

    case 'SET_UNREAD_ROOM':
      return { ...state, unreadRooms: { ...state.unreadRooms, [action.roomId]: action.count } };
    case 'INCREMENT_UNREAD_ROOM':
      return { ...state, unreadRooms: { ...state.unreadRooms, [action.roomId]: (state.unreadRooms[action.roomId] || 0) + 1 } };
    case 'CLEAR_UNREAD_ROOM':
      return { ...state, unreadRooms: { ...state.unreadRooms, [action.roomId]: 0 } };
    case 'SET_UNREAD_DM':
      return { ...state, unreadDms: { ...state.unreadDms, [action.threadId]: action.count } };
    case 'INCREMENT_UNREAD_DM':
      return { ...state, unreadDms: { ...state.unreadDms, [action.threadId]: (state.unreadDms[action.threadId] || 0) + 1 } };
    case 'CLEAR_UNREAD_DM':
      return { ...state, unreadDms: { ...state.unreadDms, [action.threadId]: 0 } };

    case 'SET_MY_PROFILE':
      return { ...state, myProfile: action.profile };

    case 'SET_FONT_SCALE':
      return { ...state, fontScale: action.scale };

    default:
      return state;
  }
}

// ==============================
// Context
// ==============================

const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);
  const navigationRef = useRef(null);
  // Always-current state reference for use in stable event handlers
  const stateRef = useRef(state);
  stateRef.current = state;

  // Load persisted UI preferences on mount
  useEffect(() => {
    StorageService.get('font_scale').then(v => {
      if (v != null) dispatch({ type: 'SET_FONT_SCALE', scale: parseFloat(v) || 1.0 });
    }).catch(() => {});
  }, []);

  // ---- Auth ----

  const login = useCallback(async (username, password) => {
    const result = await NetworkService.login(username, password);
    if (result.ok) {
      dispatch({ type: 'SET_AUTH', username, token: result.token });
      await StorageService.setAuth({ username, token: result.token, refreshToken: result.refreshToken });
    }
    return result;
  }, []);

  const verify2fa = useCallback(async (tempToken, code) => {
    const result = await NetworkService.verify2fa(tempToken, code);
    if (result.ok) {
      dispatch({ type: 'SET_AUTH', username: result.username, token: result.token });
      await StorageService.setAuth({ username: result.username, token: result.token, refreshToken: result.refreshToken });
    }
    return result;
  }, []);

  const logout = useCallback(async () => {
    CryptoService.lockSession();
    await NetworkService.logout();
    await StorageService.clearAll();
    dispatch({ type: 'CLEAR_AUTH' });
  }, []);

  // ---- Rooms ----

  const loadMyRooms = useCallback(async () => {
    try {
      const rooms = await NetworkService.getRooms();
      dispatch({ type: 'SET_MY_ROOMS', rooms: rooms || [] });
    } catch (_e) { /* ignore */ }
  }, []);

  const loadPublicRooms = useCallback(async (query = '') => {
    try {
      const rooms = await NetworkService.getPublicRooms(query);
      dispatch({ type: 'SET_PUBLIC_ROOMS', rooms: rooms || [] });
    } catch (_e) { /* ignore */ }
  }, []);

  const connectRoom = useCallback((roomId, roomName, roomAlias) => {
    dispatch({ type: 'SET_CURRENT_ROOM', roomId, roomName, roomAlias });
    // Persist so auto-reconnect works on next launch (before auth_ok, to survive crashes)
    StorageService.setLastConn({ room: roomId, roomName, roomAlias }).catch(() => {});
    // History is loaded and decrypted by ChatScreen's mount effect
    NetworkService.connectRoom(roomId);
  }, []);

  const disconnectRoom = useCallback(() => {
    NetworkService.disconnectRoom();
    dispatch({ type: 'SET_CURRENT_ROOM', roomId: null, roomName: null, roomAlias: null });
  }, []);

  const sendMessage = useCallback(async (text) => {
    if (!state.currentRoomId) return;
    await NetworkService.sendMessage(text);
  }, [state.currentRoomId]);

  // ---- DMs ----

  const loadDmThreads = useCallback(async () => {
    try {
      const threads = await NetworkService.getDmThreads();
      dispatch({ type: 'SET_DM_THREADS', threads: threads || [] });
    } catch (_e) { /* ignore */ }
  }, []);

  const openDmThread = useCallback(async (threadId, peer) => {
    dispatch({ type: 'SET_CURRENT_DM', threadId, peer });
    // History is loaded and decrypted by DMChatScreen's mount effect — don't pre-load here
    // (pre-loading without decryption caused stale encrypted messages on screen open)
    try { await NetworkService.openDmThread(peer); } catch (_e) {
      console.warn('[AppContext] openDmThread failed:', _e?.message);
    }
    NetworkService.connectDm(threadId, peer);
    // Persist for auto-reconnect DM WS on next app start
    StorageService.setLastDm({ threadId, peer }).catch(() => {});
  }, []);

  // ---- Invites ----

  const loadInvites = useCallback(async () => {
    try {
      const invites = await NetworkService.getIncomingRoomInvites();
      dispatch({ type: 'SET_INVITES', invites: invites || [] });
    } catch (_e) { /* ignore */ }
  }, []);

  // ---- UI preferences ----

  const setFontScale = useCallback((scale) => {
    dispatch({ type: 'SET_FONT_SCALE', scale });
    StorageService.set('font_scale', scale).catch(() => {});
  }, []);

  // ---- Profile ----

  const loadMyProfile = useCallback(async () => {
    try {
      const profile = await NetworkService.getMyProfile();
      dispatch({ type: 'SET_MY_PROFILE', profile });
    } catch (_e) { /* ignore */ }
  }, []);

  // ---- NetworkService event listener setup ----
  // Call once after login to wire up WS events.
  // NetworkService._post() emits 'message' for every event, so we only need
  // one listener and route by msg.type inside _handleNetworkMessage.
  const setupNetworkListeners = useCallback(() => {
    const handler = (msg) => _handleNetworkMessage(msg, dispatch, stateRef);
    NetworkService.on('message', handler);
    return () => NetworkService.off('message', handler);
  }, []); // eslint-disable-line

  const ctx = {
    state,
    dispatch,
    navigationRef,
    // Actions
    login,
    verify2fa,
    logout,
    loadMyRooms,
    loadPublicRooms,
    connectRoom,
    disconnectRoom,
    sendMessage,
    loadDmThreads,
    openDmThread,
    loadInvites,
    loadMyProfile,
    setFontScale,
    setupNetworkListeners,
  };

  return <AppContext.Provider value={ctx}>{children}</AppContext.Provider>;
}

export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}

// ==============================
// Internal: handle raw WS/network events from NetworkService
// ==============================
// NetworkService emits actual types: 'status', 'dm_status', 'auth_state', 'presence',
// 'message' (room chat), 'dm_message'. All arrive via the 'message' emitter event.
// Room/DM messages are intentionally NOT dispatched here — ChatScreen/DMChatScreen
// handle them directly with inline decryption to avoid storing encrypted ciphertext.

function _handleNetworkMessage(msg, dispatch, stateRef) {
  if (!msg || !msg.type) return;
  const state = stateRef?.current;

  switch (msg.type) {
    // Room WebSocket connection status
    case 'status':
      dispatch({ type: 'SET_WS_ONLINE', online: !!msg.online });
      break;

    // DM WebSocket connection status
    case 'dm_status':
      dispatch({ type: 'SET_DM_WS_ONLINE', online: !!msg.online });
      break;

    // Session expired / logged out
    case 'auth_state':
      if (!msg.loggedIn) dispatch({ type: 'CLEAR_AUTH' });
      break;

    // Banned by server — show alert before logging out
    case 'banned':
      Alert.alert('Account Banned', msg.message || 'Your account has been banned.');
      dispatch({ type: 'CLEAR_AUTH' });
      break;

    // Online users in a room (presence)
    case 'presence':
      if (msg.room_id) {
        dispatch({ type: 'SET_ONLINE_IN_ROOM', roomId: msg.room_id, users: msg.online || [] });
      }
      break;

    // Room chat / DM message unread badges are handled exclusively by the
    // notifHandler in App.tsx — not here. Previously both incremented,
    // causing 2× badge counts on every message.
    case 'message':
    case 'dm_message':
      break;

    default:
      break;
  }
}

export default AppContext;
