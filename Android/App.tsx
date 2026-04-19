// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * App.tsx — Root navigation + providers for WS Messenger
 *
 * Navigation structure:
 *   RootNavigator
 *   ├── AuthStack        (when !isLoggedIn)
 *   │   ├── LoginScreen
 *   │   └── RegisterScreen
 *   └── AppTabs          (when isLoggedIn)
 *       ├── RoomsTab
 *       │   ├── RoomsListScreen
 *       │   └── ChatScreen
 *       ├── DMTab
 *       │   ├── DMListScreen
 *       │   └── DMChatScreen
 *       ├── InvitesTab  → InvitesScreen
 *       └── ProfileTab  → ProfileScreen
 */

import React, { useEffect, useRef, useCallback, useState } from 'react';
import { AppState, BackHandler, Alert, StatusBar, Image, View, Text, TextInput, TouchableOpacity, ActivityIndicator, StyleSheet as RNStyleSheet } from 'react-native';
import { NavigationContainer, useNavigationContainerRef } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';
import { KeyboardProvider } from 'react-native-keyboard-controller';

import { AppProvider, useApp } from './src/contexts/AppContext';
import ErrorBoundary from './src/components/ErrorBoundary';

const Icons = {
  door:   require('./src/assets/icons/door_white.png'),
  dm:     require('./src/assets/icons/dm_white.png'),
  invite: require('./src/assets/icons/invite_white.png'),
  cog:    require('./src/assets/icons/cog_white.png'),
};

function TabIcon({ icon, focused }: { icon: any; focused?: boolean }) {
  return <Image source={icon} style={{ width: 24, height: 24, opacity: focused ? 1 : 0.5 }} resizeMode="contain" />;
}
import { Colors } from './src/theme';
import StorageService from './src/services/StorageService';
import NetworkService from './src/services/NetworkService';
import NotificationService from './src/services/NotificationService';
import CryptoService from './src/services/CryptoService';
import { CryptoUtils } from './src/crypto';

// Screens
import LoginScreen from './src/screens/LoginScreen';
import RegisterScreen from './src/screens/RegisterScreen';
import MnemonicModal from './src/components/MnemonicModal';
import ImportKeyScreen from './src/screens/ImportKeyScreen';
import RecoveryScreen from './src/screens/RecoveryScreen';
import RoomsListScreen from './src/screens/RoomsListScreen';
import ChatScreen from './src/screens/ChatScreen';
import DMListScreen from './src/screens/DMListScreen';
import DMChatScreen, { activeScreenThreadIds as activeDmScreens } from './src/screens/DMChatScreen';
import InvitesScreen from './src/screens/InvitesScreen';
import ProfileScreen from './src/screens/ProfileScreen';

const Stack = createStackNavigator();
const Tab = createBottomTabNavigator();
const RoomsStack = createStackNavigator();
const DMStack = createStackNavigator();

// ---- Rooms stack ----
function RoomsStackNavigator() {
  return (
    <RoomsStack.Navigator screenOptions={{ headerShown: false }}>
      <RoomsStack.Screen name="RoomsList" component={RoomsListScreen} />
      <RoomsStack.Screen name="Chat" component={ChatScreen} />
    </RoomsStack.Navigator>
  );
}

// ---- DM stack ----
function DMStackNavigator() {
  return (
    <DMStack.Navigator screenOptions={{ headerShown: false }}>
      <DMStack.Screen name="DMList" component={DMListScreen} />
      <DMStack.Screen name="DMChat" component={DMChatScreen} />
    </DMStack.Navigator>
  );
}

// ---- Main tab navigator ----
function AppTabs() {
  const { state } = useApp();
  const inviteCount = (state.receivedInvites || []).length + (state.friendRequests || []).length + (state.joinRequests || []).length;
  const dmUnread = Object.values(state.unreadDms || {}).reduce((s: number, n: number) => s + (n || 0), 0);
  const roomUnread = Object.values(state.unreadRooms || {}).reduce((s: number, n: number) => s + (n || 0), 0);

  return (
    <Tab.Navigator
      screenOptions={{
        headerShown: false,
        tabBarStyle: {
          backgroundColor: Colors.bgPanel,
          borderTopColor: 'rgba(255,255,255,0.06)',
          borderTopWidth: 1,
          elevation: 8,
          paddingTop: 4,
          paddingBottom: 8,
          height: 60,
        },
        tabBarActiveTintColor: Colors.accent,
        tabBarInactiveTintColor: Colors.textMuted,
        tabBarLabelStyle: { fontSize: 11, fontWeight: '600', letterSpacing: 0.2 },
      }}
    >
      <Tab.Screen
        name="Rooms"
        component={RoomsStackNavigator}
        options={{
          tabBarLabel: 'Rooms',
          tabBarBadge: roomUnread > 0 ? roomUnread : undefined,
          tabBarBadgeStyle: { backgroundColor: '#2aabee', color: '#071018', fontSize: 10, fontWeight: '700' },
          tabBarIcon: ({ focused }: { focused: boolean }) => <TabIcon icon={Icons.door} focused={focused} />,
        }}
      />
      <Tab.Screen
        name="DMs"
        component={DMStackNavigator}
        options={{
          tabBarLabel: 'Messages',
          tabBarBadge: dmUnread > 0 ? dmUnread : undefined,
          tabBarBadgeStyle: { backgroundColor: Colors.accentDm, color: '#fff', fontSize: 10, fontWeight: '700' },
          tabBarIcon: ({ focused }: { focused: boolean }) => <TabIcon icon={Icons.dm} focused={focused} />,
        }}
      />
      <Tab.Screen
        name="Invites"
        component={InvitesScreen}
        options={{
          tabBarLabel: 'Invites',
          tabBarBadge: inviteCount > 0 ? inviteCount : undefined,
          tabBarBadgeStyle: { backgroundColor: Colors.accentDm, color: '#fff', fontSize: 10, fontWeight: '700' },
          tabBarIcon: ({ focused }: { focused: boolean }) => <TabIcon icon={Icons.invite} focused={focused} />,
        }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileScreen}
        options={{
          tabBarLabel: 'Profile',
          tabBarIcon: ({ focused }: { focused: boolean }) => <TabIcon icon={Icons.cog} focused={focused} />,
        }}
      />
    </Tab.Navigator>
  );
}

// ---- Auth stack ----
function AuthStackNavigator() {
  return (
    <Stack.Navigator screenOptions={{ headerShown: false }}>
      <Stack.Screen name="Login" component={LoginScreen} />
      <Stack.Screen name="Register" component={RegisterScreen} />
      <Stack.Screen name="ImportKey" component={ImportKeyScreen} />
      <Stack.Screen name="Recovery" component={RecoveryScreen} />
    </Stack.Navigator>
  );
}

// ---- Unlock screen (shown once after auto-login if crypto not ready) ----
function UnlockScreen({ onUnlocked, onLogout }: { onUnlocked: () => void; onLogout?: () => void }) {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Try auto-unlock: first check in-memory, then Keychain cache
  useEffect(() => {
    if (CryptoService.isReady()) { onUnlocked(); return; }
    CryptoService.ensureReady({ interactive: false }).then(ok => {
      if (ok) onUnlocked();
    });
  }, []);

  async function handleUnlock() {
    if (!password.trim()) return;
    setLoading(true);
    setError('');
    try {
      const ok = await CryptoService.unlockWithPassword(password);
      setPassword(''); // Clear password from memory immediately after use
      if (ok) {
        onUnlocked();
      } else {
        setError('Wrong password or no encryption key on this device');
      }
    } catch (e: any) {
      setError(e?.message || 'Unlock failed');
    } finally {
      setLoading(false);
    }
  }

  function handleLogout() {
    Alert.alert(
      'Log Out',
      'Sign out and return to the login screen?',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Log Out', style: 'destructive', onPress: () => onLogout?.() },
      ],
    );
  }

  return (
    <View style={unlockStyles.root}>
      <View style={unlockStyles.card}>
        <Text style={unlockStyles.title}>Unlock Encryption</Text>
        <Text style={unlockStyles.subtitle}>Enter your password to decrypt messages</Text>
        <TextInput
          style={unlockStyles.input}
          placeholder="Password"
          placeholderTextColor="#888"
          secureTextEntry
          value={password}
          onChangeText={setPassword}
          onSubmitEditing={handleUnlock}
          autoFocus
        />
        {error ? <Text style={unlockStyles.error}>{error}</Text> : null}
        <TouchableOpacity style={unlockStyles.btn} onPress={handleUnlock} disabled={loading}>
          {loading ? <ActivityIndicator color="#fff" /> : <Text style={unlockStyles.btnText}>Unlock</Text>}
        </TouchableOpacity>
        <TouchableOpacity style={unlockStyles.logoutBtn} onPress={handleLogout}>
          <Text style={unlockStyles.logoutText}>Log Out</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
}

const unlockStyles = RNStyleSheet.create({
  root: { flex: 1, backgroundColor: Colors.bgMain, justifyContent: 'center', alignItems: 'center', padding: 24 },
  card: { width: '100%', maxWidth: 360, backgroundColor: Colors.bgPanel, borderRadius: 14, padding: 24, borderWidth: 1, borderColor: Colors.border, elevation: 8 },
  title: { color: Colors.textMain, fontSize: 20, fontWeight: '700', textAlign: 'center', marginBottom: 8 },
  subtitle: { color: Colors.textMuted, fontSize: 14, textAlign: 'center', marginBottom: 20 },
  input: { backgroundColor: Colors.inputBg, color: Colors.textMain, borderRadius: 10, padding: 12, fontSize: 16, borderWidth: 1, borderColor: Colors.border, marginBottom: 12 },
  error: { color: Colors.danger, fontSize: 13, marginBottom: 8, textAlign: 'center' },
  btn: { backgroundColor: '#238636', borderRadius: 10, padding: 14, alignItems: 'center' },
  btnText: { color: '#fff', fontSize: 16, fontWeight: '600' },
  logoutBtn: { marginTop: 16, alignItems: 'center', padding: 8 },
  logoutText: { color: Colors.textMuted, fontSize: 14 },
});

// ---- Root navigator (auth gate + AppState + BackHandler) ----
function RootNavigator() {
  const { state, dispatch, setupNetworkListeners, openDmThread, logout } = useApp();
  const navigationRef = useNavigationContainerRef();
  const appStateRef = useRef(AppState.currentState);
  const [cryptoUnlocked, setCryptoUnlocked] = useState(false);
  // Pending recovery-phrase ack — surfaced if the user closed the app between
  // a successful registration and tapping "I have saved my phrase". Cleared
  // only on user confirmation; survives crashes via Keychain.
  const [pendingMnemonicWords, setPendingMnemonicWords] = useState<string[] | null>(null);
  // Refs to avoid stale closures in event handlers
  const currentDmThreadIdRef = useRef(state.currentDmThreadId);
  useEffect(() => { currentDmThreadIdRef.current = state.currentDmThreadId; }, [state.currentDmThreadId]);
  const stateRef = useRef(state);
  useEffect(() => { stateRef.current = state; }, [state]);

  // Reset cryptoUnlocked when user logs out; auto-set when crypto is already ready (e.g. LoginScreen unlocked it)
  useEffect(() => {
    if (!state.isLoggedIn) {
      setCryptoUnlocked(false);
      setPendingMnemonicWords(null);
    } else if (!cryptoUnlocked && CryptoService.isReady()) {
      setCryptoUnlocked(true);
    }
  }, [state.isLoggedIn]);

  // Pending mnemonic check — runs once per unlock. Re-derives the phrase from
  // the in-memory raw private key (no password prompt), so the user finishes
  // the post-register acknowledgement on next launch even after a crash.
  useEffect(() => {
    if (!state.isLoggedIn || !cryptoUnlocked) return;
    let cancelled = false;
    (async () => {
      try {
        const pending = await StorageService.getPendingMnemonicAck();
        if (!pending?.username) return;
        const activeUser = (state.username || '').toLowerCase();
        if (activeUser && pending.username !== activeUser) {
          // Stale flag from a different account — clear and bail.
          await StorageService.clearPendingMnemonicAck().catch(() => {});
          return;
        }
        const mnemonic = CryptoService.exportCurrentMnemonic?.();
        if (!mnemonic) return;
        if (cancelled) return;
        setPendingMnemonicWords(mnemonic.split(' '));
      } catch (_e) { /* best-effort */ }
    })();
    return () => { cancelled = true; };
  }, [state.isLoggedIn, cryptoUnlocked, state.username]);

  const handlePendingMnemonicAck = useCallback(async () => {
    await StorageService.clearPendingMnemonicAck().catch(() => {});
    setPendingMnemonicWords(null);
  }, []);

  // ---- Restore auth from SecureStore on first launch ----
  useEffect(() => {
    (async () => {
      // Set up notification channel early — before WS connects and messages arrive
      await NotificationService.setup().catch(() => {});
      // KDF self-test (Argon2id) — fire-and-forget; fail-closed gate lives in deriveRawKeyFromPassword.
      // Don't await — @noble/hashes/argon2 JS reference blocks the JS thread for seconds (UI becomes unresponsive).
      CryptoUtils.runKdfSelfTest().then((kdfRes) => {
        if (!kdfRes?.ok) {
          Alert.alert(
            'Security Error',
            'Password-based encryption self-test failed.\n\n' +
            (kdfRes?.error || 'Unknown error') + '\n\n' +
            'Key derivation is blocked. Please reinstall the app.',
          );
        }
      }).catch(() => { /* already cached as failed result */ });
      // Restore user's preferred crypto idle lock timeout
      await CryptoService.restoreIdleLockSetting().catch(() => {});
      // Restore custom server config (self-host) before any network calls
      await NetworkService.loadServerConfig().catch(() => {});
      try {
        const auth = await StorageService.getAuth();
        if (auth?.token && auth?.username) {
          // Restore token into NetworkService so WS auth works on auto-connect
          NetworkService.setRestoredAuth(auth.username, auth.token, auth.refreshToken || '');
          // Verify the session is still valid (token not expired, or refresh succeeds).
          // Without this, a stale token in Keychain (e.g. after failed logout cleanup)
          // shows empty AppTabs instead of the login screen.
          const sessionOk = await NetworkService.validateSession();
          if (!sessionOk) {
            // Token expired and refresh failed — clean up stale auth and show login
            await StorageService.removeAuth().catch(() => {});
            await StorageService.clearAll().catch(() => {});
            return;
          }
          // Auto-unlock crypto from Keychain before navigating to AppTabs
          await CryptoService.ensureReady({ interactive: false }).catch(() => {});
          dispatch({ type: 'SET_AUTH', username: auth.username, token: auth.token });
        }
      } catch (_e) { /* ignore */ }
      // Fetch server broadcast notice (MOTD)
      try {
        const notice = await NetworkService.fetchNotice();
        if (notice) {
          const titles = {
            info: 'Server Notice',
            warning: 'Warning',
            maintenance: 'Maintenance',
          };
          Alert.alert(titles[notice.type] || titles.info, notice.message);
        }
      } catch (_e) { /* ignore */ }
    })();
  }, []);

  // ---- Wire NetworkService events when logged in ----
  useEffect(() => {
    if (!state.isLoggedIn || !state.token) return;
    const unsub = setupNetworkListeners();
    // Auto-connect room WS (for notifications even before user navigates to a room)
    StorageService.getLastConn().then(async (conn) => {
      if (conn?.room) {
        NetworkService.connectRoomAuto(conn.room, conn.roomPass || '');
      } else {
        // No saved room — connect to the first room from the user's list
        try {
          const rooms = await NetworkService.getRooms();
          if (rooms?.length) {
            const first = rooms[0];
            const rid = first.id || first.room_id;
            NetworkService.connectRoomAuto(rid, '');
          }
        } catch (_e) { /* ignore */ }
      }
    }).catch(() => {});
    // Auto-connect DM WS (for notifications even before user navigates to a DM)
    StorageService.getLastDm().then(async (dm) => {
      if (dm?.threadId && dm?.peer) {
        NetworkService.connectDm(dm.threadId, dm.peer);
      } else {
        // No saved DM — connect to the most recent DM thread
        try {
          const threads = await NetworkService.getDmThreads();
          if (threads?.length) {
            const first = threads[0];
            const tid = first.thread_id || first.id;
            const peer = first.peer_username;
            if (tid && peer) {
              NetworkService.connectDm(tid, peer);
              StorageService.setLastDm({ threadId: tid, peer }).catch(() => {});
            }
          }
        } catch (_e) { /* ignore */ }
      }
    }).catch(() => {});
    // Connect notification WS for all rooms/DMs
    NetworkService.connectNotify();
    // Ensure notification channel exists (idempotent — may already be created in init effect)
    NotificationService.setup().then(() => {
      NotificationService.registerFcmToken(async (token) => {
        try { await NetworkService.registerFcmToken(token); } catch (_e) { /* ignore */ }
      });
    });
    return unsub;
  }, [state.token]);

  // ---- AppState: background ↔ foreground ----
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextState) => {
      const prev = appStateRef.current;
      appStateRef.current = nextState;

      if (nextState === 'active') {
        // App came to foreground
        _handleForeground();
      } else if (prev === 'active' && (nextState === 'background' || nextState === 'inactive')) {
        // App going to background
        _handleBackground();
      }
    });

    return () => subscription.remove();
  }, []); // handlers use stateRef — no deps needed

  function _handleForeground() {
    const s = stateRef.current;
    if (s.currentRoomId) NotificationService.cancelRoom(s.currentRoomId);
    if (s.currentDmThreadId) NotificationService.cancelDm(s.currentDmThreadId);
  }

  function _handleBackground() {
    const s = stateRef.current;
    if (s.currentRoomId) {
      StorageService.setLastConn({
        room: s.currentRoomId,
        roomName: s.currentRoomName,
        roomAlias: s.currentRoomAlias,
      }).catch(() => {});
    }
  }

  // ---- Notification tap → navigate ----
  useEffect(() => {
    NotificationService.setNavigationHandler(({ screen, params }) => {
      if (!navigationRef.isReady()) return;
      try {
        if (screen === 'Chat') {
          navigationRef.navigate('Rooms');
          navigationRef.navigate('Chat', params);
        } else if (screen === 'DMChat') {
          // Ensure DM WS is connected (normally done by DMListScreen → openDmThread)
          if (params?.threadId && params?.peer) {
            openDmThread(params.threadId, params.peer);
          }
          navigationRef.navigate('DMs');
          navigationRef.navigate('DMChat', params);
        } else if (screen === 'Invites') {
          navigationRef.navigate('App');
          navigationRef.navigate('Invites');
        }
      } catch (_e) { /* ignore nav errors */ }
    });
  }, []);

  // ---- Android BackHandler — double-back to exit ----
  const backPressCount = useRef(0);
  useEffect(() => {
    const handler = BackHandler.addEventListener('hardwareBackPress', () => {
      // Let navigation handle back first
      if (navigationRef.canGoBack()) {
        navigationRef.goBack();
        return true;
      }
      // Root screen: second press exits
      if (backPressCount.current === 0) {
        backPressCount.current = 1;
        Alert.alert('', 'Press back again to exit', [{ text: 'OK' }]);
        setTimeout(() => { backPressCount.current = 0; }, 2000);
        return true;
      }
      return false; // let OS handle (exit)
    });
    return () => handler.remove();
  }, []);

  // ---- Global DM handler — dispatch incoming DMs to AppContext even when DMChatScreen is not mounted ----
  // DMChatScreen only registers its own handler while it's mounted. Messages arriving when the user
  // is on the Rooms tab would be lost from state (only recovered later by REST history fetch).
  // This handler fills that gap: it dispatches APPEND_DM_MESSAGE for any thread DMChatScreen
  // isn't actively viewing (currentDmThreadIdRef prevents double-dispatch).
  const dmThreadsRef = useRef(state.dmThreads);
  useEffect(() => { dmThreadsRef.current = state.dmThreads; }, [state.dmThreads]);

  useEffect(() => {
    if (!state.isLoggedIn) return;
    const globalDmHandler = async (msg) => {
      if (msg?.type !== 'dm_message') return;
      const p = msg?.payload || msg;
      if (!p?.thread_id) return;
      const threadId = String(p.thread_id);
      // DMChatScreen is mounted and handles this thread itself — skip.
      // activeScreenThreadIds is a synchronous module-level Set (no React state lag).
      // Note: we no longer check currentDmThreadIdRef here — it's updated via useEffect
      // (async) while activeScreenThreadIds updates synchronously, so the ref check
      // created a brief window where neither handler processed the message.
      if (activeDmScreens.has(threadId)) return;

      // Find peer for decryption (sealed sender — username not in WS payload)
      const thread = (dmThreadsRef.current || []).find(
        t => String(t.thread_id || t.id) === threadId
      );
      const peer = thread?.peer_username;

      // Try to decrypt if crypto is already unlocked (no interactive prompt here)
      let normalized = { ...p };
      const raw = p.ciphertext_b64 || p.body || p.text || '';
      if (raw && peer) {
        // If crypto isn't ready yet (Keychain auto-unlock in progress), wait briefly.
        // This prevents the race where WS message arrives during idle → unlock transition.
        if (!CryptoService.isReady()) {
          await CryptoService.ensureReady({ interactive: false });
        }
        if (CryptoService.isReady()) {
          try {
            let encryptedJson = null;
            try {
              const b64 = raw.replace(/-/g, '+').replace(/_/g, '/');
              const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
              const decoded = atob(padded);
              const parsed = JSON.parse(decoded);
              if (parsed.encrypted && parsed.iv && parsed.data) encryptedJson = decoded;
            } catch (_e) { /* not base64url */ }
            if (!encryptedJson) {
              try {
                const parsed = JSON.parse(raw);
                if (parsed.encrypted && parsed.iv && parsed.data) encryptedJson = raw;
              } catch (_e) { /* not JSON */ }
            }
            if (encryptedJson) {
              const result = await CryptoService.decryptDm(threadId, encryptedJson, peer);
              if (result !== null) {
                const text     = result?.text     ?? result;
                const from     = result?.from     ?? null;
                const sigValid = result?.sigValid ?? null;
                // Sealed sender: "from" should be either the peer or ourselves.
                // On mismatch, still store the decrypted text (so the message isn't lost
                // and redecryptExisting won't loop), but flag it for UI warning.
                const myUser = (stateRef.current.username || '').toLowerCase();
                if (sigValid === false) {
                  // Ed25519 signature verification failed — possible forgery
                  console.warn('[App] DM Ed25519 signature INVALID — from:', from);
                  normalized = { ...p, _decrypted: text,
                    ...(from ? { author: from, username: from } : {}),
                    _sealedSenderSigFailed: true };
                } else if (!from) {
                  // No sender identity in decrypted payload — use text but don't set author
                  normalized = { ...p, _decrypted: text };
                } else if (from.toLowerCase() !== String(peer).toLowerCase() && from.toLowerCase() !== myUser) {
                  console.warn('[App] sealed sender mismatch — from:', from, 'expected:', peer);
                  normalized = { ...p, _decrypted: text, author: from, username: from, _sealedSenderMismatch: true };
                } else {
                  normalized = { ...p, _decrypted: text, author: from, username: from };
                }
              } else {
                // Decryption returned null — key not loaded or mismatch.
                // Mark for re-decryption when DMChatScreen mounts or crypto unlocks.
                normalized = { ...p, _needsDecrypt: true };
              }
            }
          } catch (_e) {
            // Decryption threw — mark for retry in DMChatScreen
            normalized = { ...p, _needsDecrypt: true };
          }
        } else {
          // Crypto still not ready after ensureReady — mark for later decryption
          normalized = { ...p, _needsDecrypt: true };
        }
      }

      // Normalize server timestamp (seconds → ms)
      if (normalized.ts != null && normalized.ts < 1e12) {
        normalized = { ...normalized, ts: normalized.ts * 1000 };
      }
      // Set text field from ciphertext for dedup in APPEND_DM_MESSAGE reducer
      if (!normalized.text && normalized.ciphertext_b64) {
        normalized = { ...normalized, text: normalized.ciphertext_b64 };
      }

      dispatch({ type: 'APPEND_DM_MESSAGE', threadId, message: normalized });
    };

    NetworkService.on('message', globalDmHandler);
    return () => NetworkService.off('message', globalDmHandler);
  }, [state.isLoggedIn, dispatch]);

  // ---- Incoming messages → show notification when in background ----
  // NetworkService emits type='message' for room chat and type='dm_message' for DMs.
  // Uses stateRef throughout to avoid frequent re-registrations (prevents listener churn).
  useEffect(() => {
    if (!state.isLoggedIn) return;
    const notifHandler = (msg) => {
      if (!msg) return;
      const st = stateRef.current;
      const isBackground = appStateRef.current !== 'active';
      // Room message: show notification when not actively viewing that room
      if (msg.type === 'message') {
        const notViewingRoom = String(msg.room_id) !== String(st.currentRoomId);
        if (isBackground || notViewingRoom) {
          const body = msg.body || msg.text || '';
          NotificationService.showRoomMessage({
            roomId: msg.room_id,
            roomName: msg.room_name || `Room ${msg.room_id}`,
            author: msg.author || msg.username || msg.from || 'Someone',
            text: body && !body.includes('"encrypted"') ? body : '🔒 encrypted message',
          });
          // Increment unread counter for rooms reached via primary WS (not just notify WS)
          if (notViewingRoom && msg.room_id) {
            dispatch({ type: 'INCREMENT_UNREAD_ROOM', roomId: msg.room_id });
          }
        }
      // DM message: show notification when not actively viewing that thread
      } else if (msg.type === 'dm_message') {
        const notViewingThread = String(msg.thread_id) !== String(st.currentDmThreadId);
        if (isBackground || notViewingThread) {
          const thread = (st.dmThreads || []).find(
            t => String(t.thread_id || t.id) === String(msg.thread_id)
          );
          const peer = thread?.peer_username || msg.author || msg.username || msg.from || 'Someone';
          NotificationService.showDmMessage({
            threadId: msg.thread_id,
            peer,
            text: '🔒 New encrypted message',
          });
          // Increment unread counter for DMs reached via primary WS (not just notify WS)
          if (notViewingThread && msg.thread_id) {
            dispatch({ type: 'INCREMENT_UNREAD_DM', threadId: msg.thread_id });
          }
        }

      // ---- /ws-notify fan-out: room message notification ----
      } else if (msg.type === 'notify_room_msg') {
        if (NetworkService.isConnectedToRoom(msg.room_id)) return;
        const notViewingRoom = String(msg.room_id) !== String(st.currentRoomId);
        if (isBackground || notViewingRoom) {
          NotificationService.showRoomMessage({
            roomId: msg.room_id,
            roomName: msg.room_name || `Room ${msg.room_id}`,
            author: msg.from || 'Someone',
            text: '🔒 New encrypted message',
          });
          dispatch({ type: 'INCREMENT_UNREAD_ROOM', roomId: msg.room_id });
        }

      // ---- Join request from room WS (owner/admin only) ----
      } else if (msg.type === 'join_request') {
        if (msg.username && msg.room_id) {
          dispatch({
            type: 'APPEND_JOIN_REQUEST',
            request: { room_id: msg.room_id, room_name: msg.room_name || '', username: msg.username },
          });
        }

      // ---- /ws-notify fan-out: DM notification ----
      } else if (msg.type === 'notify_dm_msg') {
        if (NetworkService.isConnectedToDm(msg.thread_id)) return;
        const notViewingThread = String(msg.thread_id) !== String(st.currentDmThreadId);
        if (isBackground || notViewingThread) {
          const thread = (st.dmThreads || []).find(
            t => String(t.thread_id || t.id) === String(msg.thread_id)
          );
          const peer = thread?.peer_username || 'Someone';
          NotificationService.showDmMessage({
            threadId: msg.thread_id,
            peer,
            text: '🔒 New encrypted message',
          });
          dispatch({ type: 'INCREMENT_UNREAD_DM', threadId: msg.thread_id });
        }
      }
    };
    NetworkService.on('message', notifHandler);
    return () => NetworkService.off('message', notifHandler);
  }, [state.isLoggedIn]);

  // ---- Poll for friend requests & room invites (every 30s) ----
  const _lastFriendReqIds = useRef(new Set());
  const _lastInviteIds = useRef(new Set());

  useEffect(() => {
    if (!state.isLoggedIn) return;

    let cancelled = false;

    async function poll() {
      try {
        // Friend requests
        const incoming = await NetworkService.getIncomingFriendRequests();
        if (!cancelled && Array.isArray(incoming)) {
          const newReqs = incoming.filter(r => !_lastFriendReqIds.current.has(r.from_username || r.username));
          for (const r of newReqs) {
            const from = r.from_username || r.username;
            NotificationService.showFriendRequest({ from });
          }
          _lastFriendReqIds.current = new Set(incoming.map(r => r.from_username || r.username));
          dispatch({ type: 'SET_FRIEND_REQUESTS', requests: incoming });
        }
      } catch (_e) { /* ignore */ }

      try {
        // Room invites
        const invites = await NetworkService.getIncomingRoomInvites();
        if (!cancelled && Array.isArray(invites)) {
          const newInvites = invites.filter(i => !_lastInviteIds.current.has(String(i.room_id)));
          for (const inv of newInvites) {
            NotificationService.showRoomInvite({
              roomName: inv.room_name || `Room ${inv.room_id}`,
              from: inv.from_username || inv.invited_by || 'Someone',
            });
          }
          _lastInviteIds.current = new Set(invites.map(i => String(i.room_id)));
          // Also update AppContext invites list
          dispatch({ type: 'SET_INVITES', invites });
        }
      } catch (_e) { /* ignore */ }
    }

    // Initial fetch (silent — no notifications for already-existing items)
    (async () => {
      try {
        const incoming = await NetworkService.getIncomingFriendRequests();
        if (Array.isArray(incoming)) {
          _lastFriendReqIds.current = new Set(incoming.map(r => r.from_username || r.username));
          dispatch({ type: 'SET_FRIEND_REQUESTS', requests: incoming });
        }
      } catch (_e) {}
      try {
        const invites = await NetworkService.getIncomingRoomInvites();
        if (Array.isArray(invites)) {
          _lastInviteIds.current = new Set(invites.map(i => String(i.room_id)));
          dispatch({ type: 'SET_INVITES', invites });
        }
      } catch (_e) {}
    })();

    const timer = setInterval(poll, 30_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [state.isLoggedIn]);

  // Three states: not logged in → UnlockScreen (enter password once) → AppTabs
  if (state.isLoggedIn && !cryptoUnlocked) {
    return (
      <NavigationContainer ref={navigationRef}>
        <UnlockScreen onUnlocked={() => setCryptoUnlocked(true)} onLogout={logout} />
      </NavigationContainer>
    );
  }

  return (
    <>
      <NavigationContainer ref={navigationRef}>
        <Stack.Navigator screenOptions={{ headerShown: false }}>
          {state.isLoggedIn ? (
            <Stack.Screen name="App" component={AppTabs} />
          ) : (
            <Stack.Screen name="Auth" component={AuthStackNavigator} />
          )}
        </Stack.Navigator>
      </NavigationContainer>
      <MnemonicModal
        visible={!!pendingMnemonicWords}
        words={pendingMnemonicWords || []}
        onAck={handlePendingMnemonicAck}
      />
    </>
  );
}

// ---- Root component ----
export default function App() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <KeyboardProvider>
          <StatusBar barStyle="light-content" backgroundColor={Colors.bgMain} />
          <ErrorBoundary>
            <AppProvider>
              <RootNavigator />
            </AppProvider>
          </ErrorBoundary>
        </KeyboardProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}
