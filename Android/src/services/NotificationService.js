// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * NotificationService.js — Push & local notifications
 *
 * Responsibilities:
 *   - Show local (in-app heads-up) notifications for new messages
 *   - Register FCM token with backend (when Firebase is configured)
 *   - Handle notification taps → navigate to the relevant screen
 *
 * Dependencies:
 *   - @notifee/react-native  — local notifications (install separately, see README)
 *   - @react-native-firebase/messaging — FCM tokens (optional, needs google-services.json)
 *
 * To enable push notifications:
 *   1. npm install @notifee/react-native
 *   2. cd android && ./gradlew assembleDebug   (triggers auto-linking)
 *   3. For FCM: add Firebase to the project (google-services.json → android/app/)
 *      npm install @react-native-firebase/app @react-native-firebase/messaging
 *      Follow React Native Firebase setup guide
 */

import { Platform, AppState } from 'react-native';

// ---- Optional imports (graceful fallback if not installed) ----
let notifee = null;
let AndroidVisibility = null;
let messaging = null;

try {
  const mod = require('@notifee/react-native');
  notifee = mod.default;
  AndroidVisibility = mod.AndroidVisibility;
} catch (_e) {
  console.log('[NotificationService] @notifee/react-native not installed — local notifications disabled');
}

try {
  messaging = require('@react-native-firebase/messaging').default;
} catch (_e) {
  console.log('[NotificationService] Firebase Messaging not installed — FCM disabled');
}

// ---- State ----

let _channelId = null;
let _navigationRef = null;  // Set by App.tsx
let _onNotificationTap = null; // Callback: ({screen, params}) => void

// ---- Public API ----

const NotificationService = {

  /**
   * Set up notification channels and request permissions.
   * Call once at app startup.
   */
  async setup() {
    if (!notifee) return;

    try {
      // Request permission (Android 13+ requires explicit permission)
      const settings = await notifee.requestPermission();
      // authorizationStatus: 1 = AUTHORIZED, 2 = PROVISIONAL, 0 = DENIED, -1 = NOT_DETERMINED
      const granted = settings?.authorizationStatus === 1 || settings?.authorizationStatus === 2;
      console.log('[NotificationService] permission granted:', granted, 'status:', settings?.authorizationStatus);
      if (!granted) {
        console.warn('[NotificationService] notifications permission DENIED — notifications will not appear');
      }

      // Create the main channel
      _channelId = await notifee.createChannel({
        id: 'ws_messages',
        name: 'Messages',
        importance: 4,  // HIGH
        sound: 'default',
        vibration: true,
      });

      // Create a silent channel for background updates
      await notifee.createChannel({
        id: 'ws_silent',
        name: 'Background updates',
        importance: 1,  // LOW
      });

      console.log('[NotificationService] Channels created, channelId:', _channelId);
    } catch (e) {
      console.warn('[NotificationService] setup error:', e?.message);
    }
  },

  /**
   * Set the navigation callback for notification taps.
   * @param {function({screen: string, params: object}): void} fn
   */
  setNavigationHandler(fn) {
    _onNotificationTap = fn;

    // Remove previous listener if any
    if (this._unsubForeground) {
      this._unsubForeground();
      this._unsubForeground = null;
    }

    // Handle notification tap when app was in background
    if (notifee) {
      this._unsubForeground = notifee.onForegroundEvent(({ type, detail }) => {
        if (type === 1 /* PRESS */ && detail.notification) {
          _handleNotificationPress(detail.notification);
        }
      });
    }
  },

  /**
   * Register FCM token with backend.
   * No-op if Firebase Messaging is not configured.
   * @param {function(string): Promise<void>} registerFn  — calls NetworkService.registerFcmToken
   */
  async registerFcmToken(registerFn) {
    if (!messaging) return;
    try {
      const authStatus = await messaging().requestPermission();
      const enabled = authStatus === 1 || authStatus === 2;
      if (!enabled) return;

      const token = await messaging().getToken();
      if (token && registerFn) {
        await registerFn(token);
        console.log('[NotificationService] FCM token registered');
      }

      // Listen for token refresh
      messaging().onTokenRefresh(async (newToken) => {
        if (registerFn) await registerFn(newToken);
      });

      // Handle background FCM messages (when app is in background/quit)
      messaging().setBackgroundMessageHandler(async (remoteMessage) => {
        await _showRemoteNotification(remoteMessage);
      });

      // Handle foreground FCM messages
      messaging().onMessage(async (remoteMessage) => {
        await _showRemoteNotification(remoteMessage);
      });
    } catch (e) {
      console.warn('[NotificationService] FCM registration error:', e?.message);
    }
  },

  /**
   * Show a local notification for a new room message.
   * @param {{ roomId: string|number, roomName: string, author: string, text: string }} msg
   */
  async showRoomMessage({ roomId, roomName, author, text }) {
    if (!notifee) { console.warn('[NotificationService] showRoomMessage: notifee not available'); return; }
    if (!_channelId) { console.warn('[NotificationService] showRoomMessage: channelId not set — setup() not called?'); return; }
    try {
      await notifee.displayNotification({
        id: `room_${roomId}`,  // Replace previous notification for this room
        title: `${roomName}`,
        body: `${author}: ${text}`,
        android: {
          channelId: _channelId,
          smallIcon: 'ic_notification',
          pressAction: { id: 'default' },
          groupId: 'rooms',
          // Hide content on lock screen — E2EE messages must not be visible without unlock
          visibility: AndroidVisibility?.PRIVATE ?? 0,
        },
        data: { screen: 'Chat', roomId: String(roomId), roomName },
      });
    } catch (_e) { /* ignore */ }
  },

  /**
   * Show a local notification for a new DM.
   * @param {{ threadId: string|number, peer: string, text: string }} msg
   */
  async showDmMessage({ threadId, peer, text }) {
    if (!notifee) { console.warn('[NotificationService] showDmMessage: notifee not available'); return; }
    if (!_channelId) { console.warn('[NotificationService] showDmMessage: channelId not set'); return; }
    try {
      console.log('[NotificationService] displayNotification DM, channelId:', _channelId, 'peer:', peer);
      await notifee.displayNotification({
        id: `dm_${threadId}`,
        title: peer,
        body: text,
        android: {
          channelId: _channelId,
          smallIcon: 'ic_notification',
          pressAction: { id: 'default' },
          color: '#8b5cf6',
          groupId: 'dms',
          visibility: AndroidVisibility?.PRIVATE ?? 0,
        },
        data: { screen: 'DMChat', threadId: String(threadId), peer },
      });
      console.log('[NotificationService] displayNotification DM OK');
    } catch (e) {
      console.warn('[NotificationService] displayNotification DM error:', e?.message, e?.code);
    }
  },

  /**
   * Show a local notification for a friend request.
   */
  async showFriendRequest({ from }) {
    if (!notifee || !_channelId) return;
    try {
      await notifee.displayNotification({
        id: `friend_req_${from}`,
        title: 'Friend Request',
        body: `${from} wants to be your friend`,
        android: {
          channelId: _channelId,
          smallIcon: 'ic_notification',
          pressAction: { id: 'default' },
          groupId: 'social',
        },
        data: { screen: 'Invites' },
      });
    } catch (_e) { /* ignore */ }
  },

  /**
   * Show a local notification for a room invite.
   */
  async showRoomInvite({ roomName, from }) {
    if (!notifee || !_channelId) return;
    try {
      await notifee.displayNotification({
        id: `room_invite_${roomName}`,
        title: 'Room Invite',
        body: `${from} invited you to "${roomName}"`,
        android: {
          channelId: _channelId,
          smallIcon: 'ic_notification',
          pressAction: { id: 'default' },
          groupId: 'social',
        },
        data: { screen: 'Invites' },
      });
    } catch (_e) { /* ignore */ }
  },

  /**
   * Cancel all notifications (e.g., after user opens the app).
   */
  async cancelAll() {
    if (!notifee) return;
    try { await notifee.cancelAllNotifications(); } catch (_e) { /* ignore */ }
  },

  /**
   * Cancel notifications for a specific room (user opened the chat).
   */
  async cancelRoom(roomId) {
    if (!notifee) return;
    try { await notifee.cancelNotification(`room_${roomId}`); } catch (_e) { /* ignore */ }
  },

  /**
   * Cancel notifications for a specific DM thread.
   */
  async cancelDm(threadId) {
    if (!notifee) return;
    try { await notifee.cancelNotification(`dm_${threadId}`); } catch (_e) { /* ignore */ }
  },
};

// ---- Internal helpers ----

function _handleNotificationPress(notification) {
  if (!notification?.data || !_onNotificationTap) return;
  const { screen, roomId, threadId, roomName, peer } = notification.data;
  if (screen === 'Chat' && roomId) {
    _onNotificationTap({ screen: 'Chat', params: { roomId, roomName } });
  } else if (screen === 'DMChat' && threadId) {
    _onNotificationTap({ screen: 'DMChat', params: { threadId, peer } });
  } else if (screen === 'Invites') {
    _onNotificationTap({ screen: 'Invites', params: {} });
  }
}

async function _showRemoteNotification(remoteMessage) {
  if (!notifee || !_channelId) return;
  try {
    const { notification, data } = remoteMessage;
    if (!notification) return;
    await notifee.displayNotification({
      title: notification.title || 'New message',
      body: notification.body || '',
      android: { channelId: _channelId, smallIcon: 'ic_notification' },
      data: data || {},
    });
  } catch (_e) { /* ignore */ }
}

export default NotificationService;
