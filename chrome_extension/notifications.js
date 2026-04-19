// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// notifications.js
// Centralized "notification" fetch + badge helpers for panel UI.
// Kept framework-free (plain <script>) for MV3 extension pages.

(function () {
  if (window.Notifications) return;

  /** @type {(msg:any)=>void|null} */
  let _safePost = null;

  function _byId(id) {
    return document.getElementById(id);
  }

  function init({ safePost } = {}) {
    _safePost = safePost || window.safePost || null;
  }

  // === Badges ===
  function setFriendsInvitesBadge(count) {
    const friendsBadgeEl = _byId("friendsBadge");
    if (!friendsBadgeEl) return;

    const n = Number(count) || 0;
    if (n <= 0) {
      friendsBadgeEl.style.display = "none";
      friendsBadgeEl.textContent = "";
      return;
    }

    // "dot" badge (no text) — matches current UI behavior
    friendsBadgeEl.style.display = "inline-flex";
    friendsBadgeEl.textContent = "";
  }

  function setRoomReqBadge(count) {
    const roomReqBadgeEl = _byId("roomReqBadge");
    if (!roomReqBadgeEl) return;

    const n = Number(count) || 0;
    if (n <= 0) {
      roomReqBadgeEl.style.display = "none";
      roomReqBadgeEl.textContent = "";
      return;
    }

    roomReqBadgeEl.style.display = "inline-flex";
    roomReqBadgeEl.textContent = String(n);
  }

  // === Fetch triggers ===
  function requestFriendsAll() {
    if (!_safePost) return;
    _safePost({ type: "friends_requests_incoming" });
    _safePost({ type: "friends_requests_outgoing" });
    _safePost({ type: "friends_list" });
  }

  function requestGroupInvites() {
    if (!_safePost) return;
    _safePost({ type: "rooms_invites_incoming" });
  }

  function refreshRoomJoinRequestsAll() {
    if (!_safePost) return;
    _safePost({ type: "rooms_join_requests_all" });
  }

  // === Lifecycle ===
  function afterLogin() {
    // Load notifications immediately after login (before opening drawers / explicit presence).
    requestFriendsAll();
    requestGroupInvites();
    refreshRoomJoinRequestsAll();
    // Unread dots for DM/Rooms (computed client-side from lastSeen vs last_message_at)
    try { window.__refreshUnreadFromServer?.(); } catch {}
  }

  function afterLogout() {
    setFriendsInvitesBadge(0);
    setRoomReqBadge(0);
  }

  window.Notifications = {
    init,
    afterLogin,
    afterLogout,
    // exposed so panel.js handlers can reuse the same rendering logic
    setFriendsInvitesBadge,
    setRoomReqBadge,
    requestFriendsAll,
    requestGroupInvites,
    refreshRoomJoinRequestsAll,
  };
})();
