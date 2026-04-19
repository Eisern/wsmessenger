// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// ===== panel-ui.js =====
// UI: chat search, profile, unread, rooms, friends, recent

// ===== SVG sanitizer (security: prevent XSS via server-supplied SVG) =====
/**
 * Parse an SVG string via DOMParser and strip all dangerous content:
 *  - <script>, <foreignObject>, <iframe>, <object>, <embed>, <use> with external href
 *  - All on* event-handler attributes (onclick, onload, onerror, …)
 *  - href/xlink:href with javascript: or data: URIs
 *  - <style> elements (can exfiltrate data via CSS)
 *  - <animate>/<set> that target event-handler attributes
 * Returns a sanitized SVGSVGElement or null on failure.
 */
function __sanitizeSvg(rawSvgString) {
  try {
    const str = String(rawSvgString || "").trim();
    if (!str) return null;

    const parser = new DOMParser();
    const doc = parser.parseFromString(str, "image/svg+xml");

    // DOMParser returns an error document if parsing fails
    const parseErr = doc.querySelector("parsererror");
    if (parseErr) return null;

    const svg = doc.querySelector("svg");
    if (!svg) return null;

    // Dangerous elements to remove entirely
    const DANGEROUS_TAGS = [
      "script", "foreignObject", "iframe", "object", "embed",
      "style", "link", "meta", "base", "use", "image",
    ];

    for (const tag of DANGEROUS_TAGS) {
      const els = svg.querySelectorAll(tag);
      for (const el of els) el.remove();
    }

    // Walk ALL elements, strip dangerous attributes
    const all = svg.querySelectorAll("*");
    for (const el of all) {
      const attrs = [...el.attributes];
      for (const attr of attrs) {
        const name = attr.name.toLowerCase();

        // Remove all event handlers (on*)
        if (name.startsWith("on")) {
          el.removeAttribute(attr.name);
          continue;
        }

        // Remove javascript:/data: in href and xlink:href
        if (name === "href" || name === "xlink:href") {
          const val = (attr.value || "").trim().toLowerCase();
          if (val.startsWith("javascript:") || val.startsWith("data:")) {
            el.removeAttribute(attr.name);
          }
          continue;
        }

        // Remove set/animate targeting event handlers
        if (name === "attributename") {
          const val = (attr.value || "").trim().toLowerCase();
          if (val.startsWith("on")) {
            el.remove();
            break; // element removed, skip remaining attrs
          }
        }
      }
    }

    // Adopt into current document so it can be appended
    return document.adoptNode(svg);
  } catch (e) {
    console.warn("SVG sanitization failed:", e);
    return null;
  }
}

// ===== In-chat search (local, E2EE-safe) =====
// IMPORTANT: messages are stored on server as ciphertext (E2EE), so server-side substring search will return 0 matches.
// So we search locally inside already-rendered decrypted messages.
function searchInRenderedChat(queryRaw) {
  const q = (queryRaw || "").trim();
  if (!q) return [];

  const ql = q.toLowerCase();
  const out = [];

  const texts = chat?.querySelectorAll?.(".msg-text") || [];
  for (const el of texts) {
    const t = (el.textContent || "");
    if (!t.toLowerCase().includes(ql)) continue;

    // find last author header above this message
    let author = "";
    let p = el;
    while (p && p !== chat) {
      p = p.previousElementSibling;
      if (!p) break;
      if (p.classList?.contains("msg-author")) {
        author = (p.textContent || "").trim();
        break;
      }
    }

    out.push({ author, text: t, el });
  }
  return out;
}

function renderSearchResultsBlock(kindLabel, idLabel, queryRaw, results) {
  const q = (queryRaw || "").trim();
  const header = `------------ ${kindLabel} ${idLabel} search: "${q}" (${results.length}) ------------`;
  addMsg("", header, false, Date.now());

  if (!results.length) {
    addMsg("", "`------------ end ------------`", false, Date.now());
    return;
  }

  // Make each result clickable -> scroll to the message
  for (const r of results.slice(0, 50)) {
    const line = document.createElement("div");
    line.className = "msg";
    line.style.cursor = "pointer";
    line.style.opacity = "0.95";
    line.title = "Click to jump to message";

    const who = (r.author || "").trim();
    const prefix = who ? `${who}: ` : "";
    const textSpan = document.createElement("span");
    textSpan.className = "msg-text";
    textSpan.textContent = prefix + r.text;
    line.appendChild(textSpan);

    line.onclick = () => {
      try { r.el?.scrollIntoView({ behavior: "smooth", block: "center" }); } catch {}
      try { r.el?.classList?.add("flash"); setTimeout(() => r.el?.classList?.remove("flash"), 600); } catch {}
    };

    chat.appendChild(line);
  }

  addMsg("", "`------------ end ------------`", false, Date.now());
  chat.scrollTop = chat.scrollHeight;
}

// ===== Chat search UI (local, E2EE-safe) =====
let __chatSearchOpen = false;
let __chatSearchLastQuery = "";
let __chatSearchHits = [];   // [{author,text,el}]
let __chatSearchIdx = -1;

function ensureChatSearchStyles() {
  // styles moved to panel.css
}

function getChatSearchEls() {
  const shell = document.querySelector(".chat-search-shell");
  const handle = document.getElementById("chatSearchHandle");
  const panel = document.getElementById("chatSearchPanel");
  const input = document.getElementById("chatSearchInput");
  const prev = document.getElementById("chatSearchPrev");
  const next = document.getElementById("chatSearchNext");
  const close = document.getElementById("chatSearchClose");
  const meta = document.getElementById("chatSearchMeta");
  const actions = panel ? panel.querySelector(".chat-search-actions") : null;
  return { shell, actions, handle, panel, input, prev, next, close, meta };
}

function applyChatSearchHighlights() {
  clearChatSearchHighlights();

  for (const h of __chatSearchHits) {
    try {
      const el = h?.el;
      const box = el?.closest?.(".msg") || el?.closest?.(".msg-row") || el?.closest?.(".msg-item") || el;
      box?.classList?.add("search-hit");
    } catch {}
  }

  if (__chatSearchIdx >= 0 && __chatSearchIdx < __chatSearchHits.length) {
    try {
      const el = __chatSearchHits[__chatSearchIdx]?.el;
      const box = el?.closest?.(".msg") || el?.closest?.(".msg-row") || el?.closest?.(".msg-item") || el;
      box?.classList?.add("search-hit-active");
    } catch {}
  }
}

function clearChatSearchHighlights() {
  try {
    const hits = chat?.querySelectorAll?.(".msg.search-hit, .msg.search-hit-active") || [];
    for (const el of hits) el.classList.remove("search-hit", "search-hit-active");
  } catch {}
}

function scrollToChatSearchActive() {
  if (__chatSearchIdx < 0 || __chatSearchIdx >= __chatSearchHits.length) return;
  const el = __chatSearchHits[__chatSearchIdx].el;
  try { el?.scrollIntoView({ behavior: "smooth", block: "center" }); } catch {}
}

function updateChatSearchMeta() {
  const { meta } = getChatSearchEls();
  if (!meta) return;
  const total = __chatSearchHits.length;
  if (!__chatSearchLastQuery) { meta.textContent = ""; return; }
  if (!total) { meta.textContent = `0 matches`; return; }
  meta.textContent = `${__chatSearchIdx + 1}/${total}`;
}

function runChatSearch(qRaw) {
  const q = (qRaw || "").trim();
  __chatSearchLastQuery = q;
  __chatSearchHits = q ? searchInRenderedChat(q) : [];
  __chatSearchIdx = __chatSearchHits.length ? 0 : -1;
  applyChatSearchHighlights();
  updateChatSearchMeta();
  scrollToChatSearchActive();
}

function stepChatSearch(dir) {
  const total = __chatSearchHits.length;
  if (!total) return;
  __chatSearchIdx = (__chatSearchIdx + dir + total) % total;
  applyChatSearchHighlights();
  updateChatSearchMeta();
  scrollToChatSearchActive();
}

let __searchRunnerInited = false;

function openChatSearchUI(focus=true) {

  const { handle, panel, input, actions, shell } = getChatSearchEls();
  if (!handle || !panel) return;

  // init hover-runner exactly once (when DOM is guaranteed to exist)
  if (!__searchRunnerInited) {
    __searchRunnerInited = true;
    initSearchHoverRunner();
  }

  __chatSearchOpen = true;

  shell?.classList.add("search-open");

  handle.classList.add("open");
  panel.classList.add("open");
  panel.setAttribute("aria-hidden", "false");

  if (focus) {
    try { input?.focus(); input?.select?.(); } catch {}
  }
}

function closeChatSearchUI() {
  const { handle, panel, shell } = getChatSearchEls();
  __chatSearchOpen = false;

  shell?.classList?.remove("search-open");   // NEW

  handle?.classList?.remove("open");
  panel?.classList?.remove("open");
  panel?.setAttribute?.("aria-hidden", "true");

  __chatSearchLastQuery = "";
  __chatSearchHits = [];
  __chatSearchIdx = -1;
  clearChatSearchHighlights();
  updateChatSearchMeta();
}

function toggleChatSearchUI() {
  if (__chatSearchOpen) closeChatSearchUI();
  else openChatSearchUI(true);
}

function bindChatSearchUIOnce() {
  ensureChatSearchStyles();
  const { handle, input, prev, next, close } = getChatSearchEls();
  if (!handle || handle.__bound) return;
  handle.__bound = true;

  handle.addEventListener("click", (e) => { e.preventDefault(); toggleChatSearchUI(); });
  handle.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggleChatSearchUI(); }
  });

  input?.addEventListener?.("input", () => runChatSearch(input.value || ""));
  input?.addEventListener?.("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); stepChatSearch(1); }
    if (e.key === "Escape") { e.preventDefault(); closeChatSearchUI(); }
  });

  prev?.addEventListener?.("click", () => stepChatSearch(-1));
  next?.addEventListener?.("click", () => stepChatSearch(1));
  close?.addEventListener?.("click", () => closeChatSearchUI());
}

// Ctrl/Cmd + Shift + F opens search drawer
document.addEventListener("keydown", (e) => {
  const key = (e.key || "").toLowerCase();
  const isFind = (key === "f") && (e.ctrlKey || e.metaKey) && e.shiftKey;
  if (!isFind) return;

  // Avoid interfering with typing in inputs/textarea (except our search input)
  const tag = (e.target && e.target.tagName) ? String(e.target.tagName).toLowerCase() : "";
  const id = (e.target && e.target.id) ? String(e.target.id) : "";
  if ((tag === "input" || tag === "textarea") && id !== "chatSearchInput") return;

  e.preventDefault();
  e.stopPropagation();
  bindChatSearchUIOnce();
  openChatSearchUI(true);
});

setTimeout(bindChatSearchUIOnce, 0);

// Esc closes search drawer if open
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && __chatSearchOpen) {
    closeChatSearchUI();
  }
});

let lastRoomJoinRequestsAll = []; // [{room_id, room_name, room_alias, username}]

// ----- Profile drawer (public + me) -----
let profileBtn = document.getElementById("profileBtn");
let profileDrawer = document.getElementById("profileDrawer");
let profileBackdrop = document.getElementById("profileBackdrop");
let profileTitleEl, profileUsernameEl, profileAboutEl, profilePrivacySectionEl,
    profileAllowInvitesEl, profileAllowDmEl, profileSaveBtn, profileRefreshBtn,
    profileMessageBtn, profileMeActionsEl, profilePublicActionsEl, profileStatusEl, closeProfileBtn;
let __profileOpen = false;
let __profileMode = "me";
let __profileTarget = "";
let __profileMeCache = null


function __hasProfileTabsUI() {
  return !!(
    document.getElementById("settingsTabProfile") &&
    document.getElementById("settingsPaneProfile") &&
    document.getElementById("settingsTabSecurity") &&
    document.getElementById("settingsPaneSecurity")
  );
}

function ensureProfileStyles() {
  if (document.getElementById("profileDrawerStyles")) return;
  const st = document.createElement("style");
  st.id = "profileDrawerStyles";
  st.textContent = `
#profileBackdrop{ position:fixed; inset:0; background:rgba(0,0,0,.25); display:none; z-index:9998; }
#profileBackdrop.open{ display:block; }
#profileDrawer{ position:fixed; left:0; right:0; bottom:0; max-height:75vh; background:#161b22; border-top:1px solid #ddd; box-shadow:0 -12px 40px rgba(0,0,0,.2); transform: translateY(110%); transition: transform 180ms ease; z-index:9999; padding:12px; overflow:auto; }
#profileDrawer.open{ transform: translateY(0); }
.profile-head{ display:flex; align-items:center; gap:10px; }
.profile-head .spacer{ flex:1; }
.profile-title{ font-weight:600; }
.profile-username{ font-size:15px; font-weight:600; word-break:break-word; }
.profile-about{ width:100%; box-sizing:border-box; min-height:70px; resize:vertical; padding:8px; font-family:inherit; font-size:13px; color: var(--text-main) }
.profile-section{ margin-top:10px; }
.profile-section h4{ margin:8px 0 6px; font-size:12px; text-transform:uppercase; opacity:.7; letter-spacing:.04em; }
.profile-row{ display:flex; align-items:center; gap:8px; padding:8px 0; border-bottom:1px solid #eee; }
.profile-row:last-child{ border-bottom:none; }
.profile-actions{ display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }
.profile-hint{ opacity:.7; font-size:12px; line-height:1.3; margin-top:6px; }
.profile-status{ margin-top:10px; font-size:12px; opacity:.8; white-space:pre-wrap; }
`;
  document.head.appendChild(st);
}

function ensureProfileUI() {
  ensureProfileStyles();
  const hasTabs = __hasProfileTabsUI();

  if (!hasTabs && !profileBtn && friendsBtn && friendsBtn.parentElement) {
    profileBtn = document.createElement("button");
    profileBtn.id = "profileBtn";
    profileBtn.className = friendsBtn.className || "invite-btn";
    profileBtn.type = "button";
    profileBtn.title = "Profile";
    profileBtn.textContent = "Profile";

    friendsBtn.parentElement.insertBefore(profileBtn, friendsBtn.nextSibling);
  }

  if (!profileBackdrop) {
    profileBackdrop = document.createElement("div");
    profileBackdrop.id = "profileBackdrop";
    profileBackdrop.setAttribute("aria-hidden", "true");
    document.body.appendChild(profileBackdrop);
  }
   
  const existingDrawer = document.getElementById("profileDrawer");
  const needsUpdate = existingDrawer && (!existingDrawer.querySelector("#profileDeleteAccount") || !existingDrawer.querySelector("#profileAbout") || !existingDrawer.querySelector("#profileSave"));
  
  if (!profileDrawer || needsUpdate) {
    
    if (needsUpdate && existingDrawer) {
      existingDrawer.remove();
      profileDrawer = null;
    }
    
    profileDrawer = document.createElement("div");
    profileDrawer.id = "profileDrawer";
    profileDrawer.setAttribute("aria-hidden", "true");
    const __twofaHtml = hasTabs ? "" : `
<div class="profile-section" id="profile2faSection">
        <h4 style="margin-top:16px;">&#128274; Two-Factor Authentication</h4>
        <div id="twofa-status-area" style="font-size:13px; margin-bottom:8px;">
          <span id="twofa-status-text" style="opacity:0.7;">Checking...</span>
        </div>
        <div id="twofa-actions">
          <button id="twofa-enable-btn" type="button" style="display:none; background:#28a745; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Enable 2FA</button>
          <button id="twofa-disable-btn" type="button" style="display:none; background:#dc3545; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Disable 2FA</button>
        </div>
        <div id="twofa-setup-area" style="display:none; margin-top:12px; text-align:center;">
          <p style="font-size:12px; opacity:0.7; margin:0 0 8px;">Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
          <div id="twofa-qr" style="margin:8px auto; display:inline-block; background:white; padding:8px; border-radius:8px;"></div>
          <div id="twofa-secret-row" style="margin:8px 0; font-size:11px;">
            <span style="opacity:0.6;">Manual key: </span>
            <code id="twofa-secret" style="user-select:all; letter-spacing:2px; font-size:12px;"></code>
          </div>
          <input id="twofa-setup-code" type="text" inputmode="numeric" maxlength="6" placeholder="Enter 6-digit code"
            style="font-size:16px; letter-spacing:4px; text-align:center; width:160px; padding:8px;
                   border:1px solid rgba(255,255,255,0.2); border-radius:6px; background:rgba(255,255,255,0.05);
                   color:inherit; outline:none; font-family:monospace;" />
          <div id="twofa-setup-err" style="color:#dc3545; font-size:12px; min-height:16px; margin-top:4px;"></div>
          <div style="margin-top:6px; display:flex; gap:6px; justify-content:center;">
            <button id="twofa-confirm-btn" type="button" style="background:#28a745; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Confirm</button>
            <button id="twofa-cancel-btn" type="button" style="background:#6c757d; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Cancel</button>
          </div>
        </div>
        <div id="twofa-backup-area" style="display:none; margin-top:12px; text-align:center;">
          <p style="font-size:13px; color:#28a745; margin:0 0 8px;">&#10004; 2FA enabled successfully!</p>
          <div id="twofa-backup-codes" style="display:none;">
            <p style="font-size:12px; opacity:0.7; margin:0 0 6px;">Save these backup codes in a safe place:</p>
            <div id="twofa-codes-list" style="font-family:monospace; font-size:13px; background:rgba(255,255,255,0.05); padding:8px; border-radius:6px; user-select:all;"></div>
          </div>
          <button id="twofa-backup-done" type="button" style="margin-top:8px; background:#007bff; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Done</button>
        </div>
        <div id="twofa-disable-area" style="display:none; margin-top:12px;">
          <p style="font-size:12px; opacity:0.7; margin:0 0 8px;">Enter your TOTP code or password to disable 2FA:</p>
          <input id="twofa-disable-code" type="text" inputmode="numeric" maxlength="6" placeholder="TOTP code"
            style="font-size:14px; letter-spacing:2px; text-align:center; width:140px; padding:6px;
                   border:1px solid rgba(255,255,255,0.2); border-radius:6px; background:rgba(255,255,255,0.05);
                   color:inherit; outline:none; font-family:monospace;" />
          <div id="twofa-disable-err" style="color:#dc3545; font-size:12px; min-height:16px; margin-top:4px;"></div>
          <div style="margin-top:6px; display:flex; gap:6px; justify-content:center;">
            <button id="twofa-disable-confirm" type="button" style="background:#dc3545; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Disable</button>
            <button id="twofa-disable-cancel" type="button" style="background:#6c757d; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Cancel</button>
          </div>
        </div>
        <div class="profile-hint" style="margin-top:8px;">Adds an extra layer of security to your account.</div>
      </div>
      `;
    profileDrawer.innerHTML = `
      <div class="profile-head">
        <div class="profile-title" id="profileTitle">Profile</div>
        <div class="spacer"></div>
        <button id="closeProfile" type="button" class="drawer-close">Close</button>
      </div>

      <div class="profile-section">
        <div class="profile-hint">User</div>
        <div class="profile-username" id="profileUsername">-</div>
      </div>

      <div class="profile-section">
        <h4>About</h4>
        <textarea id="profileAbout" class="profile-about" rows="3" maxlength="360" placeholder="2-3 lines about you"></textarea>
        <div class="profile-hint" id="profileAboutHint">Visible to other users.</div>
      </div>

      <div class="profile-section" id="profilePrivacySection">
        <h4>Privacy</h4>
        <label class="profile-row"><input id="profileAllowInvites" type="checkbox"> <span>Allow group invites from non-friends</span></label>
        <label class="profile-row"><input id="profileAllowDm" type="checkbox"> <span>Allow DMs from non-friends</span></label>
        <div class="profile-hint">Privacy settings are visible only to you.</div>
      </div>

      <div class="profile-actions" id="profileMeActions">
        <button id="profileSave" type="button">Save</button>
        <button id="profileRefresh" type="button">Refresh</button>
      </div>

            ${__twofaHtml}


      <div class="profile-danger-zone" id="profileDangerZone">
        <h4 style="color: #dc3545; margin-top: 16px;">Danger Zone</h4>
        <button id="profileDeleteAccount" type="button" style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Delete Account</button>
        <div class="profile-hint" style="color: #dc3545;">This action cannot be undone!</div>
      </div>

       <div class="profile-actions" id="profilePublicActions" style="display:none;">
         <button id="profileMessage" type="button">Message</button>
         <button id="profileReport" type="button" style="background:#dc2626;color:#fff;">Report</button>
         <button id="profileClose2" type="button">Close</button>
       </div>

      <div class="profile-section" id="profileSafetySection" style="display:none;">
        <h4>Safety Number</h4>
        <div id="profileKeyWarning" style="display:none; background:#dc354520; border:1px solid #dc3545; border-radius:6px; padding:8px 10px; margin-bottom:8px; font-size:12px; color:#dc3545; line-height:1.4;">
          WARNING! <strong>Key changed!</strong> This user's encryption key is different from what you saw before. Verify in person or via another channel before sending sensitive messages.
        </div>
        <div id="profileSafetyNumber" style="font-family:monospace; font-size:15px; letter-spacing:1px; line-height:1.8; word-break:break-word; user-select:all; padding:8px; background:rgba(255,255,255,.05); border-radius:6px; text-align:center; min-height:40px;"></div>
        <div class="profile-hint" style="margin-top:6px; line-height:1.4;">
          Compare this number with your contact in person or via a trusted channel. If the numbers match, the connection is secure.
        </div>
        <div class="profile-actions" style="margin-top:8px; gap:6px;">
          <button id="profileVerifyKeyBtn" type="button" style="font-size:12px;">I verified this</button>
          <button id="profileCopySafetyBtn" type="button" style="font-size:12px;">Copy number</button>
        </div>
        <div id="profileVerifyStatus" style="font-size:12px; margin-top:4px; opacity:.8;"></div>
      </div>

      <div class="profile-status" id="profileStatus"></div>
    `;
    document.body.appendChild(profileDrawer);
  }

  profileTitleEl = document.getElementById("profileTitle");
  profileUsernameEl = document.getElementById("profileUsername");
  profileAboutEl = document.getElementById("profileAbout");
  profilePrivacySectionEl = document.getElementById("profilePrivacySection");
  profileAllowInvitesEl = document.getElementById("profileAllowInvites");
  profileAllowDmEl = document.getElementById("profileAllowDm");
  profileSaveBtn = document.getElementById("profileSave");
  profileRefreshBtn = document.getElementById("profileRefresh");
  profileMessageBtn = document.getElementById("profileMessage");
  profileMeActionsEl = document.getElementById("profileMeActions");
  profilePublicActionsEl = document.getElementById("profilePublicActions");
  profileStatusEl = document.getElementById("profileStatus");
  closeProfileBtn = document.getElementById("closeProfile");
  const close2 = document.getElementById("profileClose2");

  if (profileBtn) profileBtn.onclick = () => {

    const el = __inlineEls();
    if (el.username || el.about) openProfileMeInline(true);
    else openProfileMe(true);
  };
  if (closeProfileBtn) closeProfileBtn.onclick = closeProfile;
  if (close2) close2.onclick = closeProfile;
  const reportBtn = document.getElementById("profileReport");
  if (reportBtn) reportBtn.onclick = () => {
    if (__profileTarget && __profileMode !== "me") reportUser(__profileTarget);
  };
  if (profileBackdrop) profileBackdrop.onclick = closeProfile;

  if (!window.__profileEscBound) {
    window.__profileEscBound = true;
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!profileDrawer?.classList.contains("open")) return;
      closeProfile();
    });
  }

  if (profileRefreshBtn) profileRefreshBtn.onclick = () => {
    if (__profileMode === "me") openProfileMe(true);
    else if (__profileTarget) openProfilePublic(__profileTarget, true);
  };
  if (profileSaveBtn) profileSaveBtn.onclick = saveProfileMe;

  // Delete Account button
  const deleteAccountBtn = document.getElementById("profileDeleteAccount");
  if (deleteAccountBtn) {
    deleteAccountBtn.onclick = handleDeleteAccount;
  }


  // Tabs UI present: ensure 2FA is mounted ONLY in Security tab
  if (hasTabs) {
    try { ensureInline2faSection(); } catch {}
    try { ensureCryptoAutolockSection(); } catch {}
    try { ensureChangePasswordSection(); } catch {}
    try { ensureRecoverySection(); } catch {}
  }
  // 2FA init will run when UI is present (ensureInline2faSection triggers it).
}

function init2faSettings() {
  const statusText = document.getElementById("twofa-status-text");
  if (!statusText) return; // UI not present yet

  if (window.__2faInitDone) {
    // Already initialized — just refresh status
    try { safePost({ type: "totp_status" }); } catch {}
    return;
  }
  window.__2faInitDone = true;

  const enableBtn = document.getElementById("twofa-enable-btn");
  const disableBtn = document.getElementById("twofa-disable-btn");
  const setupArea = document.getElementById("twofa-setup-area");
  const backupArea = document.getElementById("twofa-backup-area");
  const disableArea = document.getElementById("twofa-disable-area");


  let _2faEnabled = false;

  // --- RPC listener for 2FA messages ---
  function on2faMsg(msg) {
    if (!msg || !msg.type) return;

    if (msg.type === "totp_status") {
      _2faEnabled = !!msg.enabled;
      statusText.textContent = _2faEnabled ? "Enabled" : "Not enabled";
      statusText.style.color = _2faEnabled ? "#28a745" : "";
      if (enableBtn) enableBtn.style.display = _2faEnabled ? "none" : "";
      if (disableBtn) disableBtn.style.display = _2faEnabled ? "" : "none";
    }

    if (msg.type === "totp_status_error") {
      statusText.textContent = "Could not check status";
    }

    if (msg.type === "totp_setup_data") {
      if (setupArea) setupArea.style.display = "";
      const qrEl = document.getElementById("twofa-qr");
      const secretEl = document.getElementById("twofa-secret");

      if (msg.qr_svg && qrEl) {
        // ── Sanitize SVG to prevent XSS ──────────────────────
        // Server SVG could contain <script>, event handlers, or
        // <foreignObject> if server is compromised / MITM.
        const safeSvg = __sanitizeSvg(String(msg.qr_svg));
        qrEl.textContent = ""; // clear previous
        if (safeSvg) {
          qrEl.appendChild(safeSvg);
        } else {
          // SVG failed sanitization — fall back to manual entry
          const fallback = document.createElement("div");
          fallback.style.cssText = "padding:12px; color:#333; font-size:13px;";
          fallback.textContent = "QR code unavailable. Enter the key manually in your authenticator app.";
          qrEl.appendChild(fallback);
        }
      } else if (qrEl) {
        // No server-side QR available — show manual entry prompt
        qrEl.textContent = "";
        const fallback = document.createElement("div");
        fallback.style.cssText = "padding:12px; color:#333; font-size:13px;";
        fallback.textContent = "Enter the key manually in your authenticator app";
        qrEl.appendChild(fallback);
      }
      if (secretEl) secretEl.textContent = (msg.secret || "").replace(/(.{4})/g, "$1 ").trim();
    }

    if (msg.type === "totp_setup_complete") {
      if (setupArea) setupArea.style.display = "none";
      if (backupArea) backupArea.style.display = "";

      const codesList = document.getElementById("twofa-codes-list");
      const codesContainer = document.getElementById("twofa-backup-codes");
      if (msg.backup_codes && msg.backup_codes.length && codesList) {
        codesContainer.style.display = "";
        codesList.textContent = msg.backup_codes.join("\n");
      }

      _2faEnabled = true;
      statusText.textContent = "Enabled";
      statusText.style.color = "#28a745";
      if (enableBtn) enableBtn.style.display = "none";
      if (disableBtn) disableBtn.style.display = "";
    }

    if (msg.type === "totp_setup_error") {
      const errEl = document.getElementById("twofa-setup-err");
      if (errEl) errEl.textContent = msg.message || "Setup failed";
      const btn = document.getElementById("twofa-confirm-btn");
      if (btn) btn.disabled = false;
    }

    if (msg.type === "totp_disabled") {
      _2faEnabled = false;
      statusText.textContent = "Not enabled";
      statusText.style.color = "";
      if (enableBtn) enableBtn.style.display = "";
      if (disableBtn) disableBtn.style.display = "none";
      if (disableArea) disableArea.style.display = "none";
    }

    if (msg.type === "totp_disable_error") {
      const errEl = document.getElementById("twofa-disable-err");
      if (errEl) errEl.textContent = msg.message || "Failed to disable";
      const btn = document.getElementById("twofa-disable-confirm");
      if (btn) btn.disabled = false;
    }
  }

  // Subscribe to RPC messages
  if (typeof rpcOnMessage === "function") {
    rpcOnMessage(on2faMsg);
  }

  // --- Check current 2FA status ---
  safePost({ type: "totp_status" });

  // --- Enable button → initiate setup ---
  if (enableBtn) {
    enableBtn.onclick = () => {
      enableBtn.style.display = "none";
      safePost({ type: "totp_setup" });
    };
  }

  // --- Confirm setup with code ---
  const confirmBtn = document.getElementById("twofa-confirm-btn");
  const setupCodeInput = document.getElementById("twofa-setup-code");
  if (confirmBtn && setupCodeInput) {
    const doConfirm = () => {
      const code = (setupCodeInput.value || "").replace(/\D/g, "");
      const errEl = document.getElementById("twofa-setup-err");
      if (code.length !== 6) {
        if (errEl) errEl.textContent = "Enter a 6-digit code";
        return;
      }
      if (errEl) errEl.textContent = "";
      confirmBtn.disabled = true;
      safePost({ type: "totp_verify_setup", code });
    };
    confirmBtn.onclick = doConfirm;
    setupCodeInput.addEventListener("input", () => {
      setupCodeInput.value = setupCodeInput.value.replace(/\D/g, "").slice(0, 6);
    });
    setupCodeInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") doConfirm();
    });
  }

  // --- Cancel setup ---
  const cancelBtn = document.getElementById("twofa-cancel-btn");
  if (cancelBtn) {
    cancelBtn.onclick = () => {
      if (setupArea) setupArea.style.display = "none";
      if (enableBtn) enableBtn.style.display = _2faEnabled ? "none" : "";
      const qrEl = document.getElementById("twofa-qr");
      if (qrEl) qrEl.textContent = "";
      if (setupCodeInput) setupCodeInput.value = "";
    };
  }

  // --- Backup done ---
  const backupDoneBtn = document.getElementById("twofa-backup-done");
  if (backupDoneBtn) {
    backupDoneBtn.onclick = () => {
      if (backupArea) backupArea.style.display = "none";
    };
  }

  // --- Disable button → show disable area ---
  if (disableBtn) {
    disableBtn.onclick = () => {
      disableBtn.style.display = "none";
      if (disableArea) disableArea.style.display = "";
    };
  }

  // --- Confirm disable ---
  const disableConfirmBtn = document.getElementById("twofa-disable-confirm");
  const disableCodeInput = document.getElementById("twofa-disable-code");
  if (disableConfirmBtn && disableCodeInput) {
    disableConfirmBtn.onclick = () => {
      const code = (disableCodeInput.value || "").replace(/\D/g, "");
      const errEl = document.getElementById("twofa-disable-err");
      if (code.length !== 6) {
        if (errEl) errEl.textContent = "Enter a 6-digit code";
        return;
      }
      if (errEl) errEl.textContent = "";
      disableConfirmBtn.disabled = true;
      safePost({ type: "totp_disable", code });
    };
    disableCodeInput.addEventListener("input", () => {
      disableCodeInput.value = disableCodeInput.value.replace(/\D/g, "").slice(0, 6);
    });
  }

  // --- Cancel disable ---
  const disableCancelBtn = document.getElementById("twofa-disable-cancel");
  if (disableCancelBtn) {
    disableCancelBtn.onclick = () => {
      if (disableArea) disableArea.style.display = "none";
      if (disableBtn) disableBtn.style.display = _2faEnabled ? "" : "none";
      if (disableCodeInput) disableCodeInput.value = "";
    };
  }
}

function getMeUsername() {
  return String(nameInput?.value || "").trim();
}

async function handleDeleteAccount() {
 
  const statusEl = document.getElementById("profileInlineStatus") || profileStatusEl;

  const confirmed1 = confirm(
    "WARNING! DELETE ACCOUNT?\n\n" +
    "This will permanently delete:\n" +
    "WARNING! All your rooms and messages\n" +
    "WARNING! All your DM conversations\n" +
    "WARNING! All your friends and requests\n" +
    "WARNING! All your encryption keys\n" +
    "WARNING! Your account\n\n" +
    "This action CANNOT be undone!\n\n" +
    "Press OK to continue..."
  );
  if (!confirmed1) return;

  const password = (await __ui.prompt(
    "Enter your password to confirm deletion:", {
      title: "Delete account",
      placeholder: "password",
      inputType: "password",
      okText: "Continue",
    }
  ) || "").trim();
  if (!password) {
    try { await __ui.alert("Deletion cancelled."); } catch {}
    return;
  }

  const confirmation = (await __ui.prompt(
    "Type DELETE (in capitals) to confirm:", {
      title: "Final confirmation",
      placeholder: "DELETE",
      okText: "Delete my account",
    }
  ) || "").trim();
  if (confirmation !== "DELETE") {
    try { await __ui.alert("Deletion cancelled. You must type DELETE exactly."); } catch {}
    return;
  }

  if (statusEl) {
    statusEl.textContent = "Deleting account...";
    statusEl.style.color = "#dc3545";
  }

  try {
    await apiJson("/auth/delete-account", {
      method: "POST",
      body: JSON.stringify({
        password: password,
        confirmation: confirmation
      })
    });

    alert("Your account has been deleted. Goodbye!");
    
     safePost({ type: "auth_logout" });
    
    setTimeout(() => {
      window.location.href = "login.html";
    }, 500);

  } catch (e) {
    console.error("Delete account error:", e);
    if (statusEl) {
      statusEl.textContent = "Error: " + (e.message || "Failed to delete account");
      statusEl.style.color = "#dc3545";
    }
    alert("Failed to delete account: " + (e.message || "Unknown error"));
  }
}

async function apiJson(path, opts = {}) {
  const token = await requestToken();
  if (!token) throw new Error("Not logged in");
  const headers = Object.assign({}, opts.headers || {}, {
    "Authorization": "Bearer " + token,
  });

  const hasBody = Object.prototype.hasOwnProperty.call(opts, "body") && opts.body != null;
  if (hasBody && !(opts.body instanceof FormData) && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }
  const r = await fetch(API_BASE + path, Object.assign({}, opts, { headers }));
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = data?.detail || data?.message || `HTTP ${r.status}`;
    throw new Error(msg);
  }
  return data;
}

function openProfileDrawer() {
  ensureProfileUI();
  if (!profileDrawer || !profileBackdrop) return;
  profileDrawer.classList.add("open");
  profileBackdrop.classList.add("open");
  profileDrawer.setAttribute("aria-hidden", "false");
  profileBackdrop.setAttribute("aria-hidden", "false");
  // avoid aria-hidden focus warnings
  try { profileDrawer.inert = false; } catch { profileDrawer.removeAttribute("inert"); }
  document.body.style.overflow = "hidden";
  __profileOpen = true;
  // Refresh 2FA status each time profile opens
  try { safePost({ type: "totp_status" }); } catch {}
}

function closeProfile() {
  if (!profileDrawer || !profileBackdrop) return;
  // if focus is inside, blur to avoid aria-hidden warnings
  try {
    if (profileDrawer.contains(document.activeElement)) document.activeElement.blur();
  } catch {}
  try { profileDrawer.inert = true; } catch { profileDrawer.setAttribute("inert", ""); }
  profileDrawer.classList.remove("open");
  profileBackdrop.classList.remove("open");
  profileDrawer.setAttribute("aria-hidden", "true");
  profileBackdrop.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "auto";
  __profileOpen = false;
  if (profileStatusEl) profileStatusEl.textContent = "";
}

function renderProfileView({ username, about, privacy }, mode) {
  ensureProfileUI();
  __profileMode = mode;
  __profileTarget = username || "";
  if (profileTitleEl) profileTitleEl.textContent = (mode === "me") ? "My profile" : "Profile";
  if (profileUsernameEl) profileUsernameEl.textContent = username || "-";
  if (profileAboutEl) {
    profileAboutEl.value = about || "";
    profileAboutEl.readOnly = (mode !== "me");
  }
  if (profilePrivacySectionEl) profilePrivacySectionEl.style.display = (mode === "me") ? "" : "none";
  if (profileMeActionsEl) profileMeActionsEl.style.display = (mode === "me") ? "" : "none";
  if (profilePublicActionsEl) profilePublicActionsEl.style.display = (mode === "me") ? "none" : "";
  
  // Hide danger zone for non-me profiles
  const dangerZone = document.getElementById("profileDangerZone");
  if (dangerZone) dangerZone.style.display = (mode === "me") ? "" : "none";

  // Safety number section, only for other users' profiles
  const safetySection = document.getElementById("profileSafetySection");
  if (safetySection) {
    safetySection.style.display = (mode === "me") ? "none" : "";
    if (mode !== "me") {
      _loadSafetyNumberUI(username);
    }
  }

  if (mode === "me") {
    const p = privacy || {};
    if (profileAllowInvitesEl) profileAllowInvitesEl.checked = !!p.allow_group_invites_from_non_friends;
    if (profileAllowDmEl) profileAllowDmEl.checked = !!p.allow_dm_from_non_friends;

    setTimeout(() => profileAboutEl?.focus(), 0);
  } else {

    if (profileMessageBtn) {
      profileMessageBtn.onclick = () => {
        const u = String(username || "").trim();
        if (!u) return;
        safePost({ type: "dm_open", username: u });
        closeProfile();
      };
    }
  }
}

/**
 * Load and display safety number for a peer in the profile drawer.
 * Called asynchronously when opening a public profile.
 */
async function _loadSafetyNumberUI(peerUsername) {
  const snEl = document.getElementById("profileSafetyNumber");
  const warnEl = document.getElementById("profileKeyWarning");
  const verifyBtn = document.getElementById("profileVerifyKeyBtn");
  const copyBtn = document.getElementById("profileCopySafetyBtn");
  const statusEl = document.getElementById("profileVerifyStatus");

  if (!snEl) return;

  // Reset state
  snEl.textContent = "Loading...";
  snEl.style.opacity = "0.5";
  if (warnEl) warnEl.style.display = "none";
  if (statusEl) statusEl.textContent = "";
  if (verifyBtn) verifyBtn.style.display = "";

  // Check if crypto is available
  const sn = window.__safetyNumbers;
  if (!sn) {
    snEl.textContent = "Crypto not initialized";
    snEl.style.opacity = "0.5";
    return;
  }

  try {
    const result = await sn.getSafetyNumber(peerUsername);
    snEl.textContent = result.safetyNumber;
    snEl.style.opacity = "1";

    // Key change warning
    if (warnEl) {
      warnEl.style.display = result.keyChanged ? "" : "none";
    }

    // Check verification status
    const verified = await sn.isKeyVerified(peerUsername);

    if (result.keyChanged) {

      if (statusEl) statusEl.textContent = "";
      if (verifyBtn) {
        verifyBtn.textContent = "I verified the new key";
        verifyBtn.style.display = "";
      }
    } else if (verified) {
      if (statusEl) {
        statusEl.textContent = "Verified";
        statusEl.style.color = "#2ea043";
      }
      if (verifyBtn) verifyBtn.style.display = "none";
    } else {
      if (statusEl) statusEl.textContent = "Not yet verified";
      if (verifyBtn) {
        verifyBtn.textContent = "I verified this";
        verifyBtn.style.display = "";
      }
    }

    // Wire up buttons
    if (verifyBtn) {
      verifyBtn.onclick = async () => {
        try {
          await sn.markKeyVerified(peerUsername);
          if (statusEl) {
            statusEl.textContent = "Verified";
            statusEl.style.color = "#2ea043";
          }
          if (warnEl) warnEl.style.display = "none";
          verifyBtn.style.display = "none";
        } catch (e) {
          if (statusEl) statusEl.textContent = "Error: " + (e?.message || e);
        }
      };
    }

    if (copyBtn) {
      copyBtn.onclick = () => {
        try {
          navigator.clipboard.writeText(result.safetyNumber);
          const orig = copyBtn.textContent;
          copyBtn.textContent = "Copied!";
          setTimeout(() => { copyBtn.textContent = orig; }, 1500);
        } catch {
          // Fallback: select the text
          const sel = window.getSelection();
          const range = document.createRange();
          range.selectNodeContents(snEl);
          sel.removeAllRanges();
          sel.addRange(range);
        }
      };
    }

  } catch (e) {
    console.warn("Safety number load failed:", e);
    snEl.textContent = "Unavailable";
    snEl.style.opacity = "0.5";
    if (statusEl) statusEl.textContent = e?.message || "Failed to compute";
  }
}

// ============================
// Key Change Event Listener (Step 5)
// ============================
// When a key change is detected by the proactive check system,
// auto-refresh the safety number panel if it's currently showing that peer.
window.addEventListener("peer_key_changed", (e) => {
  const changedUser = e?.detail?.username;
  if (!changedUser) return;

  // If the profile panel is showing this user's safety number, refresh it
  const profilePanel = document.getElementById("userProfilePanel");
  const profileUsername = document.getElementById("profileUsername");
  if (profilePanel && profileUsername) {
    const shown = !profilePanel.classList.contains("is-hidden") &&
                  !profilePanel.hasAttribute("hidden");
    if (shown && profileUsername.textContent?.trim() === changedUser) {
      // Re-load the safety number with updated "keyChanged" flag
      try { loadSafetyNumber(changedUser); } catch {}
    }
  }
});

// =======================
// Profile (inline panel)
// =======================
function __inlineEls() {
  return {
    refresh: document.getElementById("profileInlineRefresh"),
    save: document.getElementById("profileInlineSave"),
    username: document.getElementById("profileInlineUsername"),
    about: document.getElementById("profileInlineAbout"),
    allowInv: document.getElementById("profileInlineAllowInvites"),
    allowDm: document.getElementById("profileInlineAllowDm"),
    status: document.getElementById("profileInlineStatus"),
  };
}

let __profileAutoLoaded = false;

async function autoLoadProfileIfReady() {
  if (__profileAutoLoaded) return;

  const el = (typeof __inlineEls === "function") ? __inlineEls() : {};
  const hasInlineProfile = !!(el.username || el.about || el.allowInv || el.allowDm);

  if (!hasInlineProfile) return;

  const token = await requestToken().catch(() => "");
  if (!token) return;

  __profileAutoLoaded = true;
  await openProfileMeInline(true).catch(() => {});
}

async function openProfileMeInline(forceReload = false) {
  const el = __inlineEls();
  if (!el.username || !el.about || !el.status) return;

  // 2FA UI is mounted only in Security tab when tabs UI exists
  if (!__hasProfileTabsUI()) ensureInline2faSection();

  el.status.textContent = "Loading...";
  try {
    const data = await apiJson("/profile/me", { method: "GET" });

    el.username.textContent = data.username || "...";
    el.about.value = data.about || "";

    const p = data.privacy || {};
    if (el.allowInv) el.allowInv.checked = !!p.allow_group_invites_from_non_friends;
    if (el.allowDm)  el.allowDm.checked  = !!p.allow_dm_from_non_friends;

    el.status.textContent = "";
    // Refresh 2FA status
    try { safePost({ type: "totp_status" }); } catch {}
  } catch (e) {
    el.status.textContent = "Failed to load: " + (e?.message || e);
    console.warn("openProfileMeInline failed", e);
  }
}

async function saveProfileMeInline() {
  const el = __inlineEls();
  if (!el.about || !el.status) return;

  const about = String(el.about.value || "").slice(0, 360);
  const privacy = {
    allow_group_invites_from_non_friends: !!el.allowInv?.checked,
    allow_dm_from_non_friends: !!el.allowDm?.checked,
  };

  el.status.textContent = "Saving...";
  try {
    const data = await apiJson("/profile/me", {
      method: "PUT",
      body: JSON.stringify({ about, privacy }),
    });

    el.username.textContent = data.username || el.username.textContent || "...";
    el.about.value = data.about || "";
    const p = data.privacy || {};
    if (el.allowInv) el.allowInv.checked = !!p.allow_group_invites_from_non_friends;
    if (el.allowDm)  el.allowDm.checked  = !!p.allow_dm_from_non_friends;

    el.status.textContent = "Saved";
    setTimeout(() => { if (el.status) el.status.textContent = ""; }, 1200);
  } catch (e) {
    el.status.textContent = "Save failed: " + (e?.message || e);
    console.warn("saveProfileMeInline failed", e);
  }
}

// ─── Crypto auto-lock section in Security tab ─────────────────────────────
const CRYPTO_IDLE_LOCK_UI_KEY = "crypto_idle_lock_ms";
const CRYPTO_IDLE_LOCK_UI_DEFAULT_MS = 5 * 60 * 1000;
const CRYPTO_IDLE_LOCK_UI_OPTIONS = [
  { value: 1 * 60 * 1000, label: "1 minute" },
  { value: 5 * 60 * 1000, label: "5 minutes" },
  { value: 15 * 60 * 1000, label: "15 minutes" },
  { value: 30 * 60 * 1000, label: "30 minutes" },
];

(function bindProfileInlineOnce(){
  const el = __inlineEls();

  if (el.refresh && !el.refresh.dataset.bound) {
    el.refresh.dataset.bound = "1";
    el.refresh.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      openProfileMeInline(true);
    });
  }

  if (el.save && !el.save.dataset.bound) {
    el.save.dataset.bound = "1";
    el.save.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      saveProfileMeInline();
    });
  }

  // Delete Account button
  const deleteBtn = document.getElementById("deleteAccountBtn");
  if (deleteBtn && !deleteBtn.dataset.bound) {
    deleteBtn.dataset.bound = "1";
    deleteBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleDeleteAccount();
    });
  }

  // 2FA UI is mounted only in Security tab when tabs UI exists
  // ensureInline2faSection() will mount to Security tab when tabs UI is present, or fall back inline when not.
  ensureInline2faSection();
  try { ensureCryptoAutolockSection(); } catch {}
  try { ensureChangePasswordSection(); } catch {}
  try { ensureRecoverySection(); } catch {}
})();
/**
 * Dynamically inject 2FA settings section into inline profile.
 * Finds an anchor (deleteAccountBtn or profileInlineStatus) and inserts before it.
 */

function build2faSectionDom() {
  const section = document.createElement("div");
  section.id = "inline-2fa-section";
  section.style.cssText = "margin-top:16px; padding:12px; border:1px solid rgba(255,255,255,0.1); border-radius:8px;";
  section.innerHTML = `
    <h4 style="margin:0 0 8px; font-size:14px;">&#128274; Two-Factor Authentication</h4>
    <div id="twofa-status-area" style="font-size:13px; margin-bottom:8px;">
      <span id="twofa-status-text" style="opacity:0.7;">Checking...</span>
    </div>
    <div id="twofa-actions">
      <button id="twofa-enable-btn" type="button" style="display:none; background:#28a745; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Enable 2FA</button>
      <button id="twofa-disable-btn" type="button" style="display:none; background:#dc3545; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Disable 2FA</button>
    </div>
    <div id="twofa-setup-area" style="display:none; margin-top:12px; text-align:center;">
      <p style="font-size:12px; opacity:0.7; margin:0 0 8px;">Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
      <div id="twofa-qr" style="margin:8px auto; display:inline-block; background:white; padding:8px; border-radius:8px;"></div>
      <div id="twofa-secret-row" style="margin:8px 0; font-size:11px;">
        <span style="opacity:0.6;">Manual key: </span>
        <code id="twofa-secret" style="user-select:all; letter-spacing:2px; font-size:12px;"></code>
      </div>
      <input id="twofa-setup-code" type="text" inputmode="numeric" maxlength="6" placeholder="Enter 6-digit code"
        style="font-size:16px; letter-spacing:4px; text-align:center; width:160px; padding:8px;
               border:1px solid rgba(255,255,255,0.2); border-radius:6px; background:rgba(255,255,255,0.05);
               color:inherit; outline:none; font-family:monospace;" />
      <div id="twofa-setup-err" style="color:#dc3545; font-size:12px; min-height:16px; margin-top:4px;"></div>
      <div style="margin-top:6px; display:flex; gap:6px; justify-content:center;">
        <button id="twofa-confirm-btn" type="button" style="background:#28a745; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Confirm</button>
        <button id="twofa-cancel-btn" type="button" style="background:#6c757d; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Cancel</button>
      </div>
    </div>
    <div id="twofa-backup-area" style="display:none; margin-top:12px; text-align:center;">
      <p style="font-size:13px; color:#28a745; margin:0 0 8px;">&#10004; 2FA enabled successfully!</p>
      <div id="twofa-backup-codes" style="display:none;">
        <p style="font-size:12px; opacity:0.7; margin:0 0 6px;">Save these backup codes in a safe place:</p>
        <div id="twofa-codes-list" style="font-family:monospace; font-size:13px; background:rgba(255,255,255,0.05); padding:8px; border-radius:6px; user-select:all;"></div>
      </div>
      <button id="twofa-backup-done" type="button" style="margin-top:8px; background:#007bff; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Done</button>
    </div>
    <div id="twofa-disable-area" style="display:none; margin-top:12px;">
      <p style="font-size:12px; opacity:0.7; margin:0 0 8px;">Enter your TOTP code or password to disable 2FA:</p>
      <input id="twofa-disable-code" type="text" inputmode="numeric" maxlength="6" placeholder="TOTP code"
        style="font-size:14px; letter-spacing:2px; text-align:center; width:140px; padding:6px;
               border:1px solid rgba(255,255,255,0.2); border-radius:6px; background:rgba(255,255,255,0.05);
               color:inherit; outline:none; font-family:monospace;" />
      <div id="twofa-disable-err" style="color:#dc3545; font-size:12px; min-height:16px; margin-top:4px;"></div>
      <div style="margin-top:6px; display:flex; gap:6px; justify-content:center;">
        <button id="twofa-disable-confirm" type="button" style="background:#dc3545; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Disable</button>
        <button id="twofa-disable-cancel" type="button" style="background:#6c757d; color:white; border:none; padding:6px 16px; border-radius:4px; cursor:pointer; font-size:13px;">Cancel</button>
      </div>
    </div>
    <div style="font-size:11px; opacity:0.5; margin-top:8px;">Adds an extra layer of security to your account.</div>
  `;
  return section;
}

/**
 * Mount 2FA settings UI.
 * Canonical location: Security tab mount (#security2faMount) in the v2 Profile tabs.
 * Legacy fallback: inline Profile (near delete button / status) only when tabs UI is NOT present.
 */
function ensureInline2faSection() {
  const hasTabs = __hasProfileTabsUI();
  const securityMount = document.getElementById("security2faMount") || null;

  // If already exists, move it to Security mount when possible and exit.
  const existing = document.getElementById("inline-2fa-section");
  if (existing) {
    if (securityMount && existing.parentElement !== securityMount) {
      while (securityMount.firstChild) securityMount.removeChild(securityMount.firstChild);
      securityMount.appendChild(existing);
      try { safePost({ type: "totp_status" }); } catch {}
    }
    return;
  }

  // If tabs UI exists, we ONLY mount into Security tab.
  if (hasTabs) {
    if (!securityMount) return; // mount not yet in DOM
    const section = build2faSectionDom();
    while (securityMount.firstChild) securityMount.removeChild(securityMount.firstChild);
    securityMount.appendChild(section);
    // Remount: allow init to bind DOM again (RPC binding is guarded separately)
    window.__2faInitDone = false;
    try { init2faSettings(); } catch {}
    return;
  }

  // ===== Legacy inline fallback (no tabs UI) =====
  // Find anchor: insert before deleteAccountBtn (or its container), else after profileInlineStatus.
  const deleteBtn = document.getElementById("deleteAccountBtn");
  const statusEl = document.getElementById("profileInlineStatus");

  let anchor = null;
  let insertMode = "before";

  if (deleteBtn) {
    anchor =
      deleteBtn.closest(".danger-zone, .profile-danger-zone, div[style*='danger'], section") ||
      deleteBtn;
    insertMode = "before";
  } else if (statusEl) {
    anchor = statusEl;
    insertMode = "after";
  }

  if (!anchor) {
    const inlineUsername = document.getElementById("profileInlineUsername");
    if (inlineUsername) {
      const container = inlineUsername.closest("section, .profile-section, .settings-section, div");
      if (container && container.parentElement) {
        anchor = container.parentElement.lastElementChild;
        insertMode = "after";
      }
    }
  }

  if (!anchor) return;

  const section = build2faSectionDom();
  const parent = anchor.parentElement;
  if (!parent) return;

  if (insertMode === "before") parent.insertBefore(section, anchor);
  else {
    if (anchor.nextSibling) parent.insertBefore(section, anchor.nextSibling);
    else parent.appendChild(section);
  }

  window.__2faInitDone = false;
  try { init2faSettings(); } catch {}
}

function normalizeCryptoIdleLockUiMs(ms) {
  const n = Number(ms || 0);
  if (!Number.isFinite(n)) return CRYPTO_IDLE_LOCK_UI_DEFAULT_MS;
  return CRYPTO_IDLE_LOCK_UI_OPTIONS.some((o) => o.value === n)
    ? n
    : CRYPTO_IDLE_LOCK_UI_DEFAULT_MS;
}

async function ensureCryptoAutolockSection() {
  const mount = document.getElementById("securityAutolockMount");
  if (!mount || document.getElementById("crypto-autolock-section")) return;

  const section = document.createElement("div");
  section.id = "crypto-autolock-section";

  const hint = document.createElement("div");
  hint.className = "panel-hint";
  hint.textContent = "Lock local decrypted keys after inactivity.";
  section.appendChild(hint);

  const group = document.createElement("div");
  group.className = "security-radio-group";
  group.setAttribute("role", "radiogroup");
  group.setAttribute("aria-label", "Crypto auto-lock timeout");
  section.appendChild(group);

  const status = document.createElement("div");
  status.className = "panel-hint";
  status.style.marginTop = "6px";
  section.appendChild(status);

  mount.appendChild(section);

  let currentMs = CRYPTO_IDLE_LOCK_UI_DEFAULT_MS;
  try {
    const got = await chrome.storage.local.get([CRYPTO_IDLE_LOCK_UI_KEY]);
    currentMs = normalizeCryptoIdleLockUiMs(got?.[CRYPTO_IDLE_LOCK_UI_KEY]);
  } catch {
    currentMs = CRYPTO_IDLE_LOCK_UI_DEFAULT_MS;
  }

  for (const opt of CRYPTO_IDLE_LOCK_UI_OPTIONS) {
    const row = document.createElement("label");
    row.className = "security-radio-option";

    const input = document.createElement("input");
    input.type = "radio";
    input.name = "cryptoIdleLockMs";
    input.value = String(opt.value);
    input.checked = opt.value === currentMs;

    const text = document.createElement("span");
    text.textContent = opt.label;

    row.appendChild(input);
    row.appendChild(text);
    group.appendChild(row);

    input.addEventListener("change", async () => {
      if (!input.checked) return;
      const next = normalizeCryptoIdleLockUiMs(opt.value);
      try { await chrome.storage.local.set({ [CRYPTO_IDLE_LOCK_UI_KEY]: next }); } catch {}
      try { await window.__setCryptoIdleLockMs?.(next); } catch {}
      status.textContent = "Saved.";
    });
  }

  try { await window.__setCryptoIdleLockMs?.(currentMs); } catch {}
}

// ─── Recovery phrase section in Security tab ───────────────────────────────

function ensureRecoverySection() {
  const mount = document.getElementById("securityRecoveryMount");
  if (!mount || document.getElementById("recovery-phrase-section")) return;

  const section = document.createElement("div");
  section.id = "recovery-phrase-section";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn-sm";
  btn.style.cssText = "margin-top:6px;";
  btn.textContent = "Show recovery phrase";

  const statusEl = document.createElement("div");
  statusEl.style.cssText = "font-size:12px;min-height:16px;margin-top:4px;";

  const phraseBox = document.createElement("div");
  phraseBox.style.cssText = "display:none;margin-top:10px;";

  section.appendChild(btn);
  section.appendChild(statusEl);
  section.appendChild(phraseBox);
  mount.appendChild(section);

  btn.addEventListener("click", async () => {
    phraseBox.style.display = "none";
    phraseBox.innerHTML = "";
    statusEl.style.color = "";
    statusEl.textContent = "Enter password to continue…";
    btn.disabled = true;

    try {
      // 1. Prompt for password
      const password = await promptPassword({ reason: "Show recovery phrase" });
      if (!password) { statusEl.textContent = ""; btn.disabled = false; return; }

      statusEl.textContent = "Deriving key…";

      // 2. Load encrypted private key from local device storage
      const username = String(getMeUsername() || "").trim().toLowerCase();
      if (!username) throw new Error("Username is not initialized yet");
      const storageKey = "e2ee_local_identity_v2:" + username;
      const stored = await chrome.storage.local.get([storageKey]);
      let epk = stored?.[storageKey]?.encrypted_private_key;
      if (!epk?.salt || !epk?.iv || !epk?.data) throw new Error("No local encrypted key on this device");

      // 3. Derive AES key from password (PBKDF2, same params as at registration)
      const kdf = epk.kdf || {};
      const aesKey = await CryptoUtils.deriveKeyFromPassword(password, epk.salt, {
        name: kdf.name,
        iterations: kdf.iterations,
        hash: kdf.hash,
        time_cost: kdf.time_cost,
        memory_kib: kdf.memory_kib,
        parallelism: kdf.parallelism,
        version: kdf.version,
        preferArgon2: true,
      });

      if (Number(epk?.v || 2) !== 3) {
        const migrated = await CryptoUtils.migrateLegacyPrivateKeyContainerV2ToV3WithAesKey(
          epk,
          aesKey,
          { username }
        );
        const nextIdentity = {
          ...(stored?.[storageKey] || {}),
          v: 3,
          username,
          encrypted_private_key: migrated,
          updated_at: Date.now(),
        };
        await chrome.storage.local.set({ [storageKey]: nextIdentity });
        epk = migrated;
      }

      // 4. AES-GCM decrypt to get pkcs8 base64 string (without importing as CryptoKey)
      const iv = CryptoUtils.base64ToArrayBuffer(epk.iv);
      const ciphertext = CryptoUtils.base64ToArrayBuffer(epk.data);
      const decryptParams = CryptoUtils.buildPrivateKeyContainerGcmParams(epk, iv);
      const decrypted = await crypto.subtle.decrypt(decryptParams, aesKey, ciphertext);
      const pkcs8B64 = new TextDecoder().decode(decrypted);

      // 5. Decode base64 PKCS8 → raw key bytes → BIP39 mnemonic
      const pkcs8Bytes = new Uint8Array(CryptoUtils.base64ToArrayBuffer(pkcs8B64));
      const rawKey = CryptoUtils.extractRawKeyFromPkcs8(pkcs8Bytes);
      const mnemonic = CryptoUtils.bip39Encode(rawKey);
      const words = mnemonic.split(" ");

      // 6. Render phrase grid
      const grid = document.createElement("div");
      grid.style.cssText = "display:grid;grid-template-columns:repeat(3,1fr);gap:4px;font-size:12px;";
      words.forEach((w, i) => {
        const cell = document.createElement("div");
        cell.style.cssText = "padding:4px 6px;background:rgba(255,255,255,0.06);border-radius:4px;font-family:monospace;";
        cell.textContent = `${i+1}. ${w}`;
        grid.appendChild(cell);
      });

      const note = document.createElement("p");
      note.style.cssText = "font-size:11px;opacity:0.6;margin:8px 0 0;";
      note.textContent = "Write these 24 words down and keep them safe. They are the only way to recover your account if you forget your password.";

      phraseBox.innerHTML = "";
      phraseBox.appendChild(grid);
      phraseBox.appendChild(note);
      phraseBox.style.display = "";

      statusEl.style.color = "#28a745";
      statusEl.textContent = "Recovery phrase loaded.";
    } catch (e) {
      statusEl.style.color = "#dc3545";
      statusEl.textContent = e?.message || "Failed to load recovery phrase";
    } finally {
      btn.disabled = false;
    }
  });
}

// ─── Change password section in Security tab ───────────────────────────────

function ensureChangePasswordSection() {
  const mount = document.getElementById("securityChangePassMount");
  if (!mount || document.getElementById("change-password-section")) return;

  const section = document.createElement("div");
  section.id = "change-password-section";

  // Form fields
  function makeInput(placeholder, id) {
    const inp = document.createElement("input");
    inp.type = "password";
    inp.id = id;
    inp.placeholder = placeholder;
    inp.autocomplete = "off";
    inp.style.cssText = "width:100%;box-sizing:border-box;margin-top:6px;padding:6px 8px;background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:inherit;font-size:13px;";
    return inp;
  }

  const oldInput = makeInput("Current password", "cpOldPass");
  const newInput = makeInput("New password (min 8 chars)", "cpNewPass");
  const confirmInput = makeInput("Confirm new password", "cpConfirmPass");

  const warn = document.createElement("div");
  warn.style.cssText = "font-size:11px;opacity:0.55;margin-top:6px;margin-bottom:2px;";
  warn.textContent = "All other sessions will be signed out on all devices.";

  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn-sm";
  btn.style.cssText = "margin-top:8px;";
  btn.textContent = "Change password";

  const statusEl = document.createElement("div");
  statusEl.style.cssText = "font-size:12px;min-height:16px;margin-top:6px;";

  section.appendChild(oldInput);
  section.appendChild(newInput);
  section.appendChild(confirmInput);
  section.appendChild(warn);
  section.appendChild(btn);
  section.appendChild(statusEl);
  mount.appendChild(section);

  btn.addEventListener("click", async () => {
    const oldPass = oldInput.value;
    const newPass = newInput.value;
    const confirmPass = confirmInput.value;

    statusEl.style.color = "";
    statusEl.textContent = "";

    if (!oldPass) { statusEl.style.color = "#dc3545"; statusEl.textContent = "Enter current password."; return; }
    if (newPass.length < 8) { statusEl.style.color = "#dc3545"; statusEl.textContent = "New password must be at least 8 characters."; return; }
    if (newPass !== confirmPass) { statusEl.style.color = "#dc3545"; statusEl.textContent = "New passwords don't match."; return; }

    btn.disabled = true;
    statusEl.style.color = "";
    statusEl.textContent = "Changing password…";

    try {
      // 1. Load local EPK from device storage
      const username = String(getMeUsername() || "").trim().toLowerCase();
      if (!username) throw new Error("Username not initialized");
      const storageKey = "e2ee_local_identity_v2:" + username;
      const stored = await chrome.storage.local.get([storageKey]);
      const epk = stored?.[storageKey]?.encrypted_private_key;
      if (!epk?.salt || !epk?.iv || !epk?.data) throw new Error("No local encrypted key on this device");

      // 2. Verify old password by decrypting EPK (throws if wrong)
      statusEl.textContent = "Verifying current password…";
      let pkcs8B64;
      try {
        pkcs8B64 = await CryptoUtils.decryptPrivateKeyToPkcs8B64(epk, oldPass, { expectedUsername: username });
      } catch {
        throw new Error("Incorrect current password");
      }

      // 3. Re-encrypt with new password (Argon2id preferred)
      statusEl.textContent = "Re-encrypting key…";
      const newEpk = await CryptoUtils.encryptPrivateKey(pkcs8B64, newPass, { username });

      // 4. Send to background: server verify + save
      statusEl.textContent = "Saving…";
      await new Promise((resolve, reject) => {
        window.__changePassResolve = resolve;
        window.__changePassReject = reject;
        safePost({ type: "change_password", oldPassword: oldPass, newPassword: newPass, newEpk });
        setTimeout(() => reject(new Error("Timed out")), 30000);
      });

      statusEl.style.color = "#28a745";
      statusEl.textContent = "Password changed. Signing out…";
      oldInput.value = "";
      newInput.value = "";
      confirmInput.value = "";
      // All refresh tokens were revoked server-side — log out this session too.
      setTimeout(() => {
        try { safePost({ type: "auth_logout" }); } catch {}
      }, 1200);
    } catch (e) {
      statusEl.style.color = "#dc3545";
      statusEl.textContent = e?.message || "Failed to change password.";
    } finally {
      btn.disabled = false;
      window.__changePassResolve = null;
      window.__changePassReject = null;
    }
  });
}

async function openProfileMe(forceReload = false) {
  ensureProfileUI();
  openProfileDrawer();
  if (profileStatusEl) profileStatusEl.textContent = "Loading...";
  try {
    const data = await apiJson("/profile/me", { method: "GET" });
    __profileMeCache = data;
    renderProfileView(data, "me");
    if (profileStatusEl) profileStatusEl.textContent = "";
  } catch (e) {
    if (profileStatusEl) profileStatusEl.textContent = "Failed to load profile: " + (e?.message || e);
  }
}

async function openProfilePublic(username, forceReload = false) {
  ensureProfileUI();
  const u = String(username || "").trim();
  if (!u) return;

  if (u === getMeUsername()) {
    return openProfileMe(forceReload);
  }
  openProfileDrawer();
  if (profileStatusEl) profileStatusEl.textContent = "Loading...";
  try {
    const data = await apiJson("/profile/" + encodeURIComponent(u), { method: "GET" });
    renderProfileView(data, "public");
    if (profileStatusEl) profileStatusEl.textContent = "";
  } catch (e) {
    if (profileStatusEl) profileStatusEl.textContent = "Failed to load profile: " + (e?.message || e);
  }
}

function openProfile(username) {
  const u = String(username || "").trim();
  if (!u) return;
  if (u === getMeUsername()) openProfileMe();
  else openProfilePublic(u);
}

async function saveProfileMe() {
  ensureProfileUI();
  const about = String(profileAboutEl?.value || "").slice(0, 360);
  const privacy = {
    allow_group_invites_from_non_friends: !!profileAllowInvitesEl?.checked,
    allow_dm_from_non_friends: !!profileAllowDmEl?.checked,
  };
  if (profileStatusEl) profileStatusEl.textContent = "Saving...";
  try {
    const data = await apiJson("/profile/me", {
      method: "PUT",
      body: JSON.stringify({ about, privacy })
    });
    renderProfileView(data, "me");
    if (profileStatusEl) profileStatusEl.textContent = "Saved";
    setTimeout(() => { if (profileStatusEl && __profileOpen) profileStatusEl.textContent = ""; }, 1200);
  } catch (e) {
    if (profileStatusEl) profileStatusEl.textContent = "Save failed: " + (e?.message || e);
  }
}

ensureProfileUI();

document.addEventListener("DOMContentLoaded", () => {
	  
  loadPinnedContextRooms();
  loadDmPins();
  autoLoadProfileIfReady();
});

const attachBtn = document.getElementById("attachBtn");
const dmListEl = document.getElementById("dmList");
// Rail buttons (for unread dots)
const navRoomsBtn = document.getElementById("navRooms");
const navDmBtn = document.getElementById("navDM");

// =============================
// Unread indicators (green dots)
// =============================
// No counters, only dots on:
//  - right rail icons (Rooms/DM)
//  - room cards in Rooms drawer
//  - DM items in DM drawer

const __unreadRooms = new Set();      // roomId as string
const __unreadDmThreads = new Set();  // threadId as string

function __ensureDot(parent, className) {
  if (!parent) return null;

  const selector =
    "." + String(className || "").trim().split(/\s+/).filter(Boolean).join(".");

  let d = null;
  try { d = parent.querySelector(selector); } catch { d = null; }

  if (!d) {
    d = document.createElement("span");
    d.className = className;
    parent.appendChild(d);
  }
  return d;
}


let __railRoomsDot = null;
let __railDmDot = null;

function __updateRailUnreadDots() {
  const navRoomsBtn = document.getElementById("navRooms");
  const navDmBtn = document.getElementById("navDM");
  
  if (navRoomsBtn) {
    let dot = navRoomsBtn.querySelector(".notif-dot.rail-dot");
    if (!dot) {
      dot = document.createElement("span");
      dot.className = "notif-dot rail-dot";
      navRoomsBtn.appendChild(dot);
    }
    dot.style.display = __unreadRooms.size ? "block" : "none";
  }

  if (navDmBtn) {
    let dot = navDmBtn.querySelector(".notif-dot.rail-dot");
    if (!dot) {
      dot = document.createElement("span");
      dot.className = "notif-dot rail-dot";
      navDmBtn.appendChild(dot);
    }
    dot.style.display = __unreadDmThreads.size ? "block" : "none";
  }
}

function __markRoomUnread(roomId) {
  const rid = String(Number(roomId));
  if (!rid || rid === "NaN") return;
  // Don't mark currently open room
  if (activeRoomId != null && Number(activeRoomId) === Number(rid)) return;
  __unreadRooms.add(rid);
  __updateRailUnreadDots();
  __renderUnreadDotsInLists();
}

function __clearRoomUnread(roomId) {
  const rid = String(Number(roomId));
  if (!rid || rid === "NaN") return;
  if (__unreadRooms.delete(rid)) {
    __updateRailUnreadDots();
    __renderUnreadDotsInLists();
  }
}

function __markDmUnread(threadId) {
  const tid = String(Number(threadId));
  if (!tid || tid === "NaN") return;
  if (dmMode && activeDmThreadId != null && Number(activeDmThreadId) === Number(tid)) return;
  __unreadDmThreads.add(tid);
  __updateRailUnreadDots();
  __renderUnreadDotsInLists();
}

function __clearDmUnread(threadId) {
  const tid = String(Number(threadId));
  if (!tid || tid === "NaN") return;
  if (__unreadDmThreads.delete(tid)) {
    __updateRailUnreadDots();
    __renderUnreadDotsInLists();
  }
}

function __renderUnreadDotsInLists() {
  // Rooms drawer: .room-card carries data-room-id
  try {
    const roomEls = document.querySelectorAll('.room-card[data-room-id]');
    for (const el of roomEls) {
      const rid = String(el.dataset.roomId || "");
      const has = rid && __unreadRooms.has(rid);
      el.classList.toggle("is-unread", !!has);
      
      const logo = el.querySelector('.roomcard-logo');
      if (logo) {
        const dot = __ensureDot(logo, "notif-dot logo-dot");
        if (dot) dot.style.display = has ? "block" : "none";
      }
    }
  } catch {}

  // DM drawer: .dm-item carries data-thread-id
  try {
    const dmEls = document.querySelectorAll('.dm-item[data-thread-id]');
    for (const el of dmEls) {
      const tid = String(el.dataset.threadId || "");
      const has = tid && __unreadDmThreads.has(tid);
      el.classList.toggle("is-unread", !!has);
      const dot = __ensureDot(el, "notif-dot list-dot");
      if (dot) dot.style.display = has ? "block" : "none";
    }
  } catch {}
}

// =============================
// Refresh unread from server data
// =============================
const __lastSeenKey = "ws_last_seen";
let __lastSeenRooms = {};
let __lastSeenDm = {};

chrome.storage?.local.get([__lastSeenKey], (d) => {
  const data = d[__lastSeenKey] || {};
  __lastSeenRooms = data.rooms || {};
  __lastSeenDm = data.dm || {};
});

function __saveLastSeen() {
  chrome.storage?.local.set({
    [__lastSeenKey]: { rooms: __lastSeenRooms, dm: __lastSeenDm }
  });
}

function __markRoomSeen(roomId) {
  if (!roomId) return;
  const rid = String(roomId);
  __lastSeenRooms[rid] = Date.now();
  __saveLastSeen();
  __clearRoomUnread(roomId);
    
  __updateRailUnreadDots();
  __renderUnreadDotsInLists();
    
  (async () => {
    try {
      const token = await requestToken();
      if (!token) return;
      await fetch(API_BASE + `/rooms/${roomId}/mark_seen`, {
        method: "POST",
        headers: { "Authorization": "Bearer " + token }
      });
    } catch (err) {
      console.warn("mark_seen failed:", err);
    }
  })();
}

function __markDmSeen(threadId) {
  if (!threadId) return;
  const tid = String(threadId);
  // Watermark = max(server's last_message_at, Date.now()).
  // Using only last_message_at caused own-message false-unread: when the user
  // sends a DM, dmItems still holds T_prev (the previous message time). The
  // server then sets last_message_at = T_new > T_prev. On the next periodic
  // poll, lastMsg(T_new) > lastSeen(T_prev) → thread incorrectly marked unread.
  // Taking max with Date.now() ensures the watermark covers the just-sent message.
  const dm = (dmItems || []).find(d => String(d.thread_id) === tid);
  const serverTs = dm?.last_message_at ? new Date(dm.last_message_at).getTime() : 0;
  __lastSeenDm[tid] = Math.max(serverTs, Date.now());
  __saveLastSeen();
  __clearDmUnread(threadId);
}

window.__refreshUnreadFromServer = function() {
  for (const room of (lastMineRooms || [])) {
    const rid = String(room.id || "");
    if (!rid) continue;
    if (activeRoomId != null && String(activeRoomId) === rid) continue;

    const lastMsg = room.last_message_at ? new Date(room.last_message_at).getTime() : 0;
    // Take the max of server's last_seen_at and the local optimistic mark from
    // __markRoomSeen. The server value alone can be stale when the periodic poll
    // fires before POST /mark_seen is reflected in the DB (race with the async
    // REST call), which causes own sent messages to trigger the unread dot.
    const serverSeenTs = room.last_seen_at ? new Date(room.last_seen_at).getTime() : 0;
    const lastSeen = Math.max(serverSeenTs, __lastSeenRooms[rid] || 0);

    if (room.unread || room.has_unread || (lastMsg > 0 && lastMsg > lastSeen)) {
      __unreadRooms.add(rid);
    }
  }

  for (const dm of (dmItems || [])) {
    const tid = String(dm.thread_id || "");
    if (!tid) continue;
    if (dmMode && activeDmThreadId != null && String(activeDmThreadId) === tid) continue;

    const lastMsg = dm.last_message_at ? new Date(dm.last_message_at).getTime() : 0;
    // Server DM list doesn't return last_seen_at — rely solely on local watermark.
    const lastSeen = __lastSeenDm[tid] || 0;

    if (dm.unread || dm.has_unread || (lastMsg > 0 && lastMsg > lastSeen)) {
      __unreadDmThreads.add(tid);
    }
  }

  __updateRailUnreadDots();
  __renderUnreadDotsInLists();
};
function updateJoinButton(status) {
  if (!connectBtn) return;
  if (status.online || status.reconnecting) {
    connectBtn.disabled = true;
    connectBtn.title = status.online
      ? "You are already in room"
      : "Connecting...";
  } else {
    connectBtn.disabled = false;
    connectBtn.title = "Connect to the room";
  }
}

// --- active room & saved passwords ---
let activeRoomId = null;
let activeRoomName = "";
let roomPassById = {}; // room_id -> saved password

// =======================
// DM (direct) mode state
// =======================
let dmMode = false;
let activeDmThreadId = null;
let activeDmPeer = "";
let dmItems = []; // [{thread_id, peer_username, last_message_at}]
const DM_PINNED_KEY = "dm_pinned_threads_v1";
let __dmPinnedThreadIds = []; // string[]

function __normTid(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) return "";
  return String(n);
}

function __isDmPinned(threadId) {
  const tid = __normTid(threadId);
  return !!tid && __dmPinnedThreadIds.includes(tid);
}

function __setDmPinned(threadId, pinned) {
  const tid = __normTid(threadId);
  if (!tid) return;
  __dmPinnedThreadIds = __dmPinnedThreadIds.filter(x => x !== tid);
  if (pinned) __dmPinnedThreadIds.unshift(tid);
  __dmPinnedThreadIds = __dmPinnedThreadIds.slice(0, 50);
}

function saveDmPins() {
  try {
    chrome.storage.local.set({ [DM_PINNED_KEY]: __dmPinnedThreadIds.slice() });
  } catch {}
}

function loadDmPins() {
  try {
    chrome.storage.local.get([DM_PINNED_KEY], (d) => {
      const arr = Array.isArray(d?.[DM_PINNED_KEY]) ? d[DM_PINNED_KEY] : [];
      __dmPinnedThreadIds = arr.map(__normTid).filter(Boolean);
      if (Array.isArray(dmItems)) renderDmList(dmItems);
    });
  } catch {}
}

function __fmtDmTime(v) {
  if (!v) return "";
  const ms = Date.parse(String(v));
  if (!Number.isFinite(ms)) return "";
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "";
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  if (sameDay) return `${hh}:${mm}`;
  const dd = String(d.getDate()).padStart(2, "0");
  const mo = String(d.getMonth() + 1).padStart(2, "0");
  return `${dd}.${mo}`;
}

async function __openDmActionsMenu(threadId, peer) {
  const isPinned = __isDmPinned(threadId);
  const menuRaw = (await __ui.prompt(
    `DM with "${peer}"\n1 Open\n2 Mark as read\n3 ${isPinned ? "Unpin" : "Pin"}\n4 Delete for me\n5 Delete for both (needs second confirm)`,
    {
      title: "Conversation actions",
      placeholder: "1-5",
      inputType: "text",
      okText: "Apply",
      cancelText: "Cancel",
    }
  )) || "";

  const choice = String(menuRaw || "").trim();
  if (!choice) return;

  if (choice === "1") {
    setModeDm(threadId, peer);
    pushRecent("dm", threadId, peer);
    clearChat();
    try {
      await ensureDmKeyReady(threadId, peer);
    } catch (e) {
      // Locked or key load failure: don't connect / fetch history as if
      // the key were ready. The DM will stay in pending state until the
      // user unlocks (panel.js queues a retry via __pendingDmThreadId).
      if (e?.code !== "DM_KEY_LOCKED") console.warn("ensureDmKeyReady failed:", e);
      return;
    }
    safePost({ type: "dm_connect", thread_id: threadId, peer_username: peer });
    safePost({ type: "dm_history", thread_id: threadId, limit: 50 });
    return;
  }

  if (choice === "2") {
    __markDmSeen(threadId);
    renderDmList(dmItems);
    return;
  }

  if (choice === "3") {
    __setDmPinned(threadId, !isPinned);
    saveDmPins();
    renderDmList(dmItems);
    return;
  }

  if (choice === "4" || choice === "5") {
    const scope = (choice === "5") ? "both" : "self";
      const ok = await __ui.confirm(
        scope === "both"
          ? `Request delete for both users?\nSecond participant must confirm within limited time.\nAfter confirmation DM messages/files are removed for both.`
          : `Delete this conversation only for you?`,
        "Confirm deletion"
      );
    if (!ok) return;
    const reqId = `dm_del:${Date.now()}:${Math.random().toString(16).slice(2)}`;
    safePost({ type: "dm_delete", reqId, ts: Date.now(), thread_id: threadId, scope });
    return;
  }
}

function __setDmModeUI(on) {
  document.body.classList.toggle("is-dm-mode", !!on);

  const p = document.getElementById("presence");
  if (p) p.classList.add("is-hidden");
}

function applyComposerPolicyUI() {
  if (!msgInput || !sendBtn) return;

  const defaultPlaceholder = "Message";
  const isCryptoLocked = (typeof window.__isCryptoUiLocked === "function")
    ? !!window.__isCryptoUiLocked()
    : false;
  const rid = activeRoomId != null ? String(activeRoomId) : "";
  const isReadonlyRoom = !!(rid && typeof roomReadonlyById !== "undefined" && roomReadonlyById[rid]);
  const canPost = (typeof __canPostToActiveRoom === "function") ? !!__canPostToActiveRoom() : true;
  const blockRoomPosting = !dmMode && !!rid && isReadonlyRoom && !canPost;

  const blocked = !!(isCryptoLocked || blockRoomPosting);
  msgInput.disabled = blocked;
  sendBtn.disabled = blocked;
  if (attachBtn) attachBtn.disabled = blocked;

  if (isCryptoLocked) {
    msgInput.placeholder = "Crypto is locked. Click Unlock.";
  } else if (blockRoomPosting) {
    msgInput.placeholder = "Read-only channel: only owner/admin can post";
  } else {
    msgInput.placeholder = defaultPlaceholder;
  }
}
window.applyComposerPolicyUI = applyComposerPolicyUI;

function setModeRoom() {
  dmMode = false;
  activeDmThreadId = null;
  activeDmPeer = "";

  __setDmModeUI(false);

  setInviteVisible(true);
  renderCurrentRoom({ online: !!(statusEl && statusEl.classList.contains("online")) });
  applyComposerPolicyUI();
}

function setModeDm(threadId, peerUsername) {
  dmMode = true;
  activeDmThreadId = Number(threadId);
  activeDmPeer = String(peerUsername || "").trim();

  __setDmModeUI(true);

  // Clear unread dot for this DM thread when user opens it
  __markDmSeen?.(threadId) || __clearDmUnread(activeDmThreadId);
  setInviteVisible(false);

  // presence в DM не нужен
  renderPresence([]);

  renderCurrentRoom({ online: true });
  applyComposerPolicyUI();
}

// --- pending room pass (save only on success) ---
let pendingRoomId = null;
let pendingRoomPass = "";
let lastConnectRoomName = "";

// When inviting from room cards (not necessarily the active room),
// background may not echo back roomId. Keep a tiny fallback.
let __lastInviteRoomId = null;

function __sendRoomInvite(roomId, username) {
  __lastInviteRoomId = roomId != null ? Number(roomId) : null;
  safePost({ type: "rooms_invite", roomId, username });
}

// load saved rooms password
chrome.storage.local.get(["roomPassById"], data => {
  roomPassById = data.roomPassById || {};
});

function setInviteVisible(visible) {
  const v = !!visible;

  if (inviteBtn) {
    inviteBtn.classList.toggle("is-hidden", !v);
    inviteBtn.disabled = !v;
  }

  if (inviteBtnTop) {
    inviteBtnTop.classList.toggle("is-hidden", !v);
    inviteBtnTop.disabled = !v;
  }
}

setInviteVisible(false);

async function __invitePromptAndSend() {
  if (!activeRoomId) {
    await __ui.alert("Please open a room first.");
    return;
  }

  const username = (await __ui.prompt("Invite username:", {
    inputType: "text",
    placeholder: "username"
  })).trim();

  if (!username) return;

  __sendRoomInvite(activeRoomId, username);
}

if (inviteBtn) inviteBtn.onclick = __invitePromptAndSend;
if (inviteBtnTop) inviteBtnTop.onclick = __invitePromptAndSend;

if (friendsBtn) friendsBtn.onclick = openFriends;
if (friendsBackdrop) friendsBackdrop.onclick = closeFriends;
if (closeFriendsBtn) closeFriendsBtn.onclick = closeFriends;

if (roomsBtn) roomsBtn.onclick = openRoomsDrawer;
if (roomsBackdrop) roomsBackdrop.onclick = closeRoomsDrawer;
if (closeRoomsBtn) closeRoomsBtn.onclick = closeRoomsDrawer;

if (sendFriendRequestBtn) {
  sendFriendRequestBtn.onclick = () => {
    const username = (friendNameInput?.value || "").trim();
    if (!username) return;
    safePost({ type: "friends_request", username });
  };
}

// saving room-password (SEC: encrypted with master key)
async function saveRoomPass(roomId, pass) {
  if (!roomId) return;
  if (!pass) return;
  const enc = await encryptForStorage(pass);
  if (!enc) {
    console.warn("Room password was not saved: storage encryption is unavailable");
    return;
  }
  roomPassById[String(roomId)] = enc;
  chrome.storage.local.set({ roomPassById });
}


const disconnectBtn = document.getElementById("disconnectBtn");
const leaveBtn = document.getElementById("leaveBtn");
const sendBtn = document.getElementById("sendBtn");
const nameInput = document.getElementById("name");
const roomInput = document.getElementById("room");
const roomsListEl = document.getElementById("roomsList");
const refreshRoomsBtn = document.getElementById("refreshRooms");
const newRoomNameInput = document.getElementById("newRoomName");
const newRoomPassInput = document.getElementById("newRoomPass");
const newRoomDescInput = document.getElementById("newRoomDesc");
const newRoomLogoInput = document.getElementById("newRoomLogo");
const newRoomLogoHintEl = document.getElementById("newRoomLogoHint");
const newRoomPublicInput = document.getElementById("newRoomPublic");
const newRoomReadonlyInput = document.getElementById("newRoomReadonly");
const createRoomBtn = document.getElementById("createRoomBtn");
const createRoomResultEl = document.getElementById("createRoomResult");

const newRoomTypeHintEl = document.getElementById("newRoomTypeHint");
const newRoomPublicCb = document.getElementById("newRoomPublic");
const newRoomReadonlyCb = document.getElementById("newRoomReadonly");

const pickRoomLogoBtn = document.getElementById("pickRoomLogo");

let __createRoomLogoFile = null;

function resetCreateRoomLogoUI() {
  __createRoomLogoFile = null;
  if (newRoomLogoInput) newRoomLogoInput.value = "";
  if (pickRoomLogoBtn) {
    pickRoomLogoBtn.classList.remove("has-image");
    pickRoomLogoBtn.style.backgroundImage = "";
  }
}

if (pickRoomLogoBtn && newRoomLogoInput) {
  pickRoomLogoBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    newRoomLogoInput.click();
  });

  newRoomLogoInput.addEventListener("change", () => {
    const f = newRoomLogoInput.files && newRoomLogoInput.files[0];
    if (!f) return;

    if (!f.type || !f.type.startsWith("image/")) {
      alert("Please choose an image file.");
      resetCreateRoomLogoUI();
      return;
    }

    __createRoomLogoFile = f;

    const url = URL.createObjectURL(f);
    pickRoomLogoBtn.style.backgroundImage = `url("${url}")`;
    pickRoomLogoBtn.classList.add("has-image");
  });
}

function updateNewRoomTypeHint() {
  if (!newRoomTypeHintEl || !newRoomPublicCb || !newRoomReadonlyCb) return;

  if (newRoomPublicCb.checked && newRoomReadonlyCb.checked) {
    newRoomTypeHintEl.className = "room-type-hint is-public";
    newRoomTypeHintEl.textContent = "Public read-only: users join by request/approval, only owner/admin can post.";
  } else if (newRoomPublicCb.checked) {
    newRoomTypeHintEl.className = "room-type-hint is-public";
    newRoomTypeHintEl.textContent = "Public: join by alias via request/approval. The connection is encrypted (the server cannot see the content).";
  } else if (newRoomReadonlyCb.checked) {
    newRoomTypeHintEl.className = "room-type-hint is-private";
    newRoomTypeHintEl.textContent = "Private read-only: by invite only, only owner/admin can post.";
  } else {
    newRoomTypeHintEl.className = "room-type-hint is-private";
    newRoomTypeHintEl.textContent = "Private: access by invitation only. The connection is encrypted (the server cannot see the content).";
  }
}

if (newRoomPublicCb) newRoomPublicCb.addEventListener("change", updateNewRoomTypeHint);
if (newRoomReadonlyCb) newRoomReadonlyCb.addEventListener("change", updateNewRoomTypeHint);
updateNewRoomTypeHint();

// drawer create-room
const openCreateRoomBtn = document.getElementById("openCreateRoom");
const closeCreateRoomBtn = document.getElementById("closeCreateRoom");
const createRoomDrawer = document.getElementById("createRoomDrawer");
const createRoomBackdrop = document.getElementById("createRoomBackdrop");
const currentRoomEl = document.getElementById("currentRoom");
const logoutBtn = document.getElementById("logoutBtn");
if (logoutBtn) {
logoutBtn.onclick = () => {
  roomsLoadedAfterLogin = false;

  try { leaveRoomUI("Logged out"); } catch {}
  try { clearChat?.(); } catch {}
  try { setModeRooms?.(); } catch {}

  CM()?.clear?.();
  cryptoInitialized = false;
  userPassword = null;

  safePost({ type: "auth_logout" });

  location.href = "login.html";
};
}

// --- global ESC handler (friends drawer) ---
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!friendsDrawer?.classList.contains("open")) return;
  closeFriends();
});

const presenceEl = document.getElementById("presence");
if (presenceEl) presenceEl.classList.add("is-hidden");

let membersPanelOpen = false;
let lastPresenceOnline = [];
let activeRoomKey = "";

function clearChat(opts = {}) {
  const resetKeyAlerts = opts.resetKeyAlerts !== false;
  if (chat) chat.innerHTML = "";
  lastMsgAuthor = "";
  try { updatePinnedBar?.(); } catch {}
  // Reset only when switching context, not while appending older history.
  if (resetKeyAlerts) {
    try { window.__keyChangeNotifications?.resetKeyChangeAlerts?.(); } catch {}
  }
}

// ============================
// Key Change Warning (Step 5)
// ============================

/**
 * Render a prominent key-change warning banner in the chat area.
 * Styled similarly to Signal's "Safety number with X has changed" message.
 * Includes a link to open the peer's profile (where safety number is shown).
 */
function addKeyChangeWarning(username) {
  if (!chat) return;

  // Reset author streak so next real message shows author header
  lastMsgAuthor = "";

  const banner = document.createElement("div");
  banner.className = "key-change-banner";
  banner.style.cssText = `
    margin: 12px 8px;
    padding: 10px 14px;
    background: #3a2a00;
    border: 1px solid #b08800;
    border-radius: 8px;
    display: flex;
    align-items: flex-start;
    gap: 10px;
    font-size: 13px;
    color: #ffd666;
    line-height: 1.4;
  `;

  // Warning icon
  const icon = document.createElement("span");
  icon.textContent = "\u26A0\uFE0F";
  icon.style.cssText = "font-size: 18px; flex-shrink: 0; margin-top: 1px;";
  banner.appendChild(icon);

  // Text content
  const textWrap = document.createElement("div");
  textWrap.style.cssText = "flex: 1; min-width: 0;";

  const mainText = document.createElement("div");
  mainText.style.cssText = "font-weight: 600; margin-bottom: 4px;";
  mainText.textContent = `Security key for ${username} has changed`;
  textWrap.appendChild(mainText);

  const subText = document.createElement("div");
  subText.style.cssText = "font-size: 12px; color: #d4a94a; opacity: 0.9;";
  subText.textContent = "This could mean they re-registered, or someone may be intercepting messages. Verify their safety number to be sure.";
  textWrap.appendChild(subText);

  // "View" link to open profile/safety numbers
  const viewLink = document.createElement("a");
  viewLink.textContent = "View safety number";
  viewLink.href = "#";
  viewLink.style.cssText = `
    display: inline-block;
    margin-top: 6px;
    font-size: 12px;
    color: #ffd666;
    text-decoration: underline;
    cursor: pointer;
  `;
  viewLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (typeof openProfile === "function") {
      openProfile(username);
    }
  });
  textWrap.appendChild(viewLink);

  banner.appendChild(textWrap);

  // Dismiss button
  const dismiss = document.createElement("button");
  dismiss.textContent = "\u2715";
  dismiss.title = "Dismiss";
  dismiss.style.cssText = `
    background: none;
    border: none;
    color: #ffd666;
    font-size: 16px;
    cursor: pointer;
    padding: 0 2px;
    opacity: 0.7;
    flex-shrink: 0;
  `;
  dismiss.addEventListener("click", () => {
    banner.style.transition = "opacity 0.3s ease";
    banner.style.opacity = "0";
    setTimeout(() => banner.remove(), 300);
  });
  banner.appendChild(dismiss);

  chat.appendChild(banner);
  chat.scrollTop = chat.scrollHeight;
}

/**
 * Show key change warnings for multiple users at once.
 * Used after presence event when entering a room.
 */
function addKeyChangeWarnings(usernames) {
  if (!Array.isArray(usernames)) return;
  for (const u of usernames) {
    addKeyChangeWarning(u);
  }
}

function addSigFailWarning(fromUser) {
  if (!chat) return;
  lastMsgAuthor = "";
  const banner = document.createElement("div");
  banner.style.cssText = `
    margin: 6px 8px;
    padding: 8px 12px;
    background: #3a0a0a;
    border: 1px solid #c0392b;
    border-radius: 8px;
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 12px;
    color: #e74c3c;
    line-height: 1.4;
  `;
  const icon = document.createElement("span");
  icon.textContent = "\u26A0";
  icon.style.cssText = "font-size: 15px; flex-shrink: 0; margin-top: 1px;";
  banner.appendChild(icon);
  const textWrap = document.createElement("div");
  textWrap.textContent = `Signature verification failed for message from "${fromUser || "unknown"}". The sender field may have been forged.`;
  banner.appendChild(textWrap);
  chat.appendChild(banner);
}

// Shown when sigValid===null and sender is known — signature absent (older client or
// legacy message), not a forgery proof but worth flagging to the user.
function addSigUnverifiedWarning(fromUser) {
  if (!chat) return;
  lastMsgAuthor = "";
  const banner = document.createElement("div");
  banner.style.cssText = `
    margin: 4px 8px;
    padding: 5px 10px;
    background: #2a2000;
    border: 1px solid #7a6000;
    border-radius: 6px;
    display: flex;
    align-items: center;
    gap: 7px;
    font-size: 11px;
    color: #b8960a;
    line-height: 1.3;
  `;
  const icon = document.createElement("span");
  icon.textContent = "\u26A0";
  icon.style.cssText = "font-size: 13px; flex-shrink: 0;";
  banner.appendChild(icon);
  const textWrap = document.createElement("div");
  textWrap.textContent = `Unverified sender — "${fromUser || "unknown"}" sent without an Ed25519 signature. Verify identity via Safety Number.`;
  banner.appendChild(textWrap);
  chat.appendChild(banner);
}

/**
 * A3: TOFU — first time we see a peer's key in a DM thread.
 * Informational (blue/teal), not alarming. Includes link to safety number.
 */
function addTofuFirstSeenBanner(username) {
  if (!chat) return;
  lastMsgAuthor = "";
  const banner = document.createElement("div");
  banner.style.cssText = `
    margin: 8px 8px 4px;
    padding: 8px 12px;
    background: #001e2e;
    border: 1px solid #1a5276;
    border-radius: 8px;
    display: flex;
    align-items: flex-start;
    gap: 9px;
    font-size: 12px;
    color: #7fb3d3;
    line-height: 1.4;
  `;

  const icon = document.createElement("span");
  icon.textContent = "\uD83D\uDD11";
  icon.style.cssText = "font-size: 14px; flex-shrink: 0; margin-top: 1px;";
  banner.appendChild(icon);

  const textWrap = document.createElement("div");
  textWrap.style.cssText = "flex: 1; min-width: 0;";

  const mainText = document.createElement("div");
  mainText.style.cssText = "font-weight: 600; margin-bottom: 3px; color: #aed6f1;";
  mainText.textContent = `First message from ${username || "unknown"}`;
  textWrap.appendChild(mainText);

  const sub = document.createElement("div");
  sub.style.cssText = "color: #5d8aa8;";
  sub.textContent = "Their encryption key has been recorded. Verify via Safety Number to confirm their identity.";
  textWrap.appendChild(sub);

  const viewLink = document.createElement("a");
  viewLink.textContent = "View safety number";
  viewLink.href = "#";
  viewLink.style.cssText = `
    display: inline-block;
    margin-top: 4px;
    font-size: 11px;
    color: #7fb3d3;
    text-decoration: underline;
    cursor: pointer;
  `;
  viewLink.addEventListener("click", (e) => {
    e.preventDefault();
    if (typeof openProfile === "function") openProfile(username);
  });
  textWrap.appendChild(viewLink);
  banner.appendChild(textWrap);

  const dismiss = document.createElement("button");
  dismiss.textContent = "\u2715";
  dismiss.title = "Dismiss";
  dismiss.style.cssText = `
    background: none; border: none; color: #5d8aa8;
    font-size: 14px; cursor: pointer; padding: 0 2px;
    flex-shrink: 0; opacity: 0.7;
  `;
  dismiss.addEventListener("click", () => {
    banner.style.transition = "opacity 0.3s ease";
    banner.style.opacity = "0";
    setTimeout(() => banner.remove(), 300);
  });
  banner.appendChild(dismiss);

  chat.appendChild(banner);
  chat.scrollTop = chat.scrollHeight;
}

function leaveRoomUI(reason = "") {
  activeRoomId = null;
  updatePinnedBar();
  activeRoomName = "";
  activeRoomKey = "";
  lastHistoryRoomId = null;
  renderedHistoryRoomId = null;
  clearChat();
  renderPresence([]);
  setInviteVisible(false);
  highlightActiveRoom();
  renderCurrentRoom({ online: false });
  const r = String(reason || "").toLowerCase();
  let msg = "You have left the room.";
  if (r.includes("kicked")) msg = "You have been kicked from the room.";
  else if (r.includes("no access")) msg = "You no longer have access to this room.";
  try {
    addMsg("System", msg, false, Date.now());
  } catch {}
}

function updateLeaveBtnState() {
  if (!leaveBtn) return;
  const rid = activeRoomId != null ? String(activeRoomId) : "";
  const isOwner = rid ? !!roomOwnerById[rid] : false;
  leaveBtn.disabled = !(wsOnline && !dmMode && !!rid && !isOwner);
}

function setActiveRoomFromServer(room_id, room_name) {
  if (room_id == null) return;

  const rid = String(room_id);

  if (activeRoomId != null && String(activeRoomId) !== rid) return;

  try { pushRecent("room", Number(room_id), (room_name || `Room #${room_id}`)); } catch {}

  activeRoomId = Number(room_id);
  updatePinnedBar();
  activeRoomName = room_name || "";
  activeRoomKey = rid;

  try {
    chrome.storage.local.set({ conn: { room: rid } });
  } catch {}

  try { __markRoomSeen?.(activeRoomId) || __clearRoomUnread(activeRoomId); } catch {}
  applyComposerPolicyUI();
}

function highlightActiveRoom() {
  const rid = activeRoomId != null ? String(activeRoomId) : "";
  const inputKey = (roomInput?.value || "").trim();

  const containers = [];
  if (roomsOwnedListEl) containers.push(roomsOwnedListEl);
  if (roomsMemberListEl) containers.push(roomsMemberListEl);
  if (publicRoomsSearchListEl) containers.push(publicRoomsSearchListEl);
  if (roomsListEl) containers.push(roomsListEl);

  const items = [];
  for (const c of containers) {
    try {
      items.push(...c.querySelectorAll(".room-item, .room-card"));
    } catch {}
  }

  for (const el of items) {
    const roomId = el.dataset.roomId || "";
    const roomAlias = el.dataset.roomAlias || "";
    const isActive =
      (rid && roomId === rid) ||
      (!rid && inputKey && (roomAlias === inputKey || roomId === inputKey));

    el.classList.toggle("active", !!isActive);
    el.classList.toggle("is-active", !!isActive);
  }
}

 // helpers
function makeInitials(name) {
  const s = String(name || "").trim();
  if (!s) return "??";
  const parts = s.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return (s[0] + (s[1] || "")).toUpperCase();
}

function renderDmList(items) {
  if (!dmListEl) return;
  dmListEl.innerHTML = "";
  const arr = Array.isArray(items) ? items : [];
  if (arr.length === 0) {
    const empty = document.createElement("div");
    empty.className = "dm-empty";
    empty.textContent = "No conversations yet.";
    dmListEl.appendChild(empty);
    return;
  }

  const pinned = [];
  const recent = [];

  for (const it of arr) {
    const tid = __normTid(it.thread_id);
    if (!tid) continue;
    if (__isDmPinned(tid)) pinned.push(it);
    else recent.push(it);
  }

  const renderSection = (title, list, cls = "") => {
    if (!list.length) return;
    const sec = document.createElement("div");
    sec.className = "dm-section " + cls;
    const head = document.createElement("div");
    head.className = "dm-section-title";
    head.textContent = title;
    sec.appendChild(head);

    const body = document.createElement("div");
    body.className = "dm-section-body";

    for (const it of list) {
    const threadId = Number(it.thread_id);
    const peer = (it.peer_username || "").trim() || "-";
    if (!threadId) continue;

    const btn = document.createElement("button");
    btn.className = "dm-item dm-item-card";
    btn.dataset.threadId = String(threadId);
    btn.title = `Open DM with ${peer}. Right-click or tap menu for actions.`;

    const avatar = document.createElement("span");
    avatar.className = "dm-avatar";
    avatar.textContent = makeInitials(peer);
    btn.appendChild(avatar);

    const main = document.createElement("span");
    main.className = "dm-main";
    const nameEl = document.createElement("span");
    nameEl.className = "dm-peer";
    nameEl.textContent = peer;
    const metaEl = document.createElement("span");
    metaEl.className = "dm-meta";
    const ts = __fmtDmTime(it.last_message_at);
    metaEl.textContent = ts ? `Last: ${ts}` : "No messages yet";
    main.appendChild(nameEl);
    main.appendChild(metaEl);
    btn.appendChild(main);

    const actionsBtn = document.createElement("button");
    actionsBtn.type = "button";
    actionsBtn.className = "dm-actions-btn";
    actionsBtn.textContent = "...";
    actionsBtn.title = "Conversation actions";
    actionsBtn.onclick = async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      await __openDmActionsMenu(threadId, peer);
    };
    btn.appendChild(actionsBtn);

    if (dmMode && Number(activeDmThreadId) === threadId) btn.classList.add("active");
    if (__isDmPinned(threadId)) btn.classList.add("is-pinned");

    btn.onclick = async () => {
      setModeDm(threadId, peer);
	  pushRecent("dm", threadId, peer);
      clearChat();

      try {
        await ensureDmKeyReady(threadId, peer);
      } catch (e) {
        // Locked: panel.js queues a pending retry. Don't spam dm_connect
        // with a key the background can't decrypt for yet.
        if (e?.code !== "DM_KEY_LOCKED") console.warn("ensureDmKeyReady failed:", e);
        return;
      }
      safePost({ type: "dm_connect", thread_id: threadId, peer_username: peer });
      safePost({ type: "dm_history", thread_id: threadId, limit: 50 });
    };

    btn.oncontextmenu = async (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      await __openDmActionsMenu(threadId, peer);
    };

    body.appendChild(btn);
    }

    sec.appendChild(body);
    dmListEl.appendChild(sec);
  };

  renderSection("Pinned", pinned, "is-pinned-section");
  renderSection("Recent", recent, "is-recent-section");

  __renderUnreadDotsInLists();
}

// ===== Room creation UI + Join + Button handlers =====
function openCreateRoom() {
  if (!createRoomDrawer) return;
  createRoomDrawer.classList.add("open");
  createRoomDrawer.setAttribute("aria-hidden", "false");
  if (newRoomNameInput) newRoomNameInput.focus();
  document.body.style.overflow = "hidden";
  resetCreateRoomLogoUI();
}

function closeCreateRoom() {
  if (!createRoomDrawer) return;
  createRoomDrawer.classList.remove("open");
  createRoomDrawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "auto";

  // reset fields
  if (newRoomNameInput) newRoomNameInput.value = "";
  if (newRoomPassInput) newRoomPassInput.value = "";
  if (newRoomDescInput) newRoomDescInput.value = "";
  if (newRoomLogoInput) newRoomLogoInput.value = "";
  if (newRoomPublicInput) newRoomPublicInput.checked = false;
  if (newRoomReadonlyInput) newRoomReadonlyInput.checked = false;
  updateNewRoomTypeHint();

  pendingNewRoomMeta = null;
  pendingPinFromSelection = null;

  if (createRoomResultEl) createRoomResultEl.textContent = "";
}

chrome.storage.local.get(["pendingRoomFromSelection"], (data) => {
  const p = data?.pendingRoomFromSelection;
  if (!p) return;

  pendingPinFromSelection = {
    url: p.url || null,
    text: p.text || null,
  };

  openCreateRoom();

  if (newRoomNameInput) {
    newRoomNameInput.value = p.suggestedName || "";
  }

  if (createRoomResultEl) {
    const preview = String(p.text || "").replace(/\s+/g, " ").slice(0, 180);
    const more = (p.text && p.text.length > 180) ? "-" : "";
    createRoomResultEl.textContent =
      `From selection: ${preview}${more}` +
      (p.url ? `\nURL: ${p.url}` : "");
  }
  chrome.storage.local.remove([
    "pendingRoomFromSelection",
    "pendingRoomFromSelectionMode",
  ]);
});

// handlers for drawer
if (openCreateRoomBtn) openCreateRoomBtn.onclick = openCreateRoom;
if (closeCreateRoomBtn) closeCreateRoomBtn.onclick = closeCreateRoom;
if (createRoomBackdrop) createRoomBackdrop.onclick = closeCreateRoom;

document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeCreateRoom();
});

// handlers
connectBtn.onclick = () => joinByInput();
async function joinByInput() {
  const key = (roomInput.value || "").trim();
  if (!key) return;

  pendingRoomAlias = key;
  lastConnectRoomName = key;

  const isNumericId = /^\d+$/.test(key);

  if (isNumericId) {
    const rid = Number(key);

    const saved = await new Promise((resolve) => {
      chrome.storage.local.get(["roomPassById"], async (data) => {
        const m = data.roomPassById || {};
        const raw = m[String(rid)] || "";
        resolve(await _readStoredPass(raw));
      });
    });

    if (saved) {
      pendingRoomId = rid;
      pendingRoomPass = saved;
      connect(saved);
      return;
    }

    const p = ((await __ui.prompt(`Password for room #${rid}`, {
      title: "Room password",
      placeholder: "password",
      inputType: "password",
      okText: "Join",
    })) || "").trim();
    if (!p) return;

    pendingRoomId = rid;
    pendingRoomPass = p;
    connect(p);
    return;
  }

const savedAliasPass = await getAliasPass(key);

if (savedAliasPass) {
  pendingRoomPass = savedAliasPass;
  connect(savedAliasPass);
  return;
}
connect("");
}

// VISIBILITY CHANGE HANDLER
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) {
    console.log("Tab visible, checking port health");

    const elapsed = Date.now() - (window.__lastPong || 0);

    if (elapsed > 35000) {
      console.warn(`Port likely dead (${elapsed}ms), reconnecting`);

      // Use rpcDisconnect (not port.disconnect()) so rpc.js's internal
      // `port` gets nulled. A direct local disconnect does NOT fire our
      // own onDisconnect listener, leaving rpc.js with a stale dead port
      // and wedging the next connectPort() behind its `if (port) return
      // port` guard. The rpcOnDisconnect subscriber (initPort) will null
      // panel.js's `port` and reset UI state.
      try { window.rpcDisconnect?.(); } catch {}

      initPort();
    } else {
      safePost({ type: "ping" });
    }
  }
});

disconnectBtn.onclick = () => {
  if (disconnectBtn.disabled) return;

  console.log("DISCONNECT CLICK");

  disconnectBtn.disabled = true;

  safePost({ type: "disconnect" });
};

// Leave room (remove membership)
if (leaveBtn) {
  leaveBtn.onclick = async () => {
    const rid = activeRoomId != null ? Number(activeRoomId) : 0;
    if (!rid) return;
    if (dmMode) return;

    const isOwner = !!roomOwnerById[String(rid)];
    if (isOwner) {
      await __ui.alert("You are the room owner. You cannot leave - you can only delete the room.");
      return;
    }

    const ok = await __ui.confirm("Leave the room? You will no longer see it in the list.");
    if (!ok) return;

    leaveBtn.disabled = true;
    safePost({ type: "rooms_leave", roomId: rid });
  };
}

sendBtn.onclick = send;
document.getElementById("replyBarClose")?.addEventListener("click", __clearReplyTo);
if (attachBtn) {
  attachBtn.onclick = pickAndUploadFile;
}
if (refreshRoomsBtn) {
  refreshRoomsBtn.onclick = requestMyRooms;
}
msgInput.addEventListener("keydown", e => {
  if (e.key === "Enter") send();
});

if (createRoomBtn) {
  createRoomBtn.onclick = async () => {
    const name = (newRoomNameInput?.value || "").trim();
    const password = (newRoomPassInput?.value || "");
    const desc = (newRoomDescInput?.value || "").trim();
    const logoFile = (newRoomLogoInput && newRoomLogoInput.files && newRoomLogoInput.files[0]) ? newRoomLogoInput.files[0] : null;
    const is_public = !!newRoomPublicInput?.checked;
    const is_readonly = !!newRoomReadonlyInput?.checked;

    pendingNewRoomMeta = { description: desc || null, logoFile };

    if (!name) {
      alert("Please enter the Room name");
      return;
    }

    if (createRoomResultEl) createRoomResultEl.textContent = "Creating...";

    try {
      await ensureCryptoReady({ interactive: true, reason: "Create room" });
    } catch (e) {
      console.warn("Crypto init failed before room create:", e?.message || e);

      if (REQUIRE_E2EE_FOR_NEW_ROOMS) {
        if (createRoomResultEl) createRoomResultEl.textContent = "";
        alert("Cannot create a secured room: cryptography is not ready. ((unlock/\u0440\u0430\u0437\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u0442\u044c).");
        return;
      }
    }

    let encrypted_room_key = null;
    pendingCreatedRoomKeyBase64 = null;

    if (REQUIRE_E2EE_FOR_NEW_ROOMS) {
      const myPubPem = CM()?.userPublicKeyPem;
      if (!myPubPem) {
        if (createRoomResultEl) createRoomResultEl.textContent = "";
        alert("No public key. Cannot create a secured room.");
        return;
      }

      try {
        const roomKey = await CU().generateRoomKey(true);
        const roomKeyBase64 = await CU().exportRoomKey(roomKey);
        encrypted_room_key = await CU().encryptRoomKeyForUser(
          myPubPem,
          roomKeyBase64
        );

        pendingCreatedRoomKeyBase64 = roomKeyBase64;

        console.log("Room key generated and encrypted (E2EE required)");
      } catch (err) {
        console.error("Failed to generate/encrypt room key:", err, err?.name, err?.message);
        if (createRoomResultEl) createRoomResultEl.textContent = "";
        alert(`Failed to create and save the room key: ${err?.name || err}`);
        return;
      }
    }

    safePost({
      type: "rooms_create",
      name,
      password,
      encrypted_room_key,
      is_public,
      is_readonly,
    });
  };
}

// ===== Presence / Room rendering / Friends / Recent =====
function renderPresence(online) {
  if (!presenceEl) return;

  const onlineList = Array.isArray(online) ? online : [];
  const onlineSet = new Set(onlineList.map(x => String(x || "").trim()).filter(Boolean));

  const rid = activeRoomId != null ? String(activeRoomId) : "";
  const meName = (nameInput?.value || "anon").trim();
  const isOwner = !!roomOwnerById[rid];

  const members = Array.isArray(roomMembersById[rid]) ? roomMembersById[rid] : [];

  // Get current user's role
  const myMember = members.find(m => String(m.username || "").trim().toLowerCase() === meName.toLowerCase());
  const myRole = myMember ? (myMember.role || "member") : (roomRoleById[rid] || (isOwner ? "owner" : "member"));
  if (rid) roomRoleById[rid] = myRole;
  const canModerate = myRole === "owner" || myRole === "admin";
  applyComposerPolicyUI();

  const raw = members.length
    ? members.map(m => ({
        username: String(m.username || "").trim(),
        role: m.role || (m.is_owner ? "owner" : "member"),
        is_owner: !!m.is_owner
      })).filter(m => m.username)
    : onlineList.map(u => ({ username: String(u || "").trim(), role: "member", is_owner: false }))
        .filter(m => m.username);

  const filtered = presenceFilter
    ? raw.filter(x => x.username.toLowerCase().includes(presenceFilter.toLowerCase()))
    : raw;

  presenceEl.innerHTML = "";

  // ===== Head =====
  const head = document.createElement("div");
  head.className = "presence-head";

  const title = document.createElement("div");
  title.className = "presence-title";
  title.textContent = members.length ? "Members" : "Online";
  head.appendChild(title);

  const count = document.createElement("div");
  count.className = "presence-count";
  count.textContent = `(${raw.length})`;
  head.appendChild(count);

  const spacer = document.createElement("div");
  spacer.className = "presence-spacer";
  head.appendChild(spacer);

  const search = document.createElement("input");
  search.className = "presence-search";
  search.placeholder = "search...";
  search.value = presenceFilter;
  search.oninput = () => {
    presenceFilter = search.value || "";
    renderPresence(onlineList);
  };
  head.appendChild(search);

  const toggle = document.createElement("button");
  toggle.className = "presence-toggle";
  toggle.type = "button";
  toggle.textContent = presenceCollapsed ? "v" : "^";
toggle.onclick = () => {
  presenceCollapsed = !presenceCollapsed;

  chrome.storage.local.set({ presenceCollapsed });

  renderPresence(onlineList);
};
  head.appendChild(toggle);

  if (isOwner && activeRoomId) {
    const reqBtn = document.createElement("button");
    reqBtn.className = "presence-toggle";
    reqBtn.type = "button";
    reqBtn.textContent = "Requests";
    reqBtn.title = "Join requests (public rooms)";
    reqBtn.onclick = () => {
      safePost({ type: "rooms_join_requests_list", roomId: Number(activeRoomId) });
    };
    head.appendChild(reqBtn);
  }

  presenceEl.appendChild(head);

  if (presenceCollapsed) presenceEl.classList.add("collapsed");
  else presenceEl.classList.remove("collapsed");

  // ===== Body =====
  const body = document.createElement("div");
  body.className = "presence-body";

  if (!filtered.length) {
    const empty = document.createElement("div");
    empty.style.opacity = "0.7";
    empty.style.padding = "4px 6px";
    empty.textContent = raw.length ? "No matches" : "-";
    body.appendChild(empty);
    presenceEl.appendChild(body);
    return;
  }

  for (const m of filtered) {
    const username = m.username;
    const memberRole = m.role || "member";
    const isOnline = onlineSet.has(username);
    const isMe = username.toLowerCase() === meName.toLowerCase();

    const row = document.createElement("div");
    row.className = "presence-row";

    const left = document.createElement("div");
    left.className = "presence-left";
    left.style.opacity = isOnline ? "1" : "0.65";
    
    // Role badge
    let roleBadge = "";
    if (memberRole === "owner") {
      roleBadge = " \uD83D\uDC51";
    } else if (memberRole === "admin") {
      roleBadge = " \u26A1";
    }
    left.textContent = (isOnline ? "\u25CF" : "\u25CB") + username + roleBadge;
    row.appendChild(left);

    row.style.cursor = 'pointer';
    left.style.cursor = 'pointer';
    row.addEventListener('click', (e) => {
      const t = e.target;
      if (t && (t.tagName === 'BUTTON' || t.tagName === 'INPUT' || t.tagName === 'SELECT' || (t.closest && (t.closest('button') || t.closest('select'))))) return;
      openProfile(username);
    });

    // Actions container
    const actions = document.createElement("div");
    actions.className = "presence-actions";
    actions.style.display = "flex";
    actions.style.gap = "4px";
    actions.style.alignItems = "center";

    // Role selector (only owner can change roles, not for self, not for other owners)
    if (isOwner && !isMe && memberRole !== "owner") {
      const roleSelect = document.createElement("select");
      roleSelect.className = "presence-role-select";
      roleSelect.style.fontSize = "10px";
      roleSelect.style.padding = "1px 2px";
      roleSelect.style.cursor = "pointer";
      roleSelect.title = "Change role";

      const optAdmin = document.createElement("option");
      optAdmin.value = "admin";
      optAdmin.textContent = "Admin";
      optAdmin.selected = memberRole === "admin";

      const optMember = document.createElement("option");
      optMember.value = "member";
      optMember.textContent = "Member";
      optMember.selected = memberRole === "member";

      roleSelect.appendChild(optAdmin);
      roleSelect.appendChild(optMember);

      roleSelect.onchange = (e) => {
        e.stopPropagation();
        if (!activeRoomId) return;
        const newRole = roleSelect.value;
        if (newRole === memberRole) return;

        const ok = confirm(`Change ${username}'s role to ${newRole}?`);
        if (!ok) {
          roleSelect.value = memberRole;
          return;
        }

        safePost({ type: "rooms_set_role", roomId: activeRoomId, username, role: newRole });
      };

      actions.appendChild(roleSelect);
    }

    // Kick button
    // Owner can kick anyone except owner
    // Admin can kick only members (not admins or owner)
    const canKick = canModerate && !isMe && memberRole !== "owner" && 
                    (myRole === "owner" || (myRole === "admin" && memberRole === "member"));
    
    if (canKick) {
      const kickBtn = document.createElement("button");
      kickBtn.className = "presence-kick";
      kickBtn.type = "button";
      kickBtn.textContent = "Kick";
      kickBtn.title = "Remove from room";

      kickBtn.onclick = (e) => {
        e.stopPropagation();
        if (!activeRoomId) return;

        const ok = confirm(`Remove user "${username}" from the room?`);
        if (!ok) return;

        safePost({ type: "rooms_kick", roomId: activeRoomId, username });
      };

      actions.appendChild(kickBtn);
    }

    if (actions.childNodes.length > 0) {
      row.appendChild(actions);
    }

    body.appendChild(row);
  }

  presenceEl.appendChild(body);
}

function renderCurrentRoom(opts = {}) {
  if (!currentRoomEl) return;

  const online = !!opts.online;
  const inputRoom = (roomInput?.value || "").trim();
  const rid = activeRoomId != null ? String(activeRoomId) : "";
  const rname = (activeRoomName || "").trim();

  let title = "Room: -";

  if (dmMode) {
    const who = activeDmPeer ? activeDmPeer : "-";
    currentRoomEl.textContent = `Direct: ${who}`;
    currentRoomEl.style.opacity = online ? "1" : "0.7";
    applyComposerPolicyUI();
    return;
  }

  if (rname || rid) {
    const namePart = rname ? rname : "";
    const idPart = rid ? ` <#${rid}>` : "";
    title = `Room: ${namePart}${idPart}`.trim();
  } else if (inputRoom) {
    title = `Room: ${inputRoom}`;
  }
  currentRoomEl.textContent = title;
  currentRoomEl.style.opacity = online ? "1" : "0.7";
  applyComposerPolicyUI();
}

function roomInitials(s) {
  const t = (s || "").trim();
  if (!t) return "R";
  const parts = t.split(/\s+/).filter(Boolean);
  const a = (parts[0] || "").slice(0, 1).toUpperCase();
  const b = (parts[1] || "").slice(0, 1).toUpperCase();
  return (a + b).slice(0, 2);
}

function fullUrl(path) {
  if (!path) return null;
  if (String(path).startsWith("http://") || String(path).startsWith("https://")) return String(path);
  return API_BASE + String(path);
}

const __imageBlobCache = new Map();
const __IMAGE_CACHE_MAX = 200;

async function loadImageWithAuth(pathOrToken, isToken = false) {
  if (!pathOrToken) return null;

  let url;
  if (isToken) {
    url = API_BASE + "/files/" + String(pathOrToken);
  } else {
    url = fullUrl(pathOrToken);
  }
  if (!url) return null;

  //do not log raw tokens; keep logs only in debug
  if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
    const shown = isToken
      ? `[token len=${String(pathOrToken || "").length}]`
      : String(pathOrToken || "");
    console.log(`loadImageWithAuth: ${isToken ? "token" : "url"} = ${shown}, final url = ${url}`);
  }

  if (__imageBlobCache.has(url)) return __imageBlobCache.get(url);

  try {
    const token = await requestToken();
    if (!token) return null;

    const response = await fetch(url, {
      headers: { Authorization: "Bearer " + token }
    });

    if (!response.ok) {
      if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
        console.warn(`Failed to load image from ${url}: ${response.status}`);
      }
      return null;
    }

    const blob = await response.blob();

    if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
      console.log("Blob received:", { size: blob.size, type: blob.type, url });
    }

    if (!blob.type || !blob.type.startsWith("image/")) {
      if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
        console.error(`Blob is not an image! Type: ${blob.type}`);
      }
      return null;
    }

    try {
      await createImageBitmap(blob);
      if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
        console.log("createImageBitmap OK (image decodes)");
      }
    } catch (e) {
      if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
        console.error("createImageBitmap FAILED (image data invalid/corrupted)", e);
      }
      return null;
    }

    const dataUrl = await new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(String(fr.result || ""));
      fr.onerror = () => reject(fr.error || new Error("FileReader failed"));
      fr.readAsDataURL(blob);
    });

    if (__imageBlobCache.size >= __IMAGE_CACHE_MAX) {
      const oldest = __imageBlobCache.keys().next().value;
      __imageBlobCache.delete(oldest);
    }
    __imageBlobCache.set(url, dataUrl);

    if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
      console.log(`loadImageWithAuth success: ${url} -> dataUrl(len=${dataUrl.length})`);
    }

    return dataUrl;
  } catch (e) {
    if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
      console.error("loadImageWithAuth failed:", e);
    }
    return null;
  }
}

const __roomMetaCache = new Map(); // roomId -> {description, logo_token, logo_url}

// Load metadata cache from storage on startup
chrome.storage.local.get(['roomMetaCache'], (data) => {
  if (data.roomMetaCache) {
    try {
      const cached = JSON.parse(data.roomMetaCache);
      Object.entries(cached).forEach(([key, value]) => {
        __roomMetaCache.set(key, value);
      });
      console.log("Loaded room metadata cache:", __roomMetaCache.size, "rooms");
    } catch (e) {
      console.error("Failed to load room metadata cache:", e);
    }
  }
});

// Save metadata cache to storage
function saveRoomMetaCache() {
  const obj = {};
  __roomMetaCache.forEach((value, key) => {
    obj[key] = value;
  });
  chrome.storage.local.set({ roomMetaCache: JSON.stringify(obj) });
}

async function getRoomMeta(roomId, force = false) {
  const key = String(roomId);
  if (!force && __roomMetaCache.has(key)) return __roomMetaCache.get(key);

  safePost({ type: "rooms_meta_get", roomId: Number(roomId) });
  const meta = await waitRoomMeta(Number(roomId), "get");
  const norm = {
    description: meta?.description ?? null,
    logo_token: meta?.logo_token ?? null,
    logo_url: meta?.logo_url ?? null,
  };
  __roomMetaCache.set(key, norm);
  return norm;
}

function renderRooms(rooms, publicRooms = []) {
  // Prefer Rooms tab in Friends drawer
  const hasRoomsTab =
    !!roomsOwnedListEl || !!roomsMemberListEl || !!publicRoomsSearchListEl;

  // Fallback to old sidebar list (if present)
  if (!hasRoomsTab && !roomsListEl) return;

  const mine = Array.isArray(rooms) ? rooms : [];
  const pubs = Array.isArray(publicRooms) ? publicRooms : [];
  
  // Debug: log logo tokens
  console.log("Rendering rooms with logo data:", 
    mine.map(r => ({ id: r.id, name: r.name, logo_token: r.logo_token, logo_url: r.logo_url }))
  );

  // ---------- Rooms tab render ----------
  if (hasRoomsTab) {
    if (roomsOwnedListEl) roomsOwnedListEl.innerHTML = "";
    if (roomsMemberListEl) roomsMemberListEl.innerHTML = "";
    if (publicRoomsSearchListEl) publicRoomsSearchListEl.innerHTML = "";

    const owned = mine.filter(r => !!r.is_owner);
    const member = mine.filter(r => !r.is_owner);

    // --- helpers ---
    const joinMineRoom = async (r) => {
      const key = r.alias ? r.alias : String(r.id);
      roomInput.value = key;
      renderCurrentRoom({ online: false });
      highlightActiveRoom();

  //Variant 2: unlock crypto interactively on explicit user action (joining/opening room)
  try {
    const okCrypto = await ensureCryptoReady({ interactive: true, reason: `Open room: ${r.name || r.alias || r.id}` });
    if (!okCrypto) return; // user cancelled unlock
  } catch (e) {
    try { await __ui.alert("Crypto unlock failed: " + (e?.message || e)); } catch {}
    return;
  }

      if (r.has_password) {
        const pass = await new Promise((resolve) => {
          chrome.storage.local.get(["roomPassById"], async (data) => {
            const m = data.roomPassById || {};
            const raw = m[String(r.id)] || "";
            resolve(await _readStoredPass(raw));
          });
        });

        let roomPass = pass;
        if (!roomPass) {
          roomPass = (await __ui.prompt(`Password for the room "${r.name}"`, {
            title: "Room password",
            placeholder: "password",
            inputType: "password",
            okText: "Unlock",
            cancelText: "Cancel",
        })).trim();
        }
        if (!roomPass) return;

        pendingRoomId = r.id;
        pendingRoomPass = roomPass;
        lastConnectRoomName = r.name || r.alias || String(r.id);
        connect(roomPass);
      } else {
        connect("");
      }
    };

    const makeMineCard = (r) => {

      roomOwnerById[String(r.id)] = !!r.is_owner;
      roomRoleById[String(r.id)] = r.role || (r.is_owner ? "owner" : "member");
      roomHasPasswordById[String(r.id)] = !!r.has_password;
      roomReadonlyById[String(r.id)] = !!r.is_readonly;

      const item = document.createElement("div");
      item.className = "friend-item room-card";
      item.dataset.roomId = String(r.id ?? "");
      item.dataset.roomAlias = String(r.alias ?? "");

      // ---- left side ----
      const left = document.createElement("div");
      left.className = "roomcard-left";

      const top = document.createElement("div");
      top.className = "roomcard-top";

      const logo = document.createElement("div");
      logo.className = "roomcard-logo";
      logo.style.cssText = `
        width: 48px !important;
        height: 48px !important;
        border-radius: 8px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        flex-shrink: 0 !important;
        font-weight: 600 !important;
        font-size: 18px !important;
        overflow: hidden !important;
        background-color: #f0f0f0 !important;
      `;
      
if (typeof DEBUG_LOGS !== "undefined" ? DEBUG_LOGS : false) {
  console.log(`makeMineCard for room ${r.id} (${r.name}):`, {
    logo_token: r.logo_token ? `[token len=${String(r.logo_token).length}]` : null,
    has_logo_token: !!r.logo_token,
    has_logo_url: !!r.logo_url,
    logo_url: r.logo_url
  });
}
      // Set initials as fallback
      logo.textContent = roomInitials(r.name || r.alias || "");
      
      // Try logo_token first, then logo_url (even /rooms/{id}/logo with auth)
      const logoSrc = r.logo_token || r.logo_url;
      const useToken = !!r.logo_token;
      if (logoSrc) {
        loadImageWithAuth(logoSrc, useToken).then(blobUrl => {
          if (blobUrl && logo && logo.parentNode) { // Check element still exists
            console.log(`Creating img element for room ${r.id}:`, blobUrl);
            
            // Clear text first
            logo.textContent = "";
            
            // Remove flex display and change to block for proper img sizing
            logo.style.display = "block";
            logo.style.backgroundColor = "transparent";
            
            // Create img element WITHOUT src initially
            const img = document.createElement("img");
            img.alt = "Room logo";
            img.style.cssText = `
              width: 100% !important;
              height: 100% !important;
              object-fit: cover !important;
              border-radius: 8px !important;
              display: block !important;
            `;
            
            // Add to DOM first
            try {
              logo.appendChild(img);
              logo.classList.add("has-logo");
              
              // Set src AFTER adding to DOM
              img.src = blobUrl;
              
              // Debug: check img element
              console.log(`Logo img added for room ${r.id}`, {
                imgSrc: img.src,
                imgComplete: img.complete,
                imgNaturalWidth: img.naturalWidth,
                blobUrl: blobUrl,
                parentNode: img.parentNode ? 'exists' : 'null'
              });
              
              // Listen for load/error
              img.onload = () => {
                console.log(`Image loaded successfully for room ${r.id}`, {
                  naturalWidth: img.naturalWidth,
                  naturalHeight: img.naturalHeight
                });
              };
              img.onerror = (e) => {
                console.error(`Image failed to load for room ${r.id}`, e, {
                  src: img.src,
                  blobUrl: blobUrl
                });
              };
            } catch (e) {
              console.warn(`Failed to add logo for room ${r.id}:`, e);
            }
          }
        }).catch((err) => {
          console.error(`Logo load failed for room ${r.id}:`, err);
          // Keep initials on error
        });
      }

      const titleWrap = document.createElement("div");
      titleWrap.style.minWidth = "0";

      const name = document.createElement("div");
      name.className = "roomcard-name";
      name.textContent = (r.name || r.alias || `Room #${r.id}`).trim();

      const meta = document.createElement("div");
      meta.className = "roomcard-meta";
      const role = r.role ? (r.role.charAt(0).toUpperCase() + r.role.slice(1)) : (r.is_owner ? "Owner" : "Member");
      const vis = r.is_public ? "Public" : "Private";
      const ro = r.is_readonly ? "read-only" : "chat";
      const passLabel = r.has_password ? "pwd" : "open";
      const descShort = (r.description || "").trim();
      meta.textContent =
        `${role} - ${vis} - ${ro} - ${passLabel} - id:${r.id}` +
        (r.alias ? ` - ${r.alias}` : "") +
        (descShort ? ` - ${descShort.slice(0, 36)}` : "");

      titleWrap.appendChild(name);
      titleWrap.appendChild(meta);

      top.appendChild(logo);
      top.appendChild(titleWrap);

      left.appendChild(top);

      // ---- right actions ----
      const actions = document.createElement("div");
      actions.className = "friend-actions";

      const joinBtn = document.createElement("button");
      joinBtn.type = "button";
      joinBtn.textContent = "Join";
      joinBtn.onclick = (e) => { e.stopPropagation(); joinMineRoom(r); };
      actions.appendChild(joinBtn);

      // Leave room (for members only). This is a voluntary exit, not a kick.
      // IMPORTANT: handler of msg.type === "rooms_leave" in panel.js must not disconnect you
      // from the current room unless you are leaving that exact room.
      if (!r.is_owner) {
        const leaveBtnMini = document.createElement("button");
        leaveBtnMini.type = "button";
        leaveBtnMini.textContent = "Leave";
        leaveBtnMini.onclick = async (e) => {
          e.stopPropagation();
          const ok = await __ui.confirm(`Leave room "${(r.name || r.alias || r.id)}"?`, "Leave room");
          if (!ok) return;
          safePost({ type: "rooms_leave", roomId: r.id });
        };
        actions.appendChild(leaveBtnMini);
      }

      if (r.is_owner) {
        const inviteBtnMini = document.createElement("button");
        inviteBtnMini.type = "button";
        inviteBtnMini.textContent = "Invite";
        inviteBtnMini.onclick = (e) => {
          e.stopPropagation();
          (async () => {
            const uname = (await __ui.prompt("Username to invite:", {
              title: "Invite user",
              placeholder: "username",
              value: "",
              inputType: "text",
              okText: "Invite",
              cancelText: "Cancel",
            })).trim();
            if (!uname) return;
            __sendRoomInvite(r.id, uname);
          })();
        };
        actions.appendChild(inviteBtnMini);

        const delBtn = document.createElement("button");
        delBtn.type = "button";
        delBtn.textContent = "Delete";
        delBtn.onclick = async (e) => {
          e.stopPropagation();
          const ok = await __ui.confirm(`Delete room "${r.name}"?\nThis action cannot be undone.`, "Delete room");
          if (!ok) return;
          safePost({ type: "rooms_delete", roomId: r.id });
        };
        actions.appendChild(delBtn);
      }

      item.appendChild(left);
      item.appendChild(actions);

      item.onclick = () => joinMineRoom(r);

      item.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (!r.is_owner) return;

        (async () => {
          const ok = await __ui.confirm(
            `Delete room "${r.name || r.alias || r.id}"?\nThis cannot be undone.`,
            "Delete room"
          );
          if (!ok) return;
          safePost({ type: "rooms_delete", roomId: r.id });
        })();
      });

      return item;
    };

    const makePublicCard = (pr) => {
  const item = document.createElement("div");
  item.className = "friend-item room-card";
  item.dataset.roomId = String(pr.id ?? "");
  item.dataset.roomAlias = String(pr.alias ?? "");
  roomReadonlyById[String(pr.id)] = !!pr.is_readonly;

  const left = document.createElement("div");
  left.className = "roomcard-left";

  const top = document.createElement("div");
  top.className = "roomcard-top";

  const logo = document.createElement("div");
  logo.className = "roomcard-logo";
  logo.style.cssText = `
    width: 48px !important;
    height: 48px !important;
    border-radius: 8px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    flex-shrink: 0 !important;
    font-weight: 600 !important;
    font-size: 18px !important;
    overflow: hidden !important;
    background-color: #f0f0f0 !important;
  `;
  
  // Set initials as fallback
  logo.textContent = roomInitials(pr.name || pr.alias || "");
  
  const logoSrc = pr.logo_token || pr.logo_url;
  const useToken = !!pr.logo_token;
  if (logoSrc) {
    loadImageWithAuth(logoSrc, useToken).then(blobUrl => {
      if (blobUrl && logo && logo.parentNode) {
        try {
          logo.textContent = "";
          logo.style.display = "block";
          logo.style.backgroundColor = "transparent";
          
          const img = document.createElement("img");
          img.src = blobUrl;
          img.alt = "Room logo";
          img.style.cssText = `
            width: 100% !important;
            height: 100% !important;
            object-fit: cover !important;
            border-radius: 8px !important;
            display: block !important;
          `;
          logo.appendChild(img);
          logo.classList.add("has-logo");
        } catch (e) {
          console.warn(`Failed to add public room logo:`, e);
        }
      }
    }).catch(() => {
      // Keep initials on error
    });
  }

  const titleWrap = document.createElement("div");
  titleWrap.style.minWidth = "0";

  const name = document.createElement("div");
  name.className = "roomcard-name";
  name.textContent = (pr.name || pr.alias || `Room #${pr.id}`).trim();

  const meta = document.createElement("div");
  meta.className = "roomcard-meta";
  const st = (pr.my_status || "").toLowerCase();
  const statusLabel = st === "requested" ? "Pending" : (st === "accepted" ? "Member" : "Request");
  const ro = pr.is_readonly ? "read-only" : "chat";
  const passLabel = pr.has_password ? "pwd" : "open";
  const descShort = (pr.description || "").trim();
  meta.textContent =
    `Public - ${statusLabel} - ${ro} - ${passLabel} - id:${pr.id}` +
    (pr.alias ? ` - ${pr.alias}` : "") +
    (descShort ? ` - ${descShort.slice(0, 36)}` : "");

  titleWrap.appendChild(name);
  titleWrap.appendChild(meta);

  top.appendChild(logo);
  top.appendChild(titleWrap);

  left.appendChild(top);

  const actions = document.createElement("div");
  actions.className = "friend-actions";

  // Member -> Join, Requested -> Pending, else -> Request
  if (st === "accepted") {
    const joinBtn = document.createElement("button");
    joinBtn.type = "button";
    joinBtn.textContent = "Join";
    joinBtn.onclick = async (e) => {
      e.stopPropagation();
      const key = pr.alias ? pr.alias : String(pr.id);
      roomInput.value = key;
      renderCurrentRoom({ online: false });
      highlightActiveRoom();

      pushRecent("room", pr.id, (pr.name || pr.alias || `Room #${pr.id}`).trim());

      //Variant 2: unlock crypto on explicit user action (joining public room)
      try {
        const okCrypto = await ensureCryptoReady({
          interactive: true,
          reason: `Open room: ${pr.name || pr.alias || pr.id}`,
        });
        if (!okCrypto) return; // user cancelled
      } catch (e) {
        try { await __ui.alert("Crypto unlock failed: " + (e?.message || e)); } catch {}
        return;
      }

      if (pr.has_password) {
        const p = ((await __ui.prompt(`Password for the room "${pr.name}"`, {
          title: "Room password",
          placeholder: "password",
          inputType: "password",
          okText: "Join",
          cancelText: "Cancel",
        })) || "").trim();

        if (!p) return;
        pendingRoomId = pr.id;
        pendingRoomPass = p;
        lastConnectRoomName = pr.name || pr.alias || String(pr.id);
        connect(p);
      } else {
        connect("");
      }
    };

    actions.appendChild(joinBtn);
  } else if (st === "requested") {
    const pendingBtn = document.createElement("button");
    pendingBtn.type = "button";
    pendingBtn.textContent = "Pending";
    pendingBtn.disabled = true;
    actions.appendChild(pendingBtn);
  } else {
    const reqBtn = document.createElement("button");
    reqBtn.type = "button";
    reqBtn.textContent = "Request";
    reqBtn.onclick = (e) => {
      e.stopPropagation();
      safePost({ type: "rooms_join_request", roomId: pr.id, encrypted_room_key: null });
    };
    actions.appendChild(reqBtn);
  }

  item.appendChild(left);
  item.appendChild(actions);

  return item;
};

    // Owned / Member lists
    if (roomsOwnedListEl) {
      if (!owned.length) {
        const empty = document.createElement("div");
        empty.className = "sidebar-note";
        empty.textContent = "No rooms where you are owner.";
        roomsOwnedListEl.appendChild(empty);
      } else {
        for (const r of owned) roomsOwnedListEl.appendChild(makeMineCard(r));
      }
    }

    if (roomsMemberListEl) {
      if (!member.length) {
        const empty = document.createElement("div");
        empty.className = "sidebar-note";
        empty.textContent = "No rooms where you are member.";
        roomsMemberListEl.appendChild(empty);
      } else {
        for (const r of member) roomsMemberListEl.appendChild(makeMineCard(r));
      }
    }

    // Public search
    if (publicRoomsSearchListEl) {
      const q = (publicRoomsSearchQuery || "").trim().toLowerCase();
      if (!q) {
        const hint = document.createElement("div");
        hint.className = "sidebar-note";
        hint.textContent = "Type to search public rooms by name.";
        publicRoomsSearchListEl.appendChild(hint);
      } else {
        const filtered = pubs
          .filter(pr => String(pr?.name || "").toLowerCase().includes(q))
          .slice(0, 30);

        if (!filtered.length) {
          const empty = document.createElement("div");
          empty.className = "sidebar-note";
          empty.textContent = "No public rooms found.";
          publicRoomsSearchListEl.appendChild(empty);
        } else {
          for (const pr of filtered) publicRoomsSearchListEl.appendChild(makePublicCard(pr));
        }
      }
    }

    highlightActiveRoom();
    __renderUnreadDotsInLists();
    return;
  }

  // ---------- Old sidebar render (kept for safety) ----------
  // If you still have roomsListEl in HTML, you can keep the previous compact renderer.
  // Right now (per request) rooms were moved into Friends drawer, so we don't render anything here.
  if (roomsListEl) {
    roomsListEl.innerHTML = "";
  }

  highlightActiveRoom();
  __renderUnreadDotsInLists();
  __updateRailUnreadDots();
}

highlightActiveRoom();

// --- rooms request helper ---
function requestMyRooms() {
  safePost({ type: "rooms_mine" });
  safePost({ type: "rooms_public_list" });
}

function requestRoomMembers(roomId) {
  if (!roomId) return;
  safePost({ type: "rooms_members_get", roomId });
}

function openFriends(arg) {
  if (!friendsDrawer) return;
  // friendsBtn onclick passes an Event; we also allow openFriends("roomreq")
  const tab = (typeof arg === "string") ? arg : "friends";
  friendsDrawer.classList.add("open");
  friendsDrawer.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  setFriendsTab(tab);
  requestFriendsAll();
  requestGroupInvites();

  if (tab === "roomreq") refreshRoomJoinRequestsAll();

  // Mark as seen when user actually opens the drawer.
  // Delay a bit so handlers can populate __notifSetList first.
  if (tab === "friends") {
    setTimeout(() => { window.__notifMarkSeenKind?.("friends_all"); }, 250);
  } else if (tab === "roomreq") {
    setTimeout(() => { window.__notifMarkSeenKind?.("room_join_requests"); }, 250);
  }

  setTimeout(() => {
    if (tab === "friends") friendNameInput?.focus();
  }, 0);
}

function openRoomsDrawer() {
  if (!roomsDrawer) return;
  roomsDrawer.classList.add("open");
  roomsDrawer.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";

  requestMyRooms();

  setTimeout(() => {
    try { publicRoomsSearchEl?.focus({ preventScroll: true }); }
    catch { publicRoomsSearchEl?.focus(); }
  }, 0);
}

function closeRoomsDrawer() {
  if (!roomsDrawer) return;

  if (roomsDrawer.contains(document.activeElement)) {
    const opener = document.getElementById("roomsBtn");
    if (opener) opener.focus();
    else document.activeElement?.blur?.();
  }

  roomsDrawer.classList.remove("open");
  roomsDrawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "auto";
}

function setFriendsTab(tab) {
  const t = String(tab || "friends");

  const isFriends = t === "friends";
  const isRoomReq = t === "roomreq";

  if (friendsTabBtn) friendsTabBtn.classList.toggle("is-active", isFriends);
  if (roomReqTabBtn) roomReqTabBtn.classList.toggle("is-active", isRoomReq);

  if (friendsTabPaneEl) friendsTabPaneEl.style.display = isFriends ? "" : "none";
  if (roomReqTabPaneEl) roomReqTabPaneEl.style.display = isRoomReq ? "" : "none";

  if (isRoomReq) refreshRoomJoinRequestsAll();

  // When switching tabs, consider the list "seen" (user is looking at it).
  if (isRoomReq) {
    setTimeout(() => { window.__notifMarkSeenKind?.("room_join_requests"); }, 250);
  }
  if (isFriends) {
    setTimeout(() => { window.__notifMarkSeenKind?.("friends_all"); }, 250);
  }

  if (isFriends) {
    setTimeout(() => {
      try { friendNameInput?.focus({ preventScroll: true }); }
      catch { friendNameInput?.focus(); }
    }, 0);
  }
}

function refreshRoomJoinRequestsAll() {
  safePost({ type: "rooms_join_requests_all" });
}

if (friendsTabBtn) friendsTabBtn.onclick = () => setFriendsTab("friends");
if (roomReqTabBtn) roomReqTabBtn.onclick = () => setFriendsTab("roomreq");
if (roomReqRefreshBtn) roomReqRefreshBtn.onclick = () => refreshRoomJoinRequestsAll();
if (roomsRefreshBtnEl) roomsRefreshBtnEl.onclick = () => requestMyRooms();

if (publicRoomsSearchEl) {
  publicRoomsSearchEl.addEventListener("input", () => {
    publicRoomsSearchQuery = (publicRoomsSearchEl.value || "").trim().toLowerCase();
    renderRooms(lastMineRooms || [], lastPublicRooms || []);
  });
}

function setRoomReqBadge(count) {
  const n = Number(count) || 0;
  if (!roomReqBadgeEl) return;
  if (n <= 0) {
    roomReqBadgeEl.style.display = "none";
    roomReqBadgeEl.textContent = "";
    return;
  }
  roomReqBadgeEl.style.display = "inline-flex";
  roomReqBadgeEl.textContent = String(n);
}

/* ================= Notifications: "seen" state (client-side) =================
   Problem it solves:
   - badges re-appear after you already opened/seen the list
   - consistent behavior for friends requests + room invites + room join requests

   We store a small set of seen notification IDs in chrome.storage.local.
*/

const __NOTIF_SEEN_STORE_KEY = "notif_seen_v1";
let __notifSeenCache = null; // Set<string>
let __notifSeenLoadPromise = null;

async function __notifLoadSeenSet() {
  if (__notifSeenCache) return __notifSeenCache;
  if (__notifSeenLoadPromise) return __notifSeenLoadPromise;

  __notifSeenLoadPromise = (async () => {
    try {
      const r = await chrome.storage.local.get(__NOTIF_SEEN_STORE_KEY);
      const arr = Array.isArray(r?.[__NOTIF_SEEN_STORE_KEY]) ? r[__NOTIF_SEEN_STORE_KEY] : [];
      __notifSeenCache = new Set(arr.map(String));
    } catch {
      __notifSeenCache = new Set();
    }
    return __notifSeenCache;
  })().finally(() => {
    __notifSeenLoadPromise = null;
  });

  return __notifSeenLoadPromise;
}

async function __notifSaveSeenSet(setObj) {
  const arr = Array.from(setObj || []).slice(-2000); // cap growth
  try {
    await chrome.storage.local.set({ [__NOTIF_SEEN_STORE_KEY]: arr });
  } catch {
    // ignore
  }
}

function __normU(s) {
  return String(s || "").trim().toLowerCase();
}

function __notifKeyFriendsIncoming(it) {
  const u = __normU(it?.username || it?.from_username || it?.from || it?.user);
  return u ? `fr:${u}` : "";
}

function __notifKeyRoomInvite(it) {
  const rid = Number(it?.room_id ?? it?.roomId ?? it?.room_id);
  return rid ? `ri:${rid}` : "";
}

function __notifKeyRoomJoinReq(it) {
  const rid = Number(it?.room_id ?? it?.roomId);
  const u = __normU(it?.username);
  return (rid && u) ? `jr:${rid}:${u}` : "";
}

async function __notifCountUnseen(list, keyFn) {
  const items = Array.isArray(list) ? list : [];
  const seen = await __notifLoadSeenSet();
  let c = 0;
  for (const it of items) {
    const k = keyFn(it);
    if (!k) continue;
    if (!seen.has(k)) c++;
  }
  return c;
}

async function __notifMarkSeen(list, keyFn) {
  const items = Array.isArray(list) ? list : [];
  const seen = await __notifLoadSeenSet();
  let changed = false;
  for (const it of items) {
    const k = keyFn(it);
    if (!k) continue;
    if (!seen.has(k)) {
      seen.add(k);
      changed = true;
    }
  }
  if (changed) await __notifSaveSeenSet(seen);
}

// shared in-memory notification state (filled by panel.js handlers)
let __notifFriendsIncoming = [];
let __notifRoomInvites = [];
let __notifRoomJoinReqs = [];

async function __notifUpdateBadges() {
  // Friends badge: combined (friend requests + room invites)
  const fr = await __notifCountUnseen(__notifFriendsIncoming, __notifKeyFriendsIncoming);
  const ri = await __notifCountUnseen(__notifRoomInvites, __notifKeyRoomInvite);
  const total = fr + ri;

  // dot badge for "Friends" drawer (no text)
  if (friendsBadgeEl) {
    if (total <= 0) {
      friendsBadgeEl.style.display = "none";
      friendsBadgeEl.textContent = "";
    } else {
      friendsBadgeEl.style.display = "inline-flex";
      friendsBadgeEl.textContent = "";
    }
  }

  // Room join requests badge (numeric)
  const jr = await __notifCountUnseen(__notifRoomJoinReqs, __notifKeyRoomJoinReq);
  setRoomReqBadge(jr);
}

// Expose tiny API for panel.js
window.__notifSetList = function (kind, list) {
  const items = Array.isArray(list) ? list : [];
  if (kind === "friends_incoming") __notifFriendsIncoming = items;
  else if (kind === "room_invites") __notifRoomInvites = items;
  else if (kind === "room_join_requests") __notifRoomJoinReqs = items;
  __notifUpdateBadges().catch(() => {});
};

window.__notifMarkSeenKind = async function (kind) {
  try {
    if (kind === "friends_incoming") {
      await __notifMarkSeen(__notifFriendsIncoming, __notifKeyFriendsIncoming);
    } else if (kind === "room_invites") {
      await __notifMarkSeen(__notifRoomInvites, __notifKeyRoomInvite);
    } else if (kind === "room_join_requests") {
      await __notifMarkSeen(__notifRoomJoinReqs, __notifKeyRoomJoinReq);
    } else if (kind === "friends_all") {
      await __notifMarkSeen(__notifFriendsIncoming, __notifKeyFriendsIncoming);
      await __notifMarkSeen(__notifRoomInvites, __notifKeyRoomInvite);
    }
  } catch {}
  __notifUpdateBadges().catch(() => {});
};

function requestGroupInvites() {
  safePost({ type: "rooms_invites_incoming" });
}

function renderGroupInvites(list) {
  if (!groupInvitesEl) return;
  const items = Array.isArray(list) ? list : [];
  groupInvitesEl.innerHTML = "";
  if (!items.length) { groupInvitesEl.textContent = "-"; return; }

  for (const it of items) {
    const roomId = Number(it.room_id);
    const roomName = String(it.room_name || it.room_alias || roomId || "").trim();
    const inviter = String(it.invited_by_username || "").trim();

    const row = document.createElement("div");
    row.className = "friend-item";

    const name = document.createElement("div");
    name.className = "friend-name";
    name.textContent = roomName || `room ${roomId}`;

    const meta = document.createElement("div");
    meta.style.opacity = ".75";
    meta.style.fontSize = "12px";
    meta.textContent = inviter ? `invited by ${inviter}` : "invited";

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const accept = document.createElement("button");
    accept.textContent = "Accept";
    accept.onclick = () => roomId && safePost({ type: "rooms_invite_accept", roomId });

    const decline = document.createElement("button");
    decline.textContent = "Decline";
    decline.onclick = () => roomId && safePost({ type: "rooms_invite_decline", roomId });

    actions.appendChild(accept);
    actions.appendChild(decline);

    const left = document.createElement("div");
    left.style.display = "flex";
    left.style.flexDirection = "column";
    left.style.gap = "2px";
    left.appendChild(name);
    left.appendChild(meta);

    row.appendChild(left);
    row.appendChild(actions);
    groupInvitesEl.appendChild(row);
  }
}

function setFriendsInvitesBadge(count) {
  if (!friendsBadgeEl) return;
  const n = Number(count) || 0;
  if (n <= 0) {
    friendsBadgeEl.style.display = "none";
    friendsBadgeEl.textContent = "";
    return;
  }

  // dot badge (no text)
  friendsBadgeEl.style.display = "inline-flex";
  friendsBadgeEl.textContent = "";
}

function closeFriends() {
  if (!friendsDrawer) return;

  if (friendsDrawer.contains(document.activeElement)) {
    const opener = document.getElementById("friendsBtn");
    if (opener) opener.focus();
    else document.activeElement?.blur?.();
  }

  friendsDrawer.classList.remove("open");
  friendsDrawer.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "auto";
}

function requestFriendsAll() {
  safePost({ type: "friends_requests_incoming" });
  safePost({ type: "friends_requests_outgoing" });
  safePost({ type: "friends_list" });
}

function renderRoomJoinRequestsAll(items) {
  if (!roomReqListEl) return;
  const rows = Array.isArray(items) ? items : [];
  lastRoomJoinRequestsAll = rows;
  // Badge is computed from *unseen* items (client-side) via __notifSetList.
  try { window.__notifSetList?.("room_join_requests", rows); } catch {}

  roomReqListEl.innerHTML = "";
  if (!rows.length) { roomReqListEl.textContent = "-"; return; }

  const byRoom = new Map();
  for (const it of rows) {
    const rid = Number(it.room_id);
    if (!rid) continue;
    if (!byRoom.has(rid)) byRoom.set(rid, []);
    byRoom.get(rid).push(it);
  }

  for (const [rid, list] of byRoom.entries()) {
    const roomName = String(list[0]?.room_name || "room " + rid);
    const roomAlias = String(list[0]?.room_alias || "").trim();

    const box = document.createElement("div");
    box.className = "roomreq-room";

    const title = document.createElement("div");
    title.className = "roomreq-room-title";
    title.innerHTML = `<span>${escapeHtml(roomName)}${roomAlias ? ` <span style="opacity:.65;">(${escapeHtml(roomAlias)})</span>` : ""}</span>`;
    box.appendChild(title);

    for (const it of list) {
      const uname = String(it.username || "").trim();
      if (!uname) continue;

      const row = document.createElement("div");
      row.className = "roomreq-req-item";

      const name = document.createElement("div");
      name.className = "roomreq-req-name";
      name.textContent = uname;

      const actions = document.createElement("div");
      actions.className = "roomreq-actions";

      const approve = document.createElement("button");
      approve.textContent = "Approve";
      approve.onclick = (e) => {
        e.preventDefault(); e.stopPropagation();
        safePost({ type: "rooms_join_approve", roomId: rid, username: uname });
      };

      const reject = document.createElement("button");
      reject.textContent = "Reject";
      reject.onclick = (e) => {
        e.preventDefault(); e.stopPropagation();
        safePost({ type: "rooms_join_reject", roomId: rid, username: uname });
      };

      actions.appendChild(approve);
      actions.appendChild(reject);

      row.appendChild(name);
      row.appendChild(actions);
      box.appendChild(row);
    }

    roomReqListEl.appendChild(box);
  }
}

function renderIncoming(list) {
  if (!friendsIncomingEl) return;
  const items = Array.isArray(list) ? list : [];
  friendsIncomingEl.innerHTML = "";
  if (!items.length) { friendsIncomingEl.textContent = "-"; return; }

  for (const it of items) {
    const username = (it.from_username || "").trim();
    const row = document.createElement("div");
    row.className = "friend-item";

    const name = document.createElement("div");
    name.className = "friend-name";
    name.textContent = username || "unknown";
    name.style.cursor = "pointer";
    name.title = "Open profile";
    name.onclick = (e) => { e.stopPropagation(); if (username) openProfile(username); };

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const accept = document.createElement("button");
    accept.textContent = "Accept";
    accept.onclick = () => safePost({ type: "friends_accept", username });

    const decline = document.createElement("button");
    decline.textContent = "Decline";
    decline.onclick = () => safePost({ type: "friends_decline", username });

    actions.appendChild(accept);
    actions.appendChild(decline);

    row.appendChild(name);
    row.appendChild(actions);

    friendsIncomingEl.appendChild(row);
  }
}

function renderOutgoing(list) {
  if (!friendsOutgoingEl) return;
  const items = Array.isArray(list) ? list : [];
  friendsOutgoingEl.innerHTML = "";
  if (!items.length) { friendsOutgoingEl.textContent = "-"; return; }

  for (const it of items) {
    const username = (it.to_username || "").trim();
    const row = document.createElement("div");
    row.className = "friend-item";

    const name = document.createElement("div");
    name.className = "friend-name";
    name.textContent = username || "unknown";
    name.style.cursor = "pointer";
    name.title = "Open profile";
    name.onclick = (e) => { e.stopPropagation(); if (username) openProfile(username); };

    const meta = document.createElement("div");
    meta.style.opacity = ".75";
    meta.style.fontSize = "12px";
    meta.textContent = "pending";

    row.appendChild(name);
    row.appendChild(meta);
    friendsOutgoingEl.appendChild(row);
  }
}

function renderAccepted(list) {
  if (!friendsAcceptedEl) return;
  const items = Array.isArray(list) ? list : [];
  friendsAcceptedEl.innerHTML = "";
  if (!items.length) { friendsAcceptedEl.textContent = "-"; return; }

  for (const it of items) {
    const username = (it.username || "").trim();

    const row = document.createElement("div");
    row.className = "friend-item";

    const name = document.createElement("div");
    name.className = "friend-name";
    name.textContent = username || "unknown";
    name.style.cursor = "pointer";
    name.title = "Open profile";
    name.onclick = (e) => { e.stopPropagation(); if (username) openProfile(username); };

    const actions = document.createElement("div");
    actions.className = "friend-actions";

    const message = document.createElement("button");
    message.textContent = "Message";
    message.title = "Open direct chat";
    message.onclick = () => {
      if (!username) return;
      safePost({ type: "dm_open", username });
      closeFriends();
    };

    const invite = document.createElement("button");
    invite.textContent = "Invite";
    invite.title = "Invite to current room";
    invite.onclick = () => {
      if (!activeRoomId) {
        alert("Please connect to a room first.");
        return;
      }
      if (!username) return;
    __sendRoomInvite(activeRoomId, username);
    };

    const removeBtn = document.createElement("button");
    removeBtn.textContent = "\u0425";
    removeBtn.title = "Remove friend";
    removeBtn.onclick = () => {
      if (!username) return;
      (async () => {
        const ok = await __ui.confirm(`Remove ${username} from your friends?`, "Remove friend");
        if (!ok) return;
        safePost({ type: "friends_remove", username });
      })();
    };

    actions.appendChild(message);
    actions.appendChild(invite);
    actions.appendChild(removeBtn);

    row.appendChild(name);
    row.appendChild(actions);

    friendsAcceptedEl.appendChild(row);
  }
}

// ---- load UI prefs (presence panel) ----
chrome.storage.local.get(["presenceCollapsed"], (data) => {
  if (typeof data.presenceCollapsed === "boolean") {
    presenceCollapsed = data.presenceCollapsed;
  }
});

function setMembersPanelOpen(open) {
  membersPanelOpen = !!open;
  if (!presenceEl) return;

  if (typeof dmMode !== "undefined" && dmMode) {
    membersPanelOpen = false;
  }

  presenceEl.classList.toggle("is-hidden", !membersPanelOpen);

  if (!document.getElementById("__presenceOverride")) {
    const s = document.createElement("style");
    s.id = "__presenceOverride";
    s.textContent = `
      #presence .presence-body { max-height: 320px !important; }
    `;
    document.head.appendChild(s);
  }

  if (membersPanelOpen) {
    const rid = activeRoomId != null ? String(activeRoomId) : "";

    if (
      activeRoomId &&
      (!roomMembersById[rid] ||
        !Array.isArray(roomMembersById[rid]) ||
        roomMembersById[rid].length === 0)
    ) {
      requestRoomMembers(Number(activeRoomId));
    }

    const list =
      rid && Array.isArray(lastOnlineByRoomId[rid])
        ? lastOnlineByRoomId[rid]
        : lastPresenceOnline;

    renderPresence(list);
  }
}

if (currentRoomEl) {
  currentRoomEl.onclick = () => {
    console.log("currentRoom clicked; dmMode=", dmMode, "membersPanelOpen->", !membersPanelOpen);
    setMembersPanelOpen(!membersPanelOpen);
  };
}

function makeCloseX(btn) {
  if (!btn) return;
  if (btn.dataset.closeX === "1") return;

  btn.textContent = "\u0425";
  btn.title = "Close";
  btn.setAttribute("aria-label", "Close");
  btn.dataset.closeX = "1";
}

function applyCloseX() {
  makeCloseX(document.getElementById("closeFriends"));
  makeCloseX(document.getElementById("profileClose"));
  makeCloseX(document.getElementById("profileClose2"));
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", applyCloseX);
} else {
  applyCloseX();
}

{ let _closeXRaf = 0;
  new MutationObserver(() => {
    if (_closeXRaf) return;
    _closeXRaf = requestAnimationFrame(() => { _closeXRaf = 0; applyCloseX(); });
  }).observe(document.documentElement, { childList: true, subtree: true });
}


document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && roomsDrawer?.classList.contains("open")) {
    closeRoomsDrawer();
  }
});

/* =============================
 * V2 UI glue: left rail navigation
 * ============================= */
(function initV2Rail() {
  const navRooms = document.getElementById("navRooms");
  const navDM = document.getElementById("navDM");
  const navInvites = document.getElementById("navInvites");
  const navProfile = document.getElementById("navProfile");

  const panelRooms = document.getElementById("panelRooms");
  const panelDM = document.getElementById("panelDM");
  const panelInvites = document.getElementById("panelInvites");
  const panelProfile = document.getElementById("panelProfile");

  const dmRefreshBtn = document.getElementById("dmRefreshBtn");
  const invitesRefreshBtn = document.getElementById("invitesRefreshBtn");

  const sideDrawer = document.getElementById("sideDrawer");
  const sideBackdrop = document.getElementById("sideBackdrop");

  // if not v2 markup, do nothing
  if (!navRooms || !panelRooms || !sideDrawer || !sideBackdrop) return;

  const nav = [
    { btn: navRooms, panel: panelRooms, key: "rooms" },
    { btn: navDM, panel: panelDM, key: "dm" },
    { btn: navInvites, panel: panelInvites, key: "invites" },
    { btn: navProfile, panel: panelProfile, key: "profile" },
  ].filter(x => x.btn && x.panel);

  let __activeKey = "rooms";
  function openDrawer() {
    sideDrawer.classList.add("open");
    sideBackdrop.classList.add("open");
    sideDrawer.setAttribute("aria-hidden", "false");
    sideBackdrop.setAttribute("aria-hidden", "false");
    // prevent background scroll
    document.body.style.overflow = "hidden";
  }

  function closeDrawer() {
    // avoid aria-hidden focus warnings
    try {
      if (sideDrawer.contains(document.activeElement)) document.activeElement.blur();
    } catch {}
    sideDrawer.classList.remove("open");
    sideBackdrop.classList.remove("open");
    sideDrawer.setAttribute("aria-hidden", "true");
    sideBackdrop.setAttribute("aria-hidden", "true");
    document.body.style.overflow = "auto";
  }

  function setActive(key, { open = true } = {}) {
    __activeKey = key;
    for (const it of nav) {
      const isOn = it.key === key;
      it.btn.classList.toggle("is-active", isOn);
      it.btn.setAttribute("aria-pressed", isOn ? "true" : "false");
      it.panel.classList.toggle("is-active", isOn);
    }

    if (open) openDrawer();

    // auto refresh per section
    try {
      if (key === "rooms") {
        // rooms lists are rendered by renderRooms(); request triggers ws fetch
        if (typeof requestMyRooms === "function") requestMyRooms();
      }
      if (key === "dm") {
        if (typeof safePost === "function") safePost({ type: "dm_list" });
      }
      if (key === "invites") {
        if (typeof requestFriendsAll === "function") requestFriendsAll();
        if (typeof requestGroupInvites === "function") requestGroupInvites();
        if (typeof refreshRoomJoinRequestsAll === "function") refreshRoomJoinRequestsAll();
      }
    } catch (e) {
      console.warn("v2 nav refresh failed", e);
    }
  }

  function onNavClick(key) {
    const isOpen = sideDrawer.classList.contains("open");
    if (isOpen && __activeKey === key) {
      closeDrawer();
      return;
    }
    setActive(key, { open: true });
  }

  navRooms.addEventListener("click", () => onNavClick("rooms"));
  if (navDM) navDM.addEventListener("click", () => onNavClick("dm"));
  if (navInvites) navInvites.addEventListener("click", () => onNavClick("invites"));
  if (navProfile) navProfile.addEventListener("click", () => onNavClick("profile"));

  // close by clicking backdrop
  sideBackdrop.addEventListener("click", closeDrawer);

  if (dmRefreshBtn) dmRefreshBtn.addEventListener("click", () => {
    try { safePost({ type: "dm_list" }); } catch {}
  });

  if (invitesRefreshBtn) invitesRefreshBtn.addEventListener("click", () => {
    try {
      requestFriendsAll();
      requestGroupInvites();
      refreshRoomJoinRequestsAll();
    } catch {}
  });

  // ESC closes drawer first; if already closed -> switches back to rooms
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      // if modal drawer is open, let existing handlers close it
      const cr = document.getElementById("createRoomDrawer");
      if (cr && cr.classList.contains("open")) return;

      if (sideDrawer.classList.contains("open")) {
        closeDrawer();
        return;
      }
      setActive("rooms", { open: false });
    }
  });

  // default: drawer closed, but keep rooms as active tab
  setActive("rooms", { open: false });
})();

const recentBarEl   = document.getElementById("recentBar");     // legacy (optional)
const recentRailEl  = document.getElementById("railRecents");   // new (optional)
const recentRoomsEl = document.getElementById("recentRooms");   // new
const recentDmEl    = document.getElementById("recentDM");      // new

let recentItems = [];       // [{k,type,id,label}]
let recentActiveKey = "";   // "room:12" | "dm:34"

function recentKey(type, id) { return `${type}:${id}`; }

// ===== Recent: single moving indicator for Recents + Logout =====
(function initRecentHover() {
  const recentRail = recentRailEl; // #railRecents
  const railNav = document.querySelector(".rail.rail-right");
  const ind = document.getElementById("recentHover");
  const logout = document.getElementById("logoutBtn");

  if (!recentRail || !railNav || !ind) return;

  if (ind.parentElement !== railNav) railNav.appendChild(ind);

  railNav.style.position = railNav.style.position || "fixed";

  let raf = 0;

  function moveTo(btn, mode) {
    if (!btn) return;
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(() => {
      const railRect = railNav.getBoundingClientRect();
      const b = btn.getBoundingClientRect();

      ind.style.top = `${Math.round(b.top - railRect.top)}px`;
      ind.style.height = `${Math.round(b.height)}px`;

      if (mode === "logout") {
        ind.style.backgroundColor = "var(--recent-logout)";
      } else {
        const isDm = btn.classList.contains("is-dm");
        ind.style.backgroundColor = isDm ? "var(--recent-dm)" : "var(--recent-room)";
      }

      ind.classList.add("is-on");
    });
  }

  function moveToActiveOrHide() {
    const active = recentRail.querySelector(".recent-tile.is-active");
    if (active) moveTo(active, "recent");
    else ind.classList.remove("is-on");
  }

recentRail.addEventListener("mousemove", (e) => {
  const btn = e.target.closest(".recent-tile");
  if (btn && recentRail.contains(btn)) moveTo(btn, "recent");
}, { passive: true });

recentRail.addEventListener("focusin", (e) => {
  const btn = e.target.closest(".recent-tile");
  if (btn && recentRail.contains(btn)) moveTo(btn, "recent");
});

recentRail.addEventListener("mouseenter", (e) => {
  const from = e.relatedTarget;
  if (from && railNav.contains(from)) return;
  moveToActiveOrHide();
}, { passive: true });

railNav.addEventListener("mouseleave", () => moveToActiveOrHide(), { passive: true });

if (logout) {
  logout.addEventListener("mouseenter", () => moveTo(logout, "logout"), { passive: true });
  logout.addEventListener("focus",      () => moveTo(logout, "logout"), { passive: true });

  logout.addEventListener("mouseleave", () => {}, { passive: true });
  logout.addEventListener("blur",       () => {});
}

  window.__recentMoveToActiveOrHide = moveToActiveOrHide;
})();

let currentRecentUser = "";
function recentStorageKeys() {
  const u = String(currentRecentUser || "").trim().toLowerCase();
  
  return u
    ? { items: `ui_recent_items__${u}`, active: `ui_recent_active__${u}` }
    : { items: `ui_recent_items__anon`, active: `ui_recent_active__anon` };
}

function loadRecent() {
  if (!recentBarEl && !recentRailEl && !recentRoomsEl && !recentDmEl) return;

  const k = recentStorageKeys();
  chrome.storage?.local.get([k.items, k.active], (d) => {
    recentItems = Array.isArray(d[k.items]) ? d[k.items] : [];
    recentActiveKey = typeof d[k.active] === "string" ? d[k.active] : "";
    renderRecent();
  });
}

function saveRecent() {
  const k = recentStorageKeys();
  chrome.storage?.local.set({
    [k.items]: recentItems,
    [k.active]: recentActiveKey
  });
}

function pushRecent(type, id, label) {
  if (!recentBarEl && !recentRailEl && !recentRoomsEl && !recentDmEl) return;

  const k = recentKey(type, id);
  recentActiveKey = k;

  recentItems = recentItems.filter(x => x && x.k !== k);
  recentItems.unshift({ k, type, id, label: String(label || "").slice(0, 60) });

  recentItems = recentItems.slice(0, 6); // 3 rooms + 3 dm

  saveRecent();
  renderRecent();
}

function makeInitials(label) {
  const s = String(label || "").trim();
  if (!s) return "??";

  const parts = s.split(/\s+/).filter(Boolean);
  let a = "";
  if (parts.length >= 2) {
    a = (parts[0][0] || "") + (parts[1][0] || "");
  } else {
    a = s.slice(0, 2);
  }

  a = a.replace(/[^\p{L}\p{N}]/gu, "").slice(0, 2);
  return (a || s.slice(0, 2) || "??").toUpperCase();
}

function mkRecentBtn(it) {
  const b = document.createElement("button");
  b.type = "button";
  b.className =
  "recent-tile " +
  (it.type === "dm" ? "is-dm " : "is-room ") +
  (it.k === recentActiveKey ? "is-active" : "");
  b.dataset.key = it.k;

  const label = String(it.label || "").trim();
  b.title = (it.type === "dm" ? "DM: " : "Room: ") + (label || "-");

  const badge = document.createElement("span");
  badge.className = "recent-tile-badge";
  badge.style.cssText = `
    width: 36px !important;
    height: 36px !important;
    border-radius: 8px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    font-weight: 600 !important;
    font-size: 16px !important;
    overflow: hidden !important;
    background-color: #f0f0f0 !important;
  `;
  badge.textContent = makeInitials(label);

  // Load logo for room if available
  if (it.type === "room" && it.id) {
    const cached = __roomMetaCache.get(String(it.id));
    const logoSrc = cached?.logo_url || cached?.logo_token;
    if (logoSrc) {
      const useToken = !!cached?.logo_token;
      loadImageWithAuth(logoSrc, useToken).then(blobUrl => {
        if (blobUrl && badge && badge.parentNode) { // Check element still exists
          try {
            badge.textContent = "";
            badge.style.display = "block";
            badge.style.backgroundColor = "transparent";
            
            const img = document.createElement("img");
            img.src = blobUrl;
            img.alt = "Room logo";
            img.style.cssText = `
              width: 100% !important;
              height: 100% !important;
              object-fit: cover !important;
              border-radius: 8px !important;
              display: block !important;
            `;
            badge.appendChild(img);
            badge.classList.add("has-logo");
          } catch (e) {
            console.warn(`Failed to add recent logo:`, e);
          }
        }
      }).catch(() => {});
    }
  }

  b.appendChild(badge);

  b.addEventListener("click", async () => {
    recentActiveKey = it.k;
    saveRecent();
    renderRecent();

    if (it.type === "room") {
      if (roomInput) roomInput.value = String(it.id);
      renderCurrentRoom({ online: false });
      highlightActiveRoom();
      try { connect(""); } catch {}
    } else {
      try {
        setModeDm(Number(it.id), label);
        clearChat();
        await ensureDmKeyReady(Number(it.id), label);
        safePost({ type: "dm_connect", thread_id: Number(it.id), peer_username: label });
        safePost({ type: "dm_history", thread_id: Number(it.id), limit: 50 });
      } catch (e) {
        console.warn("open recent dm failed", e);
      }
    }
  });

  return b;
}

// Recent hover slider (one for all recent tiles)
const recentHoverEl = document.getElementById("recentHover");

function moveRecentHoverTo(btn) {
  if (!recentHoverEl || !recentRailEl || !btn) return;

  const railRect = recentRailEl.getBoundingClientRect();
  const b = btn.getBoundingClientRect();

  const top = Math.round(b.top - railRect.top);
  const h   = Math.round(b.height);

  recentHoverEl.style.top = `${top}px`;
  recentHoverEl.style.height = `${h}px`;

  // color by type
  const isDm = btn.classList.contains("is-dm");
  recentHoverEl.style.backgroundColor = isDm ? "var(--recent-dm)" : "var(--recent-room)";

  recentHoverEl.classList.add("is-on");
}

function moveRecentHoverToActiveOrHide() {
  if (!recentRailEl) return;
  const active = recentRailEl.querySelector(".recent-tile.is-active");
  if (active) moveRecentHoverTo(active);
  else recentHoverEl?.classList.remove("is-on");
}

function renderRecent() {
  // ===== legacy horizontal bar (#recentBar) =====
  if (recentBarEl) {
    [...recentBarEl.querySelectorAll(".recent-chip")].forEach(n => n.remove());
    for (const it of recentItems) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "recent-chip" + (it.k === recentActiveKey ? " is-active" : "");
      b.dataset.key = it.k;

      const t = document.createElement("span");
      t.className = "rc-type";
      t.textContent = it.type === "dm" ? "DM" : "Room";

      const lbl = document.createElement("span");
      lbl.className = "rc-label";
      lbl.textContent = it.label || "-";

      b.appendChild(t);
      b.appendChild(lbl);

      b.addEventListener("click", () => {
        mkRecentBtn(it).click();
      });

      recentBarEl.appendChild(b);
    }
  }

  // ===== new rail stacks (#recentRooms / #recentDM) =====
  if (recentRoomsEl) recentRoomsEl.innerHTML = "";
  if (recentDmEl) recentDmEl.innerHTML = "";

  if (recentRoomsEl || recentDmEl) {
    const rooms = recentItems.filter(x => x && x.type === "room").slice(0, 3);
    const dms   = recentItems.filter(x => x && x.type === "dm").slice(0, 3);

    for (const it of rooms) recentRoomsEl?.appendChild(mkRecentBtn(it));
    for (const it of dms)   recentDmEl?.appendChild(mkRecentBtn(it));
  }
    moveRecentHoverToActiveOrHide();
    window.__recentMoveToActiveOrHide?.();
}

// init
loadRecent();

// ===== Rail edge indicator (hover slider) =====
(function initRailIndicator(){
  const rail = document.querySelector(".rail.rail-right");
  if (!rail) return;

  // create indicator once
  let ind = rail.querySelector(".rail-edge-indicator");
  if (!ind) {
    ind = document.createElement("div");
    ind.className = "rail-edge-indicator";
    rail.appendChild(ind);
  }

  const buttons = Array.from(rail.querySelectorAll('.rail-btn:not([data-no-hover="1"])'));
  if (!buttons.length) return;

  const IND_H = 22;

  function moveIndicatorTo(btn){
    const railRect = rail.getBoundingClientRect();
    const b = btn.getBoundingClientRect();
    const top = (b.top - railRect.top) + (b.height / 2) - (IND_H / 2);
    ind.style.top = `${Math.max(8, Math.min(top, railRect.height - IND_H - 8))}px`;
    ind.classList.add("is-on");
  }

  function moveToActive(){
    const active = rail.querySelector(".rail-btn.is-active") || buttons[0];
    if (active) moveIndicatorTo(active);
  }

  // hover move
  buttons.forEach(btn => {
    btn.addEventListener("mouseenter", () => moveIndicatorTo(btn), { passive: true });
    btn.addEventListener("focus", () => moveIndicatorTo(btn), { passive: true });
  });

  rail.addEventListener("mouseleave", () => moveToActive(), { passive: true });

  rail.addEventListener("click", (e) => {
    const btn = e.target.closest(".rail-btn");
    if (btn) moveIndicatorTo(btn);
  });

  // initial position
  moveToActive();
})();

function initSearchHoverRunner() {
  const actions = document.querySelector(".chat-search-actions");
  if (!actions) return;

  const btns = actions.querySelectorAll("button");
  const setRunner = (btn) => {
    const a = actions.getBoundingClientRect();
    const b = btn.getBoundingClientRect();
    actions.style.setProperty("--hs-x", `${Math.round(b.left - a.left)}px`);
    actions.style.setProperty("--hs-w", `${Math.round(b.width)}px`);
    actions.style.setProperty("--hs-o", `1`);
  };

  btns.forEach(btn => {
    btn.addEventListener("mouseenter", () => setRunner(btn));
    btn.addEventListener("focus", () => setRunner(btn));
  });

  actions.addEventListener("mouseleave", () => {
    actions.style.setProperty("--hs-o", `0`);
  });
  actions.addEventListener("focusout", () => {
    if (!actions.contains(document.activeElement)) actions.style.setProperty("--hs-o", `0`);
  });
}

// --- Report User ---

const REPORT_REASONS = [
  { value: "spam",            label: "Spam" },
  { value: "harassment",      label: "Harassment" },
  { value: "hate_speech",     label: "Hate speech" },
  { value: "illegal_content", label: "Illegal content" },
  { value: "impersonation",   label: "Impersonation" },
  { value: "other",           label: "Other" },
];

async function reportUser(targetUsername) {
  if (!targetUsername) return;

  const token = await requestToken();
  if (!token) { await __ui.alert("Not authenticated"); return; }

  // Показываем модалку с выбором причины через __ui.prompt не получится —
  // используем нативный подход: создаём временный overlay.
  const overlay = document.createElement("div");
  overlay.style.cssText = `
    position:fixed; inset:0; z-index:10000;
    background:rgba(0,0,0,.6); display:flex; align-items:center; justify-content:center;
  `;

  const reasonRadios = REPORT_REASONS.map((r, i) =>
    `<label style="display:flex;align-items:center;gap:6px;cursor:pointer;padding:4px 0;">
       <input type="radio" name="rr" value="${r.value}" ${i === 0 ? "checked" : ""}> ${r.label}
     </label>`
  ).join("");

  overlay.innerHTML = `
    <div style="background:#1a1d27;border:1px solid #333;border-radius:10px;padding:20px;
                width:340px;max-width:90vw;color:#e1e4ea;font-size:14px;">
      <div style="font-weight:600;font-size:16px;margin-bottom:12px;">
        Report <span id="_rptTargetName"></span>
      </div>
      <div style="margin-bottom:10px;">
        ${reasonRadios}
      </div>
      <textarea id="_rptComment" placeholder="Additional details (optional)..."
        style="width:100%;height:60px;resize:vertical;background:#12141c;border:1px solid #333;
        color:#e1e4ea;border-radius:6px;padding:6px 8px;font-size:13px;font-family:inherit;
        margin-bottom:12px;"></textarea>
      <div style="display:flex;gap:8px;justify-content:flex-end;">
        <button id="_rptCancel" type="button"
          style="background:#333;color:#ccc;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;">
          Cancel</button>
        <button id="_rptSubmit" type="button"
          style="background:#dc2626;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;">
          Submit Report</button>
      </div>
      <div id="_rptStatus" style="margin-top:8px;font-size:12px;"></div>
    </div>
  `;
  document.body.appendChild(overlay);

  // SEC: set username via textContent, never innerHTML (XSS prevention)
  const rptNameEl = document.getElementById("_rptTargetName");
  if (rptNameEl) rptNameEl.textContent = targetUsername;

  const cancelBtn = document.getElementById("_rptCancel");
  const submitBtn = document.getElementById("_rptSubmit");
  const statusEl  = document.getElementById("_rptStatus");

  const cleanup = () => { overlay.remove(); };

  overlay.addEventListener("click", (e) => { if (e.target === overlay) cleanup(); });
  cancelBtn.onclick = cleanup;

  submitBtn.onclick = async () => {
    const reason = overlay.querySelector('input[name="rr"]:checked')?.value;
    if (!reason) return;
    const comment = (document.getElementById("_rptComment")?.value || "").trim();

    submitBtn.disabled = true;
    submitBtn.textContent = "Sending...";
    statusEl.textContent = "";

    try {
      await apiJson("/reports", {
        method: "POST",
        body: JSON.stringify({
          target_type: "user",
          target_username: targetUsername,
          reason,
          comment,
        }),
      });

      cleanup();
      await __ui.alert("Report submitted. Thank you.");
    } catch (e) {
      submitBtn.disabled = false;
      submitBtn.textContent = "Submit Report";
      statusEl.textContent = "Error: " + e.message;
      statusEl.style.color = "#f87171";
    }
  };
}

window.updateLeaveBtnState = updateLeaveBtnState;
window.setActiveRoomFromServer = setActiveRoomFromServer;

window.__panelUiReady = true;
try { window.dispatchEvent(new Event("ws_ui_ready")); } catch {}

// ===== Profile settings tabs (Profile/Security/Feedback) =====
// In v2 UI we keep tabs in panel.html and only toggle panes here.
// Security tab must be the ONLY place where 2FA UI is mounted.

function initSettingsTabHover() {
  const bar = document.getElementById("settingsTabbar");
  if (!bar) return;

  // create hover underline once
  let hover = document.getElementById("settingsTabHover");
  if (!hover) {
    hover = document.createElement("div");
    hover.id = "settingsTabHover";
    hover.className = "settings-tab-hover";
    hover.setAttribute("aria-hidden", "true");
    bar.appendChild(hover);
  }

  const tabs = Array.from(bar.querySelectorAll(".settings-tab"));
  if (!tabs.length) return;

  const moveTo = (el, show = true) => {
    const br = bar.getBoundingClientRect();
    const tr = el.getBoundingClientRect();
    hover.style.left = Math.round(tr.left - br.left) + "px";
    hover.style.width = Math.round(tr.width) + "px";
    hover.style.opacity = show ? "1" : "0";
  };

  const moveToActive = () => {
    const a = bar.querySelector(".settings-tab.is-active");
    if (a) moveTo(a, true);
    else hover.style.opacity = "0";
  };

  // avoid double-binding
  if (!bar.dataset.hoverBound) {
    bar.dataset.hoverBound = "1";

    tabs.forEach((t) => {
      t.addEventListener("mouseenter", () => moveTo(t, true));
      t.addEventListener("focus", () => moveTo(t, true));
    });

    bar.addEventListener("mouseleave", moveToActive);
    window.addEventListener("resize", moveToActive);
  }

  // initial position (or after any re-render)
  moveToActive();

  // expose helper so setActive() can snap underline after click
  bar.__moveSettingsHoverToActive = moveToActive;
}

function initSettingsTabs() {
  const bProfile  = document.getElementById("settingsTabProfile");
  const bSecurity = document.getElementById("settingsTabSecurity");
  const bFeedback = document.getElementById("settingsTabFeedback");

  const pProfile  = document.getElementById("settingsPaneProfile");
  const pSecurity = document.getElementById("settingsPaneSecurity");
  const pFeedback = document.getElementById("settingsPaneFeedback");

  if (!bProfile || !bSecurity || !bFeedback || !pProfile || !pSecurity || !pFeedback) return;
  
    // adapter (if HTML still uses friends-tabs/friends-tab)
  const bar = bProfile.closest(".friends-tabs") || bProfile.parentElement;
  if (bar && !bar.id) bar.id = "settingsTabbar";
  bar?.classList?.add("settings-tabs");
  bProfile.classList.add("settings-tab");
  bSecurity.classList.add("settings-tab");
  bFeedback.classList.add("settings-tab");
  
    // init moving underline hover
  try { initSettingsTabHover(); } catch {}

  const allBtns = [bProfile, bSecurity, bFeedback];
  const allPanes = [pProfile, pSecurity, pFeedback];

  function setActive(which) {
    allBtns.forEach((b) => b.classList.remove("is-active"));
    allPanes.forEach((p) => (p.style.display = "none"));

    if (which === "security") {
      bSecurity.classList.add("is-active");
      pSecurity.style.display = "";
    } else if (which === "feedback") {
      bFeedback.classList.add("is-active");
      pFeedback.style.display = "";
    } else {
      bProfile.classList.add("is-active");
      pProfile.style.display = "";
    }

    // snap underline back to active tab
    try {
      const bar = document.getElementById("settingsTabbar");
      bar?.__moveSettingsHoverToActive?.();
    } catch {}
  }

  // avoid double-binding
  if (!bProfile.dataset.boundTabs) {
    bProfile.dataset.boundTabs = "1";
    bProfile.addEventListener("click", () => setActive("profile"));
  }

  if (!bFeedback.dataset.boundTabs) {
    bFeedback.dataset.boundTabs = "1";
    bFeedback.addEventListener("click", () => setActive("feedback"));
  }

  if (!bSecurity.dataset.boundTabs) {
    bSecurity.dataset.boundTabs = "1";
    bSecurity.addEventListener("click", () => {
      setActive("security");
      // mount and init 2FA ONLY in Security tab
      try { ensureInline2faSection(); } catch {}
      try { ensureCryptoAutolockSection(); } catch {}
      try { ensureChangePasswordSection(); } catch {}
      try { ensureRecoverySection(); } catch {}
});
  }

  setActive("profile");

  // prepare 2FA early so init2faSettings can attach handlers when user opens Security
  try { ensureInline2faSection(); } catch {}
  try { ensureCryptoAutolockSection(); } catch {}
  try { ensureChangePasswordSection(); } catch {}
  try { ensureRecoverySection(); } catch {}
}

try {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      try { initSettingsTabs(); } catch {}
    });
  } else {
    initSettingsTabs();
  }
} catch {}

// ===== Room Management Tab =====

function initRoomTabs() {
  const bList   = document.getElementById("roomsTabList");
  const bManage = document.getElementById("roomsTabManage");
  const pList   = document.getElementById("roomsPaneList");
  const pManage = document.getElementById("roomsPaneManage");
  const bar     = document.getElementById("roomsTabbar");

  if (!bList || !bManage || !pList || !pManage) return;

  const allBtns  = [bList, bManage];
  const allPanes = [pList, pManage];

  function setActive(which) {
    allBtns.forEach(b => b.classList.remove("is-active"));
    allPanes.forEach(p => { p.style.display = "none"; });

    if (which === "manage") {
      bManage.classList.add("is-active");
      pManage.style.display = "";
      renderRoomManagePane(typeof activeRoomId !== "undefined" ? activeRoomId : null);
    } else {
      bList.classList.add("is-active");
      pList.style.display = "";
    }

    try { if (bar?.__moveRoomsHoverToActive) bar.__moveRoomsHoverToActive(); } catch {}
  }

  // Moving underline
  if (bar && !bar.dataset.hoverBound) {
    bar.dataset.hoverBound = "1";
    const hover = document.getElementById("roomsTabHover");
    if (hover) {
      const moveTo = (el, show = true) => {
        const br = bar.getBoundingClientRect();
        const tr = el.getBoundingClientRect();
        hover.style.left  = Math.round(tr.left - br.left) + "px";
        hover.style.width = Math.round(tr.width) + "px";
        hover.style.opacity = show ? "1" : "0";
      };
      const moveToActive = () => {
        const a = bar.querySelector(".settings-tab.is-active");
        if (a) moveTo(a, true); else hover.style.opacity = "0";
      };
      allBtns.forEach(t => {
        t.addEventListener("mouseenter", () => moveTo(t, true));
        t.addEventListener("focus",      () => moveTo(t, true));
      });
      bar.addEventListener("mouseleave", moveToActive);
      window.addEventListener("resize",  moveToActive);
      bar.__moveRoomsHoverToActive = moveToActive;
      moveToActive();
    }
  }

  if (!bList.dataset.boundTabs) {
    bList.dataset.boundTabs = "1";
    bList.addEventListener("click", () => setActive("list"));
  }
  if (!bManage.dataset.boundTabs) {
    bManage.dataset.boundTabs = "1";
    bManage.addEventListener("click", () => {
      setActive("manage");
      // Fetch fresh data when opening the tab
      const rid = typeof activeRoomId !== "undefined" ? activeRoomId : null;
      if (rid) {
        try { requestRoomMembers(rid); } catch {}
      }
    });
  }

  setActive("list");
}

function _renderRoomManageReqs(container, rid, requests) {
  container.innerHTML = "";
  if (!Array.isArray(requests) || !requests.length) {
    container.innerHTML = '<div class="panel-hint">No pending requests.</div>';
    return;
  }
  for (const req of requests) {
    const uname = String(req.username || req.user || "").trim();
    if (!uname) continue;

    const row = document.createElement("div");
    row.style.cssText = "display:flex; align-items:center; gap:6px; padding:5px 0; border-bottom:1px solid rgba(255,255,255,0.04);";

    const nameSpan = document.createElement("span");
    nameSpan.style.flex = "1";
    nameSpan.textContent = uname;
    row.appendChild(nameSpan);

    const approveBtn = document.createElement("button");
    approveBtn.className = "panel-btn";
    approveBtn.style.fontSize = "11px";
    approveBtn.textContent = "Approve";
    approveBtn.onclick = () => {
      approveBtn.disabled = true;
      rejectBtn.disabled  = true;
      safePost({ type: "rooms_join_approve", roomId: rid, username: uname });
    };
    row.appendChild(approveBtn);

    const rejectBtn = document.createElement("button");
    rejectBtn.className = "panel-btn";
    rejectBtn.style.cssText = "font-size:11px; background:rgba(220,53,69,0.3);";
    rejectBtn.textContent = "Reject";
    rejectBtn.onclick = () => {
      approveBtn.disabled = true;
      rejectBtn.disabled  = true;
      safePost({ type: "rooms_join_reject", roomId: rid, username: uname });
    };
    row.appendChild(rejectBtn);

    container.appendChild(row);
  }
}

function renderRoomManagePane(roomId) {
  const el = document.getElementById("roomManageContent");
  if (!el) return;
  el.innerHTML = "";

  const rid = Number(roomId);
  if (!rid) {
    el.innerHTML = '<div class="panel-hint" style="margin-top:16px; text-align:center;">Open a room to manage it.</div>';
    return;
  }

  const isOwner = !!(typeof roomOwnerById !== "undefined" && roomOwnerById[String(rid)]);
  const members = (typeof roomMembersById !== "undefined" && Array.isArray(roomMembersById[String(rid)]))
    ? roomMembersById[String(rid)] : [];
  const me = (typeof getMeUsername === "function" ? getMeUsername() : "") ||
             (typeof nameInput !== "undefined" ? (nameInput?.value || "") : "");
  const meLower = String(me).trim().toLowerCase();

  // ---- Room Settings (owner only) ----
  if (isOwner) {
    const settingsSection = document.createElement("div");
    settingsSection.className = "panel-block";

    const settingsTitle = document.createElement("div");
    settingsTitle.className = "panel-block-title";
    settingsTitle.textContent = activeRoomName
      ? `Room #${rid} "${activeRoomName}" Settings`
      : `Room #${rid} Settings`;
    settingsSection.appendChild(settingsTitle);

    const renameHint = document.createElement("div");
    renameHint.className = "panel-hint";
    renameHint.style.marginTop = "10px";
    renameHint.textContent = "Room name";
    settingsSection.appendChild(renameHint);

    const renameRow = document.createElement("div");
    renameRow.style.cssText = "display:flex; gap:8px; margin-top:4px;";

    const renameInput = document.createElement("input");
    renameInput.type = "text";
    renameInput.maxLength = 64;
    renameInput.placeholder = "New room name";
    renameInput.value = String(activeRoomName || "").trim();
    renameInput.style.cssText = "flex:1; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.12); color:inherit; border-radius:6px; padding:6px 8px; font-size:13px; font-family:inherit; box-sizing:border-box;";
    renameRow.appendChild(renameInput);

    const renameBtn = document.createElement("button");
    renameBtn.className = "panel-btn";
    renameBtn.textContent = "Rename";
    renameRow.appendChild(renameBtn);

    settingsSection.appendChild(renameRow);

    const settingsStatus = document.createElement("div");
    settingsStatus.className = "panel-hint";
    settingsStatus.style.cssText = "margin-top:6px; min-height:16px;";
    settingsSection.appendChild(settingsStatus);

    const doRename = async () => {
      const newName = String(renameInput.value || "").trim();
      if (!newName) {
        settingsStatus.textContent = "Error: room name is required";
        return;
      }
      renameBtn.disabled = true;
      settingsStatus.textContent = "Renaming...";
      try {
        safePost({ type: "rooms_rename", roomId: rid, name: newName });
        await waitRoomRename(rid);
        if (activeRoomId === rid) activeRoomName = newName;
        try { renderCurrentRoom({ online: !!(statusEl && statusEl.classList.contains("online")) }); } catch {}
        requestMyRooms();
        settingsTitle.textContent = `Room #${rid} "${newName}" Settings`;
        settingsStatus.textContent = "Renamed OK";
        setTimeout(() => { settingsStatus.textContent = ""; }, 2500);
      } catch (err) {
        settingsStatus.textContent = "Error: " + (err?.message || err);
      } finally {
        renameBtn.disabled = false;
      }
    };
    renameBtn.onclick = (e) => { e.stopPropagation(); doRename(); };
    renameInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        doRename();
      }
    });

    // --- Logo row ---
    const logoRow = document.createElement("div");
    logoRow.style.cssText = "display:flex; align-items:center; gap:10px; margin-top:10px;";

    const logoPreview = document.createElement("div");
    logoPreview.style.cssText = "width:48px; height:48px; border-radius:8px; overflow:hidden; flex-shrink:0; background:rgba(255,255,255,0.06); display:flex; align-items:center; justify-content:center; font-size:18px; font-weight:600;";
    logoPreview.textContent = (typeof roomInitials === "function" ? roomInitials(activeRoomName || String(rid)) : "?");

    const logoPreviewImg = document.createElement("img");
    logoPreviewImg.style.cssText = "width:100%; height:100%; object-fit:cover; display:none;";
    logoPreview.appendChild(logoPreviewImg);

    const logoRight = document.createElement("div");
    logoRight.style.cssText = "flex:1;";

    const logoHint = document.createElement("div");
    logoHint.className = "panel-hint";
    logoHint.textContent = "Logo (image/*, up to 5 MB)";
    logoRight.appendChild(logoHint);

    const logoInput = document.createElement("input");
    logoInput.type = "file";
    logoInput.accept = "image/*";
    logoInput.style.marginTop = "4px";
    logoRight.appendChild(logoInput);

    logoRow.appendChild(logoPreview);
    logoRow.appendChild(logoRight);
    settingsSection.appendChild(logoRow);

    // --- Description ---
    const descHint = document.createElement("div");
    descHint.className = "panel-hint";
    descHint.style.marginTop = "10px";
    descHint.textContent = "Description";
    settingsSection.appendChild(descHint);

    const descTa = document.createElement("textarea");
    descTa.rows = 3;
    descTa.maxLength = 800;
    descTa.placeholder = "Describe this room (optional)";
    descTa.style.cssText = "width:100%; margin-top:4px; resize:vertical; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.12); color:inherit; border-radius:6px; padding:6px 8px; font-size:13px; font-family:inherit; box-sizing:border-box;";
    settingsSection.appendChild(descTa);

    // Load current meta async
    getRoomMeta(rid, true).then(meta => {
      descTa.value = (meta?.description || "").trim();
      const logoSrc = meta?.logo_token || meta?.logo_url;
      if (logoSrc && typeof loadImageWithAuth === "function") {
        loadImageWithAuth(logoSrc, !!meta?.logo_token).then(blobUrl => {
          if (blobUrl) {
            logoPreviewImg.src = blobUrl;
            logoPreviewImg.style.display = "block";
            logoPreview.textContent = "";
            logoPreview.appendChild(logoPreviewImg);
          }
        }).catch(() => {});
      }
    }).catch(() => {});

    // --- Password ---
    const passHint = document.createElement("div");
    passHint.className = "panel-hint";
    passHint.style.marginTop = "10px";
    passHint.textContent = "Password";
    settingsSection.appendChild(passHint);

    const passInput = document.createElement("input");
    passInput.type = "password";
    passInput.autocomplete = "new-password";
    passInput.placeholder = roomHasPasswordById[String(rid)] ? "New password (leave blank to keep current)" : "Set password (optional)";
    passInput.style.cssText = "width:100%; margin-top:4px; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.12); color:inherit; border-radius:6px; padding:6px 8px; font-size:13px; font-family:inherit; box-sizing:border-box;";
    settingsSection.appendChild(passInput);

    // Save button row
    const saveBtnRow = document.createElement("div");
    saveBtnRow.style.cssText = "display:flex; gap:8px; margin-top:10px; flex-wrap:wrap;";

    const saveBtn = document.createElement("button");
    saveBtn.className = "panel-btn";
    saveBtn.style.flex = "1";
    saveBtn.textContent = "Save";
    saveBtnRow.appendChild(saveBtn);

    // Remove password button (only if room currently has one)
    let hasPass = !!roomHasPasswordById[String(rid)];
    const removePassBtn = document.createElement("button");
    removePassBtn.className = "panel-btn";
    removePassBtn.style.cssText = "background:rgba(220,53,69,0.25);";
    removePassBtn.textContent = "Remove password";
    removePassBtn.style.display = hasPass ? "" : "none";
    saveBtnRow.appendChild(removePassBtn);

    settingsSection.appendChild(saveBtnRow);
    settingsSection.appendChild(settingsStatus);

    // Save handler
    saveBtn.onclick = async (e) => {
      e.stopPropagation();
      saveBtn.disabled = true;
      removePassBtn.disabled = true;
      settingsStatus.textContent = "";
      try {
        // 1. Upload logo if selected
        const f = logoInput.files && logoInput.files[0] ? logoInput.files[0] : null;
        let logo_token = null;
        if (f) {
          settingsStatus.textContent = "Uploading logo…";
          const up = await postRoomLogoUpload(rid, f);
          logo_token = up?.token || null;
          if (up?.url && typeof loadImageWithAuth === "function") {
            loadImageWithAuth(up.url, !!logo_token).then(blobUrl => {
              if (blobUrl) {
                logoPreviewImg.src = blobUrl;
                logoPreviewImg.style.display = "block";
                logoPreview.textContent = "";
                logoPreview.appendChild(logoPreviewImg);
              }
            }).catch(() => {});
          }
          logoInput.value = "";
        }

        // 2. Save description (always)
        settingsStatus.textContent = "Saving…";
        safePost({
          type: "rooms_meta_set",
          roomId: rid,
          description: (descTa.value || "").trim() || null,
          logo_token: logo_token,
        });
        await waitRoomMeta(rid, "set");

        // 3. Change password if entered
        const newPass = passInput.value;
        if (newPass) {
          safePost({ type: "rooms_change_password", roomId: rid, password: newPass });
          const res = await waitRoomPasswordChange(rid);
          hasPass = !!res.has_password;
          roomHasPasswordById[String(rid)] = hasPass;
          removePassBtn.style.display = hasPass ? "" : "none";
          passInput.value = "";
          passInput.placeholder = hasPass ? "New password (leave blank to keep current)" : "Set password (optional)";
        }

        settingsStatus.textContent = "Saved ✓";
        setTimeout(() => { settingsStatus.textContent = ""; }, 2500);
      } catch (err) {
        settingsStatus.textContent = "Error: " + (err?.message || err);
      } finally {
        saveBtn.disabled = false;
        removePassBtn.disabled = false;
      }
    };

    // Remove password handler
    removePassBtn.onclick = async (e) => {
      e.stopPropagation();
      removePassBtn.disabled = true;
      saveBtn.disabled = true;
      settingsStatus.textContent = "Removing password…";
      try {
        safePost({ type: "rooms_change_password", roomId: rid, password: "" });
        await waitRoomPasswordChange(rid);
        hasPass = false;
        roomHasPasswordById[String(rid)] = false;
        removePassBtn.style.display = "none";
        passInput.placeholder = "Set password (optional)";
        passInput.value = "";
        settingsStatus.textContent = "Password removed ✓";
        setTimeout(() => { settingsStatus.textContent = ""; }, 2500);
      } catch (err) {
        settingsStatus.textContent = "Error: " + (err?.message || err);
      } finally {
        removePassBtn.disabled = false;
        saveBtn.disabled = false;
      }
    };

    el.appendChild(settingsSection);
  }

  // ---- Members ----
  const membersSection = document.createElement("div");
  membersSection.className = "panel-block";
  membersSection.style.marginTop = "12px";

  const membersTitle = document.createElement("div");
  membersTitle.className = "panel-block-title";
  membersTitle.textContent = "Members";
  membersSection.appendChild(membersTitle);

  if (!members.length) {
    const hint = document.createElement("div");
    hint.className = "panel-hint";
    hint.style.marginTop = "6px";
    hint.textContent = "Loading members…";
    membersSection.appendChild(hint);
  } else {
    for (const m of members) {
      const uname      = String(m.username || "").trim();
      const mRole      = m.role || (m.is_owner ? "owner" : "member");
      const isMe       = uname.toLowerCase() === meLower;
      const isMOwner   = mRole === "owner";
      const canModify  = isOwner && !isMe && !isMOwner;

      const row = document.createElement("div");
      row.style.cssText = "display:flex; align-items:center; gap:6px; padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.04); flex-wrap:wrap;";

      const nameSpan = document.createElement("span");
      nameSpan.style.flex = "1";
      nameSpan.textContent = uname + (isMOwner ? " 👑" : mRole === "admin" ? " ⚡" : "");
      row.appendChild(nameSpan);

      if (canModify) {
        const roleSelect = document.createElement("select");
        roleSelect.style.cssText = "font-size:12px; background:rgba(255,255,255,0.06); color:inherit; border:1px solid rgba(255,255,255,0.1); border-radius:4px; padding:2px 4px;";
        ["member", "admin"].forEach(r => {
          const opt = document.createElement("option");
          opt.value = r; opt.textContent = r;
          if (r === mRole) opt.selected = true;
          roleSelect.appendChild(opt);
        });
        roleSelect.onchange = () => safePost({ type: "rooms_set_role", roomId: rid, username: uname, role: roleSelect.value });
        row.appendChild(roleSelect);

        const kickBtn = document.createElement("button");
        kickBtn.className = "panel-btn";
        kickBtn.style.cssText = "font-size:11px; padding:2px 6px; background:rgba(220,53,69,0.3);";
        kickBtn.textContent = "Kick";
        kickBtn.onclick = () => {
          if (confirm(`Kick ${uname}?`)) safePost({ type: "rooms_kick", roomId: rid, username: uname });
        };
        row.appendChild(kickBtn);

        if (isOwner) {
          const reshareBtn = document.createElement("button");
          reshareBtn.className = "panel-btn";
          reshareBtn.style.cssText = "font-size:11px; padding:2px 6px;";
          reshareBtn.textContent = "Re-share key";
          reshareBtn.onclick = async () => {
            reshareBtn.disabled = true;
            reshareBtn.textContent = "…";
            try {
              await shareRoomKeyToUser(rid, uname);
              reshareBtn.textContent = "Done ✓";
            } catch (e) {
              reshareBtn.textContent = "Failed";
              console.warn("Re-share key failed:", e?.message || e);
            }
            setTimeout(() => { reshareBtn.textContent = "Re-share key"; reshareBtn.disabled = false; }, 2500);
          };
          row.appendChild(reshareBtn);
        }
      }

      membersSection.appendChild(row);
    }
  }
  el.appendChild(membersSection);

  // ---- Keys ----
  const keysSection = document.createElement("div");
  keysSection.className = "panel-block";
  keysSection.style.marginTop = "12px";

  const keysTitle = document.createElement("div");
  keysTitle.className = "panel-block-title";
  keysTitle.textContent = "Keys";
  keysSection.appendChild(keysTitle);

  const keysStatus = document.createElement("div");
  keysStatus.className = "panel-hint";
  keysStatus.style.marginTop = "6px";
  keysSection.appendChild(keysStatus);

  if (isOwner) {
    const rotateBtn = document.createElement("button");
    rotateBtn.className = "panel-btn";
    rotateBtn.style.cssText = "width:100%; margin-top:8px;";
    rotateBtn.textContent = "Rotate room key";
    rotateBtn.onclick = async () => {
      rotateBtn.disabled = true;
      rotateBtn.textContent = "Rotating…";
      keysStatus.textContent = "";
      try {
        const result = await rotateRoomKey(rid);
        if (result.ok) {
          const failNote = result.failed.length
            ? ` (${result.failed.length} failed: ${result.failed.join(", ")})`
            : "";
          keysStatus.textContent = `Key rotated. Shared to ${result.shared} member(s).${failNote}`;
        } else {
          keysStatus.textContent = "Rotation failed: " + (result.error || "unknown");
        }
      } catch (e) {
        keysStatus.textContent = "Error: " + (e?.message || e);
      }
      rotateBtn.textContent = "Rotate room key";
      rotateBtn.disabled = false;
    };
    keysSection.appendChild(rotateBtn);
  } else {
    const retryBtn = document.createElement("button");
    retryBtn.className = "panel-btn";
    retryBtn.style.cssText = "width:100%; margin-top:8px;";
    retryBtn.textContent = "Re-request my key";
    retryBtn.onclick = async () => {
      retryBtn.disabled = true;
      retryBtn.textContent = "Loading…";
      keysStatus.textContent = "";
      try {
        const ok = await loadRoomKey(rid);
        keysStatus.textContent = ok ? "Key loaded successfully." : "Key not available from server.";
      } catch (e) {
        keysStatus.textContent = "Error: " + (e?.message || e);
      }
      retryBtn.textContent = "Re-request my key";
      retryBtn.disabled = false;
    };
    keysSection.appendChild(retryBtn);
  }
  el.appendChild(keysSection);

  // ---- Join Requests (owner only) ----
  if (isOwner) {
    const reqSection = document.createElement("div");
    reqSection.className = "panel-block";
    reqSection.style.marginTop = "12px";

    const reqTitleRow = document.createElement("div");
    reqTitleRow.style.cssText = "display:flex; align-items:center; justify-content:space-between; gap:8px;";
    const reqTitle = document.createElement("div");
    reqTitle.className = "panel-block-title";
    reqTitle.textContent = "Join Requests";
    const reqRefresh = document.createElement("button");
    reqRefresh.className = "panel-btn";
    reqRefresh.style.fontSize = "11px";
    reqRefresh.textContent = "Refresh";
    reqRefresh.onclick = () => safePost({ type: "rooms_join_requests_list", roomId: rid });
    reqTitleRow.appendChild(reqTitle);
    reqTitleRow.appendChild(reqRefresh);
    reqSection.appendChild(reqTitleRow);

    const reqList = document.createElement("div");
    reqList.id = "roomManageReqList";
    reqList.style.marginTop = "8px";
    reqSection.appendChild(reqList);

    const allReqs = window.__cachedRoomJoinRequests || [];
    const roomReqs = allReqs.filter(r => Number(r.room_id) === rid);
    _renderRoomManageReqs(reqList, rid, roomReqs);

    el.appendChild(reqSection);
  }
}

function refreshRoomManageIfVisible() {
  const bManage = document.getElementById("roomsTabManage");
  if (!bManage || !bManage.classList.contains("is-active")) return;
  renderRoomManagePane(typeof activeRoomId !== "undefined" ? activeRoomId : null);
}

try {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { try { initRoomTabs(); } catch {} });
  } else {
    initRoomTabs();
  }
} catch {}

// ===== Feedback (canonical ids: feedbackMsg/feedbackSendBtn/feedbackStatus) =====
(() => {
  const btn = document.getElementById("feedbackSendBtn");
  const ta = document.getElementById("feedbackMsg");
  const st = document.getElementById("feedbackStatus");
  if (!btn || !ta || !st) return;
  if (btn.dataset.bound) return;
  btn.dataset.bound = "1";

  function setStatus(s) {
    st.textContent = s || "";
  }

  btn.addEventListener("click", async (e) => {
    e.preventDefault();
    e.stopPropagation();

    const txt = String(ta.value || "").trim();
    if (!txt) { setStatus("..."); return; }

    setStatus("Sending...");
    try {
      const username = (document.getElementById("profileInlineUsername")?.textContent || "").trim();
      await apiJson("/feedback/send", {
        method: "POST",
        body: JSON.stringify({
          message: txt,
          meta: { ts: Date.now(), username, ua: navigator.userAgent },
        }),
      });
      ta.value = "";
      setStatus("Sent");
      setTimeout(() => setStatus(""), 1500);
    } catch (err) {
      setStatus(`Error: ${err?.message || err}`);
    }
  });
})();
