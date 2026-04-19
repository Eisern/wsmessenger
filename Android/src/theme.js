// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * theme.js — Design tokens ported from panel.css
 */

export const Colors = {
  // Backgrounds
  bgMain: '#0e1117',
  bgPanel: '#161b22',
  bgCard: 'rgba(255,255,255,0.045)',
  bgHover: 'rgba(255,255,255,0.07)',
  bgPane: 'rgba(255,255,255,0.04)',

  // Text
  textMain: '#e6edf3',
  textMuted: '#9aa4af',
  textDim: 'rgba(255,255,255,0.45)',
  authorName: '#6dcff6',

  // Borders
  border: 'rgba(255,255,255,0.10)',
  borderStrong: 'rgba(255,255,255,0.16)',
  borderSubtle: 'rgba(255,255,255,0.06)',

  // Status
  success: '#3fb950',
  danger: '#f85149',
  warning: '#f0a429',

  // Accent
  accent: '#3aa0ff',
  accentDm: '#8b5cf6',
  public: 'rgba(0,160,255,0.45)',
  publicBg: 'rgba(0,160,255,0.08)',

  // Buttons
  btnBg: '#21262d',
  btnBgHover: '#2d333b',

  // Input
  inputBg: '#0d1117',

  // Overlay
  overlay: 'rgba(0,0,0,0.55)',

  // Notification
  badgeBlue: '#2aabee',
  notifRed: '#ff3b30',
};

export const Typography = {
  fontFamily: 'System',
  xs: 11,
  sm: 12,
  md: 13,
  lg: 14,
  xl: 16,
  xxl: 18,
};

export const Spacing = {
  xs: 4,
  sm: 6,
  md: 8,
  lg: 12,
  xl: 16,
  xxl: 24,
};

export const Radii = {
  xs: 4,
  sm: 6,
  md: 10,
  lg: 12,
  xl: 16,
  round: 999,
};
