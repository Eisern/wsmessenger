// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * RoomLogo — Room avatar with logo image or initials fallback.
 * Mirrors Chrome extension .roomcard-logo (48x48, rounded, initials).
 */
import React, { useState } from 'react';
import { View, Image, Text, StyleSheet } from 'react-native';
import NetworkService from '../services/NetworkService';
import { Colors, Radii } from '../theme';

function roomInitials(name) {
  const trimmed = (name || '').trim();
  if (!trimmed) return '?';
  const words = trimmed.split(/\s+/);
  if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
  return trimmed.slice(0, 2).toUpperCase();
}

// Stable color from room name — matches extension's hash-based coloring
function initialsColor(name) {
  let h = 0;
  for (let i = 0; i < (name || '').length; i++) {
    h = ((h << 5) - h + name.charCodeAt(i)) | 0;
  }
  const hue = ((h % 360) + 360) % 360;
  return `hsl(${hue}, 55%, 45%)`;
}

export default function RoomLogo({ logoUrl, roomName, size = 40 }) {
  const [imgFailed, setImgFailed] = useState(false);
  const source = logoUrl ? NetworkService.getAuthImageSource(logoUrl) : null;
  const showImage = source && !imgFailed;

  const containerStyle = [
    styles.container,
    { width: size, height: size, borderRadius: size * 0.2 },
  ];

  if (showImage) {
    return (
      <View style={containerStyle}>
        <Image
          source={source}
          style={[styles.image, { width: size, height: size, borderRadius: size * 0.2 }]}
          onError={() => setImgFailed(true)}
          resizeMode="cover"
        />
      </View>
    );
  }

  return (
    <View style={[containerStyle, { backgroundColor: initialsColor(roomName) }]}>
      <Text style={[styles.initials, { fontSize: size * 0.4 }]} numberOfLines={1}>
        {roomInitials(roomName)}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    justifyContent: 'center',
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: Colors.border,
  },
  image: {
    backgroundColor: Colors.bgCard,
  },
  initials: {
    color: '#fff',
    fontWeight: '700',
    textAlign: 'center',
  },
});
