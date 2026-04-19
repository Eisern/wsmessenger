// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * FileCard.js — renders a file attachment card (download button) for FILE2:: markers.
 */

import React, { useState } from 'react';
import {
  View, Text, TouchableOpacity, StyleSheet, Alert, PermissionsAndroid, Platform,
} from 'react-native';
import { Colors, Spacing, Radii, Typography } from '../theme';
import { formatFileSize } from '../utils/fileMarker';
import NetworkService from '../services/NetworkService';

export default function FileCard({ token, filename, sizeBytes }) {
  const [downloading, setDownloading] = useState(false);

  async function handleDownload() {
    if (downloading) return;
    setDownloading(true);
    try {
      // Request storage permission on older Android
      if (Platform.OS === 'android' && Platform.Version < 30) {
        const granted = await PermissionsAndroid.request(
          PermissionsAndroid.PERMISSIONS.WRITE_EXTERNAL_STORAGE,
          { title: 'Storage Permission', message: 'Allow download?', buttonPositive: 'OK' },
        );
        if (granted !== PermissionsAndroid.RESULTS.GRANTED) {
          Alert.alert('Permission denied', 'Cannot save file without storage permission.');
          return;
        }
      }

      const RNFS = require('react-native-fs');
      const url = NetworkService.getFileUrl(token);
      const headers = NetworkService.getFileHeaders();
      const destDir = RNFS.DownloadDirectoryPath || RNFS.DocumentDirectoryPath;
      // Defense-in-depth: strip path separators and traversal sequences from filename
      const safeName = (filename || 'file').replace(/[\/\\]/g, '_').replace(/\.\./g, '_') || 'file';
      const destPath = `${destDir}/${safeName}`;

      const res = await RNFS.downloadFile({
        fromUrl: url,
        toFile: destPath,
        headers,
      }).promise;

      if (res.statusCode === 200) {
        Alert.alert('Downloaded', `Saved to:\n${destPath}`);
      } else {
        Alert.alert('Download failed', `Server returned status ${res.statusCode}`);
      }
    } catch (e) {
      Alert.alert('Download error', e?.message || 'Unknown error');
    } finally {
      setDownloading(false);
    }
  }

  const sizeStr = formatFileSize(sizeBytes);

  return (
    <TouchableOpacity style={styles.card} onPress={handleDownload} disabled={downloading}>
      <Text style={styles.icon}>📎</Text>
      <View style={styles.info}>
        <Text style={styles.filename} numberOfLines={2}>{filename}</Text>
        {sizeStr ? <Text style={styles.size}>{sizeStr}</Text> : null}
      </View>
      <Text style={styles.dlIcon}>{downloading ? '⏳' : '⬇️'}</Text>
    </TouchableOpacity>
  );
}

const styles = StyleSheet.create({
  card: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: Colors.inputBg,
    borderWidth: 1,
    borderColor: Colors.border,
    borderRadius: Radii.md,
    padding: Spacing.sm,
    gap: Spacing.sm,
    marginTop: 2,
  },
  icon: { fontSize: 20 },
  info: { flex: 1 },
  filename: {
    color: Colors.accent,
    fontSize: Typography.sm,
    fontWeight: '500',
  },
  size: {
    color: Colors.textMuted,
    fontSize: Typography.xs,
    marginTop: 2,
  },
  dlIcon: { fontSize: 18, marginLeft: Spacing.xs },
});
