// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * ImageCard.js — inline thumbnail for image attachments (jpg/jpeg/png/webp/gif).
 *
 * Security notes:
 * - Fetched and decrypted by FileTransferService.fetchFileTo — the same path as
 *   every other file download; what the island holds is an opaque blob.
 * - The decrypted image is cached in RNFS.CachesDirectoryPath (app-private, not
 *   accessible by other apps).
 * - Cache key is the file token (validated to [A-Za-z0-9_-] by parseFileMarker).
 * - On download error falls back to a plain FileCard (no silent failure).
 */

import React, { useState, useEffect } from 'react';
import {
  View, Text, Image, TouchableOpacity, Modal, StyleSheet,
  ActivityIndicator, Dimensions, StatusBar,
} from 'react-native';
import { Colors, Spacing, Radii, Typography } from '../theme';
import { formatFileSize } from '../utils/fileMarker';
import { fetchFileTo } from '../services/FileTransferService';
import FileCard from './FileCard';

const THUMB_HEIGHT = 180;

export default function ImageCard({ file }) {
  const { token, filename, sizeBytes } = file;
  const [localUri, setLocalUri] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function fetchImage() {
      try {
        const RNFS = require('react-native-fs');
        // Token is pre-validated to [A-Za-z0-9_-] by parseFileMarker — safe as filename.
        const cachePath = `${RNFS.CachesDirectoryPath}/ws_img_${token}`;
        const exists = await RNFS.exists(cachePath);
        if (exists) {
          if (!cancelled) setLocalUri(`file://${cachePath}`);
          return;
        }
        // Throws on anything but a whole, authentic file, and leaves nothing
        // at cachePath when it does (the catch below falls back to FileCard).
        await fetchFileTo(file, cachePath);

        // Validate magic bytes: the name says "image", the content must too.
        // A sender can call anything photo.png.
        let isValidImage = false;
        try {
          const headerB64 = await RNFS.read(cachePath, 12, 0, 'base64');
          const b = Uint8Array.from(atob(headerB64), c => c.charCodeAt(0));
          isValidImage =
            (b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) ||           // JPEG
            (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47) || // PNG
            (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) ||           // GIF
            (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&  // WEBP (RIFF....WEBP)
             b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50);
        } catch (_e) {
          isValidImage = false;   // too short to be an image, or unreadable
        }
        if (!isValidImage) {
          await RNFS.unlink(cachePath).catch(() => {});
          if (!cancelled) setLoadError(true);
          return;
        }
        if (!cancelled) setLocalUri(`file://${cachePath}`);
      } catch (_e) {
        if (!cancelled) setLoadError(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchImage();
    return () => { cancelled = true; };
  }, [token]);

  // Fall back to regular FileCard on any download/render error
  if (loadError) {
    return <FileCard file={file} />;
  }

  const screenWidth = Dimensions.get('window').width;
  const thumbWidth = Math.min(220, screenWidth * 0.62);
  const sizeStr = formatFileSize(sizeBytes);

  return (
    <>
      <TouchableOpacity
        style={[styles.thumb, { width: thumbWidth }]}
        onPress={() => localUri && setFullscreen(true)}
        activeOpacity={0.85}
      >
        {loading || !localUri ? (
          <View style={[styles.placeholder, { width: thumbWidth, height: THUMB_HEIGHT }]}>
            <ActivityIndicator color={Colors.accent} />
          </View>
        ) : (
          <Image
            source={{ uri: localUri }}
            style={[styles.thumbImg, { width: thumbWidth, height: THUMB_HEIGHT }]}
            resizeMode="cover"
            onError={() => setLoadError(true)}
          />
        )}
        <View style={styles.caption}>
          <Text style={styles.captionText} numberOfLines={1}>{filename}</Text>
          {sizeStr ? <Text style={styles.captionSize}>{sizeStr}</Text> : null}
        </View>
      </TouchableOpacity>

      {fullscreen && (
        <Modal
          visible={fullscreen}
          transparent
          animationType="fade"
          statusBarTranslucent
          onRequestClose={() => setFullscreen(false)}
        >
          <StatusBar backgroundColor="rgba(0,0,0,0.96)" barStyle="light-content" />
          <TouchableOpacity
            style={styles.overlay}
            activeOpacity={1}
            onPress={() => setFullscreen(false)}
          >
            <Image
              source={{ uri: localUri }}
              style={styles.fullImg}
              resizeMode="contain"
            />
            <View style={styles.closeHintWrap}>
              <Text style={styles.closeHint}>Tap to close</Text>
            </View>
          </TouchableOpacity>
        </Modal>
      )}
    </>
  );
}

const styles = StyleSheet.create({
  thumb: {
    borderRadius: Radii.md,
    overflow: 'hidden',
    borderWidth: 1,
    borderColor: Colors.border,
    marginTop: 2,
    backgroundColor: Colors.inputBg,
  },
  placeholder: {
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: Colors.inputBg,
  },
  thumbImg: {
    // width/height set inline
  },
  caption: {
    paddingHorizontal: Spacing.sm,
    paddingVertical: 5,
    borderTopWidth: 1,
    borderTopColor: Colors.borderSubtle,
  },
  captionText: {
    color: Colors.accent,
    fontSize: Typography.xs,
    fontWeight: '500',
  },
  captionSize: {
    color: Colors.textMuted,
    fontSize: Typography.xs - 1,
    marginTop: 1,
  },
  overlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.96)',
    alignItems: 'center',
    justifyContent: 'center',
  },
  fullImg: {
    width: '100%',
    height: '90%',
  },
  closeHintWrap: {
    position: 'absolute',
    bottom: 32,
    alignSelf: 'center',
  },
  closeHint: {
    color: 'rgba(255,255,255,0.45)',
    fontSize: Typography.sm,
  },
});
