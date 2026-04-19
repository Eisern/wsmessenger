// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Yevgeniy Kropochev <y.kropochev87@gmail.com>
// This file is part of WS Messenger. See LICENSE for terms.

// @ts-nocheck
/**
 * useKeyboardHeight — reliable keyboard height tracking for Android.
 * Returns the keyboard overlap with the app content area (0 when hidden).
 *
 * On Android, Keyboard.endCoordinates.height includes the system navigation
 * bar, which is outside our content area (when edge-to-edge is off).
 * We subtract the nav bar height (screen - window) to get the actual overlap.
 */
import { useState, useEffect } from 'react';
import { Keyboard, Platform, Dimensions } from 'react-native';

function getNavBarHeight() {
  const screen = Dimensions.get('screen').height;
  const window = Dimensions.get('window').height;
  return Math.max(0, screen - window);
}

export default function useKeyboardHeight() {
  const [keyboardHeight, setKeyboardHeight] = useState(0);

  useEffect(() => {
    if (Platform.OS !== 'android') return;

    const showSub = Keyboard.addListener('keyboardDidShow', (e) => {
      const rawHeight = e.endCoordinates.height;
      const navBar = getNavBarHeight();
      setKeyboardHeight(Math.max(0, rawHeight - navBar));
    });
    const hideSub = Keyboard.addListener('keyboardDidHide', () => {
      setKeyboardHeight(0);
    });

    return () => {
      showSub.remove();
      hideSub.remove();
    };
  }, []);

  return keyboardHeight;
}
