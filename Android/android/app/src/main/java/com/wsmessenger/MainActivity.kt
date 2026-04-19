package com.wsmessenger

import android.os.Bundle
import android.view.WindowManager
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {

  override fun getMainComponentName(): String = "WsMessenger"

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    // Prevent screenshots and screen recording on the main Activity window.
    window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }

  /**
   * Apply FLAG_SECURE to every window that gains focus, including Dialog/Modal
   * windows created by React Native's Alert and Modal components.
   *
   * Previous approach (overriding getSystemService to wrap WindowManager with a
   * SecureWindowManager delegate) caused ClassCastException on Android 14-15:
   *   Dialog.<init>() casts getSystemService(WINDOW_SERVICE) to WindowManagerImpl
   *   (an internal framework class), and our delegate wrapper is not WindowManagerImpl.
   *
   * This approach is safe: onWindowFocusChanged fires for the Activity window AND
   * for every Dialog window that gains focus. FLAG_SECURE on a Dialog window prevents
   * screen capture of that dialog's content.
   */
  override fun onWindowFocusChanged(hasFocus: Boolean) {
    super.onWindowFocusChanged(hasFocus)
    if (hasFocus) {
      window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
  }

  override fun createReactActivityDelegate(): ReactActivityDelegate =
      DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled)
}
