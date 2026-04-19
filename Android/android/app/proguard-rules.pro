# Add project specific ProGuard rules here.
# By default, the flags in this file are appended to flags specified
# in /usr/local/Cellar/android-sdk/24.3.3/tools/proguard/proguard-android.txt
# You can edit the include path and order by changing the proguardFiles
# directive in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# Add any project specific keep options here:

# ---- React Native ----
-keep class com.facebook.react.** { *; }
-keep class com.facebook.hermes.** { *; }
-keep class com.facebook.jni.** { *; }
-dontwarn com.facebook.react.**
-dontwarn com.facebook.hermes.**

# ---- react-native-quick-crypto ----
-keep class com.margelo.** { *; }
-dontwarn com.margelo.**

# ---- react-native-keychain ----
-keep class com.oblador.keychain.** { *; }

# ---- @notifee/react-native ----
-keep class io.invertase.notifee.** { *; }
-dontwarn io.invertase.notifee.**

# ---- OkHttp (network stack used by RN) ----
-dontwarn okhttp3.**
-dontwarn okio.**

# ---- Keep JS entry points & JNI ----
-keepclassmembers class * {
    @com.facebook.react.bridge.ReactMethod *;
}
