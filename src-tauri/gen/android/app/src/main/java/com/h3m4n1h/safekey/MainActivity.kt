package com.h3m4n1h.safekey

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import java.io.File

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // The WebView cannot update a service worker on the app's origin, so a registered one keeps
    // serving stale app files after an update. Remove its storage before the WebView starts;
    // vault data lives in Local Storage, which is left alone.
    listOf("app_webview/Default/Service Worker", "app_webview/Service Worker").forEach {
      File(applicationInfo.dataDir, it).deleteRecursively()
    }

    // Light status/navigation bar icons to match the app's dark background
    enableEdgeToEdge(
      statusBarStyle = SystemBarStyle.dark(Color.TRANSPARENT),
      navigationBarStyle = SystemBarStyle.dark(Color.TRANSPARENT)
    )
    super.onCreate(savedInstanceState)

    // Keep vault contents out of screenshots, screen recordings and the recent-apps preview
    window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

    // Keep the WebView clear of the status bar, navigation bar, display cutout and keyboard
    val content = findViewById<View>(android.R.id.content)
    content.setBackgroundColor(Color.parseColor("#060a13"))
    ViewCompat.setOnApplyWindowInsetsListener(content) { view, insets ->
      val bars = insets.getInsets(
        WindowInsetsCompat.Type.systemBars() or
          WindowInsetsCompat.Type.displayCutout() or
          WindowInsetsCompat.Type.ime()
      )
      view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
      WindowInsetsCompat.CONSUMED
    }
  }
}
