// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.view

import android.annotation.SuppressLint
import android.graphics.Color
import android.util.Log
import android.webkit.ConsoleMessage
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView
import com.tailscale.ipn.R
import org.json.JSONObject

/**
 * Proton human-verification (CAPTCHA) WebView. Loads Proton's verify page, which posts a solved
 * token back via the "AndroidInterface" JS bridge (message type HUMAN_VERIFICATION_SUCCESS). Logs
 * page-load / network / console events under the "proton-captcha" tag for debugging.
 */
@SuppressLint("SetJavaScriptEnabled")
@Composable
fun ProtonCaptchaView(url: String, onSolved: (String, String) -> Unit, onCancel: () -> Unit) {
  Scaffold(topBar = { Header(R.string.proton_captcha_title, onBack = onCancel) }) { innerPadding ->
    AndroidView(
        modifier = Modifier.padding(innerPadding).fillMaxSize(),
        factory = { ctx ->
          Log.i("proton-captcha", "loading url: $url")
          WebView(ctx).apply {
            setBackgroundColor(Color.WHITE)
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.mediaPlaybackRequiresUserGesture = false
            WebView.setWebContentsDebuggingEnabled(true)

            webViewClient =
                object : WebViewClient() {
                  override fun onPageFinished(view: WebView?, u: String?) {
                    Log.i("proton-captcha", "pageFinished: $u")
                  }

                  override fun onReceivedError(
                      view: WebView?,
                      request: WebResourceRequest?,
                      error: WebResourceError?
                  ) {
                    Log.e(
                        "proton-captcha",
                        "error ${error?.errorCode} '${error?.description}' for ${request?.url}")
                  }

                  override fun onReceivedHttpError(
                      view: WebView?,
                      request: WebResourceRequest?,
                      errorResponse: WebResourceResponse?
                  ) {
                    Log.e(
                        "proton-captcha",
                        "httpError ${errorResponse?.statusCode} for ${request?.url}")
                  }
                }

            webChromeClient =
                object : WebChromeClient() {
                  override fun onConsoleMessage(m: ConsoleMessage): Boolean {
                    Log.i(
                        "proton-captcha",
                        "console: ${m.message()} @ ${m.sourceId()}:${m.lineNumber()}")
                    return true
                  }
                }

            addJavascriptInterface(
                object {
                  @JavascriptInterface
                  fun dispatch(message: String) {
                    Log.i("proton-captcha", "dispatch: $message")
                    try {
                      val obj = JSONObject(message)
                      if (obj.optString("type") == "HUMAN_VERIFICATION_SUCCESS") {
                        val payload = obj.optJSONObject("payload") ?: return
                        val token = payload.optString("token")
                        val type = payload.optString("type", "captcha")
                        if (token.isNotEmpty()) post { onSolved(token, type) }
                      }
                    } catch (e: Exception) {
                      Log.e("proton-captcha", "dispatch parse error: ${e.message}")
                    }
                  }
                },
                "AndroidInterface")

            loadUrl(url)
          }
        })
  }
}
