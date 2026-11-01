// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.net.HttpURLConnection
import java.net.URL
import libtailscale.Libtailscale
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Checks the native APK's client version against Proton without using a user's account. */
@RunWith(AndroidJUnit4::class)
class ProtonCompatibilityTest {
  @Test
  fun protonAcceptsNativeClientVersion() {
    val version = Libtailscale.protonClientVersion()
    fun request(path: String, method: String): HttpURLConnection {
      return (URL("https://vpn-api.proton.me$path").openConnection() as HttpURLConnection).apply {
        requestMethod = method
        connectTimeout = 20000
        readTimeout = 20000
        setRequestProperty("x-pm-appversion", "android-vpn@$version")
        setRequestProperty("User-Agent", "ProtonVPN/$version (Android)")
        setRequestProperty("Accept", "application/vnd.protonmail.v1+json")
      }
    }
    val connection = request("/auth/v4/sessions", "POST")
    val session = try {
      connection.doOutput = true
      connection.setRequestProperty("Content-Type", "application/json")
      connection.outputStream.use { it.write("{}".toByteArray()) }
      assertEquals("Proton rejected native client $version", 200, connection.responseCode)
      JSONObject(connection.inputStream.bufferedReader().use { it.readText() }).also {
        assertEquals("Proton requires a newer client than $version", 1000, it.getInt("Code"))
      }
    } finally {
      connection.disconnect()
    }
    // Revoke the anonymous probe session; never log or persist the returned tokens.
    val logout = request("/auth/v4", "DELETE")
    try {
      logout.setRequestProperty("x-pm-uid", session.getString("UID"))
      logout.setRequestProperty("Authorization", "Bearer " + session.getString("AccessToken"))
      assertEquals(200, logout.responseCode)
    } finally {
      logout.disconnect()
    }
  }
}
