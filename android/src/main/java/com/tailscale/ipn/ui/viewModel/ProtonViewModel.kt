// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import libtailscale.Libtailscale
import libtailscale.ProtonStatusReceiver

@Serializable data class ProtonCountry(val code: String, val minTier: Int = 0, val count: Int = 0)

/**
 * ProtonBridge is the singleton link between the Kotlin UI and the Go ProtonVPN control + data
 * plane (libtailscale/proton_*.go). It receives connection state/error callbacks from Go and
 * exposes everything as flows. ALL Libtailscale.proton* calls block (network I/O or the backend
 * loop), so they must run on a background thread — callers go through [ProtonViewModel], which uses
 * Dispatchers.IO.
 */
object ProtonBridge : ProtonStatusReceiver {
  private val json = Json { ignoreUnknownKeys = true }

  // Tunnel connection state (driven by Go callbacks).
  private val _state = MutableStateFlow("Disconnected")
  val state: StateFlow<String> = _state
  private val _error = MutableStateFlow<String?>(null)
  val error: StateFlow<String?> = _error

  // Account / login state.
  private val _loggedIn = MutableStateFlow(false)
  val loggedIn: StateFlow<Boolean> = _loggedIn
  private val _needs2FA = MutableStateFlow(false)
  val needs2FA: StateFlow<Boolean> = _needs2FA
  private val _countries = MutableStateFlow<List<ProtonCountry>>(emptyList())
  val countries: StateFlow<List<ProtonCountry>> = _countries
  private val _busy = MutableStateFlow(false)
  val busy: StateFlow<Boolean> = _busy

  // Human verification (CAPTCHA) WebView.
  private val _needsCaptcha = MutableStateFlow(false)
  val needsCaptcha: StateFlow<Boolean> = _needsCaptcha
  private val _captchaUrl = MutableStateFlow("")
  val captchaUrl: StateFlow<String> = _captchaUrl
  private var pendingUser = ""
  private var pendingPass = ""

  // Manual .conf fallback (debug).
  private val _config = MutableStateFlow("")
  val config: StateFlow<String> = _config

  fun register() {
    Libtailscale.setProtonStatusReceiver(this)
    refreshLoginState()
  }

  fun setConfig(value: String) {
    _config.value = value
  }

  // --- libtailscale.ProtonStatusReceiver (called from Go) ---
  override fun onProtonState(state: String) {
    _state.value = state
  }

  override fun onProtonError(code: Long, description: String) {
    _error.value = "[$code] $description"
  }

  // --- Account (all run on a background thread) ---

  fun refreshLoginState() {
    _loggedIn.value =
        try {
          Libtailscale.protonIsLoggedIn()
        } catch (e: Exception) {
          false
        }
  }

  fun login(username: String, password: String) {
    pendingUser = username
    pendingPass = password
    _error.value = null
    _busy.value = true
    try {
      when (Libtailscale.protonLogin(username, password)) {
        "ok" -> {
          _loggedIn.value = true
          loadCountriesLocked()
        }
        "2fa" -> _needs2FA.value = true
        "hv" -> {
          _captchaUrl.value =
              buildCaptchaUrl(Libtailscale.protonHVStartToken(), Libtailscale.protonHVMethods())
          _needsCaptcha.value = true
        }
      }
    } catch (e: Exception) {
      _error.value = "Login failed: ${e.message}"
    } finally {
      _busy.value = false
    }
  }

  /** onCaptchaSolved records the solved token and retries the login. */
  fun onCaptchaSolved(token: String, tokenType: String) {
    Libtailscale.protonSetHumanVerification(token, tokenType)
    _needsCaptcha.value = false
    login(pendingUser, pendingPass)
  }

  fun cancelCaptcha() {
    _needsCaptcha.value = false
  }

  private fun buildCaptchaUrl(startToken: String, methods: String): String {
    val m = methods.ifBlank { "captcha" }
    val t = java.net.URLEncoder.encode(startToken, "UTF-8")
    return "https://verify.proton.me/?embed=true&token=$t&methods=$m&theme=2"
  }

  fun submit2FA(code: String) {
    _error.value = null
    _busy.value = true
    try {
      Libtailscale.protonSubmit2FA(code)
      _needs2FA.value = false
      _loggedIn.value = true
      loadCountriesLocked()
    } catch (e: Exception) {
      _error.value = "2FA failed: ${e.message}"
    } finally {
      _busy.value = false
    }
  }

  fun loadCountries() {
    _busy.value = true
    try {
      loadCountriesLocked()
    } finally {
      _busy.value = false
    }
  }

  private fun loadCountriesLocked() {
    try {
      val raw = Libtailscale.protonListCountries()
      _countries.value =
          json.decodeFromString<List<ProtonCountry>>(raw).sortedBy { it.code }
    } catch (e: Exception) {
      _error.value = "Couldn't load servers: ${e.message}"
    }
  }

  fun connectCountry(code: String) {
    _error.value = null
    _state.value = "Connecting"
    try {
      Libtailscale.protonConnectCountry(code)
    } catch (e: Exception) {
      _state.value = "Disconnected"
      _error.value = "Connect failed: ${e.message}"
    }
  }

  fun logout() {
    try {
      Libtailscale.protonLogout()
    } catch (e: Exception) {
      // best effort
    }
    _loggedIn.value = false
    _needs2FA.value = false
    _countries.value = emptyList()
  }

  // --- Tunnel ---

  fun connectManual(conf: String) {
    val privateKey = confValue(conf, "PrivateKey")
    val publicKey = confValue(conf, "PublicKey")
    val endpoint = confValue(conf, "Endpoint")
    val address = confValue(conf, "Address") ?: ""
    if (privateKey == null || publicKey == null || endpoint == null) {
      _error.value = "Config must contain PrivateKey, PublicKey and Endpoint lines"
      return
    }
    if (address.isEmpty()) {
      _error.value = "Config is missing the [Interface] Address line"
      return
    }
    _error.value = null
    _state.value = "Connecting"
    try {
      Libtailscale.protonConnectManual(privateKey, publicKey, endpoint, address)
    } catch (e: Exception) {
      _state.value = "Disconnected"
      _error.value = "Connect failed: ${e.message}"
    }
  }

  fun disconnect() {
    try {
      Libtailscale.protonDisconnect()
    } catch (e: Exception) {
      _error.value = "Disconnect failed: ${e.message}"
    }
  }

  private fun confValue(conf: String, key: String): String? {
    val re = Regex("(?im)^\\s*$key\\s*=\\s*(.+?)\\s*$")
    return re.find(conf)?.groupValues?.get(1)?.trim()
  }
}

class ProtonViewModel : ViewModel() {
  val state: StateFlow<String> = ProtonBridge.state
  val error: StateFlow<String?> = ProtonBridge.error
  val loggedIn: StateFlow<Boolean> = ProtonBridge.loggedIn
  val needs2FA: StateFlow<Boolean> = ProtonBridge.needs2FA
  val countries: StateFlow<List<ProtonCountry>> = ProtonBridge.countries
  val busy: StateFlow<Boolean> = ProtonBridge.busy
  val config: StateFlow<String> = ProtonBridge.config
  val needsCaptcha: StateFlow<Boolean> = ProtonBridge.needsCaptcha
  val captchaUrl: StateFlow<String> = ProtonBridge.captchaUrl

  fun setConfig(value: String) = ProtonBridge.setConfig(value)

  fun login(username: String, password: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.login(username, password) }
  }

  fun onCaptchaSolved(token: String, tokenType: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.onCaptchaSolved(token, tokenType) }
  }

  fun cancelCaptcha() = ProtonBridge.cancelCaptcha()

  fun submit2FA(code: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.submit2FA(code) }
  }

  fun loadCountries() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.loadCountries() }
  }

  fun connectCountry(code: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.connectCountry(code) }
  }

  fun logout() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.logout() }
  }

  fun connectManual(conf: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.connectManual(conf) }
  }

  fun disconnect() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.disconnect() }
  }
}
