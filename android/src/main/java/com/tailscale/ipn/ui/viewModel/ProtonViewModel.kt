// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.viewModel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.tailscale.ipn.ui.localapi.Client
import com.tailscale.ipn.ui.model.Ipn
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

@Serializable
data class ProtonServer(
    val id: String,
    val name: String,
    val city: String = "",
    val load: Int = 0,
    val tier: Int = 0
)

@Serializable
data class ProtonServerStatus(
    val name: String = "",
    val country: String = "",
    val load: Int = 0
)

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

  // Country code of the currently selected Proton exit (for the exit-node UI).
  private val _connectedCountry = MutableStateFlow("")
  val connectedCountry: StateFlow<String> = _connectedCountry

  // Favorite country codes (UI-only, persisted in Go) and the servers of the
  // country currently being drilled into.
  private val _favorites = MutableStateFlow<Set<String>>(emptySet())
  val favorites: StateFlow<Set<String>> = _favorites
  private val _servers = MutableStateFlow<List<ProtonServer>>(emptyList())
  val servers: StateFlow<List<ProtonServer>> = _servers

  // Country code marked to auto-connect when the VPN starts ("" = off).
  private val _autoConnectCountry = MutableStateFlow("")
  val autoConnectCountry: StateFlow<String> = _autoConnectCountry

  // Connected server name + (connect-time) load %, and the latest ping result.
  private val _connectedServerName = MutableStateFlow("")
  val connectedServerName: StateFlow<String> = _connectedServerName
  private val _connectedLoad = MutableStateFlow(0)
  val connectedLoad: StateFlow<Int> = _connectedLoad
  private val _pingResult = MutableStateFlow("")
  val pingResult: StateFlow<String> = _pingResult

  // Human verification (CAPTCHA) WebView.
  private val _needsCaptcha = MutableStateFlow(false)
  val needsCaptcha: StateFlow<Boolean> = _needsCaptcha
  private val _captchaUrl = MutableStateFlow("")
  val captchaUrl: StateFlow<String> = _captchaUrl
  private var pendingUser = ""
  private var pendingPass = ""

  // Custom DNS server(s) used while Proton is enabled (comma-separated IPs).
  private val _customDns = MutableStateFlow("")
  val customDns: StateFlow<String> = _customDns

  // Manual .conf fallback (debug).
  private val _config = MutableStateFlow("")
  val config: StateFlow<String> = _config

  fun register() {
    Libtailscale.setProtonStatusReceiver(this)
    refreshLoginState()
    loadCustomDns()
    loadFavorites()
    loadAutoConnect()
  }

  // --- Favorites (country codes; persisted in Go, UI-only) ---

  fun loadFavorites() {
    _favorites.value =
        try {
          Libtailscale.protonGetFavoriteCountries()
              .split(",")
              .map { it.trim() }
              .filter { it.isNotEmpty() }
              .toSet()
        } catch (e: Exception) {
          emptySet()
        }
  }

  fun toggleFavorite(code: String) {
    val next = _favorites.value.toMutableSet()
    if (!next.add(code)) next.remove(code)
    _favorites.value = next
    try {
      Libtailscale.protonSetFavoriteCountries(next.joinToString(","))
    } catch (e: Exception) {
      // best effort
    }
  }

  // --- Auto-connect country (persisted in Go; armed per-country in the picker) ---

  fun loadAutoConnect() {
    _autoConnectCountry.value =
        try {
          Libtailscale.protonGetAutoConnectCountry()
        } catch (e: Exception) {
          ""
        }
  }

  fun setAutoConnect(code: String) {
    try {
      Libtailscale.protonSetAutoConnectCountry(code)
      _autoConnectCountry.value = code
    } catch (e: Exception) {
      // best effort
    }
  }

  /** Marks code for auto-connect, or clears it if it's already the marked one. */
  fun toggleAutoConnect(code: String) {
    setAutoConnect(if (_autoConnectCountry.value == code) "" else code)
  }

  // --- Individual servers in a country ---

  fun loadServers(countryCode: String) {
    _busy.value = true
    try {
      val raw = Libtailscale.protonListServers(countryCode)
      _servers.value = json.decodeFromString<List<ProtonServer>>(raw)
    } catch (e: Exception) {
      _servers.value = emptyList()
      _error.value = "Couldn't load servers: ${e.message}"
    } finally {
      _busy.value = false
    }
  }

  fun connectServer(serverId: String, countryCode: String) {
    _error.value = null
    _state.value = "Connecting"
    _connectedCountry.value = countryCode
    try {
      Libtailscale.protonConnectServer(serverId)
    } catch (e: Exception) {
      _state.value = "Disconnected"
      _connectedCountry.value = ""
      _error.value = "Connect failed: ${e.message}"
    }
  }

  // --- Quick change: fastest server in your country / fastest overall ---

  fun fastestInCountry() {
    _error.value = null
    _state.value = "Connecting"
    try {
      Libtailscale.protonFastestInCountry()
    } catch (e: Exception) {
      _state.value = "Connected"
      _error.value = "Couldn't switch server: ${e.message}"
    }
  }

  fun fastestOverall() {
    _error.value = null
    _state.value = "Connecting"
    try {
      Libtailscale.protonFastestOverall()
    } catch (e: Exception) {
      _state.value = "Connected"
      _error.value = "Couldn't switch server: ${e.message}"
    }
  }

  // --- Connected server status + latency ---

  fun refreshCurrentServer() {
    try {
      val info = json.decodeFromString<ProtonServerStatus>(Libtailscale.protonCurrentServer())
      if (info.name != _connectedServerName.value) _pingResult.value = ""
      _connectedServerName.value = info.name
      _connectedLoad.value = info.load
    } catch (e: Exception) {
      _connectedServerName.value = ""
      _connectedLoad.value = 0
    }
  }

  fun ping() {
    _pingResult.value = "…"
    try {
      _pingResult.value = "${Libtailscale.protonPingCurrent()} ms"
    } catch (e: Exception) {
      _pingResult.value = "unreachable"
    }
  }

  // tileActive / tileServerLabel and the Exit-node tile actions are called from the
  // Quick Settings tile (ProtonQuickServerTileService), which has no ViewModel /
  // coroutine scope, so they run their Libtailscale calls on a plain Thread.
  fun tileActive(): Boolean = _state.value == "Connected"

  /** "NL#42 · 35%" for the tile subtitle, or "" if the server isn't known yet. */
  fun tileServerLabel(): String {
    val name = _connectedServerName.value
    return if (name.isEmpty()) "" else "$name · ${_connectedLoad.value}%"
  }

  /** Exit-node tile: connect Proton to a fresh server (the tunnel is already up). */
  fun connectFreshFromTile() {
    _error.value = null
    _state.value = "Connecting"
    Thread {
          try {
            Libtailscale.protonConnectFresh()
          } catch (e: Exception) {
            _state.value = "Disconnected"
            _error.value = "Couldn't connect: ${e.message}"
          }
        }
        .start()
  }

  /** Exit-node tile: disconnect Proton (the Tailscale tunnel stays up). */
  fun exitNodeOff() {
    Thread {
          try {
            Libtailscale.protonDisconnect()
          } catch (e: Exception) {
            _error.value = "Disconnect failed: ${e.message}"
          }
        }
        .start()
  }

  // --- Custom DNS (run on a background thread) ---

  fun loadCustomDns() {
    _customDns.value =
        try {
          Libtailscale.protonCustomDNS()
        } catch (e: Exception) {
          ""
        }
  }

  /**
   * setCustomDns sets the DNS server(s) used whenever Proton is enabled, as a comma-separated list
   * of IPs (empty = Proton/Tailscale default). Applies immediately if currently connected.
   */
  fun setCustomDns(value: String) {
    val cleaned = value.trim()
    try {
      Libtailscale.protonSetCustomDNS(cleaned)
      _customDns.value = cleaned
      _error.value = null
    } catch (e: Exception) {
      _error.value = "Invalid DNS: ${e.message}"
    }
  }

  fun setConfig(value: String) {
    _config.value = value
  }

  // --- libtailscale.ProtonStatusReceiver (called from Go) ---
  override fun onProtonState(state: String) {
    _state.value = state
    refreshCurrentServer()
    // Reflect Proton's connection state on the Quick Settings tile.
    try {
      com.tailscale.ipn.ProtonQuickServerTileService.updateTile()
    } catch (e: Throwable) {
      // tile not bound / not on a UI build — ignore
    }
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
    _connectedCountry.value = code
    try {
      Libtailscale.protonConnectCountry(code)
    } catch (e: Exception) {
      _state.value = "Disconnected"
      _connectedCountry.value = ""
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
    _connectedCountry.value = ""
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
  val customDns: StateFlow<String> = ProtonBridge.customDns
  val connectedCountry: StateFlow<String> = ProtonBridge.connectedCountry
  val favorites: StateFlow<Set<String>> = ProtonBridge.favorites
  val servers: StateFlow<List<ProtonServer>> = ProtonBridge.servers
  val autoConnectCountry: StateFlow<String> = ProtonBridge.autoConnectCountry
  val connectedServerName: StateFlow<String> = ProtonBridge.connectedServerName
  val connectedLoad: StateFlow<Int> = ProtonBridge.connectedLoad
  val pingResult: StateFlow<String> = ProtonBridge.pingResult

  init {
    viewModelScope.launch(Dispatchers.IO) {
      ProtonBridge.loadCustomDns()
      ProtonBridge.loadFavorites()
      ProtonBridge.loadAutoConnect()
      ProtonBridge.refreshCurrentServer()
    }
  }

  fun setConfig(value: String) = ProtonBridge.setConfig(value)

  fun setCustomDns(value: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.setCustomDns(value) }
  }

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
    clearTailscaleExitNode()
  }

  fun connectServer(serverId: String, countryCode: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.connectServer(serverId, countryCode) }
    clearTailscaleExitNode()
  }

  fun toggleFavorite(code: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.toggleFavorite(code) }
  }

  fun toggleAutoConnect(code: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.toggleAutoConnect(code) }
  }

  fun loadServers(countryCode: String) {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.loadServers(countryCode) }
  }

  fun fastestOverall() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.fastestOverall() }
    clearTailscaleExitNode()
  }

  fun fastestInCountry() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.fastestInCountry() }
  }

  fun ping() {
    viewModelScope.launch(Dispatchers.IO) { ProtonBridge.ping() }
  }

  // Proton owns the default route once connected; clear any Tailscale exit node
  // so they don't both try to capture non-tailnet traffic.
  private fun clearTailscaleExitNode() {
    val prefsOut = Ipn.MaskedPrefs()
    prefsOut.ExitNodeID = null
    Client(viewModelScope).editPrefs(prefsOut) {}
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
