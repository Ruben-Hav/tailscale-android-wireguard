// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.view

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.viewModel.ProtonViewModel

/**
 * ProtonVPN screen. Adapts between log-in, 2FA, and connected states. When connected, all non-
 * tailnet traffic exits via the selected Proton country; tailnet traffic stays on Tailscale.
 */
@Composable
fun ProtonView(
    backToSettings: BackNavigation,
    onNavigateToCountries: () -> Unit,
    model: ProtonViewModel = viewModel()
) {
  val state by model.state.collectAsState()
  val error by model.error.collectAsState()
  val loggedIn by model.loggedIn.collectAsState()
  val needs2FA by model.needs2FA.collectAsState()
  val busy by model.busy.collectAsState()
  val needsCaptcha by model.needsCaptcha.collectAsState()
  val captchaUrl by model.captchaUrl.collectAsState()

  // Proton requires solving a CAPTCHA; take over the screen with the WebView.
  if (needsCaptcha && captchaUrl.isNotEmpty()) {
    ProtonCaptchaView(
        url = captchaUrl,
        onSolved = { token, type -> model.onCaptchaSolved(token, type) },
        onCancel = { model.cancelCaptcha() })
    return
  }

  Scaffold(topBar = { Header(R.string.proton_vpn, onBack = backToSettings) }) { innerPadding ->
    Column(
        modifier =
            Modifier.padding(innerPadding).verticalScroll(rememberScrollState()).padding(16.dp)) {
          Text(
              stringResource(R.string.proton_status, state),
              style = MaterialTheme.typography.titleMedium)
          error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MaterialTheme.colorScheme.error)
          }
          Spacer(Modifier.height(20.dp))

          when {
            needs2FA -> TwoFactorSection(model, busy)
            !loggedIn -> LoginSection(model, busy)
            else -> ConnectedSection(model, onNavigateToCountries)
          }
        }
  }
}

@Composable
private fun LoginSection(model: ProtonViewModel, busy: Boolean) {
  var username by remember { mutableStateOf("") }
  var password by remember { mutableStateOf("") }

  Text(stringResource(R.string.proton_login_hint))
  Spacer(Modifier.height(12.dp))
  OutlinedTextField(
      value = username,
      onValueChange = { username = it },
      modifier = Modifier.fillMaxWidth(),
      singleLine = true,
      label = { Text(stringResource(R.string.proton_username)) })
  Spacer(Modifier.height(8.dp))
  OutlinedTextField(
      value = password,
      onValueChange = { password = it },
      modifier = Modifier.fillMaxWidth(),
      singleLine = true,
      visualTransformation = PasswordVisualTransformation(),
      keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
      label = { Text(stringResource(R.string.proton_password)) })
  Spacer(Modifier.height(16.dp))
  Button(
      onClick = { model.login(username.trim(), password) },
      enabled = !busy && username.isNotBlank() && password.isNotBlank()) {
        Text(stringResource(R.string.proton_login))
      }
}

@Composable
private fun TwoFactorSection(model: ProtonViewModel, busy: Boolean) {
  var code by remember { mutableStateOf("") }

  Text(stringResource(R.string.proton_2fa_hint))
  Spacer(Modifier.height(12.dp))
  OutlinedTextField(
      value = code,
      onValueChange = { code = it },
      modifier = Modifier.fillMaxWidth(),
      singleLine = true,
      keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
      label = { Text(stringResource(R.string.proton_2fa_code)) })
  Spacer(Modifier.height(16.dp))
  Row {
    Button(onClick = { model.submit2FA(code.trim()) }, enabled = !busy && code.isNotBlank()) {
      Text(stringResource(R.string.proton_submit))
    }
    Spacer(Modifier.width(12.dp))
    TextButton(onClick = { model.logout() }) { Text(stringResource(R.string.proton_cancel)) }
  }
}

@Composable
private fun ConnectedSection(model: ProtonViewModel, onNavigateToCountries: () -> Unit) {
  val state by model.state.collectAsState()
  val connected = state == "Connected"

  if (connected) {
    CurrentServerSection(model)
    Spacer(Modifier.height(16.dp))
  }
  Button(onClick = onNavigateToCountries, modifier = Modifier.fillMaxWidth()) {
    Text(stringResource(R.string.proton_choose_country))
  }
  if (connected) {
    // Quick change: fastest server in your current country, or fastest anywhere.
    Spacer(Modifier.height(8.dp))
    Row(modifier = Modifier.fillMaxWidth()) {
      OutlinedButton(onClick = { model.fastestInCountry() }, modifier = Modifier.weight(1f)) {
        Text(stringResource(R.string.proton_fastest_in_country))
      }
      Spacer(Modifier.width(8.dp))
      OutlinedButton(onClick = { model.fastestOverall() }, modifier = Modifier.weight(1f)) {
        Text(stringResource(R.string.proton_fastest_overall))
      }
    }
  }
  Spacer(Modifier.height(8.dp))
  OutlinedButton(onClick = { model.disconnect() }, modifier = Modifier.fillMaxWidth()) {
    Text(stringResource(R.string.proton_disconnect))
  }
  Spacer(Modifier.height(24.dp))
  CustomDnsSection(model)
  Spacer(Modifier.height(16.dp))
  TextButton(onClick = { model.logout() }) { Text(stringResource(R.string.proton_logout)) }
}

@Composable
private fun CurrentServerSection(model: ProtonViewModel) {
  val serverName by model.connectedServerName.collectAsState()
  val load by model.connectedLoad.collectAsState()
  val ping by model.pingResult.collectAsState()
  if (serverName.isEmpty()) return

  Text(
      stringResource(R.string.proton_connected_to, serverName),
      style = MaterialTheme.typography.titleMedium)
  Spacer(Modifier.height(2.dp))
  val loadText = stringResource(R.string.proton_server_load, load)
  Text(
      if (ping.isNotEmpty()) "$loadText · $ping" else loadText,
      style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant)
  Spacer(Modifier.height(8.dp))
  OutlinedButton(onClick = { model.ping() }) { Text(stringResource(R.string.proton_ping)) }
}

@Composable
private fun CustomDnsSection(model: ProtonViewModel) {
  val savedDns by model.customDns.collectAsState()
  // Re-seed the editable field whenever the saved value changes (e.g. on load).
  var dns by remember(savedDns) { mutableStateOf(savedDns) }

  Text(stringResource(R.string.proton_dns_title), style = MaterialTheme.typography.titleMedium)
  Spacer(Modifier.height(4.dp))
  Text(
      stringResource(R.string.proton_dns_hint),
      style = MaterialTheme.typography.bodySmall,
      color = MaterialTheme.colorScheme.onSurfaceVariant)
  Spacer(Modifier.height(8.dp))
  OutlinedTextField(
      value = dns,
      onValueChange = { dns = it },
      modifier = Modifier.fillMaxWidth(),
      singleLine = true,
      placeholder = { Text("1.1.1.1, 1.0.0.1") },
      label = { Text(stringResource(R.string.proton_dns_label)) })
  Spacer(Modifier.height(8.dp))
  Button(onClick = { model.setCustomDns(dns.trim()) }, enabled = dns.trim() != savedDns) {
    Text(stringResource(R.string.proton_dns_apply))
  }
}
