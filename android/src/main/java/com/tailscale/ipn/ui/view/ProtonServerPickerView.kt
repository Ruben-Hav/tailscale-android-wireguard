// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.view

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.viewModel.ProtonViewModel

/**
 * Lists the individual ProtonVPN servers in a single country (fastest first). Tapping one connects
 * to that specific server, overriding the country auto-pick.
 */
@Composable
fun ProtonServerPickerView(
    countryCode: String,
    backToCountries: BackNavigation,
    model: ProtonViewModel = viewModel()
) {
  val servers by model.servers.collectAsState()
  val busy by model.busy.collectAsState()

  LaunchedEffect(countryCode) { model.loadServers(countryCode) }

  Scaffold(topBar = { Header(R.string.proton_choose_server, onBack = backToCountries) }) {
      innerPadding ->
    if (servers.isEmpty()) {
      Box(Modifier.padding(innerPadding).padding(24.dp).fillMaxWidth()) {
        Text(
            stringResource(
                if (busy) R.string.proton_loading_servers else R.string.proton_no_servers))
      }
    } else {
      LazyColumn(modifier = Modifier.padding(innerPadding)) {
        items(servers, key = { it.id }) { server ->
          ListItem(
              modifier =
                  Modifier.clickable {
                    model.connectServer(server.id, countryCode)
                    backToCountries()
                  },
              headlineContent = { Text(server.name) },
              supportingContent = {
                Text(stringResource(R.string.proton_server_load, server.load))
              })
          HorizontalDivider()
        }
      }
    }
  }
}
