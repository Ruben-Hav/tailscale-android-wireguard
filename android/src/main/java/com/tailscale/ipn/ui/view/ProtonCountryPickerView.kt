// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
package com.tailscale.ipn.ui.view

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tailscale.ipn.R
import com.tailscale.ipn.ui.viewModel.ProtonCountry
import com.tailscale.ipn.ui.viewModel.ProtonViewModel
import java.util.Locale

/**
 * Lists ProtonVPN exit countries. Tapping a row auto-picks the fastest server in that country and
 * connects. The leading star toggles a favorite (favorites sort to the top); the leading play
 * marks the country to auto-connect when the VPN starts; the trailing arrow drills into the
 * individual servers of that country.
 */
@Composable
fun ProtonCountryPickerView(
    backToProton: BackNavigation,
    onNavigateToServers: (String) -> Unit,
    model: ProtonViewModel = viewModel()
) {
  val countries by model.countries.collectAsState()
  val favorites by model.favorites.collectAsState()
  val autoConnect by model.autoConnectCountry.collectAsState()
  val busy by model.busy.collectAsState()

  LaunchedEffect(Unit) {
    if (countries.isEmpty()) model.loadCountries()
  }

  // Favorites first, then alphabetical by display name.
  val ordered =
      remember(countries, favorites) {
        countries.sortedWith(
            compareByDescending<ProtonCountry> { favorites.contains(it.code) }
                .thenBy { countryDisplayName(it.code) })
      }

  Scaffold(topBar = { Header(R.string.proton_choose_country, onBack = backToProton) }) {
      innerPadding ->
    if (countries.isEmpty()) {
      Box(Modifier.padding(innerPadding).padding(24.dp).fillMaxWidth()) {
        Text(
            stringResource(
                if (busy) R.string.proton_loading_servers else R.string.proton_no_servers))
      }
    } else {
      LazyColumn(modifier = Modifier.padding(innerPadding)) {
        items(ordered, key = { it.code }) { country ->
          val isFav = favorites.contains(country.code)
          val isAuto = autoConnect == country.code
          ListItem(
              modifier =
                  Modifier.clickable {
                    model.connectCountry(country.code)
                    backToProton()
                  },
              leadingContent = {
                Row {
                  IconButton(onClick = { model.toggleFavorite(country.code) }) {
                    Text(
                        text = if (isFav) "★" else "☆", // ★ / ☆
                        color =
                            if (isFav) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant)
                  }
                  IconButton(onClick = { model.toggleAutoConnect(country.code) }) {
                    Text(
                        text = if (isAuto) "▶" else "▷", // auto-connect on start
                        color =
                            if (isAuto) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant)
                  }
                }
              },
              headlineContent = { Text(countryDisplayName(country.code)) },
              supportingContent = {
                val count = stringResource(R.string.proton_server_count, country.count)
                Text(
                    if (isAuto) "$count · ${stringResource(R.string.proton_autoconnect_badge)}"
                    else count)
              },
              trailingContent = {
                IconButton(onClick = { onNavigateToServers(country.code) }) {
                  Icon(
                      Icons.AutoMirrored.Filled.KeyboardArrowRight,
                      contentDescription = stringResource(R.string.proton_view_servers))
                }
              })
          HorizontalDivider()
        }
      }
    }
  }
}

private fun countryDisplayName(code: String): String {
  val name = Locale("", code).displayCountry
  return if (name.isBlank() || name == code) code else name
}
