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
import java.util.Locale

/**
 * Lists ProtonVPN exit countries. Tapping one selects a server in that country and connects;
 * non-tailnet traffic then exits through it.
 */
@Composable
fun ProtonCountryPickerView(backToProton: BackNavigation, model: ProtonViewModel = viewModel()) {
  val countries by model.countries.collectAsState()
  val busy by model.busy.collectAsState()

  LaunchedEffect(Unit) {
    if (countries.isEmpty()) model.loadCountries()
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
        items(countries) { country ->
          ListItem(
              modifier =
                  Modifier.clickable {
                    model.connectCountry(country.code)
                    backToProton()
                  },
              headlineContent = { Text(countryDisplayName(country.code)) },
              supportingContent = {
                Text(stringResource(R.string.proton_server_count, country.count))
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
