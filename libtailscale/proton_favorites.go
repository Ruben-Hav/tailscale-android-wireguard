// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Favorite countries for the ProtonVPN picker. UI-only: stored as a
// comma-separated list of country codes in the app's encrypted prefs.

package libtailscale

const protonFavoritesPrefKey = "proton.favorites.v1"

// ProtonGetFavoriteCountries returns the saved favorite country codes as a
// comma-separated string (empty if none).
func ProtonGetFavoriteCountries() string {
	return protonAPIClient.loadPref(protonFavoritesPrefKey)
}

// ProtonSetFavoriteCountries stores the favorite country codes (comma-separated).
func ProtonSetFavoriteCountries(csv string) {
	protonAPIClient.savePref(protonFavoritesPrefKey, csv)
}
