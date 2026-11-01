// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"errors"
	"strconv"
)

const protonAcceleratorPrefKey = "proton.accelerator.v1"

// ProtonAcceleratorEnabled reports the saved preference for account-based
// connections. Enable by default, matching Proton's own clients.
func ProtonAcceleratorEnabled() bool { return protonAPIClient.acceleratorEnabled() }

func (a *protonAPI) acceleratorEnabled() bool {
	return a.loadPref(protonAcceleratorPrefKey) != "false"
}

// ProtonSetAcceleratorEnabled saves the preference for the next connection.
// The current key's server-side features remain unchanged until reconnecting.
// Imported WireGuard configurations retain their original server-side settings.
func ProtonSetAcceleratorEnabled(enabled bool) error {
	return protonAPIClient.setAcceleratorEnabled(enabled)
}

func (a *protonAPI) setAcceleratorEnabled(enabled bool) error {
	a.mu.Lock()
	ctx := a.persist
	a.mu.Unlock()
	if ctx == nil {
		return errors.New("proton: settings are not initialized")
	}
	return ctx.EncryptToPref(protonAcceleratorPrefKey, strconv.FormatBool(enabled))
}
