// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Auto-connect: optionally bring ProtonVPN up to the fastest server in a chosen
// country whenever the VPN starts. The UI marks the country (stored in the app's
// encrypted prefs); the trigger fires from the runBackend loop once the Tailscale
// tunnel reaches Running, so it works even when the VPN is started from the Quick
// Settings tile or at boot, not just from the app UI.

package libtailscale

import (
	"log"
	"sync/atomic"
)

const protonAutoConnectPrefKey = "proton.autoconnect.v1"

// protonAutoConnecting guards against overlapping auto-connect attempts.
var protonAutoConnecting atomic.Bool

// protonPendingFresh is set by the Exit-node tile when it starts the VPN while
// Proton is off, so Proton connects (fresh server) as soon as the tunnel is up.
var protonPendingFresh atomic.Bool

// ProtonRequestFreshConnect arms a one-shot "connect Proton once the tunnel is
// up" request (used by the Exit-node tile when it has to start the VPN first).
func ProtonRequestFreshConnect() {
	protonPendingFresh.Store(true)
}

// ProtonVPNTunnelUp reports whether the Tailscale VpnService is active, so the
// tile knows whether it can connect Proton now or must start the tunnel first.
func ProtonVPNTunnelUp() bool {
	return vpnService != nil && vpnService.service != nil
}

// ProtonGetAutoConnectCountry returns the country code marked to auto-connect on
// startup, or "" when auto-connect is off.
func ProtonGetAutoConnectCountry() string {
	return protonAPIClient.loadPref(protonAutoConnectPrefKey)
}

// ProtonSetAutoConnectCountry sets (or clears, with "") the country to
// auto-connect to when the VPN starts.
func ProtonSetAutoConnectCountry(code string) {
	protonAPIClient.savePref(protonAutoConnectPrefKey, code)
}

// protonMaybeAutoConnect connects Proton to the fastest server in the configured
// auto-connect country once the VPN comes up. It's a no-op when auto-connect is
// off, the user isn't logged in, or Proton is already enabled (so it never
// clobbers a manual selection). The connect itself runs on a background goroutine
// so the backend loop is never blocked on network I/O.
func protonMaybeAutoConnect() {
	// Consume any pending tile request; also auto-connect if a country is armed.
	fresh := protonPendingFresh.Swap(false)
	if !fresh && ProtonGetAutoConnectCountry() == "" {
		return // nothing to do
	}
	if !protonAPIClient.loggedIn() {
		log.Printf("proton: auto-connect skipped: not logged in")
		return
	}
	if protonMgr.enabled.Load() {
		return // already up; leave the current selection alone
	}
	if !protonAutoConnecting.CompareAndSwap(false, true) {
		return // an attempt is already in flight
	}
	go func() {
		defer protonAutoConnecting.Store(false)
		log.Printf("proton: auto-connecting (fresh server)")
		protonMgr.notifyState("Connecting")
		// ProtonConnectFresh uses the armed country if set, else fastest overall,
		// and avoids the previous server.
		if err := ProtonConnectFresh(); err != nil {
			log.Printf("proton: auto-connect failed: %v", err)
			protonMgr.notifyState("Disconnected")
		}
	}()
}
