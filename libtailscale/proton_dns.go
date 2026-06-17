// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Custom DNS for ProtonVPN. When set and Proton is enabled, the VpnService DNS
// servers are replaced with the user's chosen server(s); since those are
// non-tailnet IPs, DNS queries flow through the Proton tunnel (see updateTUN).
// When Proton is off, DNS is left untouched (normal Tailscale behaviour).

package libtailscale

import (
	"fmt"
	"net/netip"
	"strings"
)

const protonCustomDNSPrefKey = "proton.customdns.v1"

// ProtonSetCustomDNS sets the DNS server(s) used while ProtonVPN is enabled, as
// a comma-separated list of IPs (e.g. "1.1.1.1, 1.0.0.1"). An empty string
// restores normal DNS. Persisted across restarts.
func ProtonSetCustomDNS(servers string) error {
	addrs, err := parseDNSAddrs(servers)
	if err != nil {
		return err
	}
	protonMgr.customDNS.Store(&addrs)
	protonAPIClient.savePref(protonCustomDNSPrefKey, servers)
	// Apply immediately if connected.
	if protonMgr.enabled.Load() {
		select {
		case onProtonRefresh <- struct{}{}:
		default:
		}
	}
	return nil
}

// ProtonCustomDNS returns the configured custom DNS servers (comma-separated).
func ProtonCustomDNS() string {
	a := protonMgr.customDNS.Load()
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(*a))
	for _, ip := range *a {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ", ")
}

// loadProtonCustomDNS restores the saved custom DNS at startup.
func loadProtonCustomDNS() {
	s := protonAPIClient.loadPref(protonCustomDNSPrefKey)
	if s == "" {
		return
	}
	if addrs, err := parseDNSAddrs(s); err == nil && len(addrs) > 0 {
		protonMgr.customDNS.Store(&addrs)
	}
}

// protonCustomDNSAddrs returns the configured custom DNS servers, or nil.
func protonCustomDNSAddrs() []netip.Addr {
	if a := protonMgr.customDNS.Load(); a != nil {
		return *a
	}
	return nil
}

func parseDNSAddrs(s string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ip, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("proton: invalid DNS address %q", part)
		}
		out = append(out, ip)
	}
	return out, nil
}
