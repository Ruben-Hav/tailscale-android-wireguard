// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
)

// This covers allocated public IPv6 internet space, leaving ULA/site-local,
// multicast and link-local traffic outside the fallback route.
var protonIPv6Internet = netip.MustParsePrefix("2000::/3")

func protonHasIPv6ExitRoute(routes []netip.Prefix) bool {
	for _, route := range routes {
		if route.Addr().Is6() && route.Bits() == 0 {
			return true
		}
	}
	return false
}

// probeProtonUnderlayIPv6 races independent public TCP endpoints. A refused
// connection also proves a working route. No TLS, DNS, or user data is sent.
func probeProtonUnderlayIPv6(ctx context.Context, dial func(context.Context, string) (net.Conn, error)) bool {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan bool, 2)
	for _, endpoint := range []string{"[2606:4700:4700::1111]:443", "[2001:4860:4860::8888]:443"} {
		go func() {
			conn, err := dial(ctx, endpoint)
			if conn != nil {
				conn.Close()
			}
			results <- err == nil || errors.Is(err, syscall.ECONNREFUSED)
		}()
	}
	for range 2 {
		select {
		case reachable := <-results:
			if reachable {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}
