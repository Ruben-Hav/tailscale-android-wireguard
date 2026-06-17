// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Latency probe for the connected ProtonVPN server.

package libtailscale

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// hostOnly returns the host part of an "ip:port" endpoint (IPv4 or IPv6).
func hostOnly(endpoint string) string {
	if h, _, err := net.SplitHostPort(endpoint); err == nil {
		return h
	}
	return endpoint
}

// ProtonPingCurrent measures the round-trip latency (milliseconds) to the
// connected Proton server's entry IP. It times a TCP handshake to port 443
// (Proton servers run Stealth / OpenVPN-TCP there) over a VPN-protected socket,
// so the probe travels the underlay directly instead of back through the tunnel.
func ProtonPingCurrent() (int64, error) {
	ip := protonMgr.currentEntryIP()
	if ip == "" {
		return 0, fmt.Errorf("proton: not connected")
	}
	d := &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) { protectSocket(int(fd)) })
		},
	}
	start := time.Now()
	conn, err := d.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return 0, fmt.Errorf("proton: ping failed: %w", err)
	}
	conn.Close()
	return time.Since(start).Milliseconds(), nil
}
