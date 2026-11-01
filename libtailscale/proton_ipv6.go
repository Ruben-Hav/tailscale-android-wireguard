// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

const (
	// Proton's SERVER_FEATURES.IPV6 and WireGuard interface addresses, shared
	// with its Android client. IPv6 support is advertised per logical server.
	protonServerIPv6 = 16
	protonClientIPv4 = "10.2.0.2/32"
	protonClientIPv6 = "2a07:b944::2:2/128"
)

func protonClientAddresses(features int) string {
	if features&protonServerIPv6 != 0 {
		return protonClientIPv4 + "," + protonClientIPv6
	}
	return protonClientIPv4
}

// parseClientAddrs extracts the first IPv4 and IPv6 client addresses from a
// WireGuard [Interface] Address value (comma-separated prefixes or addrs).
func parseClientAddrs(s string) (v4, v6 netip.Addr) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if i := strings.IndexByte(part, '/'); i >= 0 {
			part = part[:i]
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			continue
		}
		if a.Is4() && !v4.IsValid() {
			v4 = a
		} else if a.Is6() && !v6.IsValid() {
			v6 = a
		}
	}
	return v4, v6
}

// rejectUnsupportedIPv6 supplies a local no-route error on IPv4-only Proton
// connections. Silent drops otherwise make serial address-family fallback wait
// for a TCP timeout. IPv6 remains captured, so this cannot leak outside the VPN.
func (p *protonTUN) rejectUnsupportedIPv6(pkt []byte) bool {
	if len(pkt) < 40 || pkt[0]>>4 != 6 {
		return false
	}
	n := protonNATConfig.Load()
	if n == nil || n.haveV6 {
		return false
	}
	select {
	case <-p.closeCh:
		return true
	default:
	}
	reply := protonIPv6Unreachable(pkt, netip.AddrFrom16(n.tunV6))
	if len(reply) > 0 {
		if e := p.writer.Load(); e != nil {
			_, _ = e.write([][]byte{reply}, 0)
		}
	}
	return true
}

func protonIPv6Unreachable(pkt []byte, router netip.Addr) []byte {
	offset, protocol, ok := ipv6Transport(pkt)
	src, _ := srcAddr(pkt)
	if !ok || !src.IsValid() || src.IsUnspecified() || src.IsMulticast() || !router.Is6() || router.IsUnspecified() {
		return nil
	}
	if protocol == 58 && len(pkt) > offset && pkt[offset] < 128 {
		return nil
	} // No errors in response to errors.
	quote := pkt
	if len(quote) > 1232 {
		quote = quote[:1232]
	} // IPv6 minimum MTU, including outer header and ICMP.
	reply := make([]byte, 48+len(quote))
	reply[0], reply[6], reply[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(reply[4:6], uint16(len(reply)-40))
	copy(reply[8:24], router.AsSlice())
	copy(reply[24:40], pkt[8:24])
	reply[40] = 1 // Destination Unreachable / No route to destination.
	copy(reply[48:], quote)
	setICMPv6Checksum(reply, 40)
	return reply
}
