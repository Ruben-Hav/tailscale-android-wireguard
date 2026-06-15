// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Stateless 1:1 NAT between the device's (Tailscale) TUN address and the
// ProtonVPN-assigned client address.
//
// The Android VpnService TUN is shared with Tailscale, so its address is the
// node's Tailscale IP (e.g. 100.x.y.z). App packets routed to Proton therefore
// carry that source IP. ProtonVPN's WireGuard server enforces cryptokey routing
// and only accepts packets whose source is the client's assigned tunnel address
// (e.g. 10.2.0.2), so without translation it drops all data (the handshake
// still completes, being key-based). We rewrite:
//   - outbound (app -> Proton): source  TUN-addr  -> Proton-addr
//   - inbound  (Proton -> app): dest    Proton-addr -> TUN-addr
// fixing the IPv4 header checksum and the L4 (TCP/UDP/ICMPv6) checksums in place.
//
// NOTE: IPv6 extension headers are not parsed; L4 is assumed to start at offset
// 40. This holds for ordinary TCP/UDP/ICMPv6 traffic.

package libtailscale

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
)

type protonNAT struct {
	tunV4, protonV4 [4]byte
	tunV6, protonV6 [16]byte
	haveV4, haveV6  bool
}

var protonNATConfig atomic.Pointer[protonNAT]

func setProtonNAT(n *protonNAT) { protonNATConfig.Store(n) }

func clearProtonNAT() { protonNATConfig.Store(nil) }

// buildProtonNAT assembles a NAT mapping from the device's TUN addresses and the
// Proton client addresses. Returns nil if no usable v4/v6 pairing exists.
func buildProtonNAT(tunAddrs []netip.Addr, protonV4, protonV6 netip.Addr) *protonNAT {
	n := &protonNAT{}
	for _, a := range tunAddrs {
		if a.Is4() && protonV4.Is4() {
			n.tunV4 = a.As4()
			n.protonV4 = protonV4.As4()
			n.haveV4 = true
		} else if a.Is6() && protonV6.Is6() {
			n.tunV6 = a.As16()
			n.protonV6 = protonV6.As16()
			n.haveV6 = true
		}
	}
	if !n.haveV4 && !n.haveV6 {
		return nil
	}
	return n
}

// snatOutbound rewrites the source address (TUN -> Proton) in place.
func snatOutbound(pkt []byte) {
	n := protonNATConfig.Load()
	if n == nil || len(pkt) < 1 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if n.haveV4 && len(pkt) >= 20 {
			rewriteV4(pkt, 12, n.tunV4, n.protonV4) // source at [12:16]
		}
	case 6:
		if n.haveV6 && len(pkt) >= 40 {
			rewriteV6(pkt, 8, n.tunV6, n.protonV6) // source at [8:24]
		}
	}
}

// dnatInbound rewrites the destination address (Proton -> TUN) in place.
func dnatInbound(pkt []byte) {
	n := protonNATConfig.Load()
	if n == nil || len(pkt) < 1 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if n.haveV4 && len(pkt) >= 20 {
			rewriteV4(pkt, 16, n.protonV4, n.tunV4) // dest at [16:20]
		}
	case 6:
		if n.haveV6 && len(pkt) >= 40 {
			rewriteV6(pkt, 24, n.protonV6, n.tunV6) // dest at [24:40]
		}
	}
}

func rewriteV4(pkt []byte, off int, from, to [4]byte) {
	if [4]byte(pkt[off:off+4]) != from {
		return // not the address we map
	}
	copy(pkt[off:off+4], to[:])

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return
	}
	// IPv4 header checksum covers the addresses.
	fixChecksum(pkt[10:12], from[:], to[:])

	l4 := pkt[ihl:]
	switch pkt[9] { // protocol
	case 6: // TCP: checksum at [16:18], includes pseudo-header (src/dst).
		if len(l4) >= 18 {
			fixChecksum(l4[16:18], from[:], to[:])
		}
	case 17: // UDP: checksum at [6:8]; 0 means "no checksum".
		if len(l4) >= 8 && (l4[6] != 0 || l4[7] != 0) {
			fixChecksum(l4[6:8], from[:], to[:])
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff // 0 is reserved for "no checksum"
			}
		}
		// ICMPv4 (1): checksum does not cover IP addresses; nothing to do.
	}
}

func rewriteV6(pkt []byte, off int, from, to [16]byte) {
	if [16]byte(pkt[off:off+16]) != from {
		return
	}
	copy(pkt[off:off+16], to[:])

	l4 := pkt[40:]
	switch pkt[6] { // next header (assumes no extension headers)
	case 6: // TCP
		if len(l4) >= 18 {
			fixChecksum(l4[16:18], from[:], to[:])
		}
	case 17: // UDP
		if len(l4) >= 8 {
			fixChecksum(l4[6:8], from[:], to[:])
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff // UDP checksum is mandatory over IPv6
			}
		}
	case 58: // ICMPv6: checksum at [2:4], includes pseudo-header.
		if len(l4) >= 4 {
			fixChecksum(l4[2:4], from[:], to[:])
		}
	}
}

// fixChecksum incrementally updates a 16-bit ones-complement checksum after the
// bytes in old were replaced by new (RFC 1624): HC' = ~(~HC + ~m + m').
func fixChecksum(csum, old, new []byte) {
	sum := uint32(^binary.BigEndian.Uint16(csum))
	for i := 0; i+1 < len(old); i += 2 {
		sum += uint32(^binary.BigEndian.Uint16(old[i:]))
		sum += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(csum, ^uint16(sum))
}
