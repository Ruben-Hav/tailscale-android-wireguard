// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"bytes"
	"encoding/binary"
	"github.com/tailscale/wireguard-go/tun"
	"net/netip"
	"testing"
)

func TestProtonClientIPv6Capability(t *testing.T) {
	for _, features := range []int{0, 1, 4, 16, 17, 20} {
		v4, v6 := parseClientAddrs(protonClientAddresses(features))
		if v4 != netip.MustParseAddr("10.2.0.2") || v6.IsValid() != (features&16 != 0) {
			t.Fatalf("features %d: addresses %s => %v, %v", features, protonClientAddresses(features), v4, v6)
		}
		if v6.IsValid() && v6 != netip.MustParseAddr("2a07:b944::2:2") {
			t.Fatalf("unexpected IPv6 client address: %v", v6)
		}
	}
}

type protonRejectSink struct {
	tun.Device
	packets [][]byte
}

func (s *protonRejectSink) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		s.packets = append(s.packets, bytes.Clone(b[offset:]))
	}
	return len(bufs), nil
}

func TestProtonIPv4OnlyRejectsIPv6Locally(t *testing.T) {
	tunAddr := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	old := protonNATConfig.Load()
	setProtonNAT(buildProtonNAT([]netip.Addr{netip.MustParseAddr("100.64.1.2"), tunAddr}, netip.MustParseAddr("10.2.0.2"), netip.Addr{}))
	t.Cleanup(func() { setProtonNAT(old) })
	p := newProtonTUN(1280)
	t.Cleanup(func() { p.Close() })
	sink := &protonRejectSink{}
	p.setWriter(&realEndpoint{real: sink})
	pkt := testIPv6TCP(tunAddr, netip.MustParseAddr("2001:db8::80"), 6, nil)
	original := bytes.Clone(pkt)
	p.enqueue(pkt)
	if len(p.inbound) != 0 || len(sink.packets) != 1 {
		t.Fatal("unsupported IPv6 was forwarded or silently dropped")
	}
	reply := sink.packets[0]
	if reply[40] != 1 || reply[41] != 0 || testIPv6Checksum(reply, 40, 58) != 0 || !bytes.Equal(reply[48:], original) {
		t.Fatal("invalid local no-route reply")
	}
	if !bytes.Equal(pkt, original) {
		t.Fatal("rejection modified the source slab")
	}
	_ = p.Close()
	p.enqueue(pkt)
	if len(sink.packets) != 1 {
		t.Fatal("closed tunnel emitted a reply")
	}
}

// Independent full pseudo-header checksum, rather than the incremental
// algorithm used by NAT. A valid complete packet sums to zero here.
func testIPv6Checksum(pkt []byte, offset int, proto byte) uint16 {
	data := append([]byte{}, pkt[8:40]...)
	length := make([]byte, 8)
	binary.BigEndian.PutUint32(length, uint32(len(pkt)-offset))
	length[7] = proto
	data = append(data, length...)
	data = append(data, pkt[offset:]...)
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(data[i]) << 8
		if i+1 < len(data) {
			sum += uint32(data[i+1])
		}
	}
	for sum > 65535 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func testIPv6TCP(src, dst netip.Addr, first byte, extensions []byte) []byte {
	p := make([]byte, 40+len(extensions)+28)
	p[0], p[6], p[7] = 0x60, first, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
	copy(p[8:24], src.AsSlice())
	copy(p[24:40], dst.AsSlice())
	copy(p[40:], extensions)
	tcp := p[40+len(extensions):]
	binary.BigEndian.PutUint16(tcp[0:2], 43210)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12], tcp[13] = 0x50, 0x18
	copy(tcp[20:], []byte("testdata"))
	binary.BigEndian.PutUint16(tcp[16:18], testIPv6Checksum(p, 40+len(extensions), 6))
	return p
}

func TestProtonIPv6NATExtensions(t *testing.T) {
	tun, proton, remote := netip.MustParseAddr("fd7a:115c:a1e0::1234"), netip.MustParseAddr("2a07:b944::2:2"), netip.MustParseAddr("2001:db8::80")
	old := protonNATConfig.Load()
	setProtonNAT(buildProtonNAT([]netip.Addr{tun}, netip.Addr{}, proton))
	t.Cleanup(func() { setProtonNAT(old) })
	for _, tc := range []struct {
		name    string
		first   byte
		headers []byte
	}{
		{"plain", 6, nil}, {"hop", 0, []byte{6, 0, 0, 0, 0, 0, 0, 0}},
		{"destination", 60, []byte{6, 0, 0, 0, 0, 0, 0, 0}},
		{"routing", 43, []byte{6, 0, 0, 0, 0, 0, 0, 0}},
		{"atomic-fragment", 44, []byte{6, 0, 0, 0, 0, 0, 0, 1}},
		{"chain", 0, []byte{60, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkt := testIPv6TCP(tun, remote, tc.first, tc.headers)
			snatOutbound(pkt)
			if got, _ := srcAddr(pkt); got != proton {
				t.Fatalf("source = %v", got)
			}
			if testIPv6Checksum(pkt, 40+len(tc.headers), 6) != 0 {
				t.Fatal("SNAT corrupted the transport checksum")
			}
			response := testIPv6TCP(remote, proton, tc.first, tc.headers)
			dnatInbound(response)
			if got, _ := dstAddr(response); got != tun {
				t.Fatalf("destination = %v", got)
			}
			if testIPv6Checksum(response, 40+len(tc.headers), 6) != 0 {
				t.Fatal("DNAT corrupted the transport checksum")
			}
		})
	}
}

func TestProtonIPv6NATNonInitialFragment(t *testing.T) {
	tun, proton := netip.MustParseAddr("fd7a:115c:a1e0::1234"), netip.MustParseAddr("2a07:b944::2:2")
	old := protonNATConfig.Load()
	setProtonNAT(buildProtonNAT([]netip.Addr{tun}, netip.Addr{}, proton))
	t.Cleanup(func() { setProtonNAT(old) })
	pkt := testIPv6TCP(tun, netip.MustParseAddr("2001:db8::80"), 44, []byte{6, 0, 0, 8, 0, 0, 0, 1})
	want := bytes.Clone(pkt[48:])
	snatOutbound(pkt)
	if !bytes.Equal(pkt[48:], want) {
		t.Fatal("NAT changed data in a non-initial fragment")
	}
}

func TestProtonIPv6PacketTooBigQuote(t *testing.T) {
	tun, proton, remote := netip.MustParseAddr("fd7a:115c:a1e0::1234"), netip.MustParseAddr("2a07:b944::2:2"), netip.MustParseAddr("2001:db8::80")
	old := protonNATConfig.Load()
	setProtonNAT(buildProtonNAT([]netip.Addr{tun}, netip.Addr{}, proton))
	t.Cleanup(func() { setProtonNAT(old) })
	quoted := testIPv6TCP(proton, remote, 6, nil)
	pkt := make([]byte, 48+len(quoted))
	pkt[0], pkt[6], pkt[7] = 0x60, 58, 64
	binary.BigEndian.PutUint16(pkt[4:6], uint16(len(pkt)-40))
	copy(pkt[8:24], remote.AsSlice())
	copy(pkt[24:40], proton.AsSlice())
	pkt[40] = 2
	binary.BigEndian.PutUint32(pkt[44:48], 1280)
	copy(pkt[48:], quoted)
	binary.BigEndian.PutUint16(pkt[42:44], testIPv6Checksum(pkt, 40, 58))
	dnatInbound(pkt)
	if got, _ := srcAddr(pkt[48:]); got != tun {
		t.Fatalf("quoted source = %v, want local TUN address", got)
	}
	if testIPv6Checksum(pkt, 40, 58) != 0 {
		t.Fatal("invalid outer ICMPv6 checksum")
	}
	if testIPv6Checksum(pkt[48:], 40, 6) != 0 {
		t.Fatal("invalid quoted TCP checksum")
	}
}
