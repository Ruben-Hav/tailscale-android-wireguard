// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
)

func natChecksum(data []byte) uint16 {
	var sum uint32
	for i, b := range data {
		if i%2 == 0 {
			sum += uint32(b) << 8
		} else {
			sum += uint32(b)
		}
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}

func natV4Packet(src, dst netip.Addr, proto byte, options, payload []byte) []byte {
	p := make([]byte, 20+len(options)+len(payload))
	p[0], p[8], p[9] = 0x40|byte((20+len(options))/4), 64, proto
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], src.AsSlice())
	copy(p[16:20], dst.AsSlice())
	copy(p[20:], options)
	copy(p[20+len(options):], payload)
	binary.BigEndian.PutUint16(p[10:12], natChecksum(p[:20+len(options)]))
	return p
}

func natV4TransportChecksum(p []byte) uint16 {
	ihl := int(p[0]&15) * 4
	pseudo := append([]byte{}, p[12:20]...)
	pseudo = append(pseudo, 0, p[9], byte((len(p)-ihl)>>8), byte(len(p)-ihl))
	return natChecksum(append(pseudo, p[ihl:]...))
}

func natV4Transport(src, dst netip.Addr, proto byte, options []byte) []byte {
	l4 := bytes.Repeat([]byte{0x61}, 64)
	csum := 16
	if proto == 17 {
		csum = 6
		binary.BigEndian.PutUint16(l4[4:6], uint16(len(l4)))
	} else {
		l4[12] = 0x50
	}
	l4[csum], l4[csum+1] = 0, 0
	p := natV4Packet(src, dst, proto, options, l4)
	binary.BigEndian.PutUint16(p[20+len(options)+csum:], natV4TransportChecksum(p))
	return p
}

func natV4Fragment(p []byte, start, end int) []byte {
	ihl := int(p[0]&15) * 4
	f := append(bytes.Clone(p[:ihl]), p[ihl+start:ihl+end]...)
	flags := uint16(start / 8)
	if end < len(p)-ihl {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(f[6:8], flags)
	binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
	f[10], f[11] = 0, 0
	binary.BigEndian.PutUint16(f[10:12], natChecksum(f[:ihl]))
	return f
}

func TestProtonIPv4Fragments(t *testing.T) {
	local, proton, remote := netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("10.2.0.2"), netip.MustParseAddr("192.0.2.80")
	for _, inbound := range []bool{false, true} {
		for _, proto := range []byte{6, 17} {
			for _, chunk := range []int{8, 16, 24, 32} {
				for _, options := range [][]byte{nil, {1, 1, 1, 1}} {
					t.Run(fmt.Sprintf("proto%d/chunk%d/options%d/inbound%v", proto, chunk, len(options), inbound), func(t *testing.T) {
						p := natV4Transport(local, remote, proto, options)
						off, from, to := 12, local.As4(), proton.As4()
						if inbound {
							p = natV4Transport(remote, proton, proto, options)
							off, from, to = 16, proton.As4(), local.As4()
						}
						ihl := int(p[0]&15) * 4
						joined := bytes.Clone(p[:ihl])
						for start := 0; start < len(p)-ihl; start += chunk {
							f := natV4Fragment(p, start, min(start+chunk, len(p)-ihl))
							rewriteV4(f, off, from, to)
							if natChecksum(f[:ihl]) != 0 || [4]byte(f[off:off+4]) != to {
								t.Fatal("invalid translated fragment header")
							}
							joined = append(joined, f[ihl:]...)
						}
						copy(joined[off:off+4], to[:])
						if natV4TransportChecksum(joined) != 0 {
							t.Fatal("reassembled transport checksum invalid")
						}
						// Every payload byte must survive reassembly; only the
						// transport checksum word is allowed to change.
						csum := 16
						if proto == 17 {
							csum = 6
						}
						copy(joined[ihl+csum:ihl+csum+2], p[ihl+csum:ihl+csum+2])
						if !bytes.Equal(joined[ihl:], p[ihl:]) {
							t.Fatal("fragment payload corrupted")
						}
					})
				}
			}
		}
	}
}

func TestProtonIPv4UDPDisabledChecksum(t *testing.T) {
	from, to := netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("10.2.0.2")
	p := natV4Transport(from, netip.MustParseAddr("192.0.2.80"), 17, nil)
	p[26], p[27] = 0, 0
	rewriteV4(p, 12, from.As4(), to.As4())
	if binary.BigEndian.Uint16(p[26:28]) != 0 {
		t.Fatal("enabled a disabled UDP checksum")
	}
}

func TestProtonIPv4UDPChecksumZeroEncoding(t *testing.T) {
	from, to, remote := netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("10.2.0.2"), netip.MustParseAddr("192.0.2.80")
	p := natV4Transport(to, remote, 17, nil)
	p[26], p[27], p[len(p)-2], p[len(p)-1] = 0, 0, 0, 0
	binary.BigEndian.PutUint16(p[len(p)-2:], natV4TransportChecksum(p))
	if natV4TransportChecksum(p) != 0 {
		t.Fatal("invalid zero-checksum fixture")
	}
	copy(p[12:16], from.AsSlice())
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], natChecksum(p[:20]))
	binary.BigEndian.PutUint16(p[26:28], natV4TransportChecksum(p))
	rewriteV4(p, 12, from.As4(), to.As4())
	if binary.BigEndian.Uint16(p[26:28]) != 65535 || natV4TransportChecksum(p) != 0 || natChecksum(p[:20]) != 0 {
		t.Fatal("translated UDP zero was not encoded as 0xffff")
	}
}

func TestProtonIPv4ICMPQuoteWithOptions(t *testing.T) {
	proton, local, remote := netip.MustParseAddr("10.2.0.2"), netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("192.0.2.80")
	quoted := natV4Transport(proton, remote, 6, bytes.Repeat([]byte{1}, 40))
	for _, length := range []int{68, 77, 78, len(quoted)} {
		icmp := append([]byte{3, 4, 0, 0, 0, 0, 5, 0}, quoted[:length]...)
		binary.BigEndian.PutUint16(icmp[2:4], natChecksum(icmp))
		p := natV4Packet(remote, proton, 1, []byte{1, 1, 1, 1}, icmp)
		rewriteV4(p, 16, proton.As4(), local.As4())
		if natChecksum(p[:24]) != 0 || natChecksum(p[24:]) != 0 || natChecksum(p[32:92]) != 0 {
			t.Fatal("options/truncated ICMP checksum invalid")
		}
		if length >= 78 {
			full := append(bytes.Clone(p[32:]), quoted[length:]...)
			if natV4TransportChecksum(full) != 0 {
				t.Fatal("options quoted TCP checksum invalid")
			}
		}
	}
}

func TestProtonIPv4ICMPErrors(t *testing.T) {
	local, proton, remote := netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("10.2.0.2"), netip.MustParseAddr("192.0.2.80")
	for _, inbound := range []bool{false, true} {
		for _, proto := range []byte{6, 17} {
			for _, quoteSize := range []int{28, 38, 84} {
				for _, kind := range []byte{3, 4, 5, 11, 12} {
					quoted := natV4Transport(proton, remote, proto, nil)
					outerSrc, outerDst := remote, proton
					off, quotedOff, from, to := 16, 12, proton.As4(), local.As4()
					if !inbound {
						quoted = natV4Transport(remote, local, proto, nil)
						outerSrc, outerDst = local, remote
						off, quotedOff, from, to = 12, 16, local.As4(), proton.As4()
					}
					icmp := append([]byte{kind, 4, 0, 0, 0, 0, 5, 0}, quoted[:quoteSize]...)
					binary.BigEndian.PutUint16(icmp[2:4], natChecksum(icmp))
					p := natV4Packet(outerSrc, outerDst, 1, nil, icmp)
					rewriteV4(p, off, from, to)
					q := p[28:]
					if [4]byte(q[quotedOff:quotedOff+4]) != to || natChecksum(q[:20]) != 0 || natChecksum(p[:20]) != 0 || natChecksum(p[20:]) != 0 {
						t.Fatalf("invalid translated ICMP error (in=%v proto=%d size=%d type=%d)", inbound, proto, quoteSize, kind)
					}
					// Reconstruct the rest of the quoted original to independently
					// validate the transport checksum when its word was quoted.
					if proto == 17 || quoteSize >= 38 {
						full := append(bytes.Clone(q), quoted[quoteSize:]...)
						if natV4TransportChecksum(full) != 0 {
							t.Fatal("quoted transport checksum invalid")
						}
					}
				}
			}
		}
	}
}

func TestProtonIPv4FragmentedICMPError(t *testing.T) {
	proton, local, remote := netip.MustParseAddr("10.2.0.2"), netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("192.0.2.80")
	quoted := natV4Transport(proton, remote, 17, nil)
	icmp := append([]byte{3, 4, 0, 0, 0, 0, 5, 0}, quoted...)
	binary.BigEndian.PutUint16(icmp[2:4], natChecksum(icmp))
	p := natV4Packet(remote, proton, 1, nil, icmp)
	first, last := natV4Fragment(p, 0, 40), natV4Fragment(p, 40, len(icmp))
	rewriteV4(first, 16, proton.As4(), local.As4())
	rewriteV4(last, 16, proton.As4(), local.As4())
	joined := append(bytes.Clone(first[20:]), last[20:]...)
	if natChecksum(joined) != 0 || [4]byte(joined[20:24]) != local.As4() {
		t.Fatal("fragmented ICMP error corrupted")
	}
}

func TestProtonIPv4InvalidHeadersUnchanged(t *testing.T) {
	from, to := netip.MustParseAddr("100.64.1.2"), netip.MustParseAddr("10.2.0.2")
	for _, tc := range []struct {
		ihl   byte
		total uint16
	}{{4, 84}, {15, 28}, {5, 19}} {
		p := natV4Transport(from, netip.MustParseAddr("192.0.2.80"), 6, nil)
		p = p[:28]
		p[0] = 0x40 | tc.ihl
		binary.BigEndian.PutUint16(p[2:4], tc.total)
		before := bytes.Clone(p)
		rewriteV4(p, 12, from.As4(), to.As4())
		if !bytes.Equal(p, before) {
			t.Fatal("partially translated malformed IPv4 header")
		}
	}
}
