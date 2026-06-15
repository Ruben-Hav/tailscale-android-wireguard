// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestDstAddr(t *testing.T) {
	v4 := make([]byte, 20)
	v4[0] = 0x45 // IPv4, IHL=5
	copy(v4[16:20], netip.MustParseAddr("8.8.8.8").AsSlice())
	if a, ok := dstAddr(v4); !ok || a != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("v4 dst = %v %v, want 8.8.8.8", a, ok)
	}

	v6 := make([]byte, 40)
	v6[0] = 0x60 // IPv6
	copy(v6[24:40], netip.MustParseAddr("2001:4860:4860::8888").AsSlice())
	if a, ok := dstAddr(v6); !ok || a != netip.MustParseAddr("2001:4860:4860::8888") {
		t.Fatalf("v6 dst = %v %v, want 2001:4860:4860::8888", a, ok)
	}

	if _, ok := dstAddr([]byte{0x45}); ok {
		t.Fatalf("short packet should not parse")
	}
}

func mkV4(dst string) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	copy(p[16:20], netip.MustParseAddr(dst).AsSlice())
	return p
}

// TestDemuxRoute verifies the split decision: tailnet -> Tailscale, everything
// else -> Proton when ready, else dropped (fail-closed kill switch). It also
// confirms buildTailnetTable skips the default route.
func TestDemuxRoute(t *testing.T) {
	table := buildTailnetTable([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("0.0.0.0/0"), // default route must be skipped
	})
	var ready atomic.Bool
	d := newDemuxRouter(&realEndpoint{}, nil, table, &ready)

	if r := d.route(mkV4("100.64.1.2")); r != routeTailscale {
		t.Fatalf("tailnet dst route = %v, want routeTailscale", r)
	}

	// Non-tailnet while Proton not ready: dropped, never leaked.
	if r := d.route(mkV4("8.8.8.8")); r != routeDrop {
		t.Fatalf("non-tailnet not-ready route = %v, want routeDrop", r)
	}

	// Non-tailnet while Proton ready: sent to Proton.
	ready.Store(true)
	if r := d.route(mkV4("8.8.8.8")); r != routeProton {
		t.Fatalf("non-tailnet ready route = %v, want routeProton", r)
	}
}
