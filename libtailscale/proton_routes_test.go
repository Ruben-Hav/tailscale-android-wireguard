// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"encoding/binary"
	"net/netip"
	"sync/atomic"
	"testing"

	rangescalc "github.com/tailscale/tailscale-android/libtailscale/ranges_calc"
)

func TestProtonAgentRouteExclusions(t *testing.T) {
	agent := netip.MustParseAddr("10.2.0.1")
	excluded, err := protonExclusionsExceptAgent([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fe80::/10")}, agent)
	if err != nil {
		t.Fatal(err)
	}
	v4, _, err := rangescalc.Calculate([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, excluded)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		addr     string
		captured bool
	}{{"10.2.0.1", true}, {"10.2.0.0", false}, {"10.2.0.2", false}, {"10.3.0.1", false}, {"192.168.1.1", false}, {"1.1.1.1", true}} {
		captured := false
		for _, prefix := range v4 {
			if prefix.Contains(netip.MustParseAddr(sample.addr)) {
				captured = true
			}
		}
		if captured != sample.captured {
			t.Fatalf("pre-33 capture %s = %v", sample.addr, captured)
		}
	}
}

func TestProtonAgentControlWhileFailClosed(t *testing.T) {
	p := newProtonTUN(1280)
	t.Cleanup(func() { p.Close() })
	var ready atomic.Bool
	d := newDemuxRouter(nil, p, buildTailnetTable([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}), &ready)
	d.agentAddr = netip.MustParseAddr("10.2.0.1")
	pkt := natV4Transport(netip.MustParseAddr("100.64.1.2"), d.agentAddr, 6, nil)
	binary.BigEndian.PutUint16(pkt[22:24], 65432)
	if d.route(pkt) != routeProton {
		t.Fatal("blocked in-tunnel agent before Connected")
	}
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	if d.route(pkt) != routeTailscale {
		t.Fatal("agent override captured a tailnet application port")
	}
	if d.route(mkV4("1.1.1.1")) != routeDrop {
		t.Fatal("allowed internet traffic before agent readiness")
	}
	if d.route(mkV4("100.64.1.3")) != routeTailscale {
		t.Fatal("blocked tailnet peer before agent readiness")
	}
	d.setTable(buildTailnetTable(nil))
	if d.route(pkt) != routeDrop {
		t.Fatal("allowed unrelated private traffic through control override")
	}
}
