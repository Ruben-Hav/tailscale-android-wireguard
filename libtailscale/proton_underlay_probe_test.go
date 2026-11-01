// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/tun"
)

func TestProtonUnderlayReachability(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"success", nil, true}, {"refused-proves-route", syscall.ECONNREFUSED, true},
		{"no-route", syscall.ENETUNREACH, false}, {"deadline", context.DeadlineExceeded, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls sync.WaitGroup
			calls.Add(2)
			var closed atomic.Int32
			got := probeProtonUnderlayIPv6(context.Background(), func(context.Context, string) (net.Conn, error) {
				defer calls.Done()
				if tc.err != nil {
					return nil, tc.err
				}
				return &protonProbeConn{closed: &closed}, nil
			})
			calls.Wait()
			if got != tc.want {
				t.Fatalf("reachable=%v, want %v", got, tc.want)
			}
			if tc.err == nil && closed.Load() != 2 {
				t.Fatal("probe leaked a connection")
			}
		})
	}
}

type protonProbeConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c *protonProbeConn) Close() error { c.closed.Add(1); return nil }

func TestProtonUnderlayProbeCancelsOtherEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	finished := make(chan struct{})
	if !probeProtonUnderlayIPv6(ctx, func(ctx context.Context, address string) (net.Conn, error) {
		if address == "[2606:4700:4700::1111]:443" {
			return nil, syscall.ECONNREFUSED
		}
		<-ctx.Done()
		close(finished)
		return nil, ctx.Err()
	}) {
		t.Fatal("working endpoint was ignored")
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("losing probe was not cancelled")
	}
}

func TestProtonUnderlayPreservesExitRoute(t *testing.T) {
	for _, tc := range []struct {
		route string
		exit  bool
	}{
		{"::/0", true}, {"0.0.0.0/0", false}, {"fd7a:115c:a1e0::/48", false}, {"2000::/3", false},
	} {
		if got := protonHasIPv6ExitRoute([]netip.Prefix{netip.MustParsePrefix(tc.route)}); got != tc.exit {
			t.Fatalf("%s: exit=%v", tc.route, got)
		}
	}
}

type protonFallbackTUN struct {
	protonPacketSource
	writes [][]byte
}

func (s *protonFallbackTUN) Write(bufs [][]byte, offset int) (int, error) {
	for _, p := range bufs {
		s.writes = append(s.writes, bytes.Clone(p[offset:]))
	}
	return len(bufs), nil
}

func TestProtonUnderlayFallbackPreservesTailnetAndRejectsInternet(t *testing.T) {
	local := netip.MustParseAddr("fd7a:115c:a1e0::1234")
	peer := testIPv6TCP(local, netip.MustParseAddr("fd7a:115c:a1e0::5678"), 6, nil)
	// An advertised public subnet route must also take precedence over fallback.
	subnet := testIPv6TCP(local, netip.MustParseAddr("2001:db8:1234::5"), 6, nil)
	public := testIPv6TCP(local, netip.MustParseAddr("2606:4700:4700::1111"), 6, nil)
	source := &protonFallbackTUN{protonPacketSource: protonPacketSource{packets: [][]byte{public, peer, subnet}}}
	var ready atomic.Bool
	d := newDemuxRouter(&realEndpoint{real: source}, nil, buildTailnetTable([]netip.Prefix{
		netip.MustParsePrefix("fd7a:115c:a1e0::/48"), netip.MustParsePrefix("2001:db8:1234::/48"),
	}), &ready)
	d.rejectIPv6From = local
	slab := make([]byte, 2048)
	packets := make([]tun.ReadPacket, 3)
	n, err := d.Read(slab, packets)
	if n != 2 || !errors.Is(err, io.EOF) {
		t.Fatalf("Read=%d,%v", n, err)
	}
	for i, want := range [][]byte{peer, subnet} {
		r := packets[i]
		if !bytes.Equal(slab[r.Offset:r.Offset+r.Size], want) {
			t.Fatal("tailnet packet changed")
		}
	}
	if len(source.writes) != 1 {
		t.Fatalf("ICMP replies=%d", len(source.writes))
	}
	reply := source.writes[0]
	if reply[40] != 1 || reply[41] != 0 || testIPv6Checksum(reply, 40, 58) != 0 || !bytes.Equal(reply[48:], public) {
		t.Fatal("invalid immediate IPv6 error")
	}
	for _, s := range []string{"fd00::1", "fe80::1", "fec0::1", "ff02::1"} {
		if d.route(testIPv6TCP(local, netip.MustParseAddr(s), 6, nil)) == routeRejectIPv6 {
			t.Fatalf("fallback captured local address %s", s)
		}
	}
}
