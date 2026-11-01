// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
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

func TestProtonReadPacketSpacing(t *testing.T) {
	p := newProtonTUN(1280)
	t.Cleanup(func() { _ = p.Close() })
	want := mkV4("8.8.8.8")
	p.enqueue(want)
	slab := bytes.Repeat([]byte{0xcc}, len(want)+2*tun.ReadPacketSpacing)
	packets := make([]tun.ReadPacket, 1)
	n, err := p.Read(slab, packets)
	if err != nil || n != 1 {
		t.Fatalf("Read = %d, %v", n, err)
	}
	r := packets[0]
	if r.Offset != tun.ReadPacketSpacing || r.Size != len(want) ||
		!bytes.Equal(slab[r.Offset:r.Offset+r.Size], want) {
		t.Fatalf("invalid packet descriptor: %+v", r)
	}
	if !bytes.Equal(slab[:r.Offset], bytes.Repeat([]byte{0xcc}, tun.ReadPacketSpacing)) ||
		!bytes.Equal(slab[r.Offset+r.Size:], bytes.Repeat([]byte{0xcc}, tun.ReadPacketSpacing)) {
		t.Fatal("Read overwrote reserved packet spacing")
	}
	p.enqueue(want)
	if _, err := p.Read(make([]byte, 2*tun.ReadPacketSpacing), packets); !errors.Is(err, tun.ErrTooManySegments) {
		t.Fatalf("short Read error = %v", err)
	}
}

// A final read can return both packets and EOF. The demux must preserve the
// tailnet packet's slab offset while diverting or dropping internet traffic.
type protonPacketSource struct {
	tun.Device
	packets [][]byte
}

func (s *protonPacketSource) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	offset := tun.ReadPacketSpacing
	for i, p := range s.packets {
		copy(slab[offset:], p)
		packets[i] = tun.ReadPacket{Offset: offset, Size: len(p)}
		offset += len(p) + tun.ReadPacketSpacing
	}
	return len(s.packets), io.EOF
}

func TestDemuxReadSlabRouting(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprint(connected), func(t *testing.T) {
			p := newProtonTUN(1280)
			t.Cleanup(func() { _ = p.Close() })
			internet, tailnet := mkV4("8.8.8.8"), mkV4("100.64.1.2")
			source := &protonPacketSource{packets: [][]byte{internet, tailnet}}
			var ready atomic.Bool
			ready.Store(connected)
			d := newDemuxRouter(&realEndpoint{real: source}, p,
				buildTailnetTable([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}), &ready)
			slab := make([]byte, 2048)
			packets := make([]tun.ReadPacket, 2)
			n, err := d.Read(slab, packets)
			if n != 1 || !errors.Is(err, io.EOF) {
				t.Fatalf("Read = %d, %v", n, err)
			}
			r := packets[0]
			if r.Offset != 2*tun.ReadPacketSpacing+len(internet) ||
				!bytes.Equal(slab[r.Offset:r.Offset+r.Size], tailnet) {
				t.Fatal("tailnet packet or slab offset corrupted")
			}
			if connected {
				select {
				case pkt := <-p.inbound:
					dst, _ := dstAddr(pkt.buf)
					releaseProtonPacket(pkt)
					if dst.String() != "8.8.8.8" {
						t.Fatalf("Proton received destination %s", dst)
					}
				default:
					t.Fatal("internet packet was not diverted to Proton")
				}
			} else if len(p.inbound) != 0 {
				t.Fatal("kill switch forwarded internet traffic before connection")
			}
		})
	}
}

// The real TUN slab is reused immediately after enqueue. Queued buffers and
// returned WireGuard slabs must remain independent, including after pool reuse.
func TestProtonPacketOwnership(t *testing.T) {
	for _, size := range []int{64, maxPacketSize, maxPacketSize + 1, 65535} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			p := newProtonTUN(1280)
			t.Cleanup(func() { _ = p.Close() })
			pkt := bytes.Repeat([]byte{0x4a}, size)
			want := bytes.Clone(pkt)
			p.enqueue(pkt)
			clear(pkt)
			slab := make([]byte, size+2*tun.ReadPacketSpacing)
			packets := make([]tun.ReadPacket, 1)
			if n, err := p.Read(slab, packets); n != 1 || err != nil {
				t.Fatalf("Read = %d, %v", n, err)
			}
			r := packets[0]
			if !bytes.Equal(slab[r.Offset:r.Offset+r.Size], want) {
				t.Fatal("reusing the source slab changed the queued packet")
			}
			for i := 0; i < 20; i++ {
				p.enqueue(pkt)
				otherSlab := make([]byte, len(slab))
				if _, err := p.Read(otherSlab, packets); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(slab[r.Offset:r.Offset+r.Size], want) {
				t.Fatal("pool reuse changed a previously returned WireGuard slab")
			}
		})
	}
}

func TestProtonQueueFullAndClose(t *testing.T) {
	p := newProtonTUN(1280)
	pkt := mkV4("8.8.8.8")
	for i := 0; i < protonQueueLen+32; i++ {
		p.enqueue(pkt)
	}
	if len(p.inbound) != protonQueueLen {
		t.Fatalf("queue length = %d", len(p.inbound))
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if len(p.inbound) != 0 {
		t.Fatal("Close retained queued packet buffers")
	}
	p.enqueue(pkt)
	if len(p.inbound) != 0 {
		t.Fatal("enqueue accepted a packet after Close")
	}
	if n, err := p.Read(make([]byte, 2048), make([]tun.ReadPacket, 1)); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read after Close = %d, %v", n, err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProtonConcurrentQueueClose(t *testing.T) {
	for round := 0; round < 20; round++ {
		p := newProtonTUN(1280)
		var wg sync.WaitGroup
		var started sync.WaitGroup
		started.Add(4)
		for writer := 0; writer < 4; writer++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				pkt := mkV4("8.8.8.8")
				for i := 0; i < 200; i++ {
					p.enqueue(pkt)
					if i == 0 {
						started.Done()
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			slab := make([]byte, 2048)
			packets := make([]tun.ReadPacket, 1)
			for {
				if _, err := p.Read(slab, packets); errors.Is(err, os.ErrClosed) {
					return
				} else if err != nil {
					t.Error(err)
					return
				}
			}
		}()
		started.Wait()
		_ = p.Close()
		wg.Wait()
		if len(p.inbound) != 0 {
			t.Fatal("concurrent enqueue leaked buffers after Close")
		}
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
