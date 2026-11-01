// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the "split tunnel" data plane that lets Tailscale and
// ProtonVPN share the single Android VpnService TUN.
//
// Android only allows one VpnService/TUN per device, so we cannot run two VPN
// apps in parallel. Instead, when ProtonVPN mode is enabled, the VpnService TUN
// captures the full default route (0.0.0.0/0, ::/0). Every outbound packet is
// then demultiplexed in-process:
//
//   - packets destined to the tailnet (or a Tailscale subnet route) are handed
//     to Tailscale's wireguard-go engine, exactly as before; and
//   - all other packets are handed to a second, independent ProtonVPN
//     wireguard-go device (see proton_device.go); and
//   - if ProtonVPN is enabled but not ready, non-tailnet packets are dropped
//     (fail-closed kill switch) so the device's real IP never leaks.
//
// Two cooperating tun.Device implementations make this work:
//
//   - demuxRouter wraps the real Android TUN. It is the device handed to the
//     Tailscale engine (via the existing multiTUN), so multiTUN keeps handling
//     device hot-swaps on every VpnService reconfigure. demuxRouter.Read pulls
//     packets off the real TUN and returns only tailnet packets to Tailscale,
//     diverting the rest to the persistent protonTUN.
//
//   - protonTUN is the device handed to the ProtonVPN wireguard-go device. It
//     persists across VpnService reconfigures so the Proton tunnel (and its
//     handshake) survive Wi-Fi<->cellular changes. It reads diverted packets
//     from demuxRouter and writes decrypted return packets back out to whatever
//     real TUN is current.
//
// ON-DEVICE VERIFICATION NOTES (cannot be checked without a build):
//   - tunReadOffset: wireguard-go reads/writes the TUN with head room reserved
//     for its transport header. We read the real device at the same offset the
//     engine uses. If packets come back malformed on device, revisit this.
//   - bart.Table.Contains: confirm the method name/signature in the pinned
//     github.com/gaissmai/bart version.
//   - BatchSize is 1 on Android (matches multitun.go).

package libtailscale

import (
	"encoding/binary"
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/tun"
)

const (
	// maxPacketSize bounds reusable packet buffers. The Android TUN MTU is
	// defaultMTU (1280); larger packets still work but are not retained in the pool.
	maxPacketSize = 2048

	// protonQueueLen bounds how many diverted packets we buffer for the Proton
	// device before dropping. A real TUN drops under pressure too.
	protonQueueLen = 1024
)

// Always keep tailnet addresses on Tailscale, even before individual peer routes arrive.
var tailscaleRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

func buildTailnetTable(routes []netip.Prefix) *bart.Lite {
	t := &bart.Lite{}
	for _, p := range tailscaleRanges {
		t.Insert(p)
	}
	for _, p := range routes {
		if p.Bits() != 0 {
			t.Insert(p)
		}
	}
	return t
}

// Diagnostic packet counters for the Proton data path.
//
//	protonOutPackets: app -> Proton (diverted by the demux)
//	protonInPackets:  Proton -> app (decrypted, written back to the real TUN)
//
// If out grows but in stays 0, packets reach Proton but nothing comes back
// (server/socket-protection issue). If out stays 0, app traffic never reaches
// the demux (routing/TUN issue).
var (
	protonOutPackets  atomic.Int64 // app -> demux -> enqueued for Proton device
	protonPulledByDev atomic.Int64 // packets the Proton device pulled to encrypt+send
	protonInPackets   atomic.Int64 // Proton device -> app (decrypted responses)
	demuxDbgCount     atomic.Int64
)

func shouldLogProtonPacket(n int64) bool { return n == 1 || n%5000 == 0 }

// A pointer wrapper avoids allocating a slice header when returning a buffer to
// sync.Pool. Each queued packet has one owner until Read copies it into the
// WireGuard slab, or a drop/Close returns it to the pool.
type protonPacket struct{ buf []byte }

var protonPacketPool = sync.Pool{New: func() any {
	return &protonPacket{buf: make([]byte, maxPacketSize)}
}}

func acquireProtonPacket(size int) *protonPacket {
	if size > maxPacketSize {
		return &protonPacket{buf: make([]byte, size)}
	}
	p := protonPacketPool.Get().(*protonPacket)
	p.buf = p.buf[:size]
	return p
}

func releaseProtonPacket(p *protonPacket) {
	if cap(p.buf) == maxPacketSize {
		protonPacketPool.Put(p)
	}
}

// pxRoute is the routing decision for a single outbound packet.
type pxRoute int

const (
	routeDrop pxRoute = iota
	routeTailscale
	routeProton
	routeRejectIPv6
)

func (r pxRoute) String() string {
	switch r {
	case routeTailscale:
		return "tailscale"
	case routeProton:
		return "proton"
	case routeRejectIPv6:
		return "reject-ipv6"
	default:
		return "drop"
	}
}

// realEndpoint bundles the current real Android TUN device with a write mutex.
// Both demuxRouter (Tailscale inbound) and protonTUN (Proton inbound) write to
// the same underlying device, so writes must be serialized.
type realEndpoint struct {
	real tun.Device
	mu   sync.Mutex
}

// write serializes writes to the underlying real Android TUN.
func (e *realEndpoint) write(bufs [][]byte, offset int) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.real.Write(bufs, offset)
}

// srcAddr extracts the source IP from a raw IPv4/IPv6 packet.
func srcAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[12:16])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[8:24])), true
	}
	return netip.Addr{}, false
}

// dstAddr extracts the destination IP from a raw IPv4/IPv6 packet.
func dstAddr(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 1 {
		return netip.Addr{}, false
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(pkt[16:20])), true
	case 6:
		if len(pkt) < 40 {
			return netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(pkt[24:40])), true
	}
	return netip.Addr{}, false
}

// protonTUN is the persistent tun.Device consumed by the ProtonVPN wireguard-go
// device. It survives VpnService reconfigures.
type protonTUN struct {
	mtu int

	// inbound carries host->internet packets (diverted by demuxRouter) for the
	// Proton device to Read and encrypt.
	inbound chan *protonPacket
	events  chan tun.Event
	// Serialize enqueue with Close so nothing can be queued after Close drains
	// the buffers. Read owns dequeued buffers and needs no queue lock.
	queueMu sync.Mutex
	closed  bool

	// writer points at the current real TUN, used to deliver internet->host
	// packets the Proton device decrypted. Swapped on each reconfigure.
	writer atomic.Pointer[realEndpoint]

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newProtonTUN(mtu int) *protonTUN {
	p := &protonTUN{
		mtu:     mtu,
		inbound: make(chan *protonPacket, protonQueueLen),
		events:  make(chan tun.Event, 1),
		closeCh: make(chan struct{}),
	}
	p.events <- tun.EventUp
	return p
}

// enqueue copies pkt and offers it to the Proton device, dropping if the queue
// is full (TUN-like behaviour under pressure).
func (p *protonTUN) enqueue(pkt []byte) {
	if p.rejectUnsupportedIPv6(pkt) {
		return
	}
	p.queueMu.Lock()
	defer p.queueMu.Unlock()
	if p.closed {
		return
	}
	n := protonOutPackets.Add(1)
	if shouldLogProtonPacket(n) {
		log.Printf("proton: app->Proton packets: %d (last dst %s)", n, packetDstString(pkt))
	}
	cp := acquireProtonPacket(len(pkt))
	copy(cp.buf, pkt)
	protonTracePacket("out-before-NAT", cp.buf)
	// SNAT the source to the Proton-assigned client address so the server's
	// cryptokey routing accepts the packet.
	snatOutbound(cp.buf)
	protonTracePacket("out-after-NAT", cp.buf)
	select {
	case p.inbound <- cp:
	default:
		releaseProtonPacket(cp) // queue full: drop.
	}
}

func packetDstString(pkt []byte) string {
	if a, ok := dstAddr(pkt); ok {
		return a.String()
	}
	return "?"
}

func (p *protonTUN) setWriter(e *realEndpoint) { p.writer.Store(e) }

// Read returns one host->internet packet for the Proton device to send.
func (p *protonTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 || len(slab) < 2*tun.ReadPacketSpacing {
		return 0, tun.ErrTooManySegments
	}
	select {
	case pkt := <-p.inbound:
		c := protonPulledByDev.Add(1)
		if shouldLogProtonPacket(c) {
			log.Printf("proton: device pulled %d packets to encrypt+send", c)
		}
		if len(pkt.buf) > len(slab)-2*tun.ReadPacketSpacing {
			releaseProtonPacket(pkt)
			return 0, tun.ErrTooManySegments
		}
		n := copy(slab[tun.ReadPacketSpacing:], pkt.buf)
		releaseProtonPacket(pkt)
		packets[0] = tun.ReadPacket{Offset: tun.ReadPacketSpacing, Size: n}
		return 1, nil
	case <-p.closeCh:
		return 0, os.ErrClosed
	}
}

// Write delivers internet->host packets (decrypted by the Proton device) to the
// current real TUN.
func (p *protonTUN) Write(bufs [][]byte, offset int) (int, error) {
	n := protonInPackets.Add(int64(len(bufs)))
	if shouldLogProtonPacket(n) {
		log.Printf("proton: Proton->app packets: %d", n)
	}
	// DNAT the destination from the Proton client address back to the device's
	// TUN address so the app receives the response on the IP it sent from.
	for _, b := range bufs {
		if len(b) > offset {
			protonTracePacket("in-before-NAT", b[offset:])
			dnatInbound(b[offset:])
			protonTracePacket("in-after-NAT", b[offset:])
		}
	}
	e := p.writer.Load()
	if e == nil {
		// No real device yet; drop silently.
		return len(bufs), nil
	}
	return e.write(bufs, offset)
}

func (p *protonTUN) MTU() (int, error)        { return p.mtu, nil }
func (p *protonTUN) Name() (string, error)    { return "proton0", nil }
func (p *protonTUN) Events() <-chan tun.Event { return p.events }
func (p *protonTUN) BatchSize() int           { return 1 }
func (p *protonTUN) File() *os.File           { panic("protonTUN.File not available") }

func (p *protonTUN) Close() error {
	p.closeOnce.Do(func() {
		p.queueMu.Lock()
		defer p.queueMu.Unlock()
		p.closed = true
		close(p.closeCh)
		close(p.events)
		for {
			select {
			case pkt := <-p.inbound:
				releaseProtonPacket(pkt)
			default:
				return
			}
		}
	})
	return nil
}

// demuxRouter wraps the real Android TUN and is the device the Tailscale engine
// drives (through multiTUN). It splits outbound traffic between Tailscale and
// the persistent protonTUN.
type demuxRouter struct {
	ep     *realEndpoint
	proton *protonTUN

	// table holds the tailnet prefixes; nil means "no tailnet routes yet".
	table atomic.Pointer[bart.Lite]
	// protonReady gates whether non-tailnet packets are forwarded (true) or
	// dropped for the fail-closed kill switch (false).
	protonReady *atomic.Bool
	// Valid only in tailnet-only mode on a confirmed broken IPv6 underlay.
	rejectIPv6From netip.Addr
	agentAddr      netip.Addr
}

func newDemuxRouter(ep *realEndpoint, proton *protonTUN, table *bart.Lite, ready *atomic.Bool) *demuxRouter {
	d := &demuxRouter{
		ep:          ep,
		proton:      proton,
		protonReady: ready,
	}
	d.table.Store(table)
	return d
}

func (d *demuxRouter) setTable(table *bart.Lite) { d.table.Store(table) }

func (d *demuxRouter) route(pkt []byte) pxRoute {
	addr, ok := dstAddr(pkt)
	if !ok {
		return routeDrop
	}
	// Only the local agent's TCP port overrides an overlapping tailnet subnet.
	// All other traffic to that address still follows the tailnet table. This
	// also lets the agent recover while normal internet traffic is fail closed.
	if d.agentAddr.IsValid() && addr == d.agentAddr && d.proton != nil && isProtonAgentTCP(pkt) {
		return routeProton
	}
	if t := d.table.Load(); t != nil {
		if t.Contains(addr) {
			return routeTailscale
		}
	}
	if d.rejectIPv6From.IsValid() && protonIPv6Internet.Contains(addr) {
		return routeRejectIPv6
	}
	// LAN / link-local / multicast must never be tunneled to Proton (it can't
	// route them and would just black-hole/flood). They're also excluded from
	// the TUN, so this is a safety net.
	if isNonRoutable(addr) {
		return routeDrop
	}
	if d.protonReady != nil && d.protonReady.Load() {
		return routeProton
	}
	return routeDrop // fail-closed: never leak non-tailnet traffic.
}

func isProtonAgentTCP(pkt []byte) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 || binary.BigEndian.Uint16(pkt[6:8])&0x1fff != 0 {
		return false
	}
	ihl := int(pkt[0]&15) * 4
	return ihl >= 20 && len(pkt) >= ihl+4 && binary.BigEndian.Uint16(pkt[ihl+2:ihl+4]) == 65432
}

func isNonRoutable(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsLoopback() || a.IsUnspecified()
}

// Read returns tailnet packets to the Tailscale engine, diverting everything
// else to Proton (or dropping it). It blocks until at least one tailnet packet
// is available, mirroring normal TUN read semantics.
func (d *demuxRouter) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	for {
		n, err := d.ep.real.Read(slab, packets)
		delivered := 0
		for i := 0; i < n; i++ {
			packet := packets[i]
			pkt := slab[packet.Offset : packet.Offset+packet.Size]
			decision := d.route(pkt)
			if c := demuxDbgCount.Add(1); c <= 10 {
				s, _ := srcAddr(pkt)
				a, _ := dstAddr(pkt)
				log.Printf("proton: demux pkt#%d src=%s dst=%s decision=%s len=%d", c, s, a, decision, len(pkt))
			}
			switch decision {
			case routeTailscale:
				packets[delivered] = packet
				delivered++
			case routeProton:
				d.proton.enqueue(pkt)
			case routeRejectIPv6:
				if reply := protonIPv6Unreachable(pkt, d.rejectIPv6From); len(reply) > 0 {
					_, _ = d.ep.write([][]byte{reply}, 0)
				}
			default:
				// drop (fail-closed)
			}
		}
		if delivered > 0 || err != nil {
			return delivered, err
		}
		// No tailnet packets this round; keep reading.
	}
}

// Write delivers Tailscale inbound (tailnet->host) packets to the real device.
func (d *demuxRouter) Write(bufs [][]byte, offset int) (int, error) {
	return d.ep.write(bufs, offset)
}

func (d *demuxRouter) MTU() (int, error)        { return d.ep.real.MTU() }
func (d *demuxRouter) Name() (string, error)    { return d.ep.real.Name() }
func (d *demuxRouter) Events() <-chan tun.Event { return d.ep.real.Events() }
func (d *demuxRouter) BatchSize() int           { return 1 }
func (d *demuxRouter) File() *os.File           { return d.ep.real.File() }

// Close closes the underlying real Android TUN. multiTUN calls this when it
// swaps to a newer device on VpnService reconfigure.
func (d *demuxRouter) Close() error {
	log.Printf("proton: demuxRouter closing real TUN")
	return d.ep.real.Close()
}
