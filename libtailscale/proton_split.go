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
	"log"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/tun"
)

const (
	// maxPacketSize bounds a single IP packet we shuttle between tunnels.
	// The Android TUN MTU is defaultMTU (1280); 2048 leaves ample margin.
	maxPacketSize = 2048

	// protonQueueLen bounds how many diverted packets we buffer for the Proton
	// device before dropping. A real TUN drops under pressure too.
	protonQueueLen = 1024
)

// Diagnostic packet counters for the Proton data path.
//   protonOutPackets: app -> Proton (diverted by the demux)
//   protonInPackets:  Proton -> app (decrypted, written back to the real TUN)
// If out grows but in stays 0, packets reach Proton but nothing comes back
// (server/socket-protection issue). If out stays 0, app traffic never reaches
// the demux (routing/TUN issue).
var (
	protonOutPackets   atomic.Int64 // app -> demux -> enqueued for Proton device
	protonPulledByDev  atomic.Int64 // packets the Proton device pulled to encrypt+send
	protonInPackets    atomic.Int64 // Proton device -> app (decrypted responses)
	demuxDbgCount      atomic.Int64
)

func logEvery(n int64, format string, args ...any) {
	if n == 1 || n%5000 == 0 {
		log.Printf(format, args...)
	}
}

// pxRoute is the routing decision for a single outbound packet.
type pxRoute int

const (
	routeDrop pxRoute = iota
	routeTailscale
	routeProton
)

func (r pxRoute) String() string {
	switch r {
	case routeTailscale:
		return "tailscale"
	case routeProton:
		return "proton"
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
	inbound chan []byte
	events  chan tun.Event

	// writer points at the current real TUN, used to deliver internet->host
	// packets the Proton device decrypted. Swapped on each reconfigure.
	writer atomic.Pointer[realEndpoint]

	closeCh   chan struct{}
	closeOnce sync.Once
}

func newProtonTUN(mtu int) *protonTUN {
	p := &protonTUN{
		mtu:     mtu,
		inbound: make(chan []byte, protonQueueLen),
		events:  make(chan tun.Event, 1),
		closeCh: make(chan struct{}),
	}
	p.events <- tun.EventUp
	return p
}

// enqueue copies pkt and offers it to the Proton device, dropping if the queue
// is full (TUN-like behaviour under pressure).
func (p *protonTUN) enqueue(pkt []byte) {
	n := protonOutPackets.Add(1)
	logEvery(n, "proton: app->Proton packets: %d (last dst %s)", n, packetDstString(pkt))
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	// SNAT the source to the Proton-assigned client address so the server's
	// cryptokey routing accepts the packet.
	snatOutbound(cp)
	select {
	case p.inbound <- cp:
	case <-p.closeCh:
	default:
		// queue full: drop.
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
func (p *protonTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case pkt := <-p.inbound:
		c := protonPulledByDev.Add(1)
		logEvery(c, "proton: device pulled %d packets to encrypt+send", c)
		n := copy(bufs[0][offset:], pkt)
		sizes[0] = n
		return 1, nil
	case <-p.closeCh:
		return 0, os.ErrClosed
	}
}

// Write delivers internet->host packets (decrypted by the Proton device) to the
// current real TUN.
func (p *protonTUN) Write(bufs [][]byte, offset int) (int, error) {
	n := protonInPackets.Add(int64(len(bufs)))
	logEvery(n, "proton: Proton->app packets: %d", n)
	// DNAT the destination from the Proton client address back to the device's
	// TUN address so the app receives the response on the IP it sent from.
	for _, b := range bufs {
		if len(b) > offset {
			dnatInbound(b[offset:])
		}
	}
	e := p.writer.Load()
	if e == nil {
		// No real device yet; drop silently.
		return len(bufs), nil
	}
	return e.write(bufs, offset)
}

func (p *protonTUN) MTU() (int, error)            { return p.mtu, nil }
func (p *protonTUN) Name() (string, error)        { return "proton0", nil }
func (p *protonTUN) Events() <-chan tun.Event     { return p.events }
func (p *protonTUN) BatchSize() int               { return 1 }
func (p *protonTUN) File() *os.File               { panic("protonTUN.File not available") }

func (p *protonTUN) Close() error {
	p.closeOnce.Do(func() { close(p.closeCh) })
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

	// scratch holds a single packet read from the real device. Only touched by
	// the single multiTUN reader goroutine, so it needs no lock.
	scratchBufs  [][]byte
	scratchSizes []int
	scratchOff   int
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
	if t := d.table.Load(); t != nil {
		if t.Contains(addr) {
			return routeTailscale
		}
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

func isNonRoutable(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsLoopback() || a.IsUnspecified()
}

func (d *demuxRouter) ensureScratch(offset int) {
	if d.scratchBufs == nil || d.scratchOff != offset {
		d.scratchBufs = [][]byte{make([]byte, offset+maxPacketSize)}
		d.scratchSizes = []int{0}
		d.scratchOff = offset
	}
}

// Read returns tailnet packets to the Tailscale engine, diverting everything
// else to Proton (or dropping it). It blocks until at least one tailnet packet
// is available, mirroring normal TUN read semantics.
func (d *demuxRouter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.ensureScratch(offset)
	for {
		n, err := d.ep.real.Read(d.scratchBufs, d.scratchSizes, offset)
		if err != nil {
			return 0, err
		}
		delivered := 0
		for i := 0; i < n; i++ {
			pkt := d.scratchBufs[i][offset : offset+d.scratchSizes[i]]
			decision := d.route(pkt)
			if c := demuxDbgCount.Add(1); c <= 10 {
				s, _ := srcAddr(pkt)
				a, _ := dstAddr(pkt)
				log.Printf("proton: demux pkt#%d src=%s dst=%s decision=%s len=%d", c, s, a, decision, len(pkt))
			}
			switch decision {
			case routeTailscale:
				if delivered < len(bufs) {
					m := copy(bufs[delivered][offset:], pkt)
					sizes[delivered] = m
					delivered++
				}
			case routeProton:
				d.proton.enqueue(pkt)
			default:
				// drop (fail-closed)
			}
		}
		if delivered > 0 {
			return delivered, nil
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
