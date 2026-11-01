// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"fmt"
	"io"
	"log"
	"runtime"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
)

// BenchmarkProtonForward measures the complete queue handoff, including the
// copy into WireGuard's read slab. It needs no account or running VPN.
func BenchmarkProtonForward(b *testing.B) {
	oldOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldOutput)
	for _, size := range []int{64, 512, 1280, 2048, 4096} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := newProtonTUN(1280)
			defer p.Close()
			pkt := make([]byte, size)
			pkt[0] = 0x45
			copy(pkt[16:20], []byte{8, 8, 8, 8})
			slab := make([]byte, size+2*tun.ReadPacketSpacing)
			packets := make([]tun.ReadPacket, 1)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.enqueue(pkt)
				if n, err := p.Read(slab, packets); n != 1 || err != nil {
					b.Fatalf("Read = %d, %v", n, err)
				}
			}
			b.StopTimer()
			runtime.ReadMemStats(&after)
			b.ReportMetric(float64(after.NumGC-before.NumGC)*1e6/float64(b.N), "GC/Mpkt")
		})
	}
}

// The demux and WireGuard consume packets on different goroutines. Keep at most
// 64 packets outstanding so the test measures their handoff without queue drops.
func BenchmarkProtonPipeline(b *testing.B) {
	oldOutput := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(oldOutput)
	p := newProtonTUN(1280)
	defer p.Close()
	const batch = 64
	pkt := make([]byte, 1280)
	pkt[0] = 0x45
	copy(pkt[16:20], []byte{8, 8, 8, 8})
	ack := make(chan error)
	go func() {
		slab := make([]byte, len(pkt)+2*tun.ReadPacketSpacing)
		packets := make([]tun.ReadPacket, 1)
		for i := 0; i < b.N; i++ {
			for j := 0; j < batch; j++ {
				if n, err := p.Read(slab, packets); n != 1 || err != nil {
					ack <- fmt.Errorf("Read = %d, %v", n, err)
					return
				}
			}
			ack <- nil
		}
	}()
	b.SetBytes(int64(len(pkt) * batch))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < batch; j++ {
			p.enqueue(pkt)
		}
		if err := <-ack; err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}
