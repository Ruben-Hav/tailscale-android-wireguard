// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build protonprofile

package libtailscale

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var protonProfiling struct {
	sync.Mutex
	kind, dir    string
	file         *os.File
	started      time.Time
	before       runtime.MemStats
	oldMutexRate int
}

// ProtonProfileStart is available only in diagnostic APKs built with
// protonprofile. Profiles stay in the app's private cache. A separate APK must
// generate traffic so these profiles describe the VPN process alone.
func ProtonProfileStart(kind string) error {
	protonProfiling.Lock()
	defer protonProfiling.Unlock()
	p := &protonProfiling
	if p.kind != "" {
		return errors.New("a VPN profile is already active")
	}
	if kind != "cpu" && kind != "allocs" && kind != "block" && kind != "mutex" {
		return errors.New("profile kind must be cpu, allocs, block, or mutex")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(cache, "proton-profiles", time.Now().UTC().Format("20060102T150405.000000000")+"-"+kind)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if kind == "cpu" {
		file, err := os.OpenFile(filepath.Join(dir, "cpu.pprof"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(file); err != nil {
			file.Close()
			return err
		}
		p.file = file
	} else {
		if kind == "allocs" {
			// Heap profiles are delayed by up to two GC cycles. Flush earlier
			// allocations before establishing the workload's baseline.
			runtime.GC()
			runtime.GC()
		}
		if err := writeProtonProfile(kind, filepath.Join(dir, kind+"-before.pprof")); err != nil {
			return err
		}
		if kind == "block" {
			runtime.SetBlockProfileRate(1000000)
		}
		if kind == "mutex" {
			p.oldMutexRate = runtime.SetMutexProfileFraction(10)
		}
	}
	p.kind, p.dir, p.started = kind, dir, time.Now()
	runtime.ReadMemStats(&p.before)
	return nil
}

// ProtonProfileResetBaseline excludes the sampling warmup from cumulative
// block/mutex profiles. It is not valid for the streaming CPU profile.
func ProtonProfileResetBaseline() error {
	protonProfiling.Lock()
	defer protonProfiling.Unlock()
	p := &protonProfiling
	if p.kind == "" || p.kind == "cpu" {
		return errors.New("baseline reset requires a cumulative profile")
	}
	if p.kind == "allocs" {
		runtime.GC()
		runtime.GC()
	}
	if err := writeProtonProfile(p.kind, filepath.Join(p.dir, p.kind+"-before.pprof")); err != nil {
		return err
	}
	p.started = time.Now()
	runtime.ReadMemStats(&p.before)
	return nil
}

func writeProtonProfile(kind, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = pprof.Lookup(kind).WriteTo(f, 0)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// ProtonProfileStop stops sampling and returns paths plus runtime counter
// deltas. It neither publishes profiles nor reads account/session data.
func ProtonProfileStop() (string, error) {
	protonProfiling.Lock()
	defer protonProfiling.Unlock()
	p := &protonProfiling
	if p.kind == "" {
		return "", errors.New("no VPN profile is active")
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	seconds := time.Since(p.started).Seconds()
	kind, dir := p.kind, p.dir
	p.kind = ""
	if kind == "cpu" {
		pprof.StopCPUProfile()
		if err := p.file.Close(); err != nil {
			return "", err
		}
		p.file = nil
	}
	if kind == "block" {
		runtime.SetBlockProfileRate(0)
	}
	if kind == "mutex" {
		runtime.SetMutexProfileFraction(p.oldMutexRate)
	}
	if kind != "cpu" {
		if kind == "allocs" {
			// Flush profile accounting after reading the measured counters.
			runtime.GC()
			runtime.GC()
		}
		if err := writeProtonProfile(kind, filepath.Join(dir, kind+"-after.pprof")); err != nil {
			return "", err
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, filepath.Join(dir, file.Name()))
	}
	data, err := json.Marshal(map[string]any{
		"kind": kind, "seconds": seconds, "paths": paths,
		"allocatedBytes": after.TotalAlloc - p.before.TotalAlloc, "mallocs": after.Mallocs - p.before.Mallocs,
		"gcCycles": after.NumGC - p.before.NumGC, "gcPauseNs": after.PauseTotalNs - p.before.PauseTotalNs,
		"heapBytes": after.HeapAlloc, "goroutines": runtime.NumGoroutine(), "gomaxprocs": runtime.GOMAXPROCS(0),
	})
	return string(data), err
}

type protonTCPTrace struct {
	Micros                      int64  `json:"micros"`
	Phase                       string `json:"phase"`
	Src, Dst                    string
	Length                      int `json:"length"`
	PayloadLength               int `json:"payloadLength"`
	SourcePort, DestinationPort uint16
	Flags                       byte `json:"flags"`
	Seq, Ack                    uint32
	ValidChecksum               bool `json:"validChecksum"`
}

var protonTracing struct {
	sync.Mutex
	enabled   atomic.Bool
	addresses map[netip.Addr]bool
	packets   []protonTCPTrace
	started   time.Time
}

// ProtonTestIPv6Available injects the IPv4-only-server case in diagnostic APKs.
// Enabling is permitted only when this tunnel actually has an assigned IPv6.
func ProtonTestIPv6Available(enabled bool) error {
	n := protonNATConfig.Load()
	if n == nil || n.protonV6 == ([16]byte{}) {
		return errors.New("the current test tunnel has no assigned IPv6")
	}
	copy := *n
	copy.haveV6 = enabled
	protonNATConfig.Store(&copy)
	return nil
}

// ProtonTraceStart records only TCP metadata/checksum validity for explicitly
// selected public test endpoints. No packet payload or TLS material is stored.
func ProtonTraceStart(addresses string) error {
	allowed := make(map[netip.Addr]bool)
	for _, text := range strings.Split(addresses, ",") {
		a, err := netip.ParseAddr(strings.TrimSpace(text))
		if err != nil || !a.IsGlobalUnicast() || a.IsPrivate() {
			return fmt.Errorf("invalid public test address %q", text)
		}
		allowed[a] = true
	}
	protonTracing.Lock()
	defer protonTracing.Unlock()
	protonTracing.addresses, protonTracing.packets = allowed, nil
	protonTracing.started = time.Now()
	protonTracing.enabled.Store(true)
	return nil
}

func ProtonTraceStop() (string, error) {
	protonTracing.Lock()
	defer protonTracing.Unlock()
	protonTracing.enabled.Store(false)
	data, err := json.Marshal(protonTracing.packets)
	return string(data), err
}

func protonTracePacket(phase string, pkt []byte) {
	if !protonTracing.enabled.Load() || len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return
	}
	src, ok := srcAddr(pkt)
	if !ok {
		return
	}
	dst, ok := dstAddr(pkt)
	if !ok {
		return
	}
	protonTracing.Lock()
	defer protonTracing.Unlock()
	if !protonTracing.enabled.Load() || len(protonTracing.packets) >= 2048 || (!protonTracing.addresses[src] && !protonTracing.addresses[dst]) {
		return
	}
	offset := int(pkt[0]&15) * 4
	length := int(binary.BigEndian.Uint16(pkt[2:4]))
	if offset < 20 || length > len(pkt) || length < offset+20 || binary.BigEndian.Uint16(pkt[6:8])&0x3fff != 0 {
		return
	}
	tcp := pkt[offset:length]
	sum := uint32(6 + len(tcp))
	for _, data := range [][]byte{pkt[12:20], tcp} {
		for len(data) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(data))
			data = data[2:]
		}
		if len(data) == 1 {
			sum += uint32(data[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	protonTracing.packets = append(protonTracing.packets, protonTCPTrace{Micros: time.Since(protonTracing.started).Microseconds(), Phase: phase, Src: src.String(), Dst: dst.String(), Length: len(tcp), PayloadLength: len(tcp) - int(tcp[12]>>4)*4, SourcePort: binary.BigEndian.Uint16(tcp[0:2]), DestinationPort: binary.BigEndian.Uint16(tcp[2:4]), Flags: tcp[13], Seq: binary.BigEndian.Uint32(tcp[4:8]), Ack: binary.BigEndian.Uint32(tcp[8:12]), ValidChecksum: uint16(sum) == 65535})
}
