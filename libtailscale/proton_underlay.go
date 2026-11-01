// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

type protonUnderlayResult struct {
	generation uint64
	reject     bool
	key        string
}

var (
	onProtonUnderlayCheck    = make(chan struct{}, 1)
	onProtonUnderlayResult   = make(chan protonUnderlayResult, 1)
	protonUnderlayForce      atomic.Bool
	protonRejectUnderlayIPv6 atomic.Bool
)

// ProtonUnderlyingNetworkChanged queues a coalesced probe. It performs no JNI
// callbacks/network I/O, so Android can call it while holding its network lock.
func ProtonUnderlyingNetworkChanged() { requestProtonUnderlayCheck(false) }
func requestProtonUnderlayCheck(force bool) {
	if force {
		protonUnderlayForce.Store(true)
	}
	select {
	case onProtonUnderlayCheck <- struct{}{}:
	default:
	}
}

func (b *backend) cancelProtonUnderlayProbe() {
	b.protonUnderlayGeneration++
	if b.protonUnderlayCancel != nil {
		b.protonUnderlayCancel()
		b.protonUnderlayCancel = nil
	}
	if b.protonUnderlayTimer != nil {
		b.protonUnderlayTimer.Stop()
		b.protonUnderlayTimer = nil
	}
}

func (b *backend) startProtonUnderlayProbe(force bool) {
	if vpnService.service == nil || b.lastCfg == nil {
		return
	}
	var info struct {
		Key  string `json:"key"`
		IPv4 bool   `json:"ipv4"`
	}
	if err := json.Unmarshal([]byte(b.appCtx.GetUnderlyingNetworkInfo()), &info); err != nil {
		return
	}
	if b.protonUnderlayStarted && !force && info.Key == b.protonUnderlayKey {
		return
	}
	b.cancelProtonUnderlayProbe()
	b.protonUnderlayStarted = true
	b.protonUnderlayKey = info.Key
	generation := b.protonUnderlayGeneration
	if !info.IPv4 {
		b.protonUnderlayFinished(protonUnderlayResult{generation: generation, key: info.Key})
		return
	}
	lifetime, cancel := context.WithCancel(context.Background())
	b.protonUnderlayCancel = cancel
	ctx, stopProbe := context.WithTimeout(lifetime, 1500*time.Millisecond)
	service := vpnService.service
	go func() {
		defer cancel()
		defer stopProbe()
		var unsafe atomic.Bool
		d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			ok := false
			err := c.Control(func(fd uintptr) { ok = service.Protect(int32(fd)) && b.appCtx.BindSocketToNetwork(int32(fd)) })
			if err != nil || !ok {
				unsafe.Store(true)
				return errors.New("could not protect and bind the IPv6 underlay probe")
			}
			return nil
		}}
		reachable := probeProtonUnderlayIPv6(ctx, func(ctx context.Context, address string) (net.Conn, error) { return d.DialContext(ctx, "tcp", address) })
		// A timeout is a negative result, but a replaced/cancelled network is
		// stale and must not alter the new network's routing.
		if lifetime.Err() != nil {
			return
		}
		select {
		case onProtonUnderlayResult <- protonUnderlayResult{generation: generation, reject: !reachable && !unsafe.Load(), key: info.Key}:
		case <-lifetime.Done():
		}
	}()
}

func (b *backend) protonUnderlayFinished(result protonUnderlayResult) {
	if result.generation != b.protonUnderlayGeneration || vpnService.service == nil {
		return
	}
	var current struct {
		Key string `json:"key"`
	}
	if json.Unmarshal([]byte(b.appCtx.GetUnderlyingNetworkInfo()), &current) != nil || current.Key != result.key {
		requestProtonUnderlayCheck(true)
		return
	}
	changed := protonRejectUnderlayIPv6.Swap(result.reject) != result.reject
	if changed {
		log.Printf("proton: IPv6 underlay fallback=%v", result.reject)
	}
	want := result.reject && b.lastCfg != nil && !protonHasIPv6ExitRoute(b.lastCfg.Routes)
	if !protonMgr.enabled.Load() && b.lastCfg != nil && b.protonUnderlayApplied != want {
		if err := b.refreshTUN(); err != nil {
			log.Printf("proton: update IPv6 fallback routes: %v", err)
			b.protonUnderlayTimer = time.NewTimer(5 * time.Second)
			return
		}
	}
	if b.protonUnderlayTimer != nil {
		b.protonUnderlayTimer.Stop()
		b.protonUnderlayTimer = nil
	}
	// Recheck failed dual-stack paths to recover IPv6 after an ISP outage,
	// without repeatedly probing healthy paths or a fully stopped VPN.
	if result.reject && !protonMgr.enabled.Load() {
		b.protonUnderlayTimer = time.NewTimer(3 * time.Minute)
	}
}

func (b *backend) protonUnderlayRetryChan() <-chan time.Time {
	if b.protonUnderlayTimer != nil {
		return b.protonUnderlayTimer.C
	}
	return nil
}
