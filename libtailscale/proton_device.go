// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The ProtonVPN data-plane device. Unlike Tailscale's engine, ProtonVPN servers
// are plain WireGuard endpoints (no disco/DERP), so we run a second, fully
// independent wireguard-go device. It is driven by the persistent protonTUN
// (see proton_split.go) and sends its encrypted UDP via a protected socket so
// the VpnService's 0.0.0.0/0 route does not loop it back into the tunnel.
//
// ON-DEVICE VERIFICATION NOTES (cannot be checked without a build):
//   - PeekLookAtSocketFd4/6 come from conn/boundif_android.go in the
//     tailscale/wireguard-go fork; only present under the android build tag.
//   - DisableSomeRoamingForBrokenMobileSemantics and BindUpdate are standard
//     wireguard-go device methods; confirm they exist in the pinned fork.

package libtailscale

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
)

// protonConfig holds the resolved parameters needed to bring up the tunnel.
// The Kotlin control plane produces these after login + cert + server pick.
type protonConfig struct {
	privateKeyHex string // X25519 interface private key (hex)
	serverPubHex  string // server X25519 public key (hex)
	endpoint      string // "ip:port", e.g. 1.2.3.4:51820
	keepalive     int    // persistent keepalive seconds (0 -> 25)
}

// protonDevice owns the ProtonVPN wireguard-go device and its TUN. The TUN
// survives Android VpnService reconfigures, but never a WireGuard device close.
type protonDevice struct {
	mu  sync.Mutex
	tun *protonTUN
	dev *device.Device
}

func newProtonDevice(mtu int, cfg protonConfig) (*protonDevice, error) {
	// Device.Close also closes its TUN. Reusing that TUN for another device
	// makes its reader immediately return os.ErrClosed and close the new device.
	ptun := newProtonTUN(mtu)
	bind := conn.NewStdNetBind()
	logger := device.NewLogger(device.LogLevelError, "proton-wg: ")
	dev := device.NewDevice(ptun, bind, logger)
	// NOTE: upstream wireguard-go's DisableSomeRoamingForBrokenMobileSemantics()
	// does not exist in the tailscale fork; the fork already handles mobile
	// roaming. We rely on persistent_keepalive + Rebind() on network changes.

	p := &protonDevice{tun: ptun, dev: dev}
	if err := p.configure(cfg); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("proton: device up: %w", err)
	}
	p.protect()
	return p, nil
}

func (p *protonDevice) configure(cfg protonConfig) error {
	keepalive := cfg.keepalive
	if keepalive <= 0 {
		keepalive = 25
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", cfg.privateKeyHex)
	fmt.Fprintf(&b, "public_key=%s\n", cfg.serverPubHex)
	fmt.Fprintf(&b, "endpoint=%s\n", cfg.endpoint)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	if err := p.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("proton: IpcSet: %w", err)
	}
	return nil
}

// protect marks the Proton UDP socket(s) so their packets bypass the VpnService
// TUN. Must be called after the bind is opened (device.Up) and after each
// BindUpdate (network change), because the fd changes.
func (p *protonDevice) protect() {
	type peeker interface {
		PeekLookAtSocketFd4() (int, error)
		PeekLookAtSocketFd6() (int, error)
	}
	pk, ok := p.dev.Bind().(peeker)
	if !ok {
		log.Printf("proton: bind has no fd peek; socket NOT protected (traffic will loop!)")
		return
	}
	// PeekLookAtSocketFd{4,6} dereference the bind's *net.UDPConn directly and
	// PANIC if that address family's socket isn't open. StdNetBind commonly
	// opens a single dual-stack socket (v6) and leaves v4 nil, so guard each
	// call and protect whichever socket(s) exist.
	v4 := protectPeek("v4", pk.PeekLookAtSocketFd4)
	v6 := protectPeek("v6", pk.PeekLookAtSocketFd6)
	if !v4 && !v6 {
		log.Printf("proton: WARNING no Proton socket protected; traffic may loop")
	}
}

// protectPeek calls a PeekLookAtSocketFd function, recovering if that socket
// isn't open, and protects the fd if found. Reports whether it protected one.
func protectPeek(name string, peek func() (int, error)) (protected bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("proton: %s socket not open (%v); skipping", name, r)
		}
	}()
	fd, err := peek()
	if err != nil {
		log.Printf("proton: %s peek: %v", name, err)
		return false
	}
	if fd > 0 {
		if !protectSocket(fd) {
			return false
		}
		log.Printf("proton: protected %s socket fd %d", name, fd)
		return true
	}
	return false
}

// Rebind reopens the UDP socket after a network change and re-protects it.
func (p *protonDevice) Rebind() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dev == nil {
		return
	}
	if err := p.dev.BindUpdate(); err != nil {
		log.Printf("proton: BindUpdate: %v", err)
		return
	}
	p.protect()
}

func (p *protonDevice) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dev != nil {
		p.dev.Close()
		p.dev = nil
	}
}

// waitForHandshake verifies the peer rather than treating Device.Up as a
// successful connection. Closing or replacing the device cancels the wait.
func (p *protonDevice) waitForHandshake(timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		p.mu.Lock()
		if p.dev == nil {
			p.mu.Unlock()
			return os.ErrClosed
		}
		state, err := p.dev.IpcGet()
		p.mu.Unlock()
		if err != nil {
			return fmt.Errorf("proton: read handshake status: %w", err)
		}
		// The IPC response contains private keys; only inspect the timestamp and
		// never include the response in logs or errors.
		for line := range strings.SplitSeq(state, "\n") {
			if value, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
				if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
					return nil
				}
			}
		}
		select {
		case <-p.tun.closeCh:
			return os.ErrClosed
		case <-timer.C:
			return fmt.Errorf("proton: WireGuard handshake timed out after %s", timeout)
		case <-ticker.C:
		}
	}
}
