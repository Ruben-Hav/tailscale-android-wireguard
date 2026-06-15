// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Bridge between the Kotlin control plane and the Go data plane for ProtonVPN.
//
// The Kotlin side handles login (protoncore, incl. 2FA/human-verification), the
// authenticated Proton REST API (account/tier, /vpn/v1/logicals server list,
// POST /vpn/v1/certificate), and country/server selection. It then drives the
// Go data plane through the exported functions below:
//
//   1. ProtonGenerateKey()  -> Go makes an ed25519 keypair, returns the PKIX
//      base64 public key. Kotlin sends it as ClientPublicKey to the cert API.
//   2. (Kotlin requests the cert and picks a server.)
//   3. ProtonConnect(...)   -> Go builds the Proton wireguard-go device + local
//      agent and installs the split-tunnel demux.
//   4. ProtonDisconnect()   -> Go tears it all down.
//
// Connection lifecycle work runs on the existing runBackend select loop (see
// backend.go) so it is serialized with updateTUN and never races it.

package libtailscale

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	agent "github.com/ProtonVPN/go-vpn-lib/localAgent"
	"github.com/gaissmai/bart"
)

// ProtonStatusReceiver is implemented in Kotlin to receive Proton connection
// state changes and errors (for the UI status line).
type ProtonStatusReceiver interface {
	OnProtonState(state string)
	OnProtonError(code int, description string)
}

// default routes used to capture all traffic into the TUN when Proton is on.
var (
	defaultRoute4 = netip.MustParsePrefix("0.0.0.0/0")
	defaultRoute6 = netip.MustParsePrefix("::/0")
)

// tailscaleRanges always route to Tailscale (the tailnet CGNAT v4 range and the
// Tailscale ULA), independent of which peer routes are currently present.
var tailscaleRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
}

// protonExcludedPrefixes are kept OFF the Proton tunnel and stay on the local
// network: RFC1918 private ranges, link-local, and multicast. Without this, LAN
// traffic gets captured by the 0/0 route and black-holed through Proton.
// NOTE: a Tailscale subnet route overlapping these ranges still wins, because
// the demux checks the tailnet table first; but such traffic is also excluded
// from the TUN here, so subnet routes into RFC1918 are a known limitation.
var protonExcludedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"), // v4 link-local
	netip.MustParsePrefix("224.0.0.0/4"),    // v4 multicast
	netip.MustParsePrefix("fe80::/10"),      // v6 link-local
	netip.MustParsePrefix("ff00::/8"),       // v6 multicast
}

// protonManager holds all ProtonVPN data-plane state. Single global instance.
type protonManager struct {
	mu       sync.Mutex
	keys     *protonKeys
	receiver ProtonStatusReceiver

	enabled atomic.Bool // demux installed + default route captured
	ready   atomic.Bool // forward non-tailnet to Proton (false = fail-closed drop)

	tun   *protonTUN    // persistent across reconfigures
	dev   *protonDevice // current data-plane device
	agent *protonAgent  // current local-agent connection
	cfg   protonConfig

	// Proton-assigned client tunnel addresses (from the .conf [Interface]
	// Address), used to SNAT outbound traffic into the Proton tunnel.
	protonV4, protonV6 netip.Addr

	// tailnetTable holds the current tailnet prefixes for the demux; curDemux
	// is the live demux so its table can be updated in place on reconfigure.
	tailnetTable atomic.Pointer[bart.Lite]
	curDemux     atomic.Pointer[demuxRouter]
}

var protonMgr = &protonManager{}

// protonConnectParams carries everything ProtonConnect needs to bring up a tunnel.
type protonConnectParams struct {
	serverPublicKeyBase64 string
	endpoint              string // "ip:port"
	certPEM               string // from POST /vpn/v1/certificate
	agentHost             string // local-agent host inside the tunnel
	agentCAsPEM           string // local-agent CA bundle
	agentServerName       string // local-agent TLS server name
	keepalive             int

	// manualPrivateKeyB64, when set, is a raw WireGuard private key (base64) used
	// instead of the dynamically generated key. Set by ProtonConnectManual for
	// testing the data plane from a downloaded .conf; no cert/agent is started.
	manualPrivateKeyB64 string

	// clientAddresses is the .conf [Interface] Address value, e.g.
	// "10.2.0.2/32" or "10.2.0.2/32,fd00::2/128". Used to SNAT into the tunnel.
	clientAddresses string
}

// parseClientAddrs extracts the first IPv4 and IPv6 client addresses from a
// WireGuard [Interface] Address value (comma-separated prefixes or addrs).
func parseClientAddrs(s string) (v4, v6 netip.Addr) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.IndexByte(part, '/'); i >= 0 {
			part = part[:i]
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			continue
		}
		if a.Is4() && !v4.IsValid() {
			v4 = a
		} else if a.Is6() && !v6.IsValid() {
			v6 = a
		}
	}
	return v4, v6
}

type protonConnectRequest struct {
	params protonConnectParams
	reply  chan error
}

var (
	onProtonConnect    = make(chan protonConnectRequest)
	onProtonDisconnect = make(chan struct{}, 1)
	onProtonReceiver   = make(chan ProtonStatusReceiver, 1)
)

// --- Exported gomobile bridge functions (callable from Kotlin) ---

// ProtonGenerateKey generates an ephemeral ed25519 keypair and returns its PKIX
// base64 public key for the certificate request.
func ProtonGenerateKey() (string, error) {
	keys, err := newProtonKeys()
	if err != nil {
		return "", err
	}
	pub, err := keys.PublicKeyPKIXBase64()
	if err != nil {
		return "", err
	}
	protonMgr.mu.Lock()
	protonMgr.keys = keys
	protonMgr.mu.Unlock()
	return pub, nil
}

// ProtonConnect brings up the ProtonVPN tunnel to the given server and starts
// the local agent. Blocks until the data-plane device is up (or errors).
func ProtonConnect(serverPublicKeyBase64, endpoint, certPEM, agentHost, agentCAsPEM, agentServerName string, keepalive int) error {
	req := protonConnectRequest{
		params: protonConnectParams{
			serverPublicKeyBase64: serverPublicKeyBase64,
			endpoint:              endpoint,
			certPEM:               certPEM,
			agentHost:             agentHost,
			agentCAsPEM:           agentCAsPEM,
			agentServerName:       agentServerName,
			keepalive:             keepalive,
		},
		reply: make(chan error, 1),
	}
	onProtonConnect <- req
	return <-req.reply
}

// ProtonConnectManual brings up the Proton tunnel from raw WireGuard parameters
// (e.g. a ProtonVPN .conf downloaded from the account dashboard), bypassing
// login/certificate/local-agent. Intended for validating the split-tunnel data
// plane on-device. privateKeyBase64 and serverPublicKeyBase64 are standard
// WireGuard base64 keys; endpoint is "ip:port".
func ProtonConnectManual(privateKeyBase64, serverPublicKeyBase64, endpoint, clientAddresses string) error {
	req := protonConnectRequest{
		params: protonConnectParams{
			serverPublicKeyBase64: serverPublicKeyBase64,
			endpoint:              endpoint,
			manualPrivateKeyB64:   privateKeyBase64,
			clientAddresses:       clientAddresses,
		},
		reply: make(chan error, 1),
	}
	onProtonConnect <- req
	return <-req.reply
}

// ProtonDisconnect tears down the ProtonVPN tunnel; non-tailnet traffic returns
// to the device's normal internet path.
func ProtonDisconnect() {
	select {
	case onProtonDisconnect <- struct{}{}:
	default:
	}
}

// SetProtonStatusReceiver registers the Kotlin callback for state/error events.
func SetProtonStatusReceiver(r ProtonStatusReceiver) {
	select {
	case onProtonReceiver <- r:
	default:
		<-onProtonReceiver
		onProtonReceiver <- r
	}
}

// --- Backend-side lifecycle (run on the runBackend select loop) ---

func (b *backend) protonConnect(p protonConnectParams) (err error) {
	// A ProtonVPN failure must never crash the Tailscale backend (this runs on
	// the runBackend loop). Convert any panic into an error.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("proton: connect panicked: %v\n%s", r, debug.Stack())
			protonMgr.enabled.Store(false)
			protonMgr.ready.Store(false)
			err = fmt.Errorf("proton: internal error: %v", r)
		}
	}()

	manual := p.manualPrivateKeyB64 != ""
	log.Printf("proton: protonConnect(manual=%v, endpoint=%s)", manual, p.endpoint)

	protonMgr.mu.Lock()
	keys := protonMgr.keys
	protonMgr.mu.Unlock()

	var privHex string
	if manual {
		h, err := wgKeyB64ToHex(p.manualPrivateKeyB64)
		if err != nil {
			return err
		}
		privHex = h
	} else {
		if keys == nil {
			return errors.New("proton: no key generated; call ProtonGenerateKey first")
		}
		privHex = keys.X25519PrivateHex()
	}

	// Record the Proton client addresses for SNAT before refreshTUN (updateTUN
	// builds the NAT mapping). Touched only on the runBackend loop.
	protonMgr.protonV4, protonMgr.protonV6 = parseClientAddrs(p.clientAddresses)
	log.Printf("proton: client addrs v4=%v v6=%v", protonMgr.protonV4, protonMgr.protonV6)

	serverHex, err := serverPublicHexFromBase64(p.serverPublicKeyBase64)
	if err != nil {
		return err
	}
	cfg := protonConfig{
		privateKeyHex: privHex,
		serverPubHex:  serverHex,
		endpoint:      p.endpoint,
		keepalive:     p.keepalive,
	}

	// Idempotency guard: if we're already up on exactly this config, don't tear
	// down and rebuild (that churn unprotects the socket and breaks traffic).
	protonMgr.mu.Lock()
	alreadyUp := protonMgr.dev != nil && protonMgr.cfg == cfg
	protonMgr.mu.Unlock()
	if alreadyUp {
		log.Printf("proton: already connected to this config; ignoring duplicate connect")
		protonMgr.ready.Store(true)
		protonMgr.notifyState("Connected")
		return nil
	}

	// Tear down any previous device/agent (reuse the persistent TUN).
	protonMgr.teardownDevice()
	if protonMgr.tun == nil {
		protonMgr.tun = newProtonTUN(defaultMTU)
	}

	protonMgr.enabled.Store(true)
	protonMgr.ready.Store(false)

	dev, err := newProtonDevice(protonMgr.tun, cfg)
	if err != nil {
		protonMgr.enabled.Store(false)
		return err
	}
	protonMgr.mu.Lock()
	protonMgr.dev = dev
	protonMgr.cfg = cfg
	protonMgr.mu.Unlock()

	// Re-run updateTUN to install the demux and capture the default route.
	b.refreshTUN()

	// Data-plane up == ready. If we start the local agent, it will flip the
	// state to Connected once its in-tunnel TLS session is up; otherwise (manual
	// connect, or dynamic connect without an agent host) report Connected now.
	willStartAgent := !manual && p.certPEM != "" && p.agentHost != ""
	protonMgr.ready.Store(true)
	if willStartAgent {
		protonMgr.notifyState("Connecting")
	} else {
		protonMgr.notifyState("Connected")
	}

	// Start the in-tunnel local agent (v1 scope) when an agent host is provided.
	if willStartAgent {
		ag, aerr := newProtonAgent(protonAgentParams{
			clientCertPEM:  p.certPEM,
			clientKeyPEM:   keys.Ed25519PrivatePEM(),
			serverCAsPEM:   p.agentCAsPEM,
			host:           p.agentHost,
			certServerName: p.agentServerName,
		}, protonMgr.agentCallbacks(), true)
		if aerr != nil {
			log.Printf("proton: local agent start failed: %v", aerr)
		} else {
			protonMgr.mu.Lock()
			protonMgr.agent = ag
			protonMgr.mu.Unlock()
		}
	}
	return nil
}

// currentDevice and currentAgent return the live device/agent under lock, for
// access from other goroutines (e.g. NetworkChanged).
func (m *protonManager) currentDevice() *protonDevice {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dev
}

func (m *protonManager) currentAgent() *protonAgent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.agent
}

func (b *backend) protonDisconnect() {
	protonMgr.enabled.Store(false)
	protonMgr.ready.Store(false)
	protonMgr.teardownDevice()
	// Re-run updateTUN to drop the demux + default route (back to tailnet-only).
	b.refreshTUN()
	protonMgr.notifyState("Disconnected")
}

// refreshTUN re-applies the last router/DNS config so updateTUN picks up the
// new Proton enabled/disabled state (installing or removing the demux and the
// captured default route).
func (b *backend) refreshTUN() {
	if b.lastCfg == nil || vpnService.service == nil {
		return
	}
	if err := b.updateTUN(b.lastCfg, b.lastDNSCfg); err != nil {
		log.Printf("proton: refreshTUN failed: %v", err)
	}
}

// teardownDevice closes the current agent + device but keeps the persistent TUN.
func (m *protonManager) teardownDevice() {
	m.mu.Lock()
	ag, dev := m.agent, m.dev
	m.agent, m.dev = nil, nil
	m.mu.Unlock()
	if ag != nil {
		ag.Close()
	}
	if dev != nil {
		dev.Close()
	}
}

// agentCallbacks maps local-agent events to readiness + UI notifications.
func (m *protonManager) agentCallbacks() protonAgentCallbacks {
	c := agent.Constants()
	return protonAgentCallbacks{
		onState: func(state string) {
			switch state {
			case c.StateClientCertificateExpiredError,
				c.StateClientCertificateUnknownCA,
				c.StateServerCertificateError,
				c.StateHardJailed:
				// Fatal: fail closed until Kotlin reconnects with a fresh cert.
				m.ready.Store(false)
			}
			m.notifyState(state)
		},
		onError: func(code int, desc string) {
			m.notifyError(code, desc)
		},
	}
}

func (m *protonManager) notifyState(state string) {
	m.mu.Lock()
	r := m.receiver
	m.mu.Unlock()
	if r != nil {
		r.OnProtonState(state)
	}
}

func (m *protonManager) notifyError(code int, desc string) {
	m.mu.Lock()
	r := m.receiver
	m.mu.Unlock()
	if r != nil {
		r.OnProtonError(code, desc)
	}
}

// buildTailnetTable builds the demux's "route via Tailscale" set from the
// router config's routes, skipping any default route.
func buildTailnetTable(routes []netip.Prefix) *bart.Lite {
	t := &bart.Lite{}
	// Always route the whole Tailscale range to Tailscale, so tailnet peer
	// traffic goes to the engine even if a specific peer route isn't present.
	for _, p := range tailscaleRanges {
		t.Insert(p)
	}
	for _, p := range routes {
		if p.Bits() == 0 {
			continue // skip 0.0.0.0/0 and ::/0
		}
		t.Insert(p)
	}
	return t
}
