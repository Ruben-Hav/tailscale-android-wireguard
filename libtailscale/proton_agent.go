// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// ProtonVPN "local agent": a TLS connection the client opens *through* the
// tunnel to a Proton-controlled in-tunnel host after connecting. It reports
// connection state, surfaces certificate expiry / account "jailing" / policy
// errors, and negotiates features. We use go-vpn-lib's localAgent verbatim.
//
// The agent authenticates with the ed25519 client cert (from
// POST /vpn/v1/certificate) + the ed25519 private key PEM (proton_keys.go).
// Its TLS socket is intentionally NOT protected, so its packets to the agent
// host (a non-tailnet IP) are routed by demuxRouter into the Proton tunnel.

package libtailscale

import (
	"log"

	agent "github.com/ProtonVPN/go-vpn-lib/localAgent"
)

// protonAgentCallbacks lets the backend react to agent events without the agent
// package depending on backend internals.
type protonAgentCallbacks struct {
	onState  func(state string)
	onError  func(code int, description string)
	onStatus func(status *agent.StatusMessage)
}

// protonNativeClient adapts localAgent.NativeClient to our callbacks.
type protonNativeClient struct {
	cb protonAgentCallbacks
}

func (c *protonNativeClient) Log(text string) { log.Printf("proton-agent: %s", text) }

func (c *protonNativeClient) OnState(state string) {
	log.Printf("proton-agent: state=%s", state)
	if c.cb.onState != nil {
		c.cb.onState(state)
	}
}

func (c *protonNativeClient) OnError(code int, description string) {
	log.Printf("proton-agent: error %d: %s", code, description)
	if c.cb.onError != nil {
		c.cb.onError(code, description)
	}
}

func (c *protonNativeClient) OnStatusUpdate(status *agent.StatusMessage) {
	if c.cb.onStatus != nil {
		c.cb.onStatus(status)
	}
}

func (c *protonNativeClient) OnTlsSessionStarted() { log.Printf("proton-agent: TLS session started") }
func (c *protonNativeClient) OnTlsSessionEnded()   { log.Printf("proton-agent: TLS session ended") }

// protonAgentParams configures the local-agent connection.
type protonAgentParams struct {
	clientCertPEM  string // cert from POST /vpn/v1/certificate
	clientKeyPEM   string // ed25519 private key PEM (keys.Ed25519PrivatePEM)
	serverCAsPEM   string // Proton local-agent CA bundle
	host           string // agent host inside the tunnel, e.g. "10.2.0.1:65432"
	certServerName string // expected server certificate name
}

// protonAgent wraps a live local-agent connection.
type protonAgent struct {
	conn *agent.AgentConnection
}

func newProtonAgent(p protonAgentParams, cb protonAgentCallbacks, connectivity bool) (*protonAgent, error) {
	client := &protonNativeClient{cb: cb}
	conn, err := agent.NewAgentConnection(
		p.clientCertPEM,
		p.clientKeyPEM,
		p.serverCAsPEM,
		p.host,
		p.certServerName,
		client,
		nil,   // default features
		connectivity,
		0, 0, // default keepalive
	)
	if err != nil {
		return nil, err
	}
	return &protonAgent{conn: conn}, nil
}

func (a *protonAgent) SetConnectivity(available bool) {
	if a != nil && a.conn != nil {
		a.conn.SetConnectivity(available)
	}
}

func (a *protonAgent) Close() {
	if a != nil && a.conn != nil {
		a.conn.Close()
	}
}
