// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package libtailscale

import (
	"crypto/x509"
	"testing"

	agent "github.com/ProtonVPN/go-vpn-lib/localAgent"
)

type agentReadinessReceiver struct {
	states []string
	errors int
}

func (r *agentReadinessReceiver) OnProtonState(state string) { r.states = append(r.states, state) }
func (r *agentReadinessReceiver) OnProtonError(int, string)  { r.errors++ }

func TestProtonAgentReadiness(t *testing.T) {
	dev, replacement := &protonDevice{}, &protonDevice{}
	r := &agentReadinessReceiver{}
	m := &protonManager{dev: dev, receiver: r}
	m.enabled.Store(true)
	cb := m.agentCallbacks(dev)
	cb.onState(agent.Constants().StateConnecting)
	cb.onState(agent.Constants().StateConnected)
	if m.ready.Load() {
		t.Fatal("agent callback changed readiness outside backend loop")
	}
	m.handleAgentEvents(nil)
	if !m.ready.Load() || len(r.states) != 2 {
		t.Fatal("authenticated readiness not applied")
	}
	cb.onState(agent.Constants().StateHardJailed)
	m.handleAgentEvents(nil)
	if m.ready.Load() {
		t.Fatal("jailed connection continued forwarding")
	}
	cb.onState(agent.Constants().StateConnected)
	m.handleAgentEvents(nil)
	if !m.ready.Load() {
		t.Fatal("agent reconnect did not restore forwarding")
	}
	// Queue a success/error, then retire the device before the backend handles it.
	cb.onState(agent.Constants().StateConnected)
	cb.onError(123, "retired error")
	m.dev, m.receiver = replacement, r
	m.ready.Store(false)
	count := len(r.states)
	m.handleAgentEvents(nil)
	cb.onState(agent.Constants().StateConnected)
	m.handleAgentEvents(nil)
	if m.ready.Load() || len(r.states) != count || r.errors != 0 {
		t.Fatal("retired agent overwrote replacement state")
	}
	newCallbacks := m.agentCallbacks(replacement)
	newCallbacks.onState(agent.Constants().StateConnected)
	m.enabled.Store(false)
	m.handleAgentEvents(nil)
	if m.ready.Load() || len(r.states) != count {
		t.Fatal("late agent success bypassed disconnect")
	}
}

func TestProtonAgentConfiguration(t *testing.T) {
	p := protonConnectParams{certPEM: "retained client certificate"}
	configureProtonAgent(&p, &connectingDomain{Domain: "node-nl-test.protonvpn.net"})
	if p.agentHost != "10.2.0.1:65432" || p.agentServerName != "node-nl-test.protonvpn.net" || p.certPEM != "retained client certificate" {
		t.Fatal("invalid authenticated agent configuration")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(p.agentCAsPEM)) {
		t.Fatal("missing pinned Proton CA certificates")
	}
}

func TestProtonAgentLateNetworkReadiness(t *testing.T) {
	dev := &protonDevice{}
	r := &agentReadinessReceiver{}
	m := &protonManager{dev: dev, receiver: r}
	m.enabled.Store(true)
	m.agentCallbacks(dev).onState(agent.Constants().StateConnected)
	m.handleAgentEvents(nil)
	oldGeneration := m.agentGeneration
	m.agentCallbacks(dev).onState(agent.Constants().StateConnecting)
	m.handleAgentEvents(nil)
	count := len(r.states)
	m.enqueueAgentEvent(protonAgentEvent{dev: dev, state: agent.Constants().StateConnected, networkReady: true, generation: oldGeneration})
	m.handleAgentEvents(nil)
	if m.ready.Load() || len(r.states) != count {
		t.Fatal("late Android validation overwrote agent reconnect")
	}
}

func TestProtonAgentWaitsForFeatureAcknowledgement(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		states := []string{}
		c := &protonNativeClient{wantAccelerator: enabled, cb: protonAgentCallbacks{onState: func(s string) { states = append(states, s) }}}
		c.OnState(agent.Constants().StateConnecting)
		c.OnState(agent.Constants().StateConnected)
		if len(states) != 1 {
			t.Fatal("published Connected before feature acknowledgement")
		}
		features := agent.NewFeatures()
		features.SetBool("split-tcp", !enabled)
		status := &agent.StatusMessage{State: "connected", Features: features}
		c.OnStatusUpdate(status)
		if len(states) != 1 {
			t.Fatal("published readiness with wrong Accelerator setting")
		}
		features.SetBool("split-tcp", enabled)
		c.OnStatusUpdate(status)
		c.OnStatusUpdate(status)
		if len(states) != 2 || states[1] != agent.Constants().StateConnected {
			t.Fatal("matching feature acknowledgement did not enable readiness exactly once")
		}
		c.OnState(agent.Constants().StateDisconnected)
		c.OnStatusUpdate(status)
		if states[len(states)-1] != agent.Constants().StateDisconnected {
			t.Fatal("late status reopened disconnected agent")
		}
	}
}

func TestProtonAgentRejectsMalformedAcknowledgement(t *testing.T) {
	if protonAgentAcceleratorConfirmed(nil, false) {
		t.Fatal("missing status confirmed disabled Accelerator")
	}
	features := agent.NewFeatures()
	if protonAgentAcceleratorConfirmed(features, false) {
		t.Fatal("missing field confirmed disabled Accelerator")
	}
	features.SetString("split-tcp", "false")
	if protonAgentAcceleratorConfirmed(features, false) {
		t.Fatal("string field confirmed boolean setting")
	}
}
