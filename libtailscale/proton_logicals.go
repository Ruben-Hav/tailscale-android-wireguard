// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"sync"
	"time"
)

// These snapshots are immutable after decoding. Country/server views and
// selection routines may retain pointers, but must not modify their contents.
type logicalsResp struct {
	LogicalServers []logicalServer `json:"LogicalServers"`
}

type logicalServer struct {
	ID          string             `json:"ID"`
	Name        string             `json:"Name"`
	ExitCountry string             `json:"ExitCountry"`
	City        string             `json:"City"`
	Tier        int                `json:"Tier"`
	Features    int                `json:"Features"`
	Load        int                `json:"Load"`
	Score       float64            `json:"Score"`
	Status      int                `json:"Status"`
	Servers     []connectingDomain `json:"Servers"`
}

type connectingDomain struct {
	EntryIP          string                     `json:"EntryIP"`
	EntryPerProtocol map[string]serverEntryInfo `json:"EntryPerProtocol"`
	Domain           string                     `json:"Domain"`
	ID               string                     `json:"ID"`
	Label            string                     `json:"Label"`
	Status           int                        `json:"Status"`
	X25519PublicKey  string                     `json:"X25519PublicKey"`
}

type serverEntryInfo struct {
	IPv4  string `json:"IPv4"`
	Ports []int  `json:"Ports"`
}

func (d *connectingDomain) entryIP() string {
	if e, ok := d.EntryPerProtocol["WireGuardUDP"]; ok && e.IPv4 != "" {
		return e.IPv4
	}
	return d.EntryIP
}

func (d *connectingDomain) port() int {
	if e, ok := d.EntryPerProtocol["WireGuardUDP"]; ok && len(e.Ports) > 0 {
		return e.Ports[0]
	}
	return 51820
}

const protonLogicalsTTL = 5 * time.Minute

type protonLogicalsFlight struct {
	done chan struct{}
	data *logicalsResp
	err  error
}

// protonLogicalsCache shares one bounded-freshness server snapshot and one
// in-flight request among country lists, server lists and connection actions.
// It is memory-only and account-scoped; errors and expired data are not reused.
type protonLogicalsCache struct {
	mu      sync.Mutex
	scope   string
	data    *logicalsResp
	expires time.Time
	flight  *protonLogicalsFlight
	now     func() time.Time // nil uses time.Now; deterministic expiry tests only
}

func (c *protonLogicalsCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *protonLogicalsCache) invalidate() {
	c.mu.Lock()
	c.data, c.flight = nil, nil
	c.mu.Unlock()
}

func (c *protonLogicalsCache) get(scope string, fetch func() (*logicalsResp, error)) (*logicalsResp, error) {
	c.mu.Lock()
	if c.scope != scope {
		c.scope, c.data, c.flight = scope, nil, nil
	}
	if c.data != nil && c.clock().Before(c.expires) {
		data := c.data
		c.mu.Unlock()
		return data, nil
	}
	if f := c.flight; f != nil {
		c.mu.Unlock()
		<-f.done
		return f.data, f.err
	}
	f := &protonLogicalsFlight{done: make(chan struct{})}
	c.flight = f
	c.mu.Unlock()

	f.data, f.err = fetch()
	c.mu.Lock()
	// A logout/account change can retire this fetch while it is in flight.
	// Its original callers still complete; it cannot refill the new cache.
	if c.flight == f {
		c.flight = nil
		if f.err == nil && f.data != nil {
			c.data, c.expires = f.data, c.clock().Add(protonLogicalsTTL)
		}
	}
	close(f.done)
	c.mu.Unlock()
	return f.data, f.err
}
