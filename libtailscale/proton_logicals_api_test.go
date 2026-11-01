// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package libtailscale

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

func TestProtonLogicalsAPISharedRequest(t *testing.T) {
	var calls atomic.Int32
	a := &protonAPI{session: protonSession{UID: "metadata-test-account", AccessToken: "metadata-test-token"}}
	a.http = &http.Client{Transport: acceleratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.Method != http.MethodGet || req.URL.Path != "/vpn/v1/logicals" || req.URL.Query().Get("WithEntriesForProtocols") != "WireGuardUDP" || req.Header.Get("Authorization") != "Bearer metadata-test-token" {
			t.Error("metadata fetch changed protocol or authentication")
		}
		return acceleratorResponse(200, `{"Code":1000,"LogicalServers":[{"ID":"test-server","ExitCountry":"NL","Features":16,"Servers":[{"EntryPerProtocol":{"WireGuardUDP":{"IPv4":"192.0.2.1","Ports":[51820]}},"X25519PublicKey":"test-server-key"}]}]}`), nil
	})}
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := a.GetLogicals()
			if err != nil || out == nil || len(out.LogicalServers) != 1 {
				t.Errorf("metadata unavailable: %v", err)
				return
			}
			s := out.LogicalServers[0]
			if s.ID != "test-server" || s.Features != 16 || s.Servers[0].entryIP() != "192.0.2.1" || s.Servers[0].port() != 51820 {
				t.Error("metadata fields lost")
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("full server list requests = %d, want 1", calls.Load())
	}
	a.mu.Lock()
	a.session.UID = "different-test-account"
	a.mu.Unlock()
	if _, err := a.GetLogicals(); err != nil || calls.Load() != 2 {
		t.Fatal("API cache was not account-scoped")
	}
}
