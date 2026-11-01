// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package libtailscale

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type acceleratorTestContext struct {
	AppContext
	prefs    map[string]string
	writeErr error
}

func (c *acceleratorTestContext) EncryptToPref(key, value string) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	c.prefs[key] = value
	return nil
}

func (c *acceleratorTestContext) DecryptFromPref(key string) (string, error) {
	return c.prefs[key], nil
}

func TestProtonAcceleratorPreference(t *testing.T) {
	a := &protonAPI{}
	if !a.acceleratorEnabled() {
		t.Fatal("Accelerator must default on before settings are available")
	}
	if err := a.setAcceleratorEnabled(false); err == nil {
		t.Fatal("saving without a preference store succeeded")
	}
	store := &acceleratorTestContext{prefs: map[string]string{}}
	a.setPersistence(store)
	if !a.acceleratorEnabled() {
		t.Fatal("new installations must default on")
	}
	if err := a.setAcceleratorEnabled(false); err != nil {
		t.Fatal(err)
	}
	// A new client must read the saved choice, rather than reset it on restart.
	restarted := &protonAPI{persist: store}
	if restarted.acceleratorEnabled() {
		t.Fatal("disabled setting did not survive a client restart")
	}
	if err := restarted.setAcceleratorEnabled(true); err != nil {
		t.Fatal(err)
	}
	store.writeErr = errors.New("test storage failure")
	if err := restarted.setAcceleratorEnabled(false); !errors.Is(err, store.writeErr) {
		t.Fatalf("save error = %v", err)
	}
	if !a.acceleratorEnabled() {
		t.Fatal("failed save changed the effective setting")
	}
}

type acceleratorRoundTripper func(*http.Request) (*http.Response, error)

func (f acceleratorRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func acceleratorResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func assertAcceleratorRequest(t *testing.T, req *http.Request, enabled bool) {
	t.Helper()
	if req.Method != http.MethodPost || req.URL.Path != "/vpn/v1/certificate" {
		t.Fatalf("unexpected certificate request: %s %s", req.Method, req.URL.Path)
	}
	var body struct {
		ClientPublicKey     string
		ClientPublicKeyMode string
		Mode                string
		Duration            string
		Features            map[string]any
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.ClientPublicKey != "test-public-key" || body.ClientPublicKeyMode != "EC" || body.Mode != "session" || body.Duration != "1440 min" {
		t.Fatal("Accelerator changed the existing certificate registration contract")
	}
	value, exists := body.Features["SplitTCP"]
	if !exists || value != enabled {
		t.Fatalf("SplitTCP = %v (present=%v), want explicit boolean %v", value, exists, enabled)
	}
	if len(body.Features) != 1 {
		t.Fatal("request changed unrelated server-side feature settings")
	}
}

func TestProtonAcceleratorCertificateFeatures(t *testing.T) {
	for _, tc := range []struct {
		name, saved string
		enabled     bool
	}{{"default", "", true}, {"enabled", "true", true}, {"disabled", "false", false}} {
		t.Run(tc.name, func(t *testing.T) {
			a := &protonAPI{
				persist: &acceleratorTestContext{prefs: map[string]string{protonAcceleratorPrefKey: tc.saved}},
				session: protonSession{UID: "test-uid", AccessToken: "test-token"},
			}
			a.http = &http.Client{Transport: acceleratorRoundTripper(func(req *http.Request) (*http.Response, error) {
				assertAcceleratorRequest(t, req, tc.enabled)
				if req.Header.Get("Authorization") != "Bearer test-token" || req.Header.Get("x-pm-uid") != "test-uid" {
					t.Fatal("certificate request lost authentication")
				}
				return acceleratorResponse(200, `{"Code":1000,"Certificate":"test-certificate","ExpirationTime":123}`), nil
			})}
			cert, err := a.GetCertificate("test-public-key")
			if err != nil || cert.Certificate != "test-certificate" || cert.ExpirationTime != 123 {
				t.Fatalf("certificate response was not preserved: err=%v", err)
			}
		})
	}
}

func TestProtonAcceleratorCertificateRefresh(t *testing.T) {
	a := &protonAPI{
		persist: &acceleratorTestContext{prefs: map[string]string{protonAcceleratorPrefKey: "false"}},
		session: protonSession{UID: "test-uid", AccessToken: "old-token", RefreshToken: "test-refresh"},
	}
	attempts, refreshes := 0, 0
	a.http = &http.Client{Transport: acceleratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/auth/v4/refresh" {
			refreshes++
			return acceleratorResponse(200, `{"Code":1000,"UID":"test-uid","AccessToken":"new-token"}`), nil
		}
		attempts++
		assertAcceleratorRequest(t, req, false)
		if attempts == 1 {
			return acceleratorResponse(401, `{"Code":401,"Error":"expired"}`), nil
		}
		if req.Header.Get("Authorization") != "Bearer new-token" {
			t.Fatal("retry did not use the refreshed token")
		}
		return acceleratorResponse(200, `{"Code":1000,"Certificate":"test-certificate"}`), nil
	})}
	if _, err := a.GetCertificate("test-public-key"); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || refreshes != 1 {
		t.Fatalf("certificate attempts=%d, token refreshes=%d", attempts, refreshes)
	}
}

func TestProtonAcceleratorCertificateError(t *testing.T) {
	a := &protonAPI{http: &http.Client{Transport: acceleratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		return acceleratorResponse(400, `{"Code":5003,"Error":"test rejection"}`), nil
	})}}
	if cert, err := a.GetCertificate("test-public-key"); err == nil || cert != nil {
		t.Fatal("server rejection was treated as successful feature negotiation")
	}
}
