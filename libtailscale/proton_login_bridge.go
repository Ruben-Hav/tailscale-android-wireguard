// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// gomobile bridge for the dynamic ProtonVPN control plane (login + country
// selection). These run network I/O and must be called from a background thread
// on the Kotlin side. The final tunnel bring-up is routed through the existing
// runBackend loop (onProtonConnect) so it's serialized with updateTUN.

package libtailscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
)

var protonAPIClient = newProtonAPI()

// ProtonLogin logs in with username+password. Returns a status string:
//   "ok"  - logged in
//   "2fa" - call ProtonSubmit2FA next
//   "hv"  - human verification needed: load the CAPTCHA WebView using
//           ProtonHVStartToken()/ProtonHVMethods(), then call
//           ProtonSetHumanVerification() and retry ProtonLogin.
func ProtonLogin(username, password string) (string, error) {
	status, err := protonAPIClient.Login(username, password)
	if err != nil {
		return "", err
	}
	if status == loginOK {
		fetchTier()
	}
	return status, nil
}

// ProtonHVStartToken / ProtonHVMethods return the WebView parameters for a
// pending human-verification challenge.
func ProtonHVStartToken() string {
	t, _ := protonAPIClient.HVParams()
	return t
}

func ProtonHVMethods() string {
	_, m := protonAPIClient.HVParams()
	return m
}

// ProtonSetHumanVerification records the solved CAPTCHA token before retrying.
func ProtonSetHumanVerification(token, tokenType string) {
	protonAPIClient.SetHumanVerification(token, tokenType)
}

// ProtonSubmit2FA completes a 2FA login with a TOTP code.
func ProtonSubmit2FA(code string) error {
	if err := protonAPIClient.Submit2FA(code); err != nil {
		return err
	}
	fetchTier()
	return nil
}

// ProtonLogout revokes the Proton session (does not disconnect the tunnel).
func ProtonLogout() error { return protonAPIClient.Logout() }

// ProtonIsLoggedIn reports whether a Proton session is active.
func ProtonIsLoggedIn() bool { return protonAPIClient.loggedIn() }

func fetchTier() {
	if info, err := protonAPIClient.GetVPNInfo(); err == nil {
		protonAPIClient.mu.Lock()
		protonAPIClient.maxTier = info.VPN.MaxTier
		protonAPIClient.mu.Unlock()
	}
}

// countryInfo is the per-country summary returned to the UI as JSON.
type countryInfo struct {
	Code    string `json:"code"`
	MinTier int    `json:"minTier"`
	Count   int    `json:"count"`
}

// ProtonListCountries fetches the server list and returns a JSON array of the
// available exit countries (code, lowest tier, server count), sorted by code.
func ProtonListCountries() (string, error) {
	logicals, err := protonAPIClient.GetLogicals()
	if err != nil {
		return "", err
	}
	byCC := map[string]*countryInfo{}
	for i := range logicals.LogicalServers {
		ls := &logicals.LogicalServers[i]
		if ls.Status != 1 || ls.ExitCountry == "" {
			continue
		}
		ci := byCC[ls.ExitCountry]
		if ci == nil {
			ci = &countryInfo{Code: ls.ExitCountry, MinTier: ls.Tier}
			byCC[ls.ExitCountry] = ci
		}
		ci.Count++
		if ls.Tier < ci.MinTier {
			ci.MinTier = ls.Tier
		}
	}
	out := make([]countryInfo, 0, len(byCC))
	for _, ci := range byCC {
		out = append(out, *ci)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ProtonConnectCountry picks the best server in countryCode, registers a fresh
// WireGuard key with Proton, and brings up the tunnel via the data plane.
func ProtonConnectCountry(countryCode string) error {
	if !protonAPIClient.loggedIn() {
		return errors.New("proton: not logged in")
	}
	logicals, err := protonAPIClient.GetLogicals()
	if err != nil {
		return err
	}
	protonAPIClient.mu.Lock()
	maxTier := protonAPIClient.maxTier
	protonAPIClient.mu.Unlock()

	ls, dom := pickServer(logicals, countryCode, maxTier)
	if dom == nil {
		return fmt.Errorf("proton: no available server in %s", countryCode)
	}

	// Generate a fresh key and certify it (this registers the public key so the
	// derived WireGuard key is accepted by the server).
	pub, err := ProtonGenerateKey()
	if err != nil {
		return err
	}
	cert, err := protonAPIClient.GetCertificate(pub)
	if err != nil {
		return err
	}

	entryIP := dom.entryIP()
	if entryIP == "" {
		return fmt.Errorf("proton: server %s has no entry IP", ls.Name)
	}
	endpoint := fmt.Sprintf("%s:%d", entryIP, dom.port())

	req := protonConnectRequest{
		params: protonConnectParams{
			serverPublicKeyBase64: dom.X25519PublicKey,
			endpoint:              endpoint,
			certPEM:               cert.Certificate,
			clientAddresses:       "10.2.0.2/32", // Proton's fixed WireGuard client address
		},
		reply: make(chan error, 1),
	}
	onProtonConnect <- req
	return <-req.reply
}

// pickServer chooses the lowest-score enabled logical server in the country
// within the user's tier, plus an online physical server within it.
func pickServer(logicals *logicalsResp, countryCode string, maxTier int) (*logicalServer, *connectingDomain) {
	var best *logicalServer
	bestScore := math.MaxFloat64
	for i := range logicals.LogicalServers {
		ls := &logicals.LogicalServers[i]
		if ls.Status != 1 || ls.ExitCountry != countryCode || ls.Tier > maxTier {
			continue
		}
		if ls.Score < bestScore {
			bestScore = ls.Score
			best = ls
		}
	}
	if best == nil {
		return nil, nil
	}
	for i := range best.Servers {
		d := &best.Servers[i]
		if d.Status == 1 && d.X25519PublicKey != "" {
			return best, d
		}
	}
	return best, nil
}
