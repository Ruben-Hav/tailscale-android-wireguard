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
	"log"
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
		protonAPIClient.saveSession()
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
	protonAPIClient.saveSession()
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

// ProtonConnectCountry auto-picks the fastest server in countryCode and connects.
func ProtonConnectCountry(countryCode string) error {
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return err
	}
	ls, dom := pickServer(logicals, countryCode, maxTier)
	if dom == nil {
		return fmt.Errorf("proton: no available server in %s", countryCode)
	}
	return connectToLogical(ls, dom)
}

// ProtonConnectServer connects to a specific logical server (by its ID, as
// returned by ProtonListServers), letting the user override the auto-pick.
func ProtonConnectServer(logicalID string) error {
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return err
	}
	var ls *logicalServer
	for i := range logicals.LogicalServers {
		if logicals.LogicalServers[i].ID == logicalID {
			ls = &logicals.LogicalServers[i]
			break
		}
	}
	if ls == nil {
		return fmt.Errorf("proton: server %s not found", logicalID)
	}
	if ls.Tier > maxTier {
		return errors.New("proton: that server needs a higher plan")
	}
	dom := pickDomain(ls)
	if dom == nil {
		return fmt.Errorf("proton: server %s is offline", ls.Name)
	}
	return connectToLogical(ls, dom)
}

// ProtonFastestOverall connects to the fastest server across all countries
// (the "Fastest overall" action). No-op if already on it.
func ProtonFastestOverall() error {
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return err
	}
	curLogicalID, _ := protonMgr.currentConn()
	ls, dom := pickBest(logicals, maxTier, func(l *logicalServer) bool {
		return l.ExitCountry != ""
	})
	if dom == nil {
		return errors.New("proton: no server available")
	}
	if ls.ID == curLogicalID {
		log.Printf("proton: already on the fastest server overall (%s)", ls.Name)
		protonMgr.notifyState("Connected")
		return nil
	}
	log.Printf("proton: fastest-overall -> %s (%s)", ls.ExitCountry, ls.Name)
	return connectToLogical(ls, dom)
}

// ProtonFastestInCountry connects to the fastest server within the country you
// are currently connected to (the "Fastest in country" action; also the QS
// tile). No-op if already on it.
func ProtonFastestInCountry() error {
	curLogicalID, curCountry := protonMgr.currentConn()
	if curCountry == "" {
		return errors.New("proton: not connected")
	}
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return err
	}
	ls, dom := pickBest(logicals, maxTier, func(l *logicalServer) bool {
		return l.ExitCountry == curCountry
	})
	if dom == nil {
		return fmt.Errorf("proton: no server available in %s", curCountry)
	}
	if ls.ID == curLogicalID {
		log.Printf("proton: already on the fastest server in %s (%s)", curCountry, ls.Name)
		protonMgr.notifyState("Connected")
		return nil
	}
	log.Printf("proton: fastest-in-country %s -> %s", curCountry, ls.Name)
	return connectToLogical(ls, dom)
}

// ProtonConnectFresh connects Proton to the fastest server, preferring one that
// isn't the server we were last on (a fresh IP each time the Exit-node tile is
// toggled on). It stays within the armed auto-connect country if one is set,
// otherwise picks the fastest server anywhere.
func ProtonConnectFresh() error {
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return err
	}
	country := ProtonGetAutoConnectCountry()
	last := protonMgr.lastConnLogicalID()
	inScope := func(l *logicalServer) bool {
		if country != "" {
			return l.ExitCountry == country
		}
		return l.ExitCountry != ""
	}
	// First try to land on a different server than last time.
	ls, dom := pickBest(logicals, maxTier, func(l *logicalServer) bool {
		return l.ID != last && inScope(l)
	})
	if dom == nil {
		// Only the previous server qualifies (or it's the sole option) — allow it.
		ls, dom = pickBest(logicals, maxTier, inScope)
	}
	if dom == nil {
		if country != "" {
			return fmt.Errorf("proton: no available server in %s", country)
		}
		return errors.New("proton: no server available")
	}
	log.Printf("proton: exit-node connect -> %s (%s)", ls.ExitCountry, ls.Name)
	return connectToLogical(ls, dom)
}

// ProtonCurrentServer returns the connected server as JSON {name, country, load}
// ("{}" when not connected), for the UI's connected-server status line.
func ProtonCurrentServer() string {
	name, country, load := protonMgr.currentServerInfo()
	if name == "" {
		return "{}"
	}
	b, err := json.Marshal(map[string]any{"name": name, "country": country, "load": load})
	if err != nil {
		return "{}"
	}
	return string(b)
}

// serverInfo is the per-server summary returned to the UI as JSON.
type serverInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	City string `json:"city"`
	Load int    `json:"load"`
	Tier int    `json:"tier"`
}

// ProtonListServers returns a JSON array of the individual servers in
// countryCode (within the user's tier), sorted fastest-first by Score.
func ProtonListServers(countryCode string) (string, error) {
	logicals, maxTier, err := protonLogicals()
	if err != nil {
		return "", err
	}
	var picked []*logicalServer
	for i := range logicals.LogicalServers {
		ls := &logicals.LogicalServers[i]
		if ls.Status != 1 || ls.ExitCountry != countryCode || ls.Tier > maxTier {
			continue
		}
		picked = append(picked, ls)
	}
	sort.Slice(picked, func(i, j int) bool {
		if picked[i].Score != picked[j].Score {
			return picked[i].Score < picked[j].Score
		}
		return picked[i].Name < picked[j].Name
	})
	out := make([]serverInfo, 0, len(picked))
	for _, ls := range picked {
		out = append(out, serverInfo{ID: ls.ID, Name: ls.Name, City: ls.City, Load: ls.Load, Tier: ls.Tier})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// protonLogicals fetches the logicals and the user's max tier, requiring login.
func protonLogicals() (*logicalsResp, int, error) {
	if !protonAPIClient.loggedIn() {
		return nil, 0, errors.New("proton: not logged in")
	}
	logicals, err := protonAPIClient.GetLogicals()
	if err != nil {
		return nil, 0, err
	}
	protonAPIClient.mu.Lock()
	maxTier := protonAPIClient.maxTier
	protonAPIClient.mu.Unlock()
	return logicals, maxTier, nil
}

// connectToLogical registers a fresh key and brings up the tunnel to ls/dom.
func connectToLogical(ls *logicalServer, dom *connectingDomain) error {
	// Generate a fresh key and certify it (registers the public key so the
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
	req := protonConnectRequest{
		params: protonConnectParams{
			serverPublicKeyBase64: dom.X25519PublicKey,
			endpoint:              fmt.Sprintf("%s:%d", entryIP, dom.port()),
			certPEM:               cert.Certificate,
			clientAddresses:       "10.2.0.2/32", // Proton's fixed WireGuard client address
			logicalID:             ls.ID,
			country:               ls.ExitCountry,
			serverName:            ls.Name,
			serverLoad:            ls.Load,
		},
		reply: make(chan error, 1),
	}
	onProtonConnect <- req
	return <-req.reply
}

// pickDomain returns the first online physical server (with a WG pubkey) in ls.
func pickDomain(ls *logicalServer) *connectingDomain {
	for i := range ls.Servers {
		d := &ls.Servers[i]
		if d.Status == 1 && d.X25519PublicKey != "" {
			return d
		}
	}
	return nil
}

// pickBest selects the fastest accepted enabled logical within maxTier (lowest
// Score, ties to lower Load) plus an online physical server in it.
func pickBest(logicals *logicalsResp, maxTier int, accept func(*logicalServer) bool) (*logicalServer, *connectingDomain) {
	var best *logicalServer
	bestScore := math.MaxFloat64
	bestLoad := math.MaxInt
	for i := range logicals.LogicalServers {
		ls := &logicals.LogicalServers[i]
		if ls.Status != 1 || ls.Tier > maxTier || !accept(ls) {
			continue
		}
		if ls.Score < bestScore || (ls.Score == bestScore && ls.Load < bestLoad) {
			bestScore = ls.Score
			bestLoad = ls.Load
			best = ls
		}
	}
	if best == nil {
		return nil, nil
	}
	return best, pickDomain(best)
}

// pickServer auto-selects the fastest enabled logical in countryCode (Proton's
// Score is the load-balancing metric, lower = faster/least-loaded, the same
// signal Proton's own "fastest" picker uses); the per-region auto-pick.
func pickServer(logicals *logicalsResp, countryCode string, maxTier int) (*logicalServer, *connectingDomain) {
	ls, dom := pickBest(logicals, maxTier, func(l *logicalServer) bool {
		return l.ExitCountry == countryCode
	})
	if ls != nil {
		log.Printf("proton: auto-picked %s in %s (score=%.2f load=%d tier=%d)",
			ls.Name, countryCode, ls.Score, ls.Load, ls.Tier)
	}
	return ls, dom
}
