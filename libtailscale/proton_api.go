// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Minimal ProtonVPN REST API client: SRP login (+2FA), server list, and
// WireGuard key certification. This is the dynamic control plane that replaces
// pasting .conf files. It talks to Proton's API the way their apps do, using
// go-srp for the SRP-6a handshake.
//
// Flow:
//   POST /auth/v4/info {Username}      -> modulus, serverEphemeral, salt, version, SRPSession
//   (go-srp computes client proof from the password)
//   POST /auth/v4 {proofs, SRPSession} -> UID, AccessToken, RefreshToken, ServerProof, 2FA
//   POST /auth/v4/2fa {TwoFactorCode}  -> (if 2FA enabled)
//   GET  /vpn/v1/logicals              -> server list
//   POST /vpn/v1/certificate {pubkey}  -> registers the key, returns cert
//
// ToS note: this uses a Proton app-version header like the official client. The
// user has accepted the risk of using a non-official client.

package libtailscale

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	srp "github.com/ProtonMail/go-srp"
)

// errHVRequired signals that Proton wants human verification (CAPTCHA). The
// caller surfaces it to the UI, which solves it in a WebView and retries.
var errHVRequired = errors.New("HUMAN_VERIFICATION_REQUIRED")

// Login status values returned by Login / ProtonLogin.
const (
	loginOK  = "ok"
	login2FA = "2fa"
	loginHV  = "hv"
)

const (
	protonAPIBase    = "https://vpn-api.proton.me"
	protonAppVersion = "android-vpn@5.10.0" // bump if the API returns a force-update (code 5003)
	protonUserAgent  = "ProtonVPN/5.10.0 (Android)"
)

// protonSession holds the session tokens. Proton requires an unauthenticated
// session (tokens present, loggedIn=false) before the SRP login, which then
// upgrades the same session to authenticated.
type protonSession struct {
	UID          string
	AccessToken  string
	RefreshToken string
	loggedIn     bool // true only after SRP (+2FA) completes
}

func (s protonSession) hasTokens() bool { return s.UID != "" && s.AccessToken != "" }

type protonAPI struct {
	http *http.Client

	mu      sync.Mutex
	session protonSession
	maxTier int

	// Human verification: hvToken/hvTokenType are sent on requests once solved;
	// pendingHV* hold the WebView start parameters from a 9001 response.
	hvToken             string
	hvTokenType         string
	pendingHVStartToken string
	pendingHVMethods    string

	// persist stores the session in the app's encrypted prefs across restarts.
	persist AppContext
}

const protonSessionPrefKey = "proton.session.v1"

// persistedSession is the JSON blob saved to encrypted prefs.
type persistedSession struct {
	UID          string `json:"uid"`
	AccessToken  string `json:"at"`
	RefreshToken string `json:"rt"`
	HVToken      string `json:"hvt"`
	HVTokenType  string `json:"hvtt"`
	MaxTier      int    `json:"tier"`
}

func (a *protonAPI) setPersistence(ctx AppContext) {
	a.mu.Lock()
	a.persist = ctx
	a.mu.Unlock()
}

func (a *protonAPI) saveSession() {
	a.mu.Lock()
	ctx := a.persist
	loggedIn := a.session.loggedIn
	ps := persistedSession{
		UID: a.session.UID, AccessToken: a.session.AccessToken, RefreshToken: a.session.RefreshToken,
		HVToken: a.hvToken, HVTokenType: a.hvTokenType, MaxTier: a.maxTier,
	}
	a.mu.Unlock()
	if ctx == nil || !loggedIn {
		return
	}
	b, err := json.Marshal(ps)
	if err != nil {
		return
	}
	if err := ctx.EncryptToPref(protonSessionPrefKey, string(b)); err != nil {
		log.Printf("proton: save session: %v", err)
	}
}

// loadSession restores a previously saved session. Returns whether one existed.
func (a *protonAPI) loadSession() bool {
	a.mu.Lock()
	ctx := a.persist
	a.mu.Unlock()
	if ctx == nil {
		return false
	}
	s, err := ctx.DecryptFromPref(protonSessionPrefKey)
	if err != nil || s == "" {
		return false
	}
	var ps persistedSession
	if json.Unmarshal([]byte(s), &ps) != nil || ps.UID == "" {
		return false
	}
	a.mu.Lock()
	a.session = protonSession{UID: ps.UID, AccessToken: ps.AccessToken, RefreshToken: ps.RefreshToken, loggedIn: true}
	a.hvToken = ps.HVToken
	a.hvTokenType = ps.HVTokenType
	a.maxTier = ps.MaxTier
	a.mu.Unlock()
	log.Printf("proton: restored saved session")
	return true
}

func (a *protonAPI) clearPersisted() {
	a.mu.Lock()
	ctx := a.persist
	a.mu.Unlock()
	if ctx != nil {
		_ = ctx.EncryptToPref(protonSessionPrefKey, "")
	}
}

// savePref / loadPref persist a small string value via the app's encrypted prefs.
func (a *protonAPI) savePref(key, val string) {
	a.mu.Lock()
	ctx := a.persist
	a.mu.Unlock()
	if ctx != nil {
		_ = ctx.EncryptToPref(key, val)
	}
}

func (a *protonAPI) loadPref(key string) string {
	a.mu.Lock()
	ctx := a.persist
	a.mu.Unlock()
	if ctx == nil {
		return ""
	}
	s, _ := ctx.DecryptFromPref(key)
	return s
}

func newProtonAPI() *protonAPI {
	// Android's Go runtime has no /etc/resolv.conf, so the default resolver
	// can't look up any hostname ("no such host"). Resolve via a known public
	// DNS server directly (dialing an IP needs no prior lookup).
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "udp", "1.1.1.1:53")
			if err != nil {
				c, err = d.DialContext(ctx, "udp", "8.8.8.8:53")
			}
			return c, err
		},
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, Resolver: resolver}
	return &protonAPI{
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:       dialer.DialContext,
				ForceAttemptHTTP2: true,
			},
		},
	}
}

// --- HTTP plumbing ---

// protonError is Proton's standard error envelope.
type protonError struct {
	Code    int    `json:"Code"`
	Error   string `json:"Error"`
	Details struct {
		HumanVerificationToken   string   `json:"HumanVerificationToken"`
		HumanVerificationMethods []string `json:"HumanVerificationMethods"`
	} `json:"Details"`
}

func (e *protonError) err() error {
	if e.Code == 1000 || e.Code == 1001 {
		return nil
	}
	msg := e.Error
	if msg == "" {
		msg = fmt.Sprintf("Proton API error code %d", e.Code)
	}
	return fmt.Errorf("proton: %s (code %d)", msg, e.Code)
}

// do sends a JSON request and decodes the JSON response into out. If authed, it
// attaches the session UID + bearer token, and refreshes the token once on 401.
func (a *protonAPI) do(method, path string, body any, out any, authed bool) error {
	return a.doRetry(method, path, body, out, authed, true)
}

func (a *protonAPI) doRetry(method, path string, body any, out any, authed, allowRefresh bool) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, protonAPIBase+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("x-pm-appversion", protonAppVersion)
	req.Header.Set("User-Agent", protonUserAgent)
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	a.mu.Lock()
	s := a.session
	hvT, hvTT := a.hvToken, a.hvTokenType
	a.mu.Unlock()
	if authed {
		req.Header.Set("x-pm-uid", s.UID)
		req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	}
	if hvT != "" {
		req.Header.Set("x-pm-human-verification-token", hvT)
		req.Header.Set("x-pm-human-verification-token-type", hvTT)
	}

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("proton: request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}

	// Always check the Proton error envelope first.
	var perr protonError
	_ = json.Unmarshal(raw, &perr)
	if perr.Code == 9001 { // human verification required
		a.mu.Lock()
		a.pendingHVStartToken = perr.Details.HumanVerificationToken
		a.pendingHVMethods = strings.Join(perr.Details.HumanVerificationMethods, ",")
		a.mu.Unlock()
		return errHVRequired
	}
	// Expired/invalid access token on a non-auth endpoint: refresh once and retry.
	if perr.Code == 401 && authed && allowRefresh && !strings.HasPrefix(path, "/auth/") {
		if err := a.refresh(); err == nil {
			return a.doRetry(method, path, body, out, authed, false)
		}
	}
	if e := perr.err(); e != nil {
		return e
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("proton: HTTP %d for %s", resp.StatusCode, path)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("proton: decode %s: %w", path, err)
		}
	}
	return nil
}

// refresh obtains a new access token using the stored refresh token, and
// re-persists the session.
func (a *protonAPI) refresh() error {
	a.mu.Lock()
	uid, rt := a.session.UID, a.session.RefreshToken
	a.mu.Unlock()
	if uid == "" || rt == "" {
		return errors.New("proton: no refresh token")
	}
	body := map[string]string{
		"GrantType":    "refresh_token",
		"RefreshToken": rt,
		"ResponseType": "token",
		"RedirectURI":  "https://protonvpn.com",
	}
	var rr struct {
		UID          string `json:"UID"`
		AccessToken  string `json:"AccessToken"`
		RefreshToken string `json:"RefreshToken"`
	}
	if err := a.doRetry(http.MethodPost, "/auth/v4/refresh", body, &rr, true, false); err != nil {
		log.Printf("proton: token refresh failed: %v", err)
		return err
	}
	a.mu.Lock()
	a.session.AccessToken = rr.AccessToken
	if rr.RefreshToken != "" {
		a.session.RefreshToken = rr.RefreshToken
	}
	if rr.UID != "" {
		a.session.UID = rr.UID
	}
	a.mu.Unlock()
	a.saveSession()
	return nil
}

// --- Auth ---

type authInfoResp struct {
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Version         int    `json:"Version"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
}

type authResp struct {
	UID          string `json:"UID"`
	AccessToken  string `json:"AccessToken"`
	RefreshToken string `json:"RefreshToken"`
	ServerProof  string `json:"ServerProof"`
	Scope        string `json:"Scope"`
	TwoFA        struct {
		Enabled int `json:"Enabled"` // bit 1 = TOTP
	} `json:"2FA"`
}

// ensureUnauthSession bootstraps an unauthenticated session if none exists.
// Proton's auth endpoints require this session's token.
func (a *protonAPI) ensureUnauthSession() error {
	a.mu.Lock()
	have := a.session.hasTokens()
	a.mu.Unlock()
	if have {
		return nil
	}
	var sess struct {
		UID          string `json:"UID"`
		AccessToken  string `json:"AccessToken"`
		RefreshToken string `json:"RefreshToken"`
	}
	if err := a.do(http.MethodPost, "/auth/v4/sessions", map[string]any{}, &sess, false); err != nil {
		return fmt.Errorf("proton: create session: %w", err)
	}
	a.mu.Lock()
	a.session = protonSession{UID: sess.UID, AccessToken: sess.AccessToken, RefreshToken: sess.RefreshToken}
	a.mu.Unlock()
	return nil
}

// Login performs the SRP login. Returns a status: loginOK, login2FA (call
// Submit2FA), or loginHV (solve human verification in a WebView, call
// SetHumanVerification, then retry Login).
func (a *protonAPI) Login(username, password string) (status string, err error) {
	if err := a.ensureUnauthSession(); err != nil {
		if errors.Is(err, errHVRequired) {
			return loginHV, nil
		}
		return "", err
	}

	var info authInfoResp
	if err := a.do(http.MethodPost, "/auth/v4/info", map[string]string{"Username": username}, &info, true); err != nil {
		if errors.Is(err, errHVRequired) {
			return loginHV, nil
		}
		return "", err
	}

	auth, err := srp.NewAuth(info.Version, username, []byte(password), info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return "", fmt.Errorf("proton: SRP init: %w", err)
	}
	proofs, err := auth.GenerateProofs(2048)
	if err != nil {
		return "", fmt.Errorf("proton: SRP proofs: %w", err)
	}

	reqBody := map[string]string{
		"Username":        username,
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}
	var ar authResp
	if err := a.do(http.MethodPost, "/auth/v4", reqBody, &ar, true); err != nil {
		if errors.Is(err, errHVRequired) {
			return loginHV, nil
		}
		return "", err
	}

	// Verify the server proof to authenticate the server to us.
	gotSP, err := base64.StdEncoding.DecodeString(ar.ServerProof)
	if err != nil || !bytes.Equal(gotSP, proofs.ExpectedServerProof) {
		return "", fmt.Errorf("proton: server proof mismatch (possible MITM)")
	}

	// /auth/v4 upgraded the session: store the authenticated tokens.
	twoFA := ar.TwoFA.Enabled&1 != 0
	a.mu.Lock()
	a.session = protonSession{
		UID:          ar.UID,
		AccessToken:  ar.AccessToken,
		RefreshToken: ar.RefreshToken,
		loggedIn:     !twoFA,
	}
	a.mu.Unlock()
	if twoFA {
		return login2FA, nil
	}
	return loginOK, nil
}

// HVParams returns the pending human-verification WebView parameters (start
// token and comma-separated methods) captured from a 9001 response.
func (a *protonAPI) HVParams() (token, methods string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pendingHVStartToken, a.pendingHVMethods
}

// SetHumanVerification records the solved verification token to send on
// subsequent requests.
func (a *protonAPI) SetHumanVerification(token, tokenType string) {
	a.mu.Lock()
	a.hvToken = token
	a.hvTokenType = tokenType
	a.mu.Unlock()
}

// Submit2FA submits a TOTP code to complete a 2FA login.
func (a *protonAPI) Submit2FA(code string) error {
	if err := a.do(http.MethodPost, "/auth/v4/2fa", map[string]string{"TwoFactorCode": code}, nil, true); err != nil {
		return err
	}
	a.mu.Lock()
	a.session.loggedIn = true
	a.mu.Unlock()
	return nil
}

// Logout revokes the session.
func (a *protonAPI) Logout() error {
	a.mu.Lock()
	has := a.session.hasTokens()
	a.mu.Unlock()
	var err error
	if has {
		err = a.do(http.MethodDelete, "/auth/v4", nil, nil, true)
	}
	a.mu.Lock()
	a.session = protonSession{}
	a.hvToken, a.hvTokenType = "", ""
	a.mu.Unlock()
	a.clearPersisted()
	return err
}

func (a *protonAPI) loggedIn() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session.loggedIn
}

// --- VPN endpoints ---

// logicalServer is one ProtonVPN logical server (a country/city endpoint).
type logicalServer struct {
	ID          string             `json:"ID"`
	Name        string             `json:"Name"`
	ExitCountry string             `json:"ExitCountry"`
	City        string             `json:"City"`
	Tier        int                `json:"Tier"`
	Features    int                `json:"Features"`
	Load        int                `json:"Load"`
	Score       float64            `json:"Score"`
	Status      int                `json:"Status"` // 1 = enabled
	Servers     []connectingDomain `json:"Servers"`
}

// connectingDomain is one physical server within a logical server.
type connectingDomain struct {
	EntryIP          string                      `json:"EntryIP"`
	EntryPerProtocol map[string]serverEntryInfo  `json:"EntryPerProtocol"`
	Domain           string                      `json:"Domain"`
	ID               string                      `json:"ID"`
	Label            string                      `json:"Label"`
	Status           int                         `json:"Status"` // 1 = online
	X25519PublicKey  string                      `json:"X25519PublicKey"`
}

type serverEntryInfo struct {
	IPv4  string `json:"IPv4"`
	Ports []int  `json:"Ports"`
}

// entryIP returns the WireGuard entry IP for this physical server.
func (d *connectingDomain) entryIP() string {
	if e, ok := d.EntryPerProtocol["WireGuardUDP"]; ok && e.IPv4 != "" {
		return e.IPv4
	}
	return d.EntryIP
}

// port returns the WireGuard UDP port (default 51820).
func (d *connectingDomain) port() int {
	if e, ok := d.EntryPerProtocol["WireGuardUDP"]; ok && len(e.Ports) > 0 {
		return e.Ports[0]
	}
	return 51820
}

type logicalsResp struct {
	LogicalServers []logicalServer `json:"LogicalServers"`
}

// GetLogicals fetches the full server list.
func (a *protonAPI) GetLogicals() (*logicalsResp, error) {
	var out logicalsResp
	if err := a.do(http.MethodGet, "/vpn/v1/logicals?SecureCoreFilter=all&WithEntriesForProtocols=WireGuardUDP", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

type vpnInfoResp struct {
	VPN struct {
		Name    string `json:"Name"`
		MaxTier int    `json:"MaxTier"`
		Status  int    `json:"Status"`
	} `json:"VPN"`
}

// GetVPNInfo returns the account's VPN tier/status.
func (a *protonAPI) GetVPNInfo() (*vpnInfoResp, error) {
	var out vpnInfoResp
	if err := a.do(http.MethodGet, "/vpn/v2", nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

type certResp struct {
	Certificate     string `json:"Certificate"`
	ServerPublicKey string `json:"ServerPublicKey"`
	ExpirationTime  int64  `json:"ExpirationTime"`
	RefreshTime     int64  `json:"RefreshTime"`
}

// GetCertificate registers clientPublicKey (ed25519 PKIX, base64) with the
// account and returns a certificate. Registration is what lets the derived
// WireGuard key connect.
func (a *protonAPI) GetCertificate(clientPublicKeyPKIXBase64 string) (*certResp, error) {
	body := map[string]any{
		"ClientPublicKey":     clientPublicKeyPKIXBase64,
		"ClientPublicKeyMode": "EC",
		"Mode":                "session",
		"Duration":            "1440 min",
	}
	var out certResp
	if err := a.do(http.MethodPost, "/vpn/v1/certificate", body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}
