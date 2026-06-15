// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Key handling for ProtonVPN. Proton issues an ephemeral ed25519 keypair per
// session: the WireGuard data plane uses the X25519 key derived from it, while
// the in-tunnel "local agent" authenticates over TLS with the ed25519 cert+key
// (see proton_agent.go). The cert itself is fetched by the Kotlin control plane
// from POST /vpn/v1/certificate using PublicKeyPKIXBase64 as ClientPublicKey.

package libtailscale

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	protoned "github.com/ProtonVPN/go-vpn-lib/ed25519"
)

// protonKeys holds the ephemeral ed25519 keypair for one Proton session.
type protonKeys struct {
	kp *protoned.KeyPair
}

func newProtonKeys() (*protonKeys, error) {
	kp, err := protoned.NewKeyPair()
	if err != nil {
		return nil, fmt.Errorf("proton: generate keypair: %w", err)
	}
	return &protonKeys{kp: kp}, nil
}

// PublicKeyPKIXBase64 is sent to POST /vpn/v1/certificate as ClientPublicKey.
func (k *protonKeys) PublicKeyPKIXBase64() (string, error) {
	return k.kp.PublicKeyPKIXBase64()
}

// X25519PrivateHex is the WireGuard interface private key (hex) for the UAPI.
func (k *protonKeys) X25519PrivateHex() string {
	return hex.EncodeToString(k.kp.ToX25519())
}

// Ed25519PrivatePEM is the TLS client private key for the local agent.
func (k *protonKeys) Ed25519PrivatePEM() string {
	return k.kp.PrivateKeyPKIXPem()
}

// wgKeyB64ToHex converts a standard 32-byte WireGuard key in base64 (as used in
// .conf files and Proton's /vpn/v1/logicals X25519PublicKey) to the hex form
// wireguard-go's UAPI expects.
func wgKeyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("proton: decode wg key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("proton: wg key wrong length %d (want 32)", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// serverPublicHexFromBase64 converts a Proton logical server's X25519PublicKey
// (base64, from /vpn/v1/logicals) to the hex form wireguard-go's UAPI expects.
func serverPublicHexFromBase64(b64 string) (string, error) {
	return wgKeyB64ToHex(b64)
}
