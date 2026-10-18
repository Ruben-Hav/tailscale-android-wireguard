// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func protonTestKey(t *testing.T) (private, public string) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(key), hex.EncodeToString(pub)
}

func protonTestDevice(t *testing.T, cfg protonConfig) *protonDevice {
	t.Helper()
	p, err := newProtonDevice(1280, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// A real loopback WireGuard peer must remain reachable after repeatedly
// replacing the client device. Each old device closes its own TUN and event
// reader; the replacement must own a fresh, working TUN.
func TestProtonDeviceReconnect(t *testing.T) {
	clientPrivate, clientPublic := protonTestKey(t)
	serverPrivate, serverPublic := protonTestKey(t)
	server := protonTestDevice(t, protonConfig{
		privateKeyHex: serverPrivate,
		serverPubHex:  clientPublic,
		endpoint:      "127.0.0.1:9",
	})
	state, err := server.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var port string
	for line := range strings.SplitSeq(state, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			port = value
		}
	}
	if port == "" || port == "0" {
		t.Fatal("server did not open a UDP socket")
	}
	cfg := protonConfig{
		privateKeyHex: clientPrivate,
		serverPubHex:  serverPublic,
		endpoint:      "127.0.0.1:" + port,
	}
	var previous *protonTUN
	for attempt := 0; attempt < 3; attempt++ {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			client := protonTestDevice(t, cfg)
			if client.tun == previous {
				t.Fatal("replacement reused the closed TUN")
			}
			if err := client.waitForHandshake(5 * time.Second); err != nil {
				t.Fatal(err)
			}
			client.Close()
			if _, err := client.tun.Read([][]byte{make([]byte, 2048)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
				t.Fatalf("old TUN read error = %v, want os.ErrClosed", err)
			}
			for range client.tun.Events() {
			}
			previous = client.tun
		})
	}
}

func TestProtonHandshakeTimeout(t *testing.T) {
	private, _ := protonTestKey(t)
	_, public := protonTestKey(t)
	p := protonTestDevice(t, protonConfig{privateKeyHex: private, serverPubHex: public, endpoint: "127.0.0.1:9"})
	if err := p.waitForHandshake(100 * time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("handshake error = %v, want timeout", err)
	}
}

func TestProtonHandshakeCancelledOnClose(t *testing.T) {
	private, _ := protonTestKey(t)
	_, public := protonTestKey(t)
	p := protonTestDevice(t, protonConfig{privateKeyHex: private, serverPubHex: public, endpoint: "127.0.0.1:9"})
	result := make(chan error, 1)
	go func() { result <- p.waitForHandshake(15 * time.Second) }()
	p.Close()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("handshake error = %v, want os.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the device did not cancel handshake verification")
	}
}
