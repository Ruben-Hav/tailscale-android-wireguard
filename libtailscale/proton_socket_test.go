// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !android

package libtailscale

// The focused host tests use ordinary loopback sockets, outside a VpnService.
func protectSocket(fd int) bool { return true }
