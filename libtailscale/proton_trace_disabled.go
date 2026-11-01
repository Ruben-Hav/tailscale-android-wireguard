// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !protonprofile

package libtailscale

// The compiler removes these calls from normal APKs.
func protonTracePacket(string, []byte) {}
