// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import "log"

// protectSocket asks the active VpnService to exclude fd from the TUN.
func protectSocket(fd int) bool {
	if vpnService == nil || vpnService.service == nil {
		log.Printf("proton: no active VpnService to protect fd %d", fd)
		return false
	}
	if !vpnService.service.Protect(int32(fd)) {
		log.Printf("proton: VpnService.protect(%d) returned false", fd)
		return false
	}
	return true
}
