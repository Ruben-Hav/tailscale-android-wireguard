// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import _ "embed"

// Public CA certificates from Proton's Android Constants.VPN_ROOT_CERTS.
// https://github.com/ProtonVPN/android-app/blob/master/app/src/main/java/com/protonvpn/android/utils/Constants.kt
//
//go:embed proton_agent_roots.pem
var protonAgentRoots string

func configureProtonAgent(p *protonConnectParams, dom *connectingDomain) {
	p.agentHost = "10.2.0.1:65432"
	p.agentServerName = dom.Domain
	p.agentCAsPEM = protonAgentRoots
}
