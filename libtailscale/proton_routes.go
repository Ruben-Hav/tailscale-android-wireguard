// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"net/netip"

	rangescalc "github.com/tailscale/tailscale-android/libtailscale/ranges_calc"
)

func protonExclusionsExceptAgent(excluded []netip.Prefix, agent netip.Addr) ([]netip.Prefix, error) {
	v4, v6, err := rangescalc.Calculate(excluded, []netip.Prefix{netip.PrefixFrom(agent, agent.BitLen())})
	if err != nil {
		return nil, err
	}
	return append(v4, v6...), nil
}
