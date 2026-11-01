# v622 network correctness and metadata caching

Real-phone testing is deferred at the user's request. Work used the existing
headless Android VM and in-place APK updates with the existing signing key.
Both saved logins and the Tailscale node identity remained unchanged.

## Connection readiness and early TLS

Account connections previously populated a client certificate but left the
local-agent parameters empty. The app reported Connected after a WireGuard
handshake, without authenticated in-tunnel readiness or feature confirmation.

A same-build, interleaved comparison used NL#799, NL#895 and NL#227. Each server
was tested twice with WireGuard-only readiness and twice with agent readiness:

| Readiness | Immediate requests | First numeric-IP TLS failures | First hostname request |
| --- | ---: | ---: | --- |
| WireGuard handshake only | 24 | 6 of 6 initial numeric requests | 3.277–3.400 seconds |
| Authenticated local agent | 24 | 0 | 0.118–0.132 seconds |

Agent-ready requests in that comparison all returned HTTP 200 in 94–152 ms.
Connection setup was measured separately. One agent attempt retried and took
9.864 seconds to reach readiness; a short request time does not mean all setup
delays have disappeared.

The production agent-only candidate still reproduced one initial numeric-IP
failure with Accelerator disabled. Adding Android's bounded network validation
wait removed the long hostname delays but also left one numeric-IP failure in
24 requests. Those candidates were not treated as a complete TLS fix.

The library's status parser emits Connected before it sends the initial feature
diff. The final implementation therefore waits for a connected server status
whose `split-tcp` boolean explicitly matches the requested setting. Missing or
malformed acknowledgements cannot enable forwarding. It then waits for Android's
VPN validation callback (up to 500 ms), outside the backend loop, before exposing
Connected. This uses real state signals, without a fixed post-connect sleep or
TLS verification bypass. Android's validation probes are allowed after Proton
has authenticated and confirmed its features.

The final normal APK passed 16/16 immediate requests across NL#799 and NL#895,
with Accelerator on/off, including the combinations that exposed both residual
candidate failures. Proton certificate-generation error 2028 stopped the first
matrix before NL#227. Testing paused for more than five minutes, then continued
only the remaining server and recovery checks, retaining all failed samples.
No session was logged out or replaced to work around the provider's limit.

Across all three servers on the exact final APK, 23/24 immediate requests passed.
One initial numeric-IP request on NL#227 still failed with Accelerator enabled;
therefore the feature-acknowledgement race is not a complete explanation for
every numeric-IP TLS failure, and that issue remains open. Successful requests
stayed below two seconds; the repeated 3.3-second hostname pattern was absent.
All 24 reused-client transition requests over four cycles passed, including
12 post-disconnect requests taking 39–63 ms. All six per-address TLS checks
(including two IPv6 destinations) returned HTTP 200.

The official Android source was compared, rather than signing into another app:
[agent configuration, feature negotiation and VPN validation](https://github.com/ProtonVPN/android-app/blob/master/app/src/main/java/com/protonvpn/android/vpn/VpnBackend.kt),
[public CA bundle and local-agent address](https://github.com/ProtonVPN/android-app/blob/master/app/src/main/java/com/protonvpn/android/utils/Constants.kt),
and the pinned [Go local-agent state machine](https://github.com/ProtonVPN/go-vpn-lib/tree/9440653831b0/localAgent).
The observed improvements establish a readiness problem in these VM cases;
they do not prove that every possible numeric-IP TLS failure has the same cause.

## IPv4 translation

NAT now adjusts the transport checksum only in the fragment containing its
checksum word. This also handles tiny TCP fragments whose first fragment lacks
the checksum. Ordinary later payload bytes are preserved. UDP checksum zero
remains disabled, and a computed zero is encoded as `0xffff`.

ICMP unreachable/fragmentation-needed, time-exceeded and other quoted IPv4 errors
translate the inner address and available IP/TCP/UDP checksums as well as the
outer checksum. The adjustment is incremental, allowing short quotes and an
outer ICMP fragment containing the quoted headers. This does not add a general
IP fragment reassembler for errors whose quoted headers span fragments.

Independent full-checksum/reassembly tests cover both directions, fragment sizes
8/16/24/32, IPv4 options, minimal/full/odd-length quotes, UDP disabled/zero-result
checksums, fragmented ICMP with the quoted headers present, and malformed headers.
The original code fails the new fragment, ICMP and malformed-header regressions;
the patched code passes.

## Shared server metadata

All country/server lists and connection actions use the same per-client,
account-scoped, memory-only snapshot. Successful responses expire after five
minutes. Concurrent misses share one fetch/decode; failures are not cached and
expired data is not served on refresh failure. Logout invalidates the snapshot;
retired requests cannot refill it after invalidation/account changes. Consumers
must treat snapshots as immutable. Account tier checks remain separate.

The mocked Android API contract test exercises 24 concurrent callers with one
full-server-list request, preserving authentication, WireGuardUDP metadata and
IPv6 capability fields. Expiry, failures, account separation and in-flight
invalidation have race-enabled host coverage. No live battery/CPU reduction or
specific startup-latency saving is claimed.

## Validation and artifacts

- 31 focused top-level host tests pass with `-race`.
- 12 top-level native Android certificate/API/agent tests pass.
- 70 Android unit tests pass with zero failures/errors.
- The project's Kotlin format-check task passes (its main-source tasks report
  NO-SOURCE; the build and unit tests compile the changed Kotlin files).
- Normal APK: `Protonscale-1.104.4-v622.apk`, package `com.tailscale.ipn.debug`,
  version code 622, ARM64 and x86-64. Profiling/trace/test APIs are excluded.
- Signing certificate SHA-256:
  `e1fe72d15c4bba9b88c49162e718168a7c8c72251d8ce9aedb4401482f90ea73`.
- APK SHA-256:
  `1aab3406125b2241334adcb68128f9a79240a7ec9c012a28cf58b71c9cc0215d`.
- Local raw reports and build logs stay under ignored `.proton-build/priorities/`:
  `agent-ab.json`, `agent-ab-trace.json`, `nat-before.log`,
  `final-native-race.log`, `final-android-api-agent-tests.log`,
  `shipping-agent-only/`, `shipping-validation/`, `shipping-feature-ack/`,
  `shipping-feature-ack-nl227/`, and `final-summary.json`.
- Repeat saved-session checks with `verify-connectivity.ps1`; stop on provider
  rate limiting and retain failed samples. The harness restores Accelerator and
  disconnects Proton even if a test fails.

Remaining work: isolate the residual numeric-IP early-close on the provider/path
or in an independent client, and perform real-phone validation when resumed.
