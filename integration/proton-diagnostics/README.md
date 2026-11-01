# Saved-session headless diagnostics

This harness reuses an already authenticated Protonscale installation. It does
not authenticate, log out, clear app data, or replace the Tailscale node. Keep
the VM headless and retain the existing `.android-docker/debug.keystore` when
installing updates with `adb install -r`. The older account-setup integration
suites are unsuitable for this workflow because they replace app data.

Build in the existing Android build environment:

```sh
PROTON_EXTRA_TAGS=protonprofile bash scripts/build-proton.sh
bash integration/proton-diagnostics/build.sh
```

Install `tailscale-debug.apk` and the two APKs under
`.proton-build/network/harness/` with `adb install -r`. Start the controller:

```sh
adb forward tcp:39089 tcp:39089
adb shell am instrument -w -r com.tailscale.ipn.networktest/.Controller
```

Leave that command running. From another PowerShell 7 terminal:

```powershell
$uri = 'http://127.0.0.1:39089'
Invoke-RestMethod "$uri/state" -Method Post -ContentType application/json -Body '{}'
Invoke-RestMethod "$uri/connect" -Method Post -ContentType application/json -Body '{}'
./integration/proton-diagnostics/profile.ps1 -Kind cpu -Direction upload
./integration/proton-diagnostics/profile.ps1 -Kind allocs -Direction upload
./integration/proton-diagnostics/profile.ps1 -Kind block -Direction upload
./integration/proton-diagnostics/profile.ps1 -Kind mutex -Direction upload
```

The loopback controller runs inside the VPN app process and verifies the saved
node identity. The load APK runs under a separate UID/process, cannot access
VPN credentials, checks the complete byte count and HTTP status, and reports
its own CPU time. Each profile manifest records both PIDs/UIDs, VPN process CPU,
runtime allocation/GC deltas, and private profile paths. Failed HTTP workloads
are marked invalid and must be excluded from comparisons.

CPU sampling starts after warmup. Cumulative allocation/block/mutex profiles
use before/after snapshots; an additional sampling warmup precedes the final
baseline. Allocation snapshots flush the Go heap profiler's delayed accounting
with two garbage collections outside the workload counter measurements.
Contention profiles record accumulated waiting, including waits that started
before sampling; they do not represent CPU usage or exact workload wall time.

Analyze on the same Go toolchain:

```sh
./tool/go tool pprof -top /path/to/cpu.pprof
./tool/go tool pprof -top -sample_index=alloc_space \
  -base /path/to/allocs-before.pprof -ignore='ProtonProfileResetBaseline|writeProtonProfile' \
  /path/to/allocs-after.pprof
./tool/go tool pprof -top -base /path/to/block-before.pprof /path/to/block-after.pprof
./tool/go tool pprof -top -base /path/to/mutex-before.pprof /path/to/mutex-after.pprof
```

Other controller commands include `/url` with an allowlisted `host`, `/detail`
for DNS and per-address TLS checks, `/network`, and `/disconnect`. TLS tests use
the platform trust store and HTTPS identity verification. `/trace/start` takes
comma-separated public test IPs in `addresses`; `/trace/stop` returns bounded
TCP metadata and checksum validity, without packet payload or TLS secrets.
The diagnostic-only `/test/ipv6` injection exercises IPv4-only-server fallback.

Profile serialization allocates memory itself; exclude those stacks when
examining allocation deltas, as shown above. Heap profiles are sampled, so use
the manifest's runtime counters for exact allocation totals. Short runs may
produce only a few allocation samples. Contention totals are summed across
goroutines and include boundary-crossing waits; do not divide them by workload
duration to estimate CPU consumption.

After testing, `/disconnect` and `/shutdown`, remove the ADB forward and only
the two harness packages (`com.tailscale.ipn.networktest` and
`com.tailscale.ipn.loadtest`). Rebuild the normal APK without
`PROTON_EXTRA_TAGS=protonprofile`, install it in place, and restart the normal
VPN service. The shipping build has no profiling, trace control, or fault
injection APIs. Never uninstall or clear `com.tailscale.ipn.debug` to clean up.

VM profiles identify expensive operations but do not measure phone battery
life. Emulator clock/syscall overhead, host scheduling, radio power, and device
hardware can change the result. See [Go diagnostics](https://go.dev/doc/diagnostics).
IPv6 server capability and client addresses follow Proton's
[Android client](https://github.com/ProtonVPN/android-app/blob/master/app/src/main/java/com/protonvpn/android/models/vpn/ConnectionParamsWireguard.kt)
and [constants](https://github.com/ProtonVPN/android-app/blob/master/app/src/main/java/com/protonvpn/android/utils/Constants.kt).
