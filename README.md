# Tailscale Android Client

## Protonscale fork

This fork combines Tailscale and Proton VPN in a single Android VPN service.
The current base is stable Tailscale Android 1.104.4, with Proton API compatibility
version 5.20.98.0. Proton's shared Go library is pinned in `go.mod`.

VPN Accelerator is enabled by default for account-based Proton connections.
The switch on the Proton VPN screen saves the setting for the next connection;
disconnect and reconnect Proton VPN after changing it. The client explicitly
requests Proton's `SplitTCP` certificate feature while retaining WireGuard UDP.
Imported WireGuard configurations keep their original server-side settings.

Account connections authenticate the in-tunnel local agent using Proton's CA
bundle and the selected server's certificate name. Forwarding waits for the
server to acknowledge the requested `split-tcp` value. Connected is then
published after Android's VPN validation signal, with a bounded 500 ms wait.
The reserved control host/port is `10.2.0.1:65432`; other application ports still
follow overlapping tailnet subnet routes. Retired-agent callbacks cannot change
a replacement connection or bypass disconnect route restoration.

Country lists, server lists and connection selection share an immutable,
account-scoped server snapshot for up to five minutes. Concurrent misses share
one request; expired data and failed refreshes are not silently reused.

IPv4 NAT respects fragment offsets (including tiny TCP fragments), UDP disabled
checksums and quoted ICMP errors. Quoted IP/transport checksums are translated
for socket matching and path-MTU errors, including IPv4 options and short quotes.

Account-based connections use Proton's IPv6 client address when the selected
server advertises IPv6 support. IPv4-only servers return local ICMPv6 no-route
errors, allowing clients to fall back promptly while IPv6 remains captured.
IPv6 translation handles extension headers and quoted ICMPv6 path-MTU errors.

When the physical network has IPv4 but both independent IPv6 reachability
probes fail, tailnet-only mode returns immediate errors for public IPv6 instead
of allowing long TCP timeouts after Proton disconnects. Working physical IPv6,
tailnet/subnet routes, and IPv6 exit nodes retain their routes. Probes use
protected, network-bound TCP connections, run on network changes/disconnect,
and retry failed paths every three minutes while the VPN service is active.

Build the debug APK for ARM64 phones and x86-64 emulators with Docker Desktop:

```powershell
.\proton-build.ps1 apk
```

The result is `tailscale-debug.apk`, package `com.tailscale.ipn.debug`, named
Protonscale. Builds explicitly use `.android-docker/debug.keystore`. Retain that
file: a different key prevents updating an existing installation in place.
The key and generated APKs are ignored by Git.

Run the focused routing and WireGuard reconnect tests inside the build environment:

```sh
bash scripts/test-proton-device.sh
```

Run the native certificate/API, saved-setting and agent-readiness tests against
an Android emulator/device accessible to ADB from the build environment. This
standalone test binary uses mocked HTTP/preferences and leaves VPN app data and
saved logins alone:

```sh
ANDROID_SERIAL=emulator-5554 bash scripts/test-proton-accelerator.sh
```

The Proton packet queue reuses buffers up to 2 KiB and returns them after the
WireGuard slab copy, a queue drop, or tunnel close. Larger packets use an
unpooled fallback. Packet log formatting runs only when a message is emitted.

Benchmark the queue handoff without an account or a running VPN:

```sh
./tool/go test -run '^$' -bench BenchmarkProton -benchmem \
  libtailscale/proton_split.go libtailscale/proton_nat.go \
  libtailscale/proton_trace_disabled.go libtailscale/proton_ipv6.go \
  libtailscale/proton_underlay_probe.go \
  libtailscale/proton_perf_test.go
```

`BenchmarkProtonForward` reports one packet per operation;
`BenchmarkProtonPipeline` reports a batch of 64 packets exchanged by separate
goroutines. These isolate queue/copy/logging overhead; use live transfers to
measure whole-app performance.

For headless connectivity checks and CPU/allocation/contention profiling using
existing logins and a separate traffic-generator UID, see
[the diagnostic harness](integration/proton-diagnostics/README.md).

https://tailscale.com

Private WireGuard® networks made easy

## Overview

This repository contains the open source Tailscale Android client.

## Using

#### Tailscale Packages

The latest stable release APK can be obtained from the [Tailscale Packages Stable Track](https://pkgs.tailscale.com/stable/#android).

Unstable releases can be obtained from the [Tailscale Packages Unstable Track](https://pkgs.tailscale.com/unstable/#android).

These APKs include all supported platforms and architectures.  For installing compact APKs, Android TV, or if you want automatic updates, visit the [Google Play Store](https://play.google.com/store/apps/details?id=com.tailscale.ipn).

#### Google Playstore

[<img src="https://play.google.com/intl/en_us/badges/images/generic/en-play-badge.png"
     alt="Get it on Google Play"
     height="80">](https://play.google.com/store/apps/details?id=com.tailscale.ipn)

Help us test new features and bug-fixes before they ship to all users! A [beta testing track](https://play.google.com/apps/testing/com.tailscale.ipn) is available on the Play Store. 

#### Amazon Appstore

The app can be downloaded from the [Amazon Appstore](https://www.amazon.com/dp/B0D38TRB3N) for Amazon Fire tablets and Fire TV devices.

#### F-Droid

The [F-Droid](https://f-droid.org/packages/com.tailscale.ipn/) project builds the source code in this repository and maintains independently-built APKs. Note that F-Droid builds are not released, updated, or verified by the Tailscale team.

## Preparing a build environment

There are several options for setting up a build environment. The Android Studio
path is the most useful path for longer term development.

In all cases you will need:

- Go runtime
- Android SDK
- Android SDK components (`make androidsdk` will install them)

### Android Studio

1. Install a Go runtime (https://go.dev/dl/).
2. Install Android Studio (https://developer.android.com/studio).
3. Start Android Studio, from the Welcome screen select "More Actions" and "SDK Manager".
4. In the SDK manager, select the "SDK Tools" tab and install the "Android SDK Command-line Tools (latest)".
3. Run `make androidsdk` to install the necessary SDK components.

If you would prefer to avoid Android Studio, you can also install an Android
SDK. The makefile detects common paths, so `sudo apt install android-sdk` is
sufficient on Debian / Ubuntu systems. To use an Android SDK installed in a
non-standard location, set the `ANDROID_SDK_ROOT` environment variable to the
path to the SDK.

If you installed Android Studio the tools may not be in your path. To get the
correct tool path, run `make androidpath` and export the provided path in your
shell.

#### Code Formatting

The ktmft plugin on the default setting should be used to autoformat all Java, Kotlin
and XML files in Android Studio.  Enable "Format on Save".

### Docker

If you wish to avoid installing software on your host system, a Docker based development strategy is available, you can build and start a shell with:

```sh
make docker-shell
```

Several other makefile recipes are available for setting up the proper build environment and running builds.

Note that the docker makefile recipes s will preserve the image and remove container on completion.
If changes are made to the build environment or toolchain, cached docker images may need to be rebuilt.
The docker build image name is parameterized in the makefile and changing it provides a simple means to do this.

### Nix

If you have Nix 2.4 or later installed, a Nix development environment can
be set up with:

```sh
alias nix='nix --extra-experimental-features "nix-command flakes"'
nix develop
```

The flake provides host tools such as Java, `make`, `curl`, and `git`, and
points the build at a repo-local Android SDK in `./android-sdk`. The SDK
directory is ignored by Git and is reused across builds.

On first use, install the Android SDK components:

```sh
make androidsdk
```

Then build normally:

```sh
make tailscale-debug
```

The debug APK is written to `./tailscale-debug.apk`.

For one-shot commands without entering an interactive shell:

```sh
nix develop --command make androidsdk
nix develop --command make tailscale-debug
```

For faster Kotlin-only iteration while avoiding the `gomobile bind` step:

```sh
nix develop --command bash -lc 'cd android && ./gradlew ktfmtCheck compileDebugKotlin'
```

## Building

```sh
make apk
make install
```

## Building a release

Use `make tag_release` to stamp the Play Store version code, update the version
name, and tag the current commit. The version code is derived from wall-clock
time (minutes since the Unix epoch) at release time and committed into
`android/build.gradle`, so it increases monotonically across all builds and
branches while staying fixed for any given commit.

We only guarantee to support the latest Go release and any Go beta or
release candidate builds (currently Go 1.14) in module mode. It might
work in earlier Go versions or in GOPATH mode, but we're making no
effort to keep those working.

## Developing on a Fire Stick TV

On the Fire Stick:

* Settings > My Fire TV > Developer Options > ADB Debugging > ON

Then some useful commands:
```
adb connect 10.2.200.213:5555
adb install -r tailscale-fdroid.apk
adb shell am start -n com.tailscale.ipn/com.tailscale.ipn.MainActivity
adb shell pm uninstall com.tailscale.ipn
```

## Bugs

Please file any issues about this code or the hosted service on
[the tailscale issue tracker](https://github.com/tailscale/tailscale/issues).

## Contributing

`under_construction.gif`

PRs welcome, but we are still working out our contribution process and
tooling.

We require [Developer Certificate of
Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin)
`Signed-off-by` lines in commits.

## About Us

We are [Tailscale](https://tailscale.com). See
https://tailscale.com/company for more about us and what we're
building.

WireGuard is a registered trademark of Jason A. Donenfeld.
