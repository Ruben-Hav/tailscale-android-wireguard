# proton-build.ps1 — one-command Docker build for the ProtonVPN-enabled fork.
#
# Prereqs: Docker Desktop installed and RUNNING. Nothing else — the build image
# contains Go, the Android SDK/NDK, JDK 21, and gomobile.
#
# Usage (from PowerShell):
#   .\proton-build.ps1            # compile the Go layer only (fast feedback)
#   .\proton-build.ps1 apk        # full debug APK (Go + Android app)
#
# The Go code lives in libtailscale/ and is compiled into libtailscale.aar by
# `gomobile bind`. The first run builds the toolchain image (slow, ~20-40 min,
# downloads the Android SDK/NDK). Subsequent runs reuse it and the cached
# Go modules/toolchain (named docker volumes), so they're much faster.

param(
    [ValidateSet("go", "apk")]
    [string]$Target = "go"
)

# NOTE: keep this "Continue", not "Stop". Native tools like docker write normal
# progress to stderr, which under "Stop" PowerShell turns into a fatal error
# before the build even runs. We check $LASTEXITCODE explicitly instead.
$ErrorActionPreference = "Continue"

# Must match DOCKER_IMAGE in the Makefile so we reuse the official build image.
$Image   = "tailscale-android-build-amd64-041425-1"
$Android = $PSScriptRoot                              # ...\tailscale-android-wireguard
$Root    = Split-Path $Android -Parent                # ...\tailscale-mobile-wireguard
$Proton  = Join-Path $Root "proton"                   # ...\proton  (has go-vpn-lib)

if (-not (Test-Path (Join-Path $Proton "go-vpn-lib"))) {
    throw "Expected go-vpn-lib at $Proton\go-vpn-lib (the go.mod replace points to ../proton/go-vpn-lib)."
}

# Make sure Docker is up before we do anything slow.
& docker version --format '{{.Server.Version}}' | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker isn't running. Start Docker Desktop and wait for it to be ready, then re-run."
}

# 1. Build the toolchain image once.
if (-not (docker images -q $Image)) {
    Write-Host "==> Building the Docker build image (first time only; this is slow)..." -ForegroundColor Cyan
    docker build --progress=plain -f (Join-Path $Android "docker\DockerFile.amd64-build") -t $Image $Android
    if ($LASTEXITCODE -ne 0) { throw "Docker image build failed." }
}

# What to run inside the container.
#   - mount the android repo at the path the Makefile expects (/build/tailscale-android)
#   - ALSO mount ../proton so the go.mod replace (../proton/go-vpn-lib) resolves
#   - persist the Go toolchain + module cache in named volumes across runs
#   - persist the debug keystore so `adb install -r` works across rebuilds
if ($Target -eq "apk") {
    $make = "make tailscale-debug"
    Write-Host "==> Building full debug APK..." -ForegroundColor Cyan
} else {
    $make = "make libtailscale"
    Write-Host "==> Compiling the Go layer (libtailscale.aar) only..." -ForegroundColor Cyan
}

$androidDocker = Join-Path $Android ".android-docker"
New-Item -ItemType Directory -Force -Path $androidDocker | Out-Null

docker run --rm `
    -v "${Android}:/build/tailscale-android" `
    -v "${Proton}:/build/proton" `
    -v "${androidDocker}:/root/.android" `
    -v "ts_android_gocache:/build/.cache" `
    -v "ts_android_gomod:/build/go" `
    $Image `
    bash -lc "cd /build/tailscale-android && rm -f libgojni.so.unstripped libgojni.so.stripped libgojni.so.debug android/libs/libtailscale.aar && ./tool/go mod tidy && $make"

if ($LASTEXITCODE -ne 0) { throw "Build failed (see output above)." }

if ($Target -eq "apk") {
    Write-Host "`n==> Done. APK: $Android\tailscale-debug.apk" -ForegroundColor Green
    Write-Host "    Install on a connected device/emulator with:  adb install -r tailscale-debug.apk"
} else {
    Write-Host "`n==> Done. Go compiled cleanly. AAR: $Android\android\libs\libtailscale.aar" -ForegroundColor Green
    Write-Host "    Run '.\proton-build.ps1 apk' to build the installable APK."
}
