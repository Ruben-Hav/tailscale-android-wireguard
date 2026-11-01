#!/bin/bash
# Run the certificate request and preference regressions in an Android VM/device.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK}"
: "${ANDROID_SERIAL:?Set ANDROID_SERIAL to the test emulator or device}"
adb_bin="${ANDROID_ADB:-$ANDROID_HOME/platform-tools/adb}"
abi=$("$adb_bin" -s "$ANDROID_SERIAL" shell getprop ro.product.cpu.abi | tr -d '\r')
case "$abi" in
    x86_64) arch=amd64; triple=x86_64-linux-android ;;
    arm64-v8a) arch=arm64; triple=aarch64-linux-android ;;
    *) echo "Unsupported test ABI: $abi" >&2; exit 1 ;;
esac

ndk="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/23.1.7779620}"
mkdir -p .proton-build
out_dir=$(mktemp -d "$PWD/.proton-build/accelerator-tests.XXXXXX")
remote="/data/local/tmp/proton-accelerator-tests-$$"
cleanup() {
    "$adb_bin" -s "$ANDROID_SERIAL" shell rm -f "$remote" >/dev/null 2>&1 || true
    rm -rf -- "$out_dir"
}
trap cleanup EXIT

if [[ ! -f tailscale.version ]]; then
    ./tool/go run tailscale.com/cmd/mkversion > tailscale.version
fi
GOOS=android GOARCH="$arch" CGO_ENABLED=1 \
CC="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/${triple}26-clang" \
    ./tool/go test -c -ldflags "$(./version-ldflags.sh)" \
    -o "$out_dir/accelerator.test" ./libtailscale
"$adb_bin" -s "$ANDROID_SERIAL" push "$out_dir/accelerator.test" "$remote"
"$adb_bin" -s "$ANDROID_SERIAL" shell chmod 755 "$remote"
"$adb_bin" -s "$ANDROID_SERIAL" shell "$remote -test.run='TestProton(Accelerator|LogicalsAPI|Agent)' -test.v=true"
