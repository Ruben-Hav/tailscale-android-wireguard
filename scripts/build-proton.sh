#!/bin/bash
# Build the phone and existing x86-64 emulator variants in one APK.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local
export GOBIN="$PWD/android/build/go/bin"
export PATH="$PWD/tool:$GOBIN:$PATH"
mkdir -p "$GOBIN" android/libs .proton-build
./tool/go run tailscale.com/cmd/mkversion > tailscale.version
./tool/go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
"$GOBIN/gomobile" bind -target "${PROTON_ANDROID_TARGETS:-android/arm64,android/amd64}" -androidapi 26 \
    -tags "$(./build-tags.sh) ts_omit_cachenetmap ${PROTON_EXTRA_TAGS:-}" \
    -ldflags "-linkmode=external -extldflags=-Wl,-z,max-page-size=16384 $(./version-ldflags.sh)" \
    -o android/libs/libtailscale_unstripped.aar ./libtailscale
aar_dir=$(mktemp -d "$PWD/.proton-build/aar.XXXXXX")
trap 'rm -rf -- "$aar_dir"' EXIT
unzip -q android/libs/libtailscale_unstripped.aar -d "$aar_dir"
strip_tool="$ANDROID_HOME/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
find "$aar_dir/jni" -name libgojni.so -exec "$strip_tool" --strip-debug {} \;
aar_output="$PWD/android/libs/libtailscale.aar"
(cd "$aar_dir" && zip -qr -FS "$aar_output" .)
(cd android && ./gradlew testDebugUnitTest assembleDebug assembleDebugAndroidTest --no-daemon --console=plain)
cp android/build/outputs/apk/debug/android-debug.apk tailscale-debug.apk
