#!/bin/bash
# Build the debug APK for ARM64 phones using the configured Android SDK/NDK.
set -euo pipefail
cd "$(dirname "$0")/.."
export GOTOOLCHAIN=local
export GOBIN="$PWD/android/build/go/bin"
export PATH="$PWD/tool:$GOBIN:$PATH"
mkdir -p "$GOBIN" android/libs .proton-build
./tool/go run tailscale.com/cmd/mkversion > tailscale.version
./tool/go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
"$GOBIN/gomobile" bind -target android/arm64 -androidapi 26 \
    -tags "$(./build-tags.sh) ts_omit_cachenetmap" \
    -ldflags "-linkmode=external -extldflags=-Wl,-z,max-page-size=16384 $(./version-ldflags.sh)" \
    -o android/libs/libtailscale_unstripped.aar ./libtailscale
aar_dir=$(mktemp -d "$PWD/.proton-build/aar.XXXXXX")
unzip -q android/libs/libtailscale_unstripped.aar -d "$aar_dir"
"$ANDROID_HOME/ndk/23.1.7779620/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" \
    --strip-debug "$aar_dir/jni/arm64-v8a/libgojni.so"
(cd "$aar_dir" && zip -qr -FS "$OLDPWD/android/libs/libtailscale.aar" .)
(cd android && ./gradlew testDebugUnitTest assembleDebug --no-daemon --console=plain)
cp android/build/outputs/apk/debug/android-debug.apk tailscale-debug.apk
