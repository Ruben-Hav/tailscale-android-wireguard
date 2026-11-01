#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
out=$root/.proton-build/network/harness
mkdir -p "$out/classes" "$out/controller-dex" "$out/load-dex"
unzip -p android/libs/libtailscale.aar classes.jar > "$out/libtailscale.jar"
tools=$ANDROID_HOME/build-tools/36.0.0
jar=$ANDROID_HOME/platforms/android-36/android.jar
javac -source 8 -target 8 -classpath "$jar:$out/libtailscale.jar" -d "$out/classes" integration/proton-diagnostics/Controller.java integration/proton-diagnostics/Load.java
for kind in controller load; do
    package=networktest; [[ $kind == load ]] && package=loadtest
    "$tools/d8" --min-api 26 --lib "$jar" --output "$out/$kind-dex" "$out/classes/com/tailscale/ipn/$package/"*.class
    "$tools/aapt2" link --manifest "integration/proton-diagnostics/$kind.xml" -I "$jar" --min-sdk-version 26 --target-sdk-version 36 -o "$out/$kind-unsigned.apk"
    (cd "$out/$kind-dex" && zip -j "$out/$kind-unsigned.apk" classes.dex)
    "$tools/zipalign" -f 4 "$out/$kind-unsigned.apk" "$out/$kind-aligned.apk"
    "$tools/apksigner" sign --ks .android-docker/debug.keystore --ks-pass pass:android --out "$out/$kind.apk" "$out/$kind-aligned.apk"
done
