#!/bin/bash
# Focused host tests for the shared Proton data plane, without Android/JNI.
set -euo pipefail
cd "$(dirname "$0")/.."
./tool/go test -race -count=1 -v \
    libtailscale/proton_device.go \
    libtailscale/proton_split.go \
    libtailscale/proton_nat.go \
    libtailscale/proton_socket_test.go \
    libtailscale/proton_device_test.go
