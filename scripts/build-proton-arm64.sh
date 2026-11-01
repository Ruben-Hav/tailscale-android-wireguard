#!/bin/bash
# Phone-only variant of the shared Protonscale build.
set -euo pipefail
export PROTON_ANDROID_TARGETS=android/arm64
exec bash "$(dirname "$0")/build-proton.sh"
