#!/usr/bin/env bash
# Assemble only the reviewed image27-derived UI candidate; no phone operations.
set -eo pipefail
stage=/build/engineering-ui-runtime-stage03
test -f "$stage/staging.json"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
python3 build/make/tools/releasetools/build_image.py \
    "$stage/compact-system" "$stage/system_image_info.compact.txt" \
    "$stage/compact-image/system.img" "$stage/compact-system"
simg2img "$stage/compact-image/system.img" "$stage/compact-image/system.raw.img"
avbtool verify_image --image "$stage/compact-image/system.raw.img" \
    --key external/avb/test/data/testkey_rsa2048.pem > "$stage/avb-verification.txt"
python3 /build/ui-runtime-input01/verify_tcl_ui_runtime_v3.py --stage "$stage" \
    --baseline /build/engineering-bluetooth-stage-27
