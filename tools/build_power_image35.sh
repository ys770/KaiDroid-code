#!/usr/bin/env bash
set -eo pipefail
stage=/build/engineering-power-stage-35
test -f "$stage/staging.json"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
sefcontext_compile -o "$stage/file_contexts.bin" "$stage/file_contexts.txt"
python3 build/make/tools/releasetools/build_image.py "$stage/compact-system" "$stage/system_image_info.compact.txt" "$stage/compact-image/system.img" "$stage/compact-system"
simg2img "$stage/compact-image/system.img" "$stage/compact-image/system.raw.img"
avbtool verify_image --image "$stage/compact-image/system.raw.img" --key external/avb/test/data/testkey_rsa2048.pem > "$stage/avb-verification.txt"
sha256sum "$stage/compact-image/system.raw.img" > "$stage/raw.sha256"
