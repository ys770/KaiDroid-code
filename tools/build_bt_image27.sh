#!/usr/bin/env bash
# Image assembly only; all input trees are preserved and no device is touched.
set -eo pipefail
stage=/build/engineering-bluetooth-stage-27
test -f "$stage/staging.json"
test -f "$stage/tree-comparison.json"
test -f "$stage/file_contexts.bin"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
python3 build/make/tools/releasetools/build_image.py \
    "$stage/compact-system" "$stage/system_image_info.compact.txt" \
    "$stage/compact-image/system.img" "$stage/compact-system"
