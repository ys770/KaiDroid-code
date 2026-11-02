#!/usr/bin/env bash
set -eo pipefail
stage=${1:?Supply fresh prepared stage}
test -f "$stage/staging.json"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 libsurfaceflinger
test ! -e "$stage/libsurfaceflinger.candidate.so"
cp -p /build/out-eng-02/target/product/n139dl/system/lib/libsurfaceflinger.so "$stage/libsurfaceflinger.candidate.so"
sha256sum "$stage/libsurfaceflinger.candidate.so" > "$stage/candidate.sha256"
