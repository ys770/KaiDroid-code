#!/usr/bin/env bash
# Module-only build; no product selection, policy activation or image assembly.
set -eo pipefail
stage=${1:?Supply fresh existing stage directory}
test -d "$stage"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 kaidroid-hall
test ! -e "$stage/kaidroid-hall"
cp -p /build/out-eng-02/target/product/n139dl/system/bin/kaidroid-hall "$stage/kaidroid-hall"
sha256sum "$stage/kaidroid-hall" > "$stage/sha256.txt"
