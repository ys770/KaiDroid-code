#!/usr/bin/env bash
# Build candidate init only; no system image assembly or device operations.
set -eo pipefail
stage=/build/init-precompiled-build01
test -f "$stage/selinux.before.cpp"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 init
test ! -e "$stage/init"
cp -p /build/out-eng-02/target/product/n139dl/system/bin/init "$stage/init"
sha256sum "$stage/init" > "$stage/sha256.txt"
