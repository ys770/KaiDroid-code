#!/usr/bin/env bash
# Generate actual product platform policy only; no policy load or image build.
set -eo pipefail
stage=${1:?Supply prepared stage}
test -f "$stage/BoardConfig.original.mk"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 plat_sepolicy.cil system_ext_sepolicy.cil
test ! -e "$stage/plat_sepolicy.cil"
cp -p /build/out-eng-02/target/product/n139dl/system/etc/selinux/plat_sepolicy.cil "$stage/plat_sepolicy.cil"
sha256sum "$stage/plat_sepolicy.cil" > "$stage/sha256.txt"
test ! -e "$stage/system_ext_sepolicy.cil"
cp -p /build/out-eng-02/target/product/n139dl/system/system_ext/etc/selinux/system_ext_sepolicy.cil "$stage/system_ext_sepolicy.cil"
grep -q kaidroid_hall "$stage/system_ext_sepolicy.cil"
sha256sum "$stage/system_ext_sepolicy.cil" >> "$stage/sha256.txt"
