#!/usr/bin/env bash
# Compile only; never flash or delete build-host files.
set -eo pipefail
stage=/build/power-endcall-build01
test -f "$stage/PhoneWindowManager.original.java"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j8 services
mkdir "$stage/output"
cp -p /build/out-eng-02/target/product/n139dl/system/framework/services.jar "$stage/output/"
mkdir -p "$stage/output/oat/arm"
for suffix in art odex vdex; do
    cp -p "/build/out-eng-02/target/product/n139dl/system/framework/oat/arm/services.$suffix" "$stage/output/oat/arm/"
done
sha256sum "$stage/output/services.jar" > "$stage/output/sha256.txt"
