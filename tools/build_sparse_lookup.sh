#!/usr/bin/env bash
# Run inside the existing build container. Preserve source and output artifacts.
set -eo pipefail
stage=/build/sparse-lookup-build01
source_file=/build/aosp/frameworks/base/libs/androidfw/LoadedArsc.cpp
test -d "$stage"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
test "$(sha256sum "$source_file" | cut -d ' ' -f1)" = 44ff1883795923dd968033e3900f69bccb663901c99217e3fb537ee60772a5dc
test "$(sha256sum "$stage/LoadedArsc.cpp" | cut -d ' ' -f1)" = a9bcb16575db742ebe145c2008e9ed8a1cd81cb7183442a9faed1e54e2b25f79
test ! -e "$stage/LoadedArsc.before.cpp"
cp -p "$source_file" "$stage/LoadedArsc.before.cpp"
cp "$stage/LoadedArsc.cpp" "$source_file"
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 libandroidfw idmap2
cp -p /build/out-eng-02/target/product/n139dl/system/lib/libandroidfw.so "$stage/libandroidfw.so"
cp -p /build/out-eng-02/host/linux-x86/bin/idmap2 "$stage/idmap2-host"
sha256sum "$stage/libandroidfw.so" "$stage/idmap2-host" > "$stage/artifacts.sha256"
# No system image assembly, phone operation or automatic restoration here.
