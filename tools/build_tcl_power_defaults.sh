#!/usr/bin/env bash
# Build donor-derived initial defaults; no existing-user migration or phone writes.
set -eo pipefail
stage=/build/tcl-power-defaults-build01
overlay=/build/aosp/device/nokia/n139dl/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
apk=/build/out-eng-02/target/product/n139dl/system/priv-app/SettingsProvider/SettingsProvider.apk
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
test "$(sha256sum "$stage/defaults.xml" | cut -d ' ' -f1)" = 385b97ca4bc889f93a469e9520be840f8b11b6786f9d4a39501ff7073144a8f9
test ! -e "$overlay"
cp -p "$apk" "$stage/SettingsProvider.before.apk"
mkdir -p "$(dirname "$overlay")"
cp "$stage/defaults.xml" "$overlay"
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 SettingsProvider
cp -p "$apk" "$stage/SettingsProvider.apk"
sha256sum "$stage/SettingsProvider.before.apk" "$stage/SettingsProvider.apk" > "$stage/apks.sha256"
