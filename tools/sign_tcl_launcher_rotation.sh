#!/usr/bin/env bash
# Lab-only migration: retain existing launcher data and permit rollback.
# Usage: script AOSP_ROOT OUT_DIR ORIGINAL_DONOR_APK NEW_OUTPUT_DIRECTORY
set -euo pipefail
aosp=$(realpath "$1")
build_out=$(realpath "$2")
donor=$(realpath "$3")
destination=$4
expected=603f00d40b5ab03bd171f7307d94a838274bdd266575d513a48ac7c7c3586204
test "$(sha256sum "$donor" | cut -d ' ' -f 1)" = "$expected"
mkdir "$destination"
destination=$(realpath "$destination")
signer=("$aosp/prebuilts/jdk/jdk11/linux-x86/bin/java" -jar "$build_out/host/linux-x86/framework/apksigner.jar")
keys="$aosp/build/target/product/security"
"${signer[@]}" rotate --out "$destination/lineage" \
  --old-signer --key "$keys/testkey.pk8" --cert "$keys/testkey.x509.pem" \
  --set-installed-data true --set-permission true --set-rollback true \
  --set-shared-uid false --set-auth false \
  --new-signer --key "$keys/platform.pk8" --cert "$keys/platform.x509.pem"
# The Android 11 tool cannot emit v4 with two lineage signer configurations.
"${signer[@]}" sign --v4-signing-enabled false --lineage "$destination/lineage" \
  --key "$keys/testkey.pk8" --cert "$keys/testkey.x509.pem" \
  --next-signer --key "$keys/platform.pk8" --cert "$keys/platform.x509.pem" \
  --out "$destination/Launcher3.apk" "$donor"
"${signer[@]}" verify --verbose --print-certs --min-sdk-version 30 \
  --max-sdk-version 30 "$destination/Launcher3.apk" > "$destination/verification.txt"
sha256sum "$destination/Launcher3.apk" "$destination/lineage"
