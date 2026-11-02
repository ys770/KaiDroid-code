#!/usr/bin/env bash
set -euo pipefail
root=${1:?Build root}
input=${2:?Aligned APK}
stage=${3:?New output directory}
test ! -e "$stage"
keys="$root/aosp/build/make/target/product/security"
test "$(openssl x509 -in "$keys/platform.x509.pem" -outform DER | sha256sum | cut -d ' ' -f 1)" = c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8
test "$(sha256sum "$input" | cut -d ' ' -f 1)" = 21928729a9fcd4d62826401aff8ba482f7a795923ea25cd342d6b9f5ff04500e
mkdir "$stage"
exec > >(tee "$stage/signing.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/signing.exit"' EXIT
signer=("$root/aosp/prebuilts/jdk/jdk11/linux-x86/bin/java" -jar "$root/out-eng-02/host/linux-x86/framework/apksigner.jar")
"${signer[@]}" sign --v4-signing-enabled false --key "$keys/platform.pk8" --cert "$keys/platform.x509.pem" --out "$stage/KaiDroidTclMessaging.apk" "$input"
"${signer[@]}" verify --verbose --print-certs "$stage/KaiDroidTclMessaging.apk" > "$stage/signature.txt"
sha256sum "$stage/KaiDroidTclMessaging.apk" > "$stage/output.sha256"
