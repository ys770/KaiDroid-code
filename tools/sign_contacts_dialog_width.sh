#!/usr/bin/env bash
# Pinned dialog-width candidate; shared-to-platform lineage retains rollback.
# Usage: script AOSP_ROOT OUT_DIR PINNED_CONTACTS_APK NEW_OUTPUT_DIRECTORY
set -euo pipefail
aosp=$(realpath "$1")
build_out=$(realpath "$2")
candidate=$(realpath "$3")
destination=$4
expected=af869a5f3c5992181adc5840ab3ea02539ce32a86e38ea09e47caa9f34a92336
test "$(sha256sum "$candidate" | cut -d ' ' -f 1)" = "$expected"
keys="$aosp/build/target/product/security"
python3 - "$keys" <<'PY'
import hashlib, pathlib, ssl, sys
root = pathlib.Path(sys.argv[1])
for name, expected in (
    ('shared', '28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd'),
    ('platform', 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8')):
    actual = hashlib.sha256(ssl.PEM_cert_to_DER_cert((root / (name + '.x509.pem')).read_text())).hexdigest()
    if actual != expected:
        raise ValueError('Unexpected development certificate: ' + name)
PY
mkdir "$destination"
destination=$(realpath "$destination")
python3 - "$candidate" "$destination/resources-stored.apk" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as src, zipfile.ZipFile(sys.argv[2], 'x') as dst:
    dst.comment = src.comment
    for entry in src.infolist():
        data = src.read(entry)
        if entry.filename == 'resources.arsc':
            entry.compress_type = zipfile.ZIP_STORED
        dst.writestr(entry, data)
PY
zipalign="$aosp/prebuilts/sdk/tools/linux/bin/zipalign"
"$zipalign" -p 4 \
  "$destination/resources-stored.apk" "$destination/aligned.apk"
signer=("$aosp/prebuilts/jdk/jdk11/linux-x86/bin/java" -jar "$build_out/host/linux-x86/framework/apksigner.jar")
"${signer[@]}" rotate --out "$destination/lineage" \
  --old-signer --key "$keys/shared.pk8" --cert "$keys/shared.x509.pem" \
  --set-installed-data true --set-permission true --set-rollback true \
  --set-shared-uid false --set-auth false \
  --new-signer --key "$keys/platform.pk8" --cert "$keys/platform.x509.pem"
"${signer[@]}" sign --v4-signing-enabled false --lineage "$destination/lineage" \
  --key "$keys/shared.pk8" --cert "$keys/shared.x509.pem" \
  --next-signer --key "$keys/platform.pk8" --cert "$keys/platform.x509.pem" \
  --out "$destination/FPContacts.apk" "$destination/aligned.apk"
"${signer[@]}" verify --verbose --print-certs --min-sdk-version 30 \
  --max-sdk-version 30 "$destination/FPContacts.apk" > "$destination/verification.txt"
"$zipalign" -c -p 4 "$destination/FPContacts.apk"
python3 - "$candidate" "$destination/FPContacts.apk" "$destination/packaging.json" <<'PY'
import hashlib, json, struct, sys, zipfile
from pathlib import Path
def payload(path):
    with zipfile.ZipFile(path) as archive:
        return {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()
                if not n.upper().startswith('META-INF/') and not n.endswith('/')}
if payload(sys.argv[1]) != payload(sys.argv[2]):
    raise ValueError('APK content changed')
with zipfile.ZipFile(sys.argv[2]) as archive, open(sys.argv[2], 'rb') as stream:
    entry = archive.getinfo('resources.arsc')
    stream.seek(entry.header_offset)
    header = stream.read(30)
    name_length, extra_length = struct.unpack_from('<HH', header, 26)
    offset = entry.header_offset + 30 + name_length + extra_length
    if entry.compress_type != zipfile.ZIP_STORED or offset % 4:
        raise ValueError('Resources are not stored and 4-byte aligned')
report = dict(apk_sha256=hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest(),
              resource_compression=entry.compress_type, resource_data_offset=offset,
              resource_aligned4=True, payload_entries_preserved=True, installed=False)
Path(sys.argv[3]).write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
sha256sum "$destination/FPContacts.apk" "$destination/lineage"
