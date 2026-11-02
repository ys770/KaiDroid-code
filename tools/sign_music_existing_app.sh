#!/usr/bin/env bash
# Match the observed Music development signer; no lineage/uninstall.
set -euo pipefail
root=${1:?Supply the existing build root}
stage=${2:?Supply a new output directory}
test ! -e "$stage"
keys="$root/aosp/build/make/target/product/security"
test "$(openssl x509 -in "$keys/testkey.x509.pem" -outform DER | sha256sum | cut -d ' ' -f 1)" = a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc
test "$(sha256sum "$root/media-app-build01/KaiDroidTclTclMusic.apk" | cut -d ' ' -f 1)" = 5f1f8ef7a3d99ef73b1053c4a1cd9121e777c0d534cc2c03bd9c5810a7b8d166
mkdir "$stage"
exec > >(tee "$stage/signing.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/signing.exit"' EXIT
signer=("$root/aosp/prebuilts/jdk/jdk11/linux-x86/bin/java" -jar "$root/out-eng-02/host/linux-x86/framework/apksigner.jar")
for name in TclMusic; do
    "${signer[@]}" sign --v4-signing-enabled false --key "$keys/testkey.pk8" \
        --cert "$keys/testkey.x509.pem" --out "$stage/KaiDroidTcl$name.apk" \
        "$root/media-app-build01/KaiDroidTcl$name.apk"
    "${signer[@]}" verify --verbose --print-certs "$stage/KaiDroidTcl$name.apk" > "$stage/$name-signature.txt"
done
python3 - "$root/media-app-build01" "$stage" <<'PY'
import hashlib, json, sys, zipfile
from pathlib import Path
source, stage = map(Path, sys.argv[1:])
def payload(path):
    with zipfile.ZipFile(path) as z:
        if z.testzip(): raise ValueError('Corrupt ZIP')
        return {n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()
                if not n.startswith('META-INF/') and not n.endswith('/')}
rows=[]
for name in ('TclMusic',):
    file='KaiDroidTcl'+name+'.apk'
    if payload(source/file)!=payload(stage/file):raise ValueError('Payload changed')
    rows.append(dict(name=name,sha256=hashlib.sha256((stage/file).read_bytes()).hexdigest(),payload_preserved=True))
(stage/'outputs.json').write_text(json.dumps(dict(apps=rows,installed=False),indent=2)+'\n')
print(json.dumps(rows))
PY
