#!/usr/bin/env bash
# Pack isolated camera image52 only; hardware owns launch, raw verification and install.
set -euo pipefail
stage=/build/engineering-camera-stage-52-retry02
test -f "$stage/staging.complete"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
python3 "$stage/stage-check.py" --check-stage "$stage"
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
avbtool add_hashtree_footer --partition_size 834666496 --algorithm SHA256_RSA2048 --key external/avb/test/data/testkey_rsa2048.pem --do_not_generate_fec --calc_max_image_size > "$stage/avb-max-image-bytes.txt"
sefcontext_compile -o "$stage/file_contexts.bin" "$stage/file_contexts.txt"
python3 build/make/tools/releasetools/build_image.py "$stage/compact-system" "$stage/system_image_info.compact.txt" "$stage/compact-image/system.img" "$stage/compact-system"
simg2img "$stage/compact-image/system.img" "$stage/compact-image/system.raw.img"
avbtool verify_image --image "$stage/compact-image/system.raw.img" --key external/avb/test/data/testkey_rsa2048.pem > "$stage/avb-verification.txt"
avbtool info_image --image "$stage/compact-image/system.raw.img" > "$stage/avb-info.txt"
sha256sum "$stage/compact-image/system.raw.img" > "$stage/raw.sha256"
python3 "$stage/stage-check.py" --check-stage "$stage"
python3 - "$stage" <<'PY'
import hashlib,json,sys,re
from pathlib import Path
s=Path(sys.argv[1]);raw=s/'compact-image/system.raw.img';m=json.loads((s/'staging.json').read_text())
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
assert raw.stat().st_size==834666496
info=(s/'avb-info.txt').read_text()
assert re.search(r'FEC num roots:\s+0\s*$',info,re.M)
assert re.search(r'Algorithm:\s+SHA256_RSA2048\s*$',info,re.M)
assert re.search(r'Hash Algorithm:\s+sha1\s*$',info,re.M)
assert re.search(r'Tree Size:\s+[1-9][0-9]* bytes',info)
assert int((s/'avb-max-image-bytes.txt').read_text())==828018688
r=dict(image=52,raw_bytes=raw.stat().st_size,raw_sha256=sha(raw),
 avb_verified=True,max_avb_payload_bytes=int((s/'avb-max-image-bytes.txt').read_text()),
 optional_fec=False,signed_hashtree_verified=True,added_paths=m['added'],
 staging_sha256=hashlib.sha256((s/'staging.json').read_bytes()).hexdigest(),
 installed=False,raw_closure_verified=False,changed_file_closure=m['changed'])
(s/'outputs.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
PY
