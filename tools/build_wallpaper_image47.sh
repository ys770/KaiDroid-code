#!/usr/bin/env bash
# Pack only isolated47, preserving immutable46 except SystemUI/revision. Never flash.
set -euo pipefail
stage=/build/engineering-wallpaper-stage-47
test -f "$stage/staging.complete"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
python3 - "$stage" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text())
assert m['image']==47 and m['baseline_image']==46
assert hashlib.sha256((s/'staging.json').read_bytes()).hexdigest()==(s/'staging.complete').read_text().strip()
assert set(m['changed'])=={'system_ext/priv-app/SystemUI/SystemUI.apk','build.prop'}
for name,pin in m['metadata_files_sha256'].items():assert hashlib.sha256((s/name).read_bytes()).hexdigest()==pin,name
for name,root in [('system-inventory.json',s/'compact-system'),('root-inventory.json',s/'compact-root')]:
 expected=json.loads((s/name).read_text());actual={}
 for folder,dirs,files in os.walk(root,followlinks=False):
  for n in dirs+files:
   p=Path(folder)/n
   actual[p.relative_to(root).as_posix()]=['link',os.readlink(p)] if p.is_symlink() else ['dir',p.stat().st_mode&4095] if p.is_dir() else ['file',p.stat().st_mode&4095,hashlib.sha256(p.read_bytes()).hexdigest()]
 assert actual==expected,'Staged payload changed: '+name
for name,pin in {**m['protected46_sha256'],**m['preserved_alarm_files']}.items():assert hashlib.sha256((s/'compact-system'/name).read_bytes()).hexdigest()==pin,name
PY
avbtool add_hashtree_footer --partition_size 834666496 --algorithm SHA256_RSA2048 --key external/avb/test/data/testkey_rsa2048.pem --calc_max_image_size > "$stage/avb-max-image-bytes.txt"
sefcontext_compile -o "$stage/file_contexts.bin" "$stage/file_contexts.txt"
python3 build/make/tools/releasetools/build_image.py "$stage/compact-system" "$stage/system_image_info.compact.txt" "$stage/compact-image/system.img" "$stage/compact-system"
simg2img "$stage/compact-image/system.img" "$stage/compact-image/system.raw.img"
avbtool verify_image --image "$stage/compact-image/system.raw.img" --key external/avb/test/data/testkey_rsa2048.pem > "$stage/avb-verification.txt"
avbtool info_image --image "$stage/compact-image/system.raw.img" > "$stage/avb-info.txt"
sha256sum "$stage/compact-image/system.raw.img" > "$stage/raw.sha256"
python3 - "$stage" <<'PY'
import hashlib,json,sys
from pathlib import Path
s=Path(sys.argv[1]);raw=s/'compact-image/system.raw.img'
assert raw.stat().st_size==834666496
r=dict(image=47,raw_bytes=raw.stat().st_size,raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
 avb_verified=True,max_avb_payload_bytes=int((s/'avb-max-image-bytes.txt').read_text()),
 installed=False,changed_file_closure=json.loads((s/'staging.json').read_text())['changed'])
(s/'outputs.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
PY
