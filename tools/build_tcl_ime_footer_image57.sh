#!/usr/bin/env bash
# Single signed-FEC0 pack of exact56+footer/Messaging/revision57; no compiler or flash.
set -euo pipefail
stage=/build/engineering-tcl-ime-footer-stage-57
test -f "$stage/staging.complete"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
python3 "$stage/inputs/tools/stage_tcl_ime_footer_image57.py" inside --stage "$stage"
cd /build/aosp
export PATH=/build/out-eng-02/host/linux-x86/bin:$PATH
avbtool add_hashtree_footer --partition_size 834666496 --algorithm SHA256_RSA2048 --key external/avb/test/data/testkey_rsa2048.pem --do_not_generate_fec --calc_max_image_size > "$stage/avb-max-image-bytes.txt"
sefcontext_compile -o "$stage/file_contexts.bin" "$stage/records/file_contexts.txt"
python3 build/make/tools/releasetools/build_image.py "$stage/compact-system" "$stage/records/system_image_info.compact.txt" "$stage/compact-image/system.img" "$stage/compact-system"
simg2img "$stage/compact-image/system.img" "$stage/compact-image/system.raw.img"
avbtool verify_image --image "$stage/compact-image/system.raw.img" --key external/avb/test/data/testkey_rsa2048.pem > "$stage/avb-verification.txt"
avbtool info_image --image "$stage/compact-image/system.raw.img" > "$stage/avb-info.txt"
python3 "$stage/inputs/tools/stage_tcl_ime_footer_image57.py" inside-check --stage "$stage"
python3 - "$stage" <<'PYFOOTER'
import json,re,sys
from pathlib import Path
s=Path(sys.argv[1]);sys.path.insert(0,str(s/'inputs/tools'));import ime_footer_image57_contract as c
m=json.loads((s/'staging.json').read_text());raw=s/'compact-image/system.raw.img';info=(s/'avb-info.txt').read_text()
if m['image']!=57 or m['baseline_image']!=56 or raw.stat().st_size!=c.PARTITION:raise ValueError('Wrong identity/partition')
for regex in [r'FEC num roots:\s+0\s*$',r'FEC offset:\s+0\s*$',r'FEC size:\s+0 bytes\s*$',r'Algorithm:\s+SHA256_RSA2048\s*$',r'Hash Algorithm:\s+sha1\s*$',r'Tree Size:\s+[1-9][0-9]* bytes']:
 if not re.search(regex,info,re.M):raise ValueError('AVB disposition differs '+regex)
if int((s/'avb-max-image-bytes.txt').read_text())!=828018688:raise ValueError('AVB payload capacity changed')
r=dict(image=57,baseline_image=56,base_raw_sha256=c.BASE,raw_bytes=raw.stat().st_size,raw_sha256=c.sha(raw),staging_sha256=c.sha(s/'staging.json'),proposal_sha256=c.PROPOSAL,packet_sha256=m['packet_sha256'],avb_verified=True,signed_hashtree_verified=True,optional_fec=False,max_avb_payload_bytes=828018688,avb_info_sha256=c.sha(s/'avb-info.txt'),avb_verification_sha256=c.sha(s/'avb-verification.txt'),changed_file_closure=sorted(m['changed']),raw_closure_verified=False,installed=False)
c.dump(s/'outputs.json',r);print(json.dumps(r))
PYFOOTER
