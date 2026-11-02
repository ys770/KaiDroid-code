#!/usr/bin/env bash
# Resource-only compile/export in the owned copy; hardware launches once.
set -euo pipefail
stage=/build/tcl-scrollbar-build01
test -f "$stage/preparation.complete"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
export PYTHONDONTWRITEBYTECODE=1
python3 "$stage/disk-monitor.py" check --root /build --stage "$stage" --phase pre-frontend
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j2 nothing > "$stage/frontend.log" 2>&1
python3 - "$stage" <<'PYGRAPH'
import json,re,sys
from pathlib import Path
s=Path(sys.argv[1]);sys.path.insert(0,str(s))
import tcl_scrollbar_build_contract as c
text=Path('/build/out-eng-02/soong/build.ninja').read_text().replace('$\n','')
found={}
for name in c.OVERLAY:
 needle='frameworks/base/core/res/res/'+name
 blocks=[b.split('\n',1)[0] for b in re.split(r'(?m)^(?=build )',text)
         if needle in b and 'aapt2' in b.split('\n',1)[0].lower()]
 if not blocks:raise ValueError('Actual resource compiler graph omits '+needle)
 found[needle]=blocks
c.dump(s/'source-graph.json',dict(required_sources=found,resource_only=True))
PYGRAPH
mapfile -t targets < "$stage/targets.txt"
test "${#targets[@]}" = 1
prebuilts/build-tools/linux-x86/bin/ninja -f "$OUT_DIR/combined-kaidroid_n139dl.ninja" -n -d explain -v "${targets[@]}" > "$stage/dependency-plan.log" 2>&1
python3 - "$stage" <<'PYPLAN'
import re,sys
from pathlib import Path
s=Path(sys.argv[1]);sys.path.insert(0,str(s))
import tcl_scrollbar_build_contract as c
lines=(s/'dependency-plan.log').read_text().splitlines()
commands=[line for line in lines if re.match(r'^\[\d+/\d+\] ',line)]
if not commands:raise ValueError('No resource build commands; inspect source mtimes/graph')
if any(re.search(r'\b(?:javac|turbine|dex2oat|clang|clang\+\+|ld\.lld|hiddenapi)\b',line) for line in commands):
 raise ValueError('Single resource APK plan contains Java/native/boot compilation')
c.dump(s/'resource-plan.json',dict(target=c.TARGET,commands=commands,plan_sha256=c.sha(s/'dependency-plan.log'),review_required=True))
PYPLAN
python3 "$stage/disk-monitor.py" await-plan --root /build --stage "$stage"
python3 "$stage/disk-monitor.py" check --root /build --stage "$stage" --phase pre-ninja
prebuilts/build-tools/linux-x86/bin/ninja -f "$OUT_DIR/combined-kaidroid_n139dl.ninja" -j2 "${targets[@]}"
python3 "$stage/disk-monitor.py" check --root /build --stage "$stage" --phase pre-export
python3 - "$stage" <<'PYEXPORT'
import json,shutil,sys,zipfile
from pathlib import Path
s=Path(sys.argv[1]);sys.path.insert(0,str(s))
import tcl_scrollbar_build_contract as c
spec=c.load_stage(Path('/build'),s);c.verify_inputs(s,spec)
product=s/'out/target/product/n139dl/system/framework/framework-res.apk'
if product.resolve(strict=True)!=product or c.sha(product)==c.BASE:raise ValueError('No new resource APK')
with zipfile.ZipFile(product) as apk:
 if any(n.startswith('classes') and n.endswith('.dex') for n in apk.namelist()):raise ValueError('Unexpected framework-res executable DEX')
for name,pin in spec['retained_product'].items():
 if c.sha(s/'out/target/product/n139dl/system'/name)!=pin:raise ValueError('Non-resource installed output changed: '+name)
out=s/'output';out.mkdir();(out/'framework').mkdir()
shutil.copy2(product,out/'framework/framework-res.apk')
if c.sha(product)!=c.sha(out/'framework/framework-res.apk'):raise ValueError('Export copy differs')
c.dump(s/'outputs.json',dict(files={'framework/framework-res.apk':c.sha(product)},
 baseline_framework_res_sha256=c.BASE,source_manifest_sha256=c.sha(s/'staging.json'),
 source_graph_sha256=c.sha(s/'source-graph.json'),plan_review_sha256=c.sha(s/'plan-review.json'),
 resource_only=True,retained_product_unchanged=True,cache_preservation_pending=True,
 compiled_resource_gate_pending=True,signature_verification_pending=True,installed=False,full_parity=False))
PYEXPORT
