#!/usr/bin/env bash
# Isolated accepted48 dialog IME policy; private OverlayFS output only. Never pack/flash.
set -eo pipefail
stage=/build/STAGE_NAME
test ! -e "$stage/build.exit"
test ! -e "$stage/build.log"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
export JAVA_HOME=/build/aosp/prebuilts/jdk/jdk11/linux-x86
export ANDROID_JAVA_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:/build/aosp/prebuilts/gdb/linux-x86/bin:$PATH"
python2.7 -c 'import zlib; assert zlib.decompress(zlib.compress(str(123))) == str(123)'
python3 - "$stage" <<'PY'
import hashlib,json,sys
from pathlib import Path
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text())
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
for n,d in json.loads((s/'control-inputs.json').read_text()).items():assert sha(s/n)==d,n
for n,d in m['baseline_pins'].items():assert sha(Path('/baseline')/n)==d,n
for n,d in m['inputs'].items():assert sha(s/'inputs'/n)==d,n
for n,d in m['overlay'].items():assert sha(Path('/build/aosp/frameworks/base')/n)==d,n
PY
python3 "$stage/disk-monitor.py" check --stage "$stage" --phase pre-frontend
source build/envsetup.sh
lunch kaidroid_n139dl-eng
# Normal frontend regeneration sees the copied directory's new Java source.
# Do not use the menu-only combined graph directly before this step.
m -j4 nothing > "$stage/frontend.log" 2>&1
python3 - "$stage" <<'PY'
import json,re,sys
from pathlib import Path
s=Path(sys.argv[1]);graph=Path('/build/out-eng-02/soong/build.ninja')
needles=['frameworks/base/core/java/android/widget/MenuBar.java',
 'frameworks/base/core/java/com/android/internal/app/TclResolverPresentation.java',
 'frameworks/base/core/java/android/app/TctDialog.java',
 'frameworks/base/core/java/android/widget/TctDialogMessage.java',
 'frameworks/base/core/java/android/widget/KeypadImeController.java']
text=graph.read_text().replace('$\n','')
hits={}
for needle in needles:
 matched=[]
 for block in re.split(r'(?m)^(?=build )',text):
  if needle in block and ('javac' in block.split('\n',1)[0] or 'turbine' in block.split('\n',1)[0]):
   matched.append(block.split('\n',1)[0][:500])
 assert matched,'Regenerated Soong graph omits source: '+needle
 hits[needle]=matched
(s/'source-graph.json').write_text(json.dumps({'required_sources':hits,'runtime_verified':False},indent=2)+'\n')
PY
mapfile -t targets < "$stage/targets.txt"
prebuilts/build-tools/linux-x86/bin/ninja -f "$OUT_DIR/combined-kaidroid_n139dl.ninja" -n -d explain -v "${targets[@]}" > "$stage/dependency-plan.log" 2>&1
# Hardware reviews the actual plan/hash while this same container waits.
# No fixed task count or prior build's plan is treated as approval.
python3 "$stage/disk-monitor.py" await-plan --stage "$stage"
python3 "$stage/disk-monitor.py" check --stage "$stage" --phase pre-ninja
prebuilts/build-tools/linux-x86/bin/ninja -f "$OUT_DIR/combined-kaidroid_n139dl.ninja" -j4 "${targets[@]}"
python3 "$stage/disk-monitor.py" check --stage "$stage" --phase pre-export
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys,zipfile
from pathlib import Path
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text());product=Path('/build/out-eng-02/target/product/n139dl/system')
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
for n,d in m['baseline_pins'].items():assert sha(Path('/baseline')/n)==d,n
for n,d in m['art_apex'].items():assert sha(product/n)==d,n
for n in ('framework/framework-res.apk','framework/services.jar'):
 assert sha(product/n)==m['before_closure'][n],n
assert sha(product/'framework/framework.jar')!=m['before_closure']['framework/framework.jar']
# DEX must actually contain the new class, rather than merely a stale source list.
with zipfile.ZipFile(product/'framework/framework.jar') as jar:
 dex=[jar.read(n) for n in jar.namelist() if n.startswith('classes') and n.endswith('.dex')]
 assert any(b'Lcom/android/internal/app/TclResolverPresentation;' in b for b in dex),'Retained resolver class missing'
 assert any(b'setImeModeEnabled' in b for b in dex),'New owner API missing'
out=s/'output';out.mkdir();files={}
for n in m['closure']:
 p=out/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(product/n,p);files[n]=sha(p)
(s/'outputs.json').write_text(json.dumps(dict(files=files,baseline_image=m['baseline_image'],baseline_preserved=True,
 art_apex_unchanged=True,new_class_in_dex=True,scope='Accepted48 dialog owner policy only; preserve current APK/data-app/provider/memory changes',
 packed=False,installed=False,dialog_overlay_version=m['dialog_overlay_version'],
 plan_review_sha256=sha(s/'plan-review.json'),
 dialog_compiled_method_audit_pending=True,native_dialog_pixels_verified=False,
 layered_cache_preservation_pending=True),indent=2)+'\n')
PY
