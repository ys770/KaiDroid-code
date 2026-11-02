#!/usr/bin/env bash
# Hardware-lane launch only. Export SystemUI APK; never pack or flash.
set -eo pipefail
stage=/build/STAGE_NAME
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
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
for n,d in m['overlay'].items():
 prefix,rel=n.split('/',1)
 source=Path('/build/aosp/frameworks/base')
 if prefix=='systemui-overlay':source=source/'packages/SystemUI'
 assert sha(source/rel)==d,n
PY
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j4 nothing > "$stage/frontend.log" 2>&1
python3 - "$stage" <<'PY'
import json,re,sys
from pathlib import Path
s=Path(sys.argv[1]);text=Path('/build/out-eng-02/soong/build.ninja').read_text().replace('$\n','')
sources=['frameworks/base/packages/SystemUI/src/com/android/systemui/'+n+'.java' for n in ('TclBatteryPresentation','TclBatteryInfo','TclBatteryMeterView')]
sources.append('frameworks/base/core/java/com/android/internal/app/TclResolverPresentation.java')
edges=[b for b in re.split(r'(?m)^(?=build )',text) if 'javac' in b.split('\n',1)[0] or 'turbine' in b.split('\n',1)[0]]
for n in sources:assert any(n in b for b in edges),'New source absent from Java graph: '+n
(s/'source-graph.json').write_text(json.dumps({'java_sources':sources,'all_present':True,'runtime_verified':False},indent=2)+'\n')
PY
m -j4 SystemUI
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
for n,d in m['framework_baseline'].items():assert sha(product/n)==d,'Framework dependency changed: '+n
apk=Path('/build/out-eng-02/soong/.intermediates/frameworks/base/packages/SystemUI/SystemUI/android_common/SystemUI.apk')
assert sha(apk)!=sha(s/'inputs/SystemUI.baseline.apk'),'Battery change absent'
with zipfile.ZipFile(apk) as archive:
 dex=[archive.read(n) for n in archive.namelist() if n.startswith('classes') and n.endswith('.dex')]
 for cls in ('TclBatteryPresentation','TclBatteryInfo','TclBatteryMeterView'):
  assert any(('Lcom/android/systemui/'+cls+';').encode() in b for b in dex),'New class absent: '+cls
out=s/'output';out.mkdir();shutil.copyfile(apk,out/'SystemUI.apk')
(s/'outputs.json').write_text(json.dumps(dict(apk_sha256=sha(out/'SystemUI.apk'),baseline_systemui_sha256=sha(s/'inputs/SystemUI.baseline.apk'),
 framework_dependencies_unchanged=True,baseline_preserved=True,new_battery_classes_in_dex=True,
 preexisting_unexported_profile_differences=m['preexisting_profile_differences'],
 export_scope='SystemUI APK only; compiled ABI/resource/manifest/signer review required before packaging',
 signer_verified=False,abi_verified=False,installed=False,runtime_verified=False,memory_saving_verified=False),indent=2)+'\n')
PY
