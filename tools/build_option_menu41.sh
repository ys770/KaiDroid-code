#!/usr/bin/env bash
# Parent-reviewed launcher only: isolated output clone, no shared output writes.
set -euo pipefail
stage=/build/STAGE_NAME
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export JAVA_HOME=/build/aosp/prebuilts/jdk/jdk11/linux-x86
export ANDROID_JAVA_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
python3 - "$stage" <<'PY'
import hashlib,json,sys
from pathlib import Path
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text())
for name,digest in m['inputs'].items():assert sha(s/name)==digest,name
for name,digest in m['baseline_pins'].items():assert sha(Path('/baseline')/name)==digest,name
assert sha(Path('/build/aosp')/'frameworks/base/core/java/android/widget/MenuBar.java')==m['candidate_sha256']
assert sha(Path('/build/out-eng-02/soong/build.ninja'))==m['shared_graph_sha256']
PY
mapfile -t targets < "$stage/targets.txt"
prebuilts/build-tools/linux-x86/bin/ninja -f "$stage/inputs/query.ninja" -n -d explain -v "${targets[@]}" > "$stage/dependency-plan.log" 2>&1
prebuilts/build-tools/linux-x86/bin/ninja -f "$stage/inputs/query.ninja" -j4 "${targets[@]}"
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys
from pathlib import Path
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text());product=Path('/build/out-eng-02/target/product/n139dl/system')
out=s/'output';out.mkdir();result={}
for name in m['closure']:
 target=out/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(product/name,target);result[name]=sha(target)
assert result['framework/framework.jar']!=m['framework_pins']['framework/framework.jar'],'Menu change absent'
for name in ('framework/framework-res.apk','framework/services.jar'):
 assert result[name]==m['framework_pins'][name],name
for name,digest in m['art_apex'].items():assert sha(product/name)==digest,name
for name,digest in m['baseline_pins'].items():assert sha(Path('/baseline')/name)==digest,name
(s/'outputs.json').write_text(json.dumps(dict(files=result,baseline_image40_preserved=True,art_apex_unchanged=True,
 scope='Only framework/preopt artifacts exported; provider68 and lazy SystemUI remain in immutable40 base',installed=False),indent=2)+'\n')
print(json.dumps(result,indent=2))
PY
