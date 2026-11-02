#!/usr/bin/env bash
# Container-only source overlays; no database or phone operations.
set -eo pipefail
stage=${1:?Unique build stage}
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > >(tee "$stage/build.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys
from pathlib import Path
stage=Path(sys.argv[1])
report=json.loads((stage/'report.json').read_text())
base=Path('/build/aosp/packages/providers/TelephonyProvider/src/com/android/providers/telephony')
for name,row in report['files'].items():
    assert hashlib.sha256((base/name).read_bytes()).hexdigest()==row['after'],name
product=Path('/build/out-eng-02/target/product/n139dl/system/priv-app/TelephonyProvider')
before={}
if product.exists():
    for source in product.rglob('*'):
        if not source.is_file():continue
        relative=source.relative_to(product)
        target=stage/'previous-output'/relative
        target.parent.mkdir(parents=True,exist_ok=True)
        with source.open('rb') as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
        before[str(relative)]=hashlib.sha256(target.read_bytes()).hexdigest()
(stage/'previous-output.json').write_text(json.dumps(before,indent=2)+'\n')
PY
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
test "$(get_build_var PLATFORM_VERSION)" = 11
test "$(get_build_var TARGET_ARCH)" = arm
m -j12 TelephonyProvider
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys
from pathlib import Path
stage=Path(sys.argv[1])
product=Path('/build/out-eng-02/target/product/n139dl/system/priv-app/TelephonyProvider')
assert (product/'TelephonyProvider.apk').is_file()
outputs=[]
for source in sorted(product.rglob('*')):
    if not source.is_file():continue
    relative=source.relative_to(product)
    target=stage/'output'/relative
    target.parent.mkdir(parents=True,exist_ok=True)
    with source.open('rb') as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
    outputs.append(dict(path=str(relative),sha256=hashlib.sha256(target.read_bytes()).hexdigest(),bytes=target.stat().st_size))
(stage/'outputs.json').write_text(json.dumps(dict(outputs=outputs,installed=False,database_modified=False),indent=2)+'\n')
print(json.dumps(outputs))
PY
