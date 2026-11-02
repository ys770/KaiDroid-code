#!/usr/bin/env bash
# Coordinated module compilation only. No image or device operations.
set -eo pipefail
stage=${1:?Supply the prepared stage directory}
test -f "$stage/staging.json"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > >(tee "$stage/build.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
test "$(get_build_var PLATFORM_VERSION)" = 11
test "$(get_build_var TARGET_ARCH)" = arm
m -j12 framework-res framework-minus-apex
python3 - "$stage" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
stage = Path(sys.argv[1])
product = Path('/build/out-eng-02/target/product/n139dl/system/framework')
outputs = {}
for name in ('framework.jar', 'framework-res.apk'):
    target = stage / name
    with (product / name).open('rb') as src, target.open('xb') as dest:
        shutil.copyfileobj(src, dest)
    outputs[name] = hashlib.sha256(target.read_bytes()).hexdigest()
report = dict(outputs=outputs, installed=False, boot_preopt_closure_verified=False)
(stage / 'outputs.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
