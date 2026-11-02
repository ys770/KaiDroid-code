#!/usr/bin/env bash
# Coordinated module-only build; no device or image operation.
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
m -j12 PermissionController
python3 - "$stage" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
stage = Path(sys.argv[1])
source = Path('/build/out-eng-02/target/product/n139dl/system/priv-app/PermissionController/PermissionController.apk')
with source.open('rb') as src, (stage / 'PermissionController.apk').open('xb') as dst:
    shutil.copyfileobj(src, dst)
report = dict(apk_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), bytes=source.stat().st_size,
              source=str(source), installed=False, parity_verified=False)
(stage / 'outputs.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
