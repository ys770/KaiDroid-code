#!/usr/bin/env bash
# Standalone media APK compilation, with no product selection or device changes.
set -eo pipefail
stage=${1:?Supply a fresh media stage}
test -f "$stage/staging.json"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
exec > >(tee "$stage/build.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
python3 - "$stage/staging.json" <<'PY'
import json, sys
assert json.load(open(sys.argv[1]))['media_apps'] is True
PY
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
test "$(get_build_var PLATFORM_VERSION)" = 11
test "$(get_build_var TARGET_ARCH)" = arm
m -j12 KaiDroidTclTclMusic KaiDroidTclTctSoundRecorder KaiDroidTclTctCamera
python3 - "$stage" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
stage = Path(sys.argv[1])
product = Path('/build/out-eng-02/target/product/n139dl/system/system_ext/priv-app')
outputs = []
for name in ('TclMusic', 'TctSoundRecorder', 'TctCamera'):
    module = 'KaiDroidTcl' + name
    source = product / module / (module + '.apk')
    target = stage / (module + '.apk')
    with source.open('rb') as src, target.open('xb') as dest:
        shutil.copyfileobj(src, dest)
    outputs.append(dict(module=module, source=str(source), bytes=target.stat().st_size,
                        sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
report = dict(outputs=outputs, installed=False, runtime_verified=False)
(stage / 'outputs.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
