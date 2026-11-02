#!/usr/bin/env bash
# Build standalone app modules only, after coordinated staging. No image/device work.
set -eo pipefail
stage=${1:?Supply a fresh stage path}
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
m -j12 KaiDroidTclFPContacts KaiDroidTclFPMessaging KaiDroidTclGcsDialer KaiDroidTclTctSettings
python3 - "$stage" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
stage = Path(sys.argv[1])
product = Path('/build/out-eng-02/target/product/n139dl/system/system_ext/priv-app')
outputs = []
for name in ('FPContacts', 'FPMessaging', 'GcsDialer', 'TctSettings'):
    module = 'KaiDroidTcl' + name
    source = product / module / (module + '.apk')
    target = stage / (module + '.apk')
    with source.open('rb') as src, target.open('xb') as dest:
        shutil.copyfileobj(src, dest)
    outputs.append(dict(module=module, source=str(source), bytes=target.stat().st_size,
                        sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
report = dict(outputs=outputs, installed_on_device=False, parity_verified=False)
(stage / 'outputs.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
PY
