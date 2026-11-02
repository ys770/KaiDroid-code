#!/usr/bin/env bash
# Coordinated Wi-Fi field module build inside the existing Android11 build image.
# No system image, device command, cleanup or unrelated source staging.
set -eo pipefail
stage=${1:?Supply the prepared /build/ui-marquee-stage directory}
test -f "$stage/staging.json"
test ! -e "$stage/build.exit"
test ! -e "$stage/build.log"
exec > >(tee "$stage/build.log") 2>&1
trap 'build_result=$?; printf "%s\n" "$build_result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
test "$(get_build_var PLATFORM_VERSION)" = 11
test "$(get_build_var TARGET_ARCH)" = arm
m -j12 framework-wifi framework-minus-apex
python3 - "$stage" <<'PY'
import hashlib, json, shutil, sys
from pathlib import Path
stage = Path(sys.argv[1])
source = Path('/build/out-eng-02/target/product/n139dl/system/apex/com.android.wifi/javalib/framework-wifi.jar')
candidate = stage / 'framework-wifi.candidate.jar'
if candidate.exists():
    raise ValueError('Candidate output already exists')
shutil.copy2(source, candidate)
result = dict(framework_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
              framework_bytes=candidate.stat().st_size,
              target='framework-wifi framework-minus-apex', installed_on_device=False)
(stage / 'outputs.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
PY
