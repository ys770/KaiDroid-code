#!/usr/bin/env bash
# Build and preserve the installed framework/preopt closure; no device writes.
set -eo pipefail
stage=/build/softkey-closure-build01
mkdir "$stage"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
python3 - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('/build')
baseline = root/'engineering-title-stage-37/compact-system'
product = root/'out-eng-02/target/product/n139dl/system'
stage = root/'softkey-closure-build01'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(product/'framework/framework.jar') == 'b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f'
assert sha(product/'framework/framework-res.apk') == '42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
assert sha(root/'aosp/frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java') == 'eae4f86569e8ea885a0a2620c99216b50637de8e0d4424b0747773e142448afc'
files = sorted(p.relative_to(baseline).as_posix() for p in (baseline/'framework').rglob('*') if p.is_file() and not p.is_symlink() and p.suffix in ('.art','.oat','.odex','.vdex'))
files += ['framework/framework-res.apk','framework/framework.jar','framework/services.jar','framework/ethernet-service.jar','framework/com.android.location.provider.jar']
assert len(files) == len(set(files))
assert all((product/p).is_file() for p in files)
(stage/'files.json').write_text(json.dumps(files, indent=2)+'\n')
(stage/'targets.txt').write_text(''.join(str(product/p)+'\n' for p in files))
(stage/'before.json').write_text(json.dumps({p:sha(product/p) for p in files}, indent=2)+'\n')
PY
source build/envsetup.sh
lunch kaidroid_n139dl-eng
mapfile -t targets < "$stage/targets.txt"
m -j8 "${targets[@]}"
python3 - <<'PY'
import hashlib, json, shutil
from pathlib import Path
stage = Path('/build/softkey-closure-build01')
product = Path('/build/out-eng-02/target/product/n139dl/system')
files = json.loads((stage/'files.json').read_text())
result = {}
for name in files:
    source, target = product/name, stage/'output'/name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    result[name] = hashlib.sha256(target.read_bytes()).hexdigest()
assert result['framework/framework.jar'] == 'b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f'
assert result['framework/framework-res.apk'] == '42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
(stage/'outputs.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps(result, indent=2))
PY
