#!/usr/bin/env bash
set -eo pipefail
stage=${1:?Unique test build output directory}
test ! -e "$stage"
mkdir "$stage"
exec > >(tee "$stage/build.log") 2>&1
trap 'result=$?; printf "%s\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export OUT_DIR=/build/out-eng-02
source build/envsetup.sh
lunch kaidroid_n139dl-eng
m -j12 KaiDroidTelephonyAttachmentTests
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys
from pathlib import Path
stage=Path(sys.argv[1]);root=Path('/build/out-eng-02/target/product/n139dl/testcases/KaiDroidTelephonyAttachmentTests')
files=list(root.rglob('KaiDroidTelephonyAttachmentTests.apk'))
assert len(files)==1,files
target=stage/'KaiDroidTelephonyAttachmentTests.apk'
with files[0].open('rb') as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
(stage/'output.json').write_text(json.dumps(dict(sha256=hashlib.sha256(target.read_bytes()).hexdigest(),source=str(files[0]),executed=False),indent=2)+'\n')
PY
