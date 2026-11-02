"""Prepare an isolated SystemUI build on the Linux host; never launches Docker."""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

SOURCE = 'frameworks/base/packages/SystemUI/src/com/android/systemui/statusbar/policy/AccessPointControllerImpl.java'
INTERMEDIATES = 'soong/.intermediates/frameworks/base/packages/SystemUI'
APK = 'SystemUI/android_common/SystemUI.apk'
ORIGINAL = '403fc9a2105b97a941cdab6871fa9441caa89d9d9214f5606533c5b1c9cdbce1'
BASE_APK = '203f2f316c48a354fc5ee2e0477da35b97b78604e63a2ae5e9ca9778719e5586'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def prepare(root, candidate, stage, dependency_modules=None):
    root = root.resolve(strict=True)
    stage = stage.absolute()
    if stage.parent != root or stage.exists():
        raise ValueError('Require a new direct child of the build root')
    source = root/'aosp'/SOURCE
    original_apk = root/'out-eng-02'/INTERMEDIATES/APK
    if sha(source) != ORIGINAL or sha(original_apk) != BASE_APK:
        raise ValueError('Current source or SystemUI APK differs from reviewed baseline')
    stage.mkdir()
    inputs = stage/'inputs'
    inputs.mkdir()
    shutil.copy2(source, inputs/'AccessPointControllerImpl.original.java')
    candidate_bytes = candidate.read_bytes().replace(b'\r\n', b'\n')
    (inputs/'AccessPointControllerImpl.java').write_bytes(candidate_bytes)
    shutil.copy2(original_apk, inputs/'SystemUI.original.apk')
    shutil.copy2(root/'out-eng-02/soong/build.ninja', inputs/'build.ninja.original')
    subprocess.run(['cp','--reflink=auto','-a',str(root/'out-eng-02'/INTERMEDIATES),
                    str(stage/'intermediates')],check=True)
    # SettingsLib's resource lists predate rebuilt AndroidX resources. Their
    # regeneration is a real dependency of SystemUI, so isolate these too.
    settings = 'soong/.intermediates/frameworks/base/packages/SettingsLib'
    subprocess.run(['cp','--reflink=auto','-a',str(root/'out-eng-02'/settings),
                    str(stage/'settingslib-intermediates')],check=True)
    extra_mounts = []
    if dependency_modules:
        modules = json.loads(dependency_modules.read_text())
        if not isinstance(modules,list) or len(modules) != len(set(modules)):
            raise ValueError('Require a unique module path list')
        for module in sorted(modules):
            if not re.fullmatch(r'[A-Za-z0-9_.+/-]+',module) or any(
                    part in ('','..','.') for part in module.split('/')):
                raise ValueError('Invalid dependency module path')
            subtree = 'soong/.intermediates/'+module
            if any(subtree == parent or subtree.startswith(parent+'/')
                   for parent in (INTERMEDIATES,settings)):
                continue
            destination = stage/'dependency-intermediates'/str(len(extra_mounts))
            destination.parent.mkdir(exist_ok=True)
            subprocess.run(['cp','--reflink=auto','-a',str(root/'out-eng-02'/subtree),
                            str(destination)],check=True)
            extra_mounts.append(dict(path=subtree,copy=destination.relative_to(stage).as_posix()))
    logs = stage/'ninja'
    logs.mkdir()
    for name in ('.ninja_log','.ninja_deps'):
        shutil.copy2(root/'out-eng-02'/name,logs/name)
    # The final root-scope assignment redirects Ninja's bookkeeping into the stage.
    (inputs/'query.ninja').write_text('pool highmem_pool\n  depth = 1\n'
        'subninja /build/out-eng-02/soong/build.ninja\n'
        f'builddir = /build/{stage.name}/ninja\n')
    manifest = dict(source=SOURCE,original_source_sha256=ORIGINAL,
        candidate_source_sha256=sha(inputs/'AccessPointControllerImpl.java'),
        baseline_apk_sha256=BASE_APK,
        ninja_manifest_sha256=sha(inputs/'build.ninja.original'),
        stage=str(stage),shared_outputs_writable=False,launched=False,
        copied_output_subtrees=[INTERMEDIATES, settings]+[m['path'] for m in extra_mounts],
        enumerated_dependency_modules=modules if dependency_modules else [],
        target='/build/out-eng-02/'+INTERMEDIATES+'/'+APK,
        output_closure='Signed SystemUI APK only; current installed folder contains no preopt artifacts.',
        inputs={p.name:sha(p) for p in inputs.iterdir() if p.is_file()})
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    build = '''#!/usr/bin/env bash
set -euo pipefail
stage=/build/STAGE
test ! -e "$stage/build.exit"
exec > "$stage/build.log" 2>&1
trap 'result=$?; printf "%s\\n" "$result" > "$stage/build.exit"' EXIT
cd /build/aosp
export JAVA_HOME=/build/aosp/prebuilts/jdk/jdk11/linux-x86
export ANDROID_JAVA_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
python3 - "$stage" <<'PY'
import hashlib,json,sys
from pathlib import Path
s=Path(sys.argv[1]);m=json.loads((s/'staging.json').read_text())
for name,digest in m['inputs'].items():
 assert hashlib.sha256((s/'inputs'/name).read_bytes()).hexdigest()==digest,name
assert hashlib.sha256(Path('/build/out-eng-02/soong/build.ninja').read_bytes()).hexdigest()==m['ninja_manifest_sha256']
assert hashlib.sha256(Path('/build/aosp/SOURCE').read_bytes()).hexdigest()==m['candidate_source_sha256']
PY
prebuilts/build-tools/linux-x86/bin/ninja -f "$stage/inputs/query.ninja" -n -d explain -v TARGET > "$stage/dependency-plan.log" 2>&1
prebuilts/build-tools/linux-x86/bin/ninja -f "$stage/inputs/query.ninja" -j4 TARGET
python3 - "$stage" <<'PY'
import hashlib,json,shutil,sys,zipfile
from pathlib import Path
s=Path(sys.argv[1]);p=s/'intermediates/APK'
out=s/'output';out.mkdir();shutil.copy2(p,out/'SystemUI.apk')
def entries(path):
 with zipfile.ZipFile(path) as z:
  assert len(z.namelist())==len(set(z.namelist()))
  return {n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if not n.endswith('/')}
before=entries(s/'inputs/SystemUI.original.apk');after=entries(p)
changed=sorted(n for n in before.keys()|after.keys() if before.get(n)!=after.get(n))
unexpected=[n for n in changed if not n.startswith('META-INF/') and not (n.startswith('classes') and n.endswith('.dex'))]
assert not unexpected,unexpected
assert any(n.endswith('.dex') for n in changed),'No code change produced'
result=dict(apk_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),bytes=p.stat().st_size,
 changed_entries=changed,noncode_entries_preserved=True,installed=False,
 closure=[dict(path='SystemUI.apk',sha256=hashlib.sha256(p.read_bytes()).hexdigest())])
(s/'outputs.json').write_text(json.dumps(result,indent=2)+'\\n');print(json.dumps(result))
PY
'''.replace('STAGE',stage.name).replace('SOURCE',SOURCE).replace('TARGET',manifest['target']).replace('APK',APK)
    (stage/'build.sh').write_text(build)
    launcher = '''#!/usr/bin/env bash
set -euo pipefail
root=ROOT
stage="$root/STAGE"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
if pgrep -x ninja >/dev/null || pgrep -x soong_build >/dev/null; then
  echo 'A shared build is active; stop before launch.' >&2
  exit 1
fi
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
sudo docker run -d --name kaidroid-STAGE \\
  -v "$root:/build:ro" \\
  -v "$stage:/build/STAGE:rw" \\
  -v "$stage/intermediates:/build/out-eng-02/INTERMEDIATES:rw" \\
  -v "$stage/settingslib-intermediates:/build/out-eng-02/soong/.intermediates/frameworks/base/packages/SettingsLib:rw" \\
EXTRA_MOUNTS
  -v "$stage/inputs/AccessPointControllerImpl.java:/build/aosp/SOURCE:ro" \\
  kaidroid-build:20261023 bash /build/STAGE/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''.replace('ROOT',str(root)).replace('STAGE',stage.name).replace('INTERMEDIATES',INTERMEDIATES).replace('SOURCE',SOURCE)
    launcher = launcher.replace('EXTRA_MOUNTS\n',''.join(
        f'  -v "$stage/{m["copy"]}:/build/out-eng-02/{m["path"]}:rw" \\\n'
        for m in extra_mounts))
    (stage/'launch.sh').write_text(launcher)
    print(json.dumps(manifest))


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('root','candidate','stage'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--dependency-modules',type=Path)
    a=p.parse_args()
    prepare(a.root,a.candidate,a.stage,a.dependency_modules)
