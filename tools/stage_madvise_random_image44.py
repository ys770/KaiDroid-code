"""Prepare exact image43 plus a DEX read-ahead hint; never build or flash."""
import argparse
import json
from pathlib import Path
import shutil

from stage_lazy_bubbles_image43 import inventory, sha

BASE_RAW = 'e47b675475c4979b73aae7ef3f73561a5bf34f1ba530d1be00941534164954ee'
SOURCE_GATE = 'be131eaae6583bcd0717747d530781b51791eff68653fa22b0d7087cc42a944f'
BASE_NAME = 'engineering-lazy-bubbles-stage-43'
STAGE_NAME = 'engineering-madvise-random-stage-44'
PROPERTY = b'dalvik.vm.madvise-random=true'


def candidate_properties(original):
    if original.splitlines().count(b'ro.kaidroid.image=43') != 1:
        raise ValueError('Require exact image43 revision')
    if any(line.strip().startswith(b'dalvik.vm.madvise-random=') for line in original.splitlines()):
        raise ValueError('Property already set in baseline build.prop')
    if not original.endswith(b'\n'):
        raise ValueError('Unexpected build.prop final newline')
    return original.replace(b'ro.kaidroid.image=43', b'ro.kaidroid.image=44') + PROPERTY + b'\n'


def stage(root, build_script, source_gate):
    root = root.resolve(strict=True)
    base, out = root/BASE_NAME, root/STAGE_NAME
    if out.exists():
        raise FileExistsError(out)
    if sha(source_gate) != SOURCE_GATE:
        raise ValueError('Source review gate changed')
    gate = json.loads(source_gate.read_text())
    if not gate['source_review_supported'] or gate['image43_sha256'] != BASE_RAW:
        raise ValueError('Source gate does not match baseline')
    if (base/'build.exit').read_text().strip() != '0' or sha(base/'compact-image/system.raw.img') != BASE_RAW:
        raise ValueError('Require successful exact image43 base')
    before, root_before = inventory(base/'compact-system'), inventory(base/'compact-root')
    original = (base/'compact-system/build.prop').read_bytes()
    candidate = candidate_properties(original)
    for tree in ('compact-system','compact-root'):
        for path in (base/tree).rglob('*.prop'):
            if path.is_file() and not path.is_symlink():
                if any(line.strip().startswith(b'dalvik.vm.madvise-random=') for line in path.read_bytes().splitlines()):
                    raise ValueError('Baseline staged property override: '+str(path))
    out.mkdir()
    for name in ('compact-system','compact-root'):
        shutil.copytree(base/name, out/name, symlinks=True)
    (out/'compact-image').mkdir()
    (out/'compact-system/build.prop').write_bytes(candidate)
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    config = (base/'system_image_info.compact.txt').read_text()
    if config.count('/build/'+BASE_NAME+'/') != 2:
        raise ValueError('Unexpected image packing config')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/'))
    after = inventory(out/'compact-system')
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    if changed != {'build.prop'}:
        raise ValueError('Unexpected payload changes')
    if before != inventory(base/'compact-system') or root_before != inventory(base/'compact-root'):
        raise ValueError('Baseline stage mutated')
    if root_before != inventory(out/'compact-root'):
        raise ValueError('Root payload changed')
    report = dict(image=44, baseline_image=43, base_raw_sha256=BASE_RAW,
        baseline_entries=len(before), baseline_stage_unchanged=True, root_unchanged=True,
        changed={'build.prop':dict(before=before['build.prop'],after=after['build.prop'])},
        source_gate_sha256=SOURCE_GATE, property='dalvik.vm.madvise-random', candidate_value='true',
        all_apks_binaries_and_provider_unchanged=True, retained_data_apks_outside_image=True,
        system_partition_bytes=834666496, avb_required=True, raw_uid_gid_xattr_verification_required=True,
        built=False, installed=False, runtime_hint_application_verified=False,
        measured_ram_or_latency_improvement=False)
    for name, value in [('staging.json',report),('system-inventory.json',after),('root-inventory.json',root_before)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n')
    shutil.copyfile(source_gate,out/'source-gate.json')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    launcher = '''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-madvise-random-stage-44"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
if pgrep -x ninja >/dev/null || pgrep -x soong_build >/dev/null || pgrep -x e2fsdroid >/dev/null; then
  echo 'Another build is active; stop before launch.' >&2
  exit 1
fi
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
sudo docker run -d --name kaidroid-memory-madvise-random-image44 \\
  -v "$root:/build:ro" \\
  -v "$stage:/build/engineering-madvise-random-stage-44:rw" \\
  kaidroid-build:20261023 bash /build/engineering-madvise-random-stage-44/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''
    (out/'launch.sh').write_text(launcher)
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root','build-script','source-gate'):
        parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    stage(args.root,args.build_script,args.source_gate)
