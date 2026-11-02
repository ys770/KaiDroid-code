"""Stage camera52 retry02 with no FEC over immutable51; retain signed hashtree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = '/opt/kaidroid/kaidroid-build-20261023'
BASE = 'engineering-tcl-ime-picker-stage-51'
STAGE = 'engineering-camera-stage-52-retry02'
RAW = '2e9f11e0b5ddd2e91970ba32ac77109f7b786f607e28504244c4c3f9a8a4181e'
MANIFEST = '85422b3fef3aaf1c6aed3bed66361273753f3cab5d81ca87db79201f4680f8cf'
PARTITION = 834666496
CONTEXTS = '0ab9ae6b9f576bb798ffe55eedc0c3140dc5e5b56c0569149441875b108405be'
RUNTIME_CONTEXTS = '2ce3cc4612906934247dbd8de653066c0f036ec027105f4583b736807a0f0e9a'
POLICY = '0957520f073b0c8c030b6f2336938034c79e4288b59d42d55f6acfe051ea4408'
CONTEXT = b'/system/etc/kaidroid-camera(/.*)? u:object_r:vendor_file:s0\n'
DIRECTORY = 'etc/kaidroid-camera'
LIBRARY = DIRECTORY + '/libmmcamera2_stats_modules.so'
RC = 'etc/init/kaidroid-camera.rc'
FC = 'etc/selinux/plat_file_contexts'
PAYLOADS = {
    LIBRARY: '41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0',
    RC: '5432fe41994dae1caf317f6570e373eedeba79f449667faac85c68f91c2feafd',
}


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            result.update(block)
    return result.hexdigest()


def inventory(root):
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(folder) / name
            result[path.relative_to(root).as_posix()] = (
                ['link', os.readlink(path)] if path.is_symlink() else
                ['dir', path.stat().st_mode & 0o7777] if path.is_dir() else
                ['file', path.stat().st_mode & 0o7777, sha(path)])
    return result


def append_context(original):
    if b'kaidroid-camera' in original:
        raise ValueError('Camera label already present')
    return original + b'\n' + CONTEXT


def launcher():
    return '''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-camera-stage-52-retry02"
test -f "$stage/staging.complete"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
for name in ninja soong_build e2fsdroid; do
 if pgrep -x "$name" >/dev/null; then echo 'Build active' >&2; exit 1; fi
done
test -z "$(sudo docker ps -q)"
python3 "$stage/stage-check.py" --check-stage "$stage"
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
test "$(cat "$stage/container-image-id")" = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
sudo docker run -d --network none --name kaidroid-camera-image52-retry02 \\
 -v "$root:/build:ro" \\
 -v "$stage:/build/engineering-camera-stage-52-retry02:rw" \\
 kaidroid-build:20261023 bash /build/engineering-camera-stage-52-retry02/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def pack_config(original):
    key = 'avb_system_add_hashtree_footer_args='
    lines = original.splitlines()
    if sum(line.startswith(key) for line in lines) != 1 or '--do_not_generate_fec' in original:
        raise ValueError('Unexpected baseline AVB footer configuration')
    if original.count('/build/' + BASE + '/') != 2:
        raise ValueError('Unexpected baseline stage paths')
    lines = [line + ' --do_not_generate_fec' if line.startswith(key) else line for line in lines]
    return ('\n'.join(lines) + '\n').replace('/build/' + BASE + '/', '/build/' + STAGE + '/')


def compare(before, after):
    added = set(after) - set(before)
    changed = {name for name in before.keys() & after.keys() if before[name] != after[name]}
    if set(before) - set(after) or added != {DIRECTORY, LIBRARY, RC} or changed != {'build.prop', FC}:
        raise ValueError('Unexpected camera image delta')
    if after[DIRECTORY] != ['dir', 0o755]:
        raise ValueError('Wrong overlay directory mode')
    for name, pin in PAYLOADS.items():
        if after[name] != ['file', 0o644, pin]:
            raise ValueError('Wrong overlay payload or mode')
    for name in changed:
        if before[name][:2] != after[name][:2]:
            raise ValueError('Existing file mode/type changed')
    return added, changed


def check(stage):
    manifest = json.loads((stage / 'staging.json').read_text())
    if (stage / 'staging.complete').read_text().strip() != sha(stage / 'staging.json'):
        raise ValueError('Incomplete stage')
    if manifest['image'] != 52 or manifest['base_raw_sha256'] != RAW or manifest['base_manifest_sha256'] != MANIFEST:
        raise ValueError('Wrong stage identity')
    for name, pin in manifest['controls'].items():
        if sha(stage / name) != pin:
            raise ValueError('Control drift: ' + name)
    base = stage.parent / BASE
    if sha(base / 'staging.json') != MANIFEST or sha(base / 'compact-image/system.raw.img') != RAW:
        raise ValueError('Immutable51 drift')
    before = inventory(base / 'compact-system')
    after = inventory(stage / 'compact-system')
    if before != json.loads((stage / 'baseline-system-inventory.json').read_text()) or after != json.loads((stage / 'system-inventory.json').read_text()):
        raise ValueError('Tree drift')
    roots = json.loads((stage / 'root-inventory.json').read_text())
    if inventory(base / 'compact-root') != roots or inventory(stage / 'compact-root') != roots:
        raise ValueError('Root tree changed')
    compare(before, after)
    if (stage / 'system_image_info.compact.txt').read_text() != pack_config((base / 'system_image_info.compact.txt').read_text()):
        raise ValueError('Unexpected image configuration delta')
    old = (base / 'compact-system/build.prop').read_bytes()
    if old.splitlines().count(b'ro.kaidroid.image=51') != 1 or (stage / 'compact-system/build.prop').read_bytes() != old.replace(b'ro.kaidroid.image=51', b'ro.kaidroid.image=52'):
        raise ValueError('Unexpected property change')
    for source, target in [(base / 'file_contexts.txt', stage / 'file_contexts.txt'),
                           (base / 'compact-system' / FC, stage / 'compact-system' / FC)]:
        if target.read_bytes() != append_context(source.read_bytes()):
            raise ValueError('Context merge differs')
    if shutil.disk_usage(stage).free < 2 * PARTITION + 2 * 1024**3:
        raise ValueError('Insufficient pack margin')


def prepare(root, bundle, builder):
    if os.name != 'posix' or os.geteuid() != 1000 or os.getegid() != 1000 or str(root.resolve()) != ROOT:
        raise ValueError('Require exact Linux build root and builder1000')
    base, output = root / BASE, root / STAGE
    if output.exists():
        raise FileExistsError(output)
    for name in ['ninja', 'soong_build', 'e2fsdroid']:
        if subprocess.run(['pgrep', '-x', name], capture_output=True).returncode != 1:
            raise ValueError('Build active or observation failed')
    if subprocess.check_output(['sudo', 'docker', 'ps', '-q'], text=True).strip():
        raise ValueError('Active container')
    if sha(base / 'staging.json') != MANIFEST or (base / 'build.exit').read_text().strip() != '0' or sha(base / 'compact-image/system.raw.img') != RAW:
        raise ValueError('Wrong immutable51')
    for name, pin in PAYLOADS.items():
        if sha(bundle / 'system' / name) != pin:
            raise ValueError('Unreviewed camera payload')
    if (bundle / 'file_contexts.fragment').read_bytes() != CONTEXT:
        raise ValueError('Wrong label fragment')
    system = base / 'compact-system'
    if sha(base / 'file_contexts.txt') != CONTEXTS or sha(system / FC) != RUNTIME_CONTEXTS or sha(system / 'etc/selinux/plat_sepolicy.cil') != POLICY:
        raise ValueError('Unexpected contexts/policy')
    if b'(allow init vendor_file (file (mounton)))' not in (system / 'etc/selinux/plat_sepolicy.cil').read_bytes():
        raise ValueError('Required existing init mount policy missing')
    before, roots = inventory(system), inventory(base / 'compact-root')
    if before != json.loads((base / 'system-inventory.json').read_text()) or roots != json.loads((base / 'root-inventory.json').read_text()):
        raise ValueError('Baseline inventory changed')
    config = (base / 'system_image_info.compact.txt').read_text()
    props = (system / 'build.prop').read_bytes()
    if config.count('/build/' + BASE + '/') != 2 or props.splitlines().count(b'ro.kaidroid.image=51') != 1:
        raise ValueError('Wrong configuration/revision')
    if shutil.disk_usage(root).free < 4 * PARTITION + 2 * 1024**3:
        raise ValueError('Insufficient copy/image space')
    output.mkdir()
    for tree in ['compact-system', 'compact-root']:
        shutil.copytree(base / tree, output / tree, symlinks=True)
    target = output / 'compact-system'
    (target / DIRECTORY).mkdir(mode=0o755)
    for name in PAYLOADS:
        shutil.copyfile(bundle / 'system' / name, target / name)
        (target / name).chmod(0o644)
    (target / 'build.prop').write_bytes(props.replace(b'ro.kaidroid.image=51', b'ro.kaidroid.image=52'))
    (target / FC).write_bytes(append_context((system / FC).read_bytes()))
    (output / 'file_contexts.txt').write_bytes(append_context((base / 'file_contexts.txt').read_bytes()))
    (output / 'system_image_info.compact.txt').write_text(pack_config(config))
    (output / 'compact-image').mkdir()
    after = inventory(target)
    added, changed = compare(before, after)
    (output / 'build.sh').write_bytes(builder.read_bytes().replace(b'\r\n', b'\n'))
    (output / 'launch.sh').write_text(launcher())
    shutil.copyfile(__file__, output / 'stage-check.py')
    for name, value in [('baseline-system-inventory.json', before), ('system-inventory.json', after), ('root-inventory.json', roots)]:
        (output / name).write_text(json.dumps(value, indent=2) + '\n')
    controls = ['build.sh', 'launch.sh', 'stage-check.py', 'file_contexts.txt', 'system_image_info.compact.txt', 'baseline-system-inventory.json', 'system-inventory.json', 'root-inventory.json']
    report = dict(image=52, baseline_image=51, base_raw_sha256=RAW, base_manifest_sha256=MANIFEST,
                  added=sorted(added), changed=sorted(changed), controls={name: sha(output / name) for name in controls},
                  camera_apk_included=False, policy_changed=False, vendor_written=False, installed=False,
                  optional_fec=False, signed_hashtree_required=True)
    (output / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'staging.complete').write_text(sha(output / 'staging.json') + '\n')
    check(output)
    print(json.dumps(report))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-stage', type=Path)
    for name in ['root', 'bundle', 'build-script']:
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    if args.check_stage:
        check(args.check_stage)
    elif all([args.root, args.bundle, args.build_script]):
        prepare(args.root, args.bundle, args.build_script)
    else:
        parser.error('Require --check-stage or --root/--bundle/--build-script')
