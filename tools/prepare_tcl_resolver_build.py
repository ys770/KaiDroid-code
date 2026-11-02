"""Prepare an isolated chooser/wrap framework build. Never launch or pack an image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from prepare_option_menu42_build import idle, sha

BASE = 'engineering-madvise-random-stage-44'
CLONE = 'option-menu42-build02/out'
RAW = 'b9d55804123a82064e3e0c806767e119cf2d628929eeb9c9e1482d886a475471'
MENU = 'core/java/android/widget/MenuBar.java'
APP = 'core/java/com/android/internal/app'
PINS = {
    'aosp/frameworks/base/'+MENU: '73f871ffa9bda03951050d91cab118f6a8f6e663e1090fc68ce8767a1389cc26',
    'aosp/frameworks/base/'+APP+'/ChooserActivity.java': '8ce601b48e97871d2d68326bebce1c44673ed27a3512adad756e6c162daecc10',
    BASE+'/compact-image/system.raw.img': RAW,
    BASE+'/compact-system/system_ext/priv-app/SystemUI/SystemUI.apk': '5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708',
    BASE+'/compact-system/priv-app/TelephonyProvider/TelephonyProvider.apk': '704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
}


def prepare(root, overlay, contract, script, stage, baseline_image=44):
    base_name, clone_name, pins = BASE, CLONE, dict(PINS)
    expected_contract = '3d056c413cb31381e71b63f77544c519efda90367ced4025c4585c183fe423e5'
    if baseline_image == 45:
        base_name, clone_name = 'engineering-tcl-resolver-stage-45', 'tcl-resolver-build01/out'
        pins = {n.replace(BASE+'/', base_name+'/'): d for n, d in pins.items()}
        pins[base_name+'/compact-image/system.raw.img'] = '77b523c3504700d1b05fdf5eb82c54715cb7e790675e52b01bc52dc1f53491e2'
        pins[base_name+'/compact-system/framework/framework.jar'] = '5126b8f1c15c0ee17a5a6c472fa5bc58bab99cdcb400b286e19f73af949f7054'
        expected_contract = '43d44ff4b551ba18344aa511b2a9c228b4e75109e3ed17f1aa68b3270498b98c'
    elif baseline_image != 44:
        raise ValueError('Unreviewed baseline image')
    root = root.resolve(strict=True)
    stage = stage.absolute()
    if stage.parent != root or not re.fullmatch(r'tcl-resolver-build[0-9]+', stage.name) or stage.exists():
        raise ValueError('Require fresh direct-child tcl-resolver-buildNN stage')
    idle()
    running = subprocess.check_output(['sudo', 'docker', 'ps', '-q'], text=True).strip()
    if running:
        raise ValueError('Running container present; coordinate before staging')
    for name, digest in pins.items():
        if sha(root/name) != digest:
            raise ValueError('Baseline mismatch: '+name)
    if (root/base_name/'build.exit').read_text().strip() != '0':
        raise ValueError('Baseline packing incomplete')
    if (root/Path(clone_name).parent/'build.exit').read_text().strip() != '0':
        raise ValueError('Output clone build incomplete')
    spec = json.loads(contract.read_text())
    if spec['canonical_sha256'] != expected_contract:
        raise ValueError('Wrong reviewed overlay contract')
    expected = {MENU, APP+'/ChooserActivity.java', APP+'/TclResolverPresentation.java'}
    if set(spec['files']) != expected:
        raise ValueError('Unexpected overlay scope')
    canonical = hashlib.sha256(json.dumps(spec['files'], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if canonical != spec['canonical_sha256']:
        raise ValueError('Overlay file map changed')
    for name, digest in spec['files'].items():
        if sha(overlay/name) != digest:
            raise ValueError('Overlay mismatch: '+name)
    base = root/base_name/'compact-system'
    product = root/clone_name/'target/product/n139dl/system'
    closure = sorted(p.relative_to(base).as_posix() for p in (base/'framework').rglob('*')
                     if p.is_file() and not p.is_symlink() and p.suffix in ('.art', '.oat', '.odex', '.vdex'))
    closure += ['framework/'+name for name in ('framework.jar', 'framework-res.apk', 'services.jar',
                'ethernet-service.jar', 'com.android.location.provider.jar')]
    if len(set(closure)) != len(closure):
        raise ValueError('Duplicate export')
    before = {name: sha(base/name) for name in closure}
    if any(sha(product/name) != digest for name, digest in before.items()):
        raise ValueError('Image44 framework differs from clone42')
    apex = {p.relative_to(base).as_posix(): sha(p) for p in (base/'apex/com.android.art.release').rglob('*')
            if p.is_file() and not p.is_symlink() and p.suffix in ('.art', '.oat', '.vdex', '.jar')}
    if not apex or any(sha(product/name) != digest for name, digest in apex.items()):
        raise ValueError('ART APEX clone differs')
    allocated = int(subprocess.check_output(['du', '-sk', str(root/clone_name)]).split()[0])*1024
    if shutil.disk_usage(root).free < allocated*2+20*1024**3:
        raise ValueError('Insufficient isolated-build headroom')
    stage.mkdir()
    inputs = stage/'inputs'
    inputs.mkdir()
    shutil.copytree(root/'aosp/frameworks/base'/APP, inputs/'app', symlinks=True)
    if (inputs/'app/TclResolverPresentation.java').exists():
        raise ValueError('New class already in shared source; re-review required')
    for name in expected:
        target = inputs/'MenuBar.java' if name == MENU else inputs/'app'/Path(name).name
        shutil.copy2(overlay/name, target)
        # Reproducible archives use epoch mtimes. Ninja keys dirtiness on mtime,
        # so copied changed bytes must be newer than the retained output cache.
        os.utime(target, None)
    source_inventory = {p.relative_to(inputs).as_posix(): sha(p) for p in inputs.rglob('*') if p.is_file()}
    (stage/'clone-state.json').write_text(json.dumps({'state': 'copying'})+'\n')
    with (stage/'clone.log').open('wb') as log:
        proc = subprocess.Popen(['cp', '--reflink=auto', '-a', str(root/clone_name), str(stage/'out')], stdout=log, stderr=subprocess.STDOUT)
        (stage/'clone.pid').write_text(str(proc.pid)+'\n')
        if proc.wait():
            raise ValueError('Clone failed; retain and inspect existing stage')
    idle()
    for name, digest in before.items():
        copied = stage/'out/target/product/n139dl/system'/name
        if sha(copied) != digest or copied.stat().st_ino == (product/name).stat().st_ino:
            raise ValueError('Independent clone verification failed: '+name)
    manifest = dict(baseline_image=baseline_image, baseline_pins=pins, before_closure=before, art_apex=apex,
                    inputs=source_inventory, overlay=spec['files'], closure=closure,
                    shared_root_read_only=True, launched=False, installed=False)
    (stage/'staging.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (stage/'targets.txt').write_text(''.join('/build/out-eng-02/target/product/n139dl/system/'+n+'\n' for n in closure))
    (stage/'build.sh').write_text(script.read_text().replace('STAGE_NAME', stage.name), newline='\n')
    launcher = '''#!/usr/bin/env bash
set -euo pipefail
root=ROOT_PATH
stage="$root/STAGE_NAME"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
for name in ninja soong_build e2fsdroid; do
  if pgrep -x "$name" >/dev/null; then echo 'Build active; do not restart.' >&2; exit 1; fi
done
test -z "$(sudo docker ps -q)"
sudo docker run -d --name kaidroid-STAGE_NAME --network none \\
 -v "$root:/build:ro" -v "$root:/baseline:ro" \\
 -v "$stage:/build/STAGE_NAME:rw" -v "$stage/out:/build/out-eng-02:rw" \\
 -v "$stage/inputs/app:/build/aosp/frameworks/base/core/java/com/android/internal/app:ro" \\
 -v "$stage/inputs/MenuBar.java:/build/aosp/frameworks/base/core/java/android/widget/MenuBar.java:ro" \\
 kaidroid-build:20261023 bash /build/STAGE_NAME/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''.replace('ROOT_PATH', str(root)).replace('STAGE_NAME', stage.name)
    (stage/'launch.sh').write_text(launcher, newline='\n')
    controls = {n: sha(stage/n) for n in ('build.sh', 'launch.sh', 'targets.txt', 'staging.json')}
    (stage/'control-inputs.json').write_text(json.dumps(controls, indent=2)+'\n')
    (stage/'clone-state.json').write_text('{"state":"complete"}\n')
    print(json.dumps({'stage': str(stage), 'launched': False, 'closure_files': len(closure)}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'overlay', 'contract', 'script', 'stage'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--baseline-image', type=int, choices=(44,45), default=44)
    a = p.parse_args()
    prepare(a.root, a.overlay, a.contract, a.script, a.stage, a.baseline_image)
