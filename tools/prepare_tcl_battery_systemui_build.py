"""Prepare an isolated SystemUI build after the hardware lane assigns a slot; never launch."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess

from prepare_option_menu42_build import idle, sha
from prepare_tcl_battery_retained_overlay import canonical

BASE = 'engineering-tcl-resolver-stage-45'
CLONE = 'tcl-resolver-build01/out'
SYSTEMUI = 'aosp/frameworks/base/packages/SystemUI'
APP = 'aosp/frameworks/base/core/java/com/android/internal/app'
MENU = 'aosp/frameworks/base/core/java/android/widget/MenuBar.java'
RAW = '77b523c3504700d1b05fdf5eb82c54715cb7e790675e52b01bc52dc1f53491e2'
FRAMEWORK = '5126b8f1c15c0ee17a5a6c472fa5bc58bab99cdcb400b286e19f73af949f7054'
PROFILE_PINS = {
    'framework/services.jar.prof': ('c310dfffa99ceb33a447bf0c4e22397ccb8b41dc73b6380e9c3fcda8cd53ea58',
                                    'b6eba97e359749713d1ab3735c177186c04bc54607c8ae7a4c4ff1e28a82a2ac'),
    'framework/services.jar.bprof': ('e7a0baaed707925fd0c479b90288060d86f8719f158511043113ddca88557fad',
                                     'aa9cb3867ee91a45547788fb39ebc69a518c8f85c80ded02fe53664148329aff'),
}
PINS = {
    BASE+'/compact-image/system.raw.img': RAW,
    BASE+'/compact-system/framework/framework.jar': FRAMEWORK,
    BASE+'/compact-system/system_ext/priv-app/SystemUI/SystemUI.apk': '5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708',
    MENU: '73f871ffa9bda03951050d91cab118f6a8f6e663e1090fc68ce8767a1389cc26',
    APP+'/ChooserActivity.java': '8ce601b48e97871d2d68326bebce1c44673ed27a3512adad756e6c162daecc10',
    SYSTEMUI+'/src/com/android/systemui/BatteryMeterView.java': 'c49da7f1e428f6897bab572af933be58fedfb502670b7c7679ab12aca838fd08',
    SYSTEMUI+'/src/com/android/systemui/statusbar/policy/BatteryController.java': '2193220d329e484be6326e7de21806f245b452e5b5debec34c739c204171f06c',
    SYSTEMUI+'/src/com/android/systemui/statusbar/policy/BatteryControllerImpl.java': '8cdb0af0f674f5e1e0ba8106265ff850bd3f534929968e89a76eaf261eff72a8',
    SYSTEMUI+'/res/layout/system_icons.xml': '9e305b936f24f2d4b1b217a7da203b028a182ecb5611159d460d16e12475a795',
    SYSTEMUI+'/src/com/android/systemui/statusbar/policy/AccessPointControllerImpl.java': '403fc9a2105b97a941cdab6871fa9441caa89d9d9214f5606533c5b1c9cdbce1',
    SYSTEMUI+'/src/com/android/systemui/bubbles/BubbleDataRepository.kt': '3f84f19dca7e4bb137634fed6b7393f50147ad04ee8ab4a92110e12cb7cb3ee9',
    SYSTEMUI+'/proguard.flags': 'b376baeed70297b70219eea0dff87e2797f52bc2d6591e8bb1a701e9dfea2a3e',
}


def prepare(root, overlay, contract, script, stage):
    root = root.resolve(strict=True)
    stage = stage.absolute()
    if stage.parent != root or stage.exists() or not re.fullmatch(r'tcl-battery-systemui-build[0-9]+', stage.name):
        raise ValueError('Require a fresh named direct-child stage')
    idle()
    if subprocess.check_output(['sudo', 'docker', 'ps', '-q'], text=True).strip():
        raise ValueError('Container active; coordinate the build slot first')
    spec = json.loads(contract.read_text())
    expected = {'systemui-overlay/'+n: d for n, d in spec['systemui_files'].items()}
    expected.update({'framework-overlay/'+n: d for n, d in spec['framework_files'].items()})
    if len(expected) != 35 or canonical(expected) != 'f9b2a24151389165964527159318ec249e83e127b593bdc561072a5d6ddb5288':
        raise ValueError('Wrong frozen combined source closure')
    for name, digest in expected.items():
        if (overlay/name).is_symlink() or sha(overlay/name) != digest:
            raise ValueError('Overlay mismatch: '+name)
    for name, digest in PINS.items():
        if sha(root/name) != digest:
            raise ValueError('Baseline changed: '+name)
    for name in (BASE, 'tcl-resolver-build01'):
        if (root/name/'build.exit').read_text().strip() != '0':
            raise ValueError('Incomplete baseline: '+name)
    for tree in (SYSTEMUI, APP):
        if any(p.is_symlink() for p in (root/tree).rglob('*')):
            raise ValueError('Review source symlinks before copying: '+tree)
    source = root/CLONE
    allocated = int(subprocess.check_output(['du', '-sk', str(source)]).split()[0])*1024
    if shutil.disk_usage(root).free < allocated*2+20*1024**3:
        raise ValueError('Insufficient isolated clone/build headroom')
    stage.mkdir()
    inputs = stage/'inputs'
    inputs.mkdir()
    shutil.copytree(root/SYSTEMUI, inputs/'SystemUI')
    shutil.copytree(root/APP, inputs/'app')
    for name in spec['systemui_files']:
        target = inputs/'SystemUI'/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(overlay/'systemui-overlay'/name, target)
    for name in spec['framework_files']:
        target = inputs/'MenuBar.java' if name.endswith('/MenuBar.java') else inputs/'app'/Path(name).name
        shutil.copyfile(overlay/'framework-overlay'/name, target)
    shutil.copyfile(root/BASE/'compact-system/system_ext/priv-app/SystemUI/SystemUI.apk', inputs/'SystemUI.baseline.apk')
    inventory = {p.relative_to(inputs).as_posix(): sha(p) for p in inputs.rglob('*') if p.is_file()}
    image_framework = {p.relative_to(root/BASE/'compact-system').as_posix(): sha(p)
                          for p in (root/BASE/'compact-system/framework').rglob('*')
                          if p.is_file() and not p.is_symlink()}
    baseline_framework = {name: sha(source/'target/product/n139dl/system'/name) for name in image_framework}
    profile_differences = {}
    for name, digest in image_framework.items():
        if baseline_framework[name] == digest:
            continue
        if name not in PROFILE_PINS or (digest, baseline_framework[name]) != PROFILE_PINS[name]:
            raise ValueError('Clone source framework differs from image45: '+name)
        profile_differences[name] = dict(image_sha256=digest, clone_sha256=baseline_framework[name])
    (stage/'clone-state.json').write_text('{"state":"copying"}\n')
    with (stage/'clone.log').open('wb') as log:
        proc = subprocess.Popen(['cp', '--reflink=auto', '-a', str(source), str(stage/'out')], stdout=log, stderr=subprocess.STDOUT)
        (stage/'clone.pid').write_text(str(proc.pid)+'\n')
        if proc.wait():
            raise ValueError('Clone failed; retain existing stage and inspect log')
    idle()
    for name, digest in baseline_framework.items():
        cloned = stage/'out/target/product/n139dl/system'/name
        original = source/'target/product/n139dl/system'/name
        if sha(cloned) != digest or cloned.stat().st_ino == original.stat().st_ino:
            raise ValueError('Independent framework clone verification failed: '+name)
    for name, digest in PINS.items():
        if sha(root/name) != digest:
            raise ValueError('Baseline changed during preparation: '+name)
    manifest = dict(baseline_image=45, baseline_pins=PINS, inputs=inventory,
                    framework_baseline=baseline_framework, overlay=expected,
                    image_framework=image_framework, preexisting_profile_differences=profile_differences,
                    systemui_source_sha256=spec['systemui_canonical_sha256'],
                    shared_source_and_outputs_read_only=True, launched=False, installed=False)
    (stage/'staging.json').write_text(json.dumps(manifest, indent=2)+'\n')
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
 -v "$stage/inputs/SystemUI:/build/aosp/frameworks/base/packages/SystemUI:ro" \\
 -v "$stage/inputs/app:/build/aosp/frameworks/base/core/java/com/android/internal/app:ro" \\
 -v "$stage/inputs/MenuBar.java:/build/aosp/frameworks/base/core/java/android/widget/MenuBar.java:ro" \\
 kaidroid-build:20261023 bash /build/STAGE_NAME/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''.replace('ROOT_PATH', str(root)).replace('STAGE_NAME', stage.name)
    (stage/'launch.sh').write_text(launcher, newline='\n')
    (stage/'control-inputs.json').write_text(json.dumps({n: sha(stage/n) for n in ('build.sh', 'launch.sh', 'staging.json')}, indent=2)+'\n')
    (stage/'clone-state.json').write_text('{"state":"complete"}\n')
    print(json.dumps(dict(stage=str(stage), launched=False, installed=False)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'overlay', 'contract', 'script', 'stage'):
        parser.add_argument('--'+name, type=Path, required=True)
    a = parser.parse_args()
    prepare(a.root, a.overlay, a.contract, a.script, a.stage)
