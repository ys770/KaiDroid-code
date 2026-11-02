"""Prepare image42 from immutable41 and the reviewed 30-file framework export."""
import argparse
import json
from pathlib import Path
import shutil

from stage_lazy_wifi_image40 import inventory, sha

BASE_RAW = '60d659580278bfe3dcc09ca92b1910d4f9d7af27ca8e62e87a67ff9e0d4ae5fe'
BUILD_MANIFEST = '7a4d95b7fc7b0ad03aa26c94c3fe3a26aec8079705efec4149b4a6c6ec385f41'
BEFORE_FRAMEWORK = 'fb116ee31688cd20f6c8ab6cbc73d69c7664c05e491e0325fc05dc4daa033d86'
PROVIDER = 'priv-app/TelephonyProvider/TelephonyProvider.apk'
SYSTEMUI = 'system_ext/priv-app/SystemUI/SystemUI.apk'
PINS = {PROVIDER: '704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
        SYSTEMUI: 'f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0',
        'framework/framework-res.apk': '42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
        'framework/services.jar': '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'}


def stage(root, build_script, framework_sha256, outputs_sha256):
    root = root.resolve(strict=True)
    base = root / 'engineering-option-menu-stage-41'
    compiled = root / 'option-menu42-build02'
    out = root / 'engineering-option-menu-stage-42'
    if out.exists():
        raise FileExistsError(out)
    assert (base / 'build.exit').read_text().strip() == '0'
    assert (compiled / 'build.exit').read_text().strip() == '0'
    assert sha(base / 'compact-image/system.raw.img') == BASE_RAW
    assert sha(compiled / 'staging.json') == BUILD_MANIFEST, 'Build metadata changed'
    assert sha(compiled / 'outputs.json') == outputs_sha256, 'Unreviewed export manifest'
    assert len(framework_sha256) == 64 and set(framework_sha256) <= set('0123456789abcdef')
    assert framework_sha256 != BEFORE_FRAMEWORK, 'No framework change'
    metadata = json.loads((compiled / 'staging.json').read_text())
    assert metadata['candidate_sha256'] == 'cf53c3f317a2470f46c713f395fd5769ebbe86977928bb07efb6819275343f4b'
    exported = json.loads((compiled / 'outputs.json').read_text())['files']
    assert len(exported) == 30 and set(exported) == set(metadata['closure'])
    assert exported['framework/framework.jar'] == framework_sha256
    assert sha(base / 'compact-system/framework/framework.jar') == BEFORE_FRAMEWORK
    for name, digest in PINS.items():
        assert sha(base / 'compact-system' / name) == digest, name
        if name in exported:
            assert exported[name] == digest, name
    for name, digest in exported.items():
        assert name.startswith('framework/') and '..' not in Path(name).parts
        assert sha(compiled / 'output' / name) == digest, name
    before = inventory(base / 'compact-system')
    roots = inventory(base / 'compact-root')
    props = (base / 'compact-system/build.prop').read_bytes()
    assert props.splitlines().count(b'ro.kaidroid.image=41') == 1
    out.mkdir()
    for name in ('compact-system', 'compact-root'):
        shutil.copytree(base / name, out / name, symlinks=True)
    (out / 'compact-image').mkdir()
    for name in exported:
        # Preserve baseline permissions/ownership metadata; replace bytes only.
        shutil.copyfile(compiled / 'output' / name, out / 'compact-system' / name)
    (out / 'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=41', b'ro.kaidroid.image=42'))
    shutil.copyfile(base / 'file_contexts.txt', out / 'file_contexts.txt')
    config = (base / 'system_image_info.compact.txt').read_text()
    assert config.count('/build/' + base.name + '/') == 2
    (out / 'system_image_info.compact.txt').write_text(config.replace('/build/' + base.name + '/', '/build/' + out.name + '/'))
    after = inventory(out / 'compact-system')
    changed = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    expected = {n for n, digest in exported.items() if before[n][2] != digest} | {'build.prop'}
    assert changed == expected, changed ^ expected
    assert inventory(base / 'compact-system') == before
    assert inventory(base / 'compact-root') == roots == inventory(out / 'compact-root')
    for name, digest in PINS.items():
        assert sha(out / 'compact-system' / name) == digest
    # Full inventory equality outside the closure also protects ART APEX and all APKs.
    report = dict(image=42, baseline_image=41, base_raw_sha256=BASE_RAW,
                  build_manifest_sha256=BUILD_MANIFEST,
                  framework_sha256=framework_sha256, outputs_sha256=outputs_sha256,
                  exported_files=exported, baseline_stage_unchanged=True, root_unchanged=True,
                  changed={n: dict(before=before[n], after=after[n]) for n in sorted(changed)},
                  apk_tree_preserved=True, art_apex_preserved=True,
                  system_partition_bytes=834666496, built=False, installed=False)
    for name, value in [('staging.json', report), ('system-inventory.json', after), ('root-inventory.json', roots)]:
        (out / name).write_text(json.dumps(value, indent=2) + '\n')
    (out / 'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n', b'\n'))
    launcher = (base / 'launch.sh').read_text().replace(base.name, out.name).replace('kaidroid-option-menu-image41', 'kaidroid-option-menu-image42')
    (out / 'launch.sh').write_text(launcher)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--build-script', type=Path, required=True)
    p.add_argument('--framework-sha256', required=True, help='Exact framework artifact reviewed after build')
    p.add_argument('--outputs-sha256', required=True, help='Exact reviewed build export manifest')
    a = p.parse_args()
    stage(a.root, a.build_script, a.framework_sha256, a.outputs_sha256)
