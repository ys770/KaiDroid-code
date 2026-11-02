"""Prepare image46 from immutable45 and the reviewed 30-file framework export."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import io
import tarfile

from stage_lazy_wifi_image40 import inventory, sha

BASE_RAW = '77b523c3504700d1b05fdf5eb82c54715cb7e790675e52b01bc52dc1f53491e2'
BEFORE_FRAMEWORK = '5126b8f1c15c0ee17a5a6c472fa5bc58bab99cdcb400b286e19f73af949f7054'
PROVIDER = 'priv-app/TelephonyProvider/TelephonyProvider.apk'
SYSTEMUI = 'system_ext/priv-app/SystemUI/SystemUI.apk'
PINS = {PROVIDER: '704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
        SYSTEMUI: '5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708',
        'framework/framework-res.apk': '42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
        'framework/services.jar': '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'}


def stage(root, build_script, framework_sha256, outputs_sha256, build_manifest_sha256, alarms):
    root = root.resolve(strict=True)
    base = root / 'engineering-tcl-resolver-stage-45'
    compiled = root / 'tcl-resolver-build02'
    out = root / 'engineering-tcl-resolver-stage-46'
    if out.exists():
        raise FileExistsError(out)
    assert (base / 'build.exit').read_text().strip() == '0'
    assert (compiled / 'build-retry02.exit').read_text().strip() == '0'
    assert sha(base / 'compact-image/system.raw.img') == BASE_RAW
    assert sha(compiled / 'staging.json') == build_manifest_sha256, 'Build metadata changed'
    assert sha(compiled / 'outputs-retry02.json') == outputs_sha256, 'Unreviewed export manifest'
    assert len(framework_sha256) == 64 and set(framework_sha256) <= set('0123456789abcdef')
    assert framework_sha256 != BEFORE_FRAMEWORK, 'No framework change'
    metadata = json.loads((compiled / 'staging.json').read_text())
    assert hashlib.sha256(json.dumps(metadata['overlay'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == '43d44ff4b551ba18344aa511b2a9c228b4e75109e3ed17f1aa68b3270498b98c'
    assert metadata['baseline_image'] == 45
    exported = json.loads((compiled / 'outputs-retry02.json').read_text())['files']
    assert len(exported) == 30 and set(exported) == set(metadata['closure'])
    assert exported['framework/framework.jar'] == framework_sha256
    assert sha(base / 'compact-system/framework/framework.jar') == BEFORE_FRAMEWORK
    for name, digest in PINS.items():
        assert sha(base / 'compact-system' / name) == digest, name
        if name in exported:
            assert exported[name] == digest, name
    for name, digest in exported.items():
        assert name.startswith('framework/') and '..' not in Path(name).parts
        assert sha(compiled / 'output-retry02' / name) == digest, name
    before = inventory(base / 'compact-system')
    roots = inventory(base / 'compact-root')
    props = (base / 'compact-system/build.prop').read_bytes()
    assert props.splitlines().count(b'ro.kaidroid.image=45') == 1
    assert sha(alarms) == 'a2b49312c22bb620a741e0665ee63436215ee601d704094f1aaef62230407fd5'
    alarm_files = {}
    alarm_dirs = set()
    with tarfile.open(fileobj=io.BytesIO(alarms.read_bytes()), mode='r:') as archive:
        members = archive.getmembers()
        assert len(members) == 11
        for member in members:
            assert member.uid == member.gid == 0 and not member.issym() and not member.islnk()
            if member.isdir():
                assert member.name in ('product/media', 'product/media/audio', 'product/media/audio/alarms')
                assert member.mode == 0o755
                alarm_dirs.add(member.name)
            else:
                assert member.isfile() and member.mode == 0o644
                assert member.name.startswith('product/media/audio/alarms/') and '..' not in Path(member.name).parts
                assert member.name not in before and member.name not in alarm_files
                alarm_files[member.name] = archive.extractfile(member).read()
    assert len(alarm_files) == 8 and len(alarm_dirs) == 3
    out.mkdir()
    for name in ('compact-system', 'compact-root'):
        shutil.copytree(base / name, out / name, symlinks=True)
    (out / 'compact-image').mkdir()
    for name in sorted(alarm_dirs, key=len):
        target = out / 'compact-system' / name
        if name not in before:
            target.mkdir(mode=0o755)
            target.chmod(0o755)
        else:
            assert target.is_dir() and not target.is_symlink()
    for name, content in alarm_files.items():
        target = out / 'compact-system' / name
        target.write_bytes(content)
        target.chmod(0o644)
    for name in exported:
        # Preserve baseline permissions/ownership metadata; replace bytes only.
        shutil.copyfile(compiled / 'output-retry02' / name, out / 'compact-system' / name)
    (out / 'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=45', b'ro.kaidroid.image=46'))
    shutil.copyfile(base / 'file_contexts.txt', out / 'file_contexts.txt')
    config = (base / 'system_image_info.compact.txt').read_text()
    assert config.count('/build/' + base.name + '/') == 2
    (out / 'system_image_info.compact.txt').write_text(config.replace('/build/' + base.name + '/', '/build/' + out.name + '/'))
    after = inventory(out / 'compact-system')
    changed = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    expected = {n for n, digest in exported.items() if before[n][2] != digest} | {'build.prop'} | set(alarm_files) | (alarm_dirs - before.keys())
    assert changed == expected, changed ^ expected
    assert inventory(base / 'compact-system') == before
    assert inventory(base / 'compact-root') == roots == inventory(out / 'compact-root')
    for name, digest in PINS.items():
        assert sha(out / 'compact-system' / name) == digest
    # Full inventory equality outside the closure also protects ART APEX and all APKs.
    report = dict(image=46, baseline_image=45, base_raw_sha256=BASE_RAW,
                  build_manifest_sha256=build_manifest_sha256,
                  framework_sha256=framework_sha256, outputs_sha256=outputs_sha256,
                  exported_files=exported, baseline_stage_unchanged=True, root_unchanged=True,
                  changed={n: dict(before=before.get(n), after=after[n]) for n in sorted(changed)},
                  apk_tree_preserved=True, art_apex_preserved=True,
                  added_alarm_files={n: hashlib.sha256(b).hexdigest() for n,b in alarm_files.items()},
                  added_alarm_dirs=sorted(alarm_dirs-before.keys()),
                  alarm_archive_sha256=sha(alarms),
                  system_partition_bytes=834666496, built=False, installed=False)
    for name, value in [('staging.json', report), ('system-inventory.json', after), ('root-inventory.json', roots)]:
        (out / name).write_text(json.dumps(value, indent=2) + '\n')
    (out / 'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n', b'\n'))
    launcher = (base / 'launch.sh').read_text().replace(base.name, out.name).replace('kaidroid-tcl-resolver-image45', 'kaidroid-tcl-resolver-image46')
    (out / 'launch.sh').write_text(launcher)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--build-script', type=Path, required=True)
    p.add_argument('--framework-sha256', required=True, help='Exact framework artifact reviewed after build')
    p.add_argument('--outputs-sha256', required=True, help='Exact reviewed build export manifest')
    p.add_argument('--build-manifest-sha256', required=True, help='Exact reviewed staging manifest')
    p.add_argument('--alarms', type=Path, required=True)
    a = p.parse_args()
    stage(a.root, a.build_script, a.framework_sha256, a.outputs_sha256, a.build_manifest_sha256, a.alarms)
