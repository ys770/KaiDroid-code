"""Preserve image34 and stage compiled power/end policy with matching preopt artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(folder) / name
            result[path.relative_to(root).as_posix()] = (
                ('link', os.readlink(path)) if path.is_symlink() else
                ('dir', path.stat().st_mode & 0o7777) if path.is_dir() else
                ('file', path.stat().st_mode & 0o7777, sha(path)))
    return result


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-root', type=Path, required=True)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
base = root / 'engineering-keyguard-stage-34'
out = root / 'engineering-power-stage-35'
system = base / 'compact-system'
assert sha(system / 'build.prop') == 'abb5d68bdf57d5c882ab1aa093f7eb78bd7a55dc7d994cd09753c1ffaf8c3c97'
assert sha(system / 'system_ext/priv-app/SystemUI/SystemUI.apk') == '203f2f316c48a354fc5ee2e0477da35b97b78604e63a2ae5e9ca9778719e5586'
build = root / 'power-endcall-build01'
assert (build / 'build.exit').read_text().strip() == '0'
manifest = json.loads((build / 'build-result.json').read_text())
expected = {
    'services.jar': '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d',
    'oat/arm/services.art': '43798bd1717e41e9529dc3e280b4cb2bab0a43911285c9635dfec4e1b824bde9',
    'oat/arm/services.odex': '0309e293bcfc95fd7759c1208b19ca074df48551491a69b4e29d57f256e74c15',
    'oat/arm/services.vdex': '55d079cc405a9eff0a8ec066af3f740dc4e3277ecaeebfde627a4c4eefd27035'}
assert manifest['files'] == expected
for name, digest in expected.items():
    assert sha(build / 'output' / name) == digest
# Preoptimized services must use the same packaged boot classpath artifacts.
product = root / 'out-eng-02/target/product/n139dl/system'
boot_files = list((system / 'framework/arm').glob('boot*'))
assert boot_files
for path in boot_files:
    assert sha(path) == sha(product / path.relative_to(system)), path.name
before = inventory(system)
out.mkdir(exist_ok=False)
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base / name, out / name, symlinks=True)
(out / 'compact-image').mkdir()
target = out / 'compact-system'
for name in expected:
    shutil.copyfile(build / 'output' / name, target / 'framework' / name)
props = (target / 'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=34') == 1
assert 'ro.kaidroid.power_endcall=' not in props
(target / 'build.prop').write_text(props.replace('ro.kaidroid.image=34', 'ro.kaidroid.image=35') + '\nro.kaidroid.power_endcall=true\n')
shutil.copyfile(base / 'file_contexts.txt', out / 'file_contexts.txt')
config = (base / 'system_image_info.compact.txt').read_text()
assert config.count('/build/' + base.name + '/') == 2
(out / 'system_image_info.compact.txt').write_text(config.replace('/build/' + base.name + '/', '/build/' + out.name + '/'))
after = inventory(target)
assert set(before) == set(after)
changed = sorted(k for k in before if before[k] != after[k])
assert changed == sorted(['build.prop'] + ['framework/' + name for name in expected]), changed
assert inventory(system) == before
assert inventory(base / 'compact-root') == inventory(out / 'compact-root')
report = dict(revision=35, base=str(base), baseline_entries=len(before),
              baseline_unchanged=True, changes={k: sha(target / k) for k in changed},
              service_disabled=True, installed=False)
(out / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
