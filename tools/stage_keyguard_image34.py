"""Preserve image33 and stage the tested center-key SystemUI plus image identifier."""
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
base = root / 'engineering-sparse-stage-33'
out = root / 'engineering-keyguard-stage-34'
system = base / 'compact-system'
assert sha(system / 'build.prop') == '1c892cd5e2947d302e24be90e33472cf0cb7be027fef10b971d6b6fa64f8b1be'
assert sha(system / 'system_ext/priv-app/SystemUI/SystemUI.apk') == '0eff22227045afb402fab66b8ac13af129ac9d9e7f60709c02759578f2e482ae'
binary = root / 'engineering-keyguard-center-stage01/SystemUI.candidate.apk'
assert sha(binary) == '203f2f316c48a354fc5ee2e0477da35b97b78604e63a2ae5e9ca9778719e5586'
assert (root / 'engineering-keyguard-center-stage01/build.exit').read_text().strip() == '0'
before = inventory(system)
out.mkdir(exist_ok=False)
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base / name, out / name, symlinks=True)
(out / 'compact-image').mkdir()
target = out / 'compact-system'
shutil.copyfile(binary, target / 'system_ext/priv-app/SystemUI/SystemUI.apk')
props = (target / 'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=33') == 1
(target / 'build.prop').write_text(props.replace('ro.kaidroid.image=33', 'ro.kaidroid.image=34'))
shutil.copyfile(base / 'file_contexts.txt', out / 'file_contexts.txt')
config = (base / 'system_image_info.compact.txt').read_text()
assert config.count('/build/' + base.name + '/') == 2
(out / 'system_image_info.compact.txt').write_text(config.replace('/build/' + base.name + '/', '/build/' + out.name + '/'))
after = inventory(target)
assert set(before) == set(after)
changed = sorted(k for k in before if before[k] != after[k])
assert changed == ['build.prop', 'system_ext/priv-app/SystemUI/SystemUI.apk'], changed
assert inventory(system) == before
assert inventory(base / 'compact-root') == inventory(out / 'compact-root')
report = dict(revision=34, base=str(base), baseline_entries=len(before),
              baseline_unchanged=True, changes={k: sha(target / k) for k in changed},
              service_disabled=True, installed=False)
(out / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
