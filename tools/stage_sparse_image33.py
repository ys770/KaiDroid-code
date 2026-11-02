"""Preserve image32 and stage only the tested sparse parser plus image identifier."""
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
base = root / 'engineering-policy-stage-32'
out = root / 'engineering-sparse-stage-33'
system = base / 'compact-system'
assert sha(system / 'build.prop') == '8380f7ca517d6086a2d714a0b513897df40d42313fc9001d9675116d324f5345'
assert sha(system / 'lib/libandroidfw.so') == 'ddea135a3e80d422e56722643d46b280d031e8e1fb63db159fd2614b327aa6b5'
binary = root / 'sparse-lookup-build01/libandroidfw.so'
assert sha(binary) == '05743c6479447b5292981a5383b230a1f3ff92b8fec8af421ccfe1b28df13c35'
assert (root / 'sparse-lookup-build01/build.exit').read_text().strip() == '0'
before = inventory(system)
out.mkdir(exist_ok=False)
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base / name, out / name, symlinks=True)
(out / 'compact-image').mkdir()
target = out / 'compact-system'
shutil.copyfile(binary, target / 'lib/libandroidfw.so')
props = (target / 'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=32') == 1
(target / 'build.prop').write_text(props.replace('ro.kaidroid.image=32', 'ro.kaidroid.image=33'))
shutil.copyfile(base / 'file_contexts.txt', out / 'file_contexts.txt')
config = (base / 'system_image_info.compact.txt').read_text()
assert config.count('/build/' + base.name + '/') == 2
(out / 'system_image_info.compact.txt').write_text(config.replace('/build/' + base.name + '/', '/build/' + out.name + '/'))
after = inventory(target)
assert set(before) == set(after)
changed = sorted(k for k in before if before[k] != after[k])
assert changed == ['build.prop', 'lib/libandroidfw.so'], changed
assert inventory(system) == before
assert inventory(base / 'compact-root') == inventory(out / 'compact-root')
report = dict(revision=33, base=str(base), baseline_entries=len(before),
              baseline_unchanged=True, changes={k: sha(target / k) for k in changed},
              service_disabled=True, installed=False)
(out / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
