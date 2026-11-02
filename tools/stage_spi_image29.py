"""Preserve image28 and stage exactly two changed files for image29."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1048576), b''):
            h.update(block)
    return h.hexdigest()

def inventory(root):
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(folder) / name
            key = path.relative_to(root).as_posix()
            result[key] = ('link', os.readlink(path)) if path.is_symlink() else (
                ('dir', path.stat().st_mode & 0o7777) if path.is_dir() else
                ('file', path.stat().st_mode & 0o7777, sha(path)))
    return result

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--base', required=True, type=Path)
p.add_argument('--library', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
base = a.base.resolve(strict=True)
out = a.output.resolve()
assert not out.exists() and base not in out.parents
system = base / 'compact-system'
assert sha(system / 'build.prop') == 'd7bb7ecdf9de97846a836df7b75e772e77e6f10aaaee1b6e8ffd959b2d1b1105'
assert sha(system / 'lib/libsurfaceflinger.so') == '3f0d105fba18197628bd1183cfc92cb963feddb7c324264a76b9e75131b22639'
assert sha(a.library) == '01f59fbd38cc93e6b96c50d49ce892a17af70782ce9a5bdd7d901d6771b071f1'
props = (system / 'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=28') == 1
assert props.splitlines().count('ro.kaidroid.rgb565_client_target=true') == 1
assert 'ro.kaidroid.force_client_composition=' not in props
before = inventory(system)
out.mkdir()
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base / name, out / name, symlinks=True)
(out / 'compact-image').mkdir()
target = out / 'compact-system'
shutil.copy2(a.library, target / 'lib/libsurfaceflinger.so')
(target / 'build.prop').write_text(props.replace('ro.kaidroid.image=28', 'ro.kaidroid.image=29') +
                                 '\nro.kaidroid.force_client_composition=true\n')
config = (base / 'system_image_info.compact.txt').read_text()
old = 'root_dir=/build/' + base.name + '/compact-root'
assert config.count(old) == 1
(out / 'system_image_info.compact.txt').write_text(config.replace(old, 'root_dir=/build/' + out.name + '/compact-root'))
after = inventory(target)
assert before.keys() == after.keys()
changed = sorted(k for k in before if before[k] != after[k])
assert changed == ['build.prop', 'lib/libsurfaceflinger.so'], changed
assert inventory(base / 'compact-root') == inventory(out / 'compact-root')
assert inventory(system) == before
report = dict(revision=29, base=str(base), entries=len(before),
              changes={k: sha(target / k) for k in changed}, baseline_unchanged=True)
(out / 'staging.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report))
