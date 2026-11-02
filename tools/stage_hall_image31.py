"""Preserve image30 and change only hinge discovery binary and image revision."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1048576), b''):
            h.update(b)
    return h.hexdigest()

def inventory(root):
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(folder)/name
            result[p.relative_to(root).as_posix()] = ('link', os.readlink(p)) if p.is_symlink() else (
                ('dir', p.stat().st_mode & 0o7777) if p.is_dir() else
                ('file', p.stat().st_mode & 0o7777, sha(p)))
    return result

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-root', required=True, type=Path)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
base = root/'engineering-hall-stage-30'
out = root/'engineering-hall-stage-31'
system = base/'compact-system'
assert sha(system/'build.prop') == '1e97abaa4954c93b5e26a5c7fadbb110b27af3b003b4fbc24fe172dde2e8b76b'
assert sha(system/'bin/kaidroid-hall') == 'bd43ad632d8a938c21e5c648986c29d2be5b21006d2ad6ddee251e95877f3fa5'
binary = root/'hall-module-stage03/kaidroid-hall'
assert sha(binary) == 'd5b4a37e3c60ee3e7240efffe90000b697fdbd5584e577630f0d6ea534e404ca'
before = inventory(system)
out.mkdir(exist_ok=False)
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base/name, out/name, symlinks=True)
(out/'compact-image').mkdir()
target = out/'compact-system'
shutil.copyfile(binary, target/'bin/kaidroid-hall')
(target/'bin/kaidroid-hall').chmod(0o755)
props = (target/'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=30') == 1
(target/'build.prop').write_text(props.replace('ro.kaidroid.image=30', 'ro.kaidroid.image=31'))
shutil.copyfile(base/'file_contexts.txt', out/'file_contexts.txt')
config = (base/'system_image_info.compact.txt').read_text()
assert config.count('/build/'+base.name+'/') == 2
(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
after = inventory(target)
assert set(after) == set(before)
changed = sorted(k for k in before if before[k] != after[k])
assert changed == ['bin/kaidroid-hall', 'build.prop'], changed
assert inventory(system) == before
assert inventory(base/'compact-root') == inventory(out/'compact-root')
report = dict(revision=31, base=str(base), baseline_entries=len(before), baseline_unchanged=True,
              changes={k:sha(target/k) for k in changed}, service_disabled=True, installed=False)
(out/'staging.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
