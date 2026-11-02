"""Stage a preserved image29 copy with a disabled hinge service; never flash."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
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
p.add_argument('--build-root', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
base = root / 'engineering-spi-stage-29'
system = base / 'compact-system'
out = a.output.resolve()
assert not out.exists() and base not in out.parents
assert sha(system / 'build.prop') == '8511a9b965f3ea57f49f2cc5fe68352357262bbddbbf2da0841d6e5bf188fd37'
binary = root / 'hall-module-stage01/kaidroid-hall'
policy = root / 'hall-policy-stage02/system_ext_sepolicy.cil'
rc = root / 'hall-module-input01/kaidroid-hall.rc'
assert sha(binary) == 'bd43ad632d8a938c21e5c648986c29d2be5b21006d2ad6ddee251e95877f3fa5'
assert sha(policy) == 'f1ed711433c6af43a1d49980ca3a37dc8d80258b41ac33bccdd1b2b401f2ca42'
assert sha(rc) == '4edca485144a9e48e1a173f561adf6cd01de1d5b757ab46e46d4ccddf6c29ad2'
context = '/system/bin/kaidroid-hall u:object_r:kaidroid_hall_exec:s0\n'
contexts = (root / 'engineering-ui-runtime-stage03/file_contexts.txt').read_text()
assert 'kaidroid-hall' not in contexts
before = inventory(system)
out.mkdir()
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base / name, out / name, symlinks=True)
(out / 'compact-image').mkdir()
target = out / 'compact-system'
for source, dest, mode in [(binary, 'bin/kaidroid-hall', 0o755),
                           (rc, 'etc/init/kaidroid-hall.rc', 0o644),
                           (policy, 'system_ext/etc/selinux/system_ext_sepolicy.cil', 0o644)]:
    shutil.copyfile(source, target / dest)
    (target / dest).chmod(mode)
props = (target / 'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=29') == 1
(target / 'build.prop').write_text(props.replace('ro.kaidroid.image=29', 'ro.kaidroid.image=30'))
fc = target / 'system_ext/etc/selinux/system_ext_file_contexts'
fc.write_bytes(fc.read_bytes() + b'\n' + context.encode())
(out / 'file_contexts.txt').write_text(contexts + '\n' + context)
config = (base / 'system_image_info.compact.txt').read_text()
old = 'root_dir=/build/' + base.name + '/compact-root'
assert config.count(old) == 1
config = config.replace(old, 'root_dir=/build/' + out.name + '/compact-root')
config = '\n'.join('system_selinux_fc=/build/' + out.name + '/file_contexts.bin'
                   if line.startswith('system_selinux_fc=') else line for line in config.splitlines()) + '\n'
(out / 'system_image_info.compact.txt').write_text(config)
after = inventory(target)
added = sorted(set(after) - set(before))
changed = sorted(k for k in before if before[k] != after.get(k))
assert added == ['bin/kaidroid-hall', 'etc/init/kaidroid-hall.rc'], added
assert changed == ['build.prop', 'system_ext/etc/selinux/system_ext_file_contexts',
                   'system_ext/etc/selinux/system_ext_sepolicy.cil'], changed
assert inventory(system) == before
assert inventory(base / 'compact-root') == inventory(out / 'compact-root')
report = dict(revision=30, base=str(base), baseline_entries=len(before), baseline_unchanged=True,
              changes={k: sha(target / k) for k in changed + added}, service_disabled=True,
              built=False, installed=False)
(out / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
