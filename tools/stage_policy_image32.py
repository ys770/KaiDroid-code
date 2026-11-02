"""Preserve image31 and add the exact-input-bound precompiled policy and init."""
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
base = root/'engineering-hall-stage-31'
out = root/'engineering-policy-stage-32'
system = base/'compact-system'
assert sha(system/'build.prop') == '58f9806811838c64cbd47bfe784a6bc9e317c0b1ba546b6100182e9feab4720e'
assert sha(system/'bin/init') == 'aa37cf3e1671db166516fcd69e2dd4308cbb2f702986a56fde5c23da6e77764b'
binary = root/'init-precompiled-build01/init'
assert sha(binary) == '08ebee7a2f463b52c8f79516cf98c8451fbb41712336971c6b1717d3a54d9bce'
policy = root/'precompiled-policy-stage01/precompiled_sepolicy'
assert sha(policy) == '31aae0cd7759cce5ea8728e19f9c682ba81f371ffe547daf051d4a9a5e8992c5'
manifest = json.loads((root/'precompiled-policy-stage01/manifest.json').read_text())
def mapped(runtime):
    return system/runtime[len('/system/'):] if runtime.startswith('/system/') else system/runtime.lstrip('/')
for runtime, digest in manifest['inputs'].items():
    assert sha(mapped(runtime)) == digest, runtime
for runtime in manifest['absent']:
    assert not mapped(runtime).exists(), runtime
before = inventory(system)
out.mkdir(exist_ok=False)
for name in ('compact-system', 'compact-root'):
    shutil.copytree(base/name, out/name, symlinks=True)
(out/'compact-image').mkdir()
target = out/'compact-system'
shutil.copyfile(binary, target/'bin/init')
(target/'bin/init').chmod(0o755)
shutil.copyfile(policy, target/'etc/selinux/kaidroid/precompiled_sepolicy')
(target/'etc/selinux/kaidroid/precompiled_sepolicy').chmod(0o644)
props = (target/'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=31') == 1
(target/'build.prop').write_text(props.replace('ro.kaidroid.image=31', 'ro.kaidroid.image=32'))
shutil.copyfile(base/'file_contexts.txt', out/'file_contexts.txt')
config = (base/'system_image_info.compact.txt').read_text()
assert config.count('/build/'+base.name+'/') == 2
(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
after = inventory(target)
added = sorted(set(after)-set(before))
assert added == ['etc/selinux/kaidroid/precompiled_sepolicy']
assert not set(before)-set(after)
changed = sorted(k for k in before if before[k] != after[k])
assert changed == ['bin/init', 'build.prop'], changed
assert inventory(system) == before
assert inventory(base/'compact-root') == inventory(out/'compact-root')
report = dict(revision=32, base=str(base), baseline_entries=len(before), baseline_unchanged=True,
              changes={k:sha(target/k) for k in changed+added}, service_disabled=True, installed=False)
(out/'staging.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
