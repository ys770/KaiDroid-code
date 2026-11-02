"""Stage the preserved MenuBar dependency closure over immutable image35."""
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
            p = Path(folder)/name
            result[p.relative_to(root).as_posix()] = (
                ('link', os.readlink(p)) if p.is_symlink() else
                ('dir', p.stat().st_mode & 0o7777) if p.is_dir() else
                ('file', p.stat().st_mode & 0o7777, sha(p)))
    return result

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-root', type=Path, required=True)
p.add_argument('--manifest', type=Path, required=True)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
base = root/'engineering-power-stage-35'
out = root/'engineering-menubar-stage-36'
build = root/'menubar-closure-build01'
assert (build/'build.exit').read_text().strip() == '0'
expected = json.loads(a.manifest.read_text())
assert expected == json.loads((build/'outputs.json').read_text())
assert expected['framework/framework.jar'] == '4225ae72bd7fc5f7a1441363b5e6a367d6a46bb31d7e224c4f3ba113faaf49ac'
assert expected['framework/services.jar'] == '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'
system = base/'compact-system'
before = inventory(system)
for name, digest in expected.items():
    assert name.startswith('framework/') and '..' not in Path(name).parts
    assert name in before and before[name][0] == 'file'
    assert sha(build/'output'/name) == digest
out.mkdir(exist_ok=False)
for name in ('compact-system','compact-root'):
    shutil.copytree(base/name, out/name, symlinks=True)
(out/'compact-image').mkdir()
target = out/'compact-system'
for name in expected:
    shutil.copyfile(build/'output'/name, target/name)
props = (target/'build.prop').read_text()
assert props.splitlines().count('ro.kaidroid.image=35') == 1
assert props.splitlines().count('ro.kaidroid.power_endcall=true') == 1
(target/'build.prop').write_text(props.replace('ro.kaidroid.image=35','ro.kaidroid.image=36'))
shutil.copyfile(base/'file_contexts.txt', out/'file_contexts.txt')
config = (base/'system_image_info.compact.txt').read_text()
assert config.count('/build/'+base.name+'/') == 2
(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
after = inventory(target)
assert set(after) == set(before)
changed = sorted(k for k in before if before[k] != after[k])
assert 'framework/framework.jar' in changed and 'build.prop' in changed
assert set(changed) <= set(expected) | {'build.prop'}
assert inventory(system) == before
assert inventory(base/'compact-root') == inventory(out/'compact-root')
report = dict(revision=36, baseline_entries=len(before), baseline_unchanged=True,
              changes={k:sha(target/k) for k in changed}, closure=expected,
              installed=False, service_disabled=True)
(out/'staging.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report, indent=2))
