"""Copy preserved image27 into a new UI runtime stage; never build or install."""
import argparse
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

INVENTORY = '5e55cba45437d7cb82611d71f53076d9497502baf07bd7b2274c4442421c1275'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def tree(root):
    rows = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(folder) / name
            rel = path.relative_to(root).as_posix()
            info = path.lstat()
            row = dict(mode=stat.S_IMODE(info.st_mode))
            if path.is_symlink():
                row.update(kind='symlink', target=os.readlink(path))
            elif path.is_dir():
                row.update(kind='directory')
            elif path.is_file():
                row.update(kind='file', sha256=sha(path))
            else:
                raise ValueError('Unexpected special file: ' + rel)
            rows[rel] = row
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'inventory', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    base = a.baseline.resolve(strict=True)
    out = a.output.resolve()
    if out.exists() or base == out or base in out.parents:
        raise ValueError('Output must be a new directory outside baseline')
    if sha(a.inventory) != INVENTORY:
        raise ValueError('Inventory identity mismatch')
    plan = json.loads(a.inventory.read_text(encoding='utf-8-sig'))
    system = base / 'compact-system'
    if str(system) != plan['baseline']:
        raise ValueError('Baseline path differs from pinned inventory')
    for row in plan['files']:
        if sha(system / row['destination']) != row['baseline_sha256']:
            raise ValueError('Baseline changed: ' + row['destination'])
        if sha(Path(row['source'])) != row['candidate_sha256']:
            raise ValueError('Build output changed: ' + row['destination'])
    for row in plan['wifi_flattened_identity']:
        if row['baseline_sha256'] != row['candidate_sha256'] or sha(system / row['path']) != row['baseline_sha256']:
            raise ValueError('Flattened Wi-Fi identity changed')
    changes = {r['destination']:r for r in plan['files'] if r['changed']}
    if len(changes) != 12:
        raise ValueError('Unexpected runtime change count')
    before = tree(system)
    root_before = tree(base / 'compact-root')
    out.mkdir()
    shutil.copytree(system, out / 'compact-system', symlinks=True)
    shutil.copytree(base / 'compact-root', out / 'compact-root', symlinks=True)
    (out / 'compact-image').mkdir()
    for name in ('file_contexts.bin', 'file_contexts.txt'):
        shutil.copy2(base / name, out / name)
    config = (base / 'system_image_info.compact.txt').read_text()
    old = '/build/' + base.name + '/'
    if config.count(old) != 2:
        raise ValueError('Unexpected root/contexts configuration')
    (out / 'system_image_info.compact.txt').write_text(config.replace(old, '/build/' + out.name + '/'))
    for name, row in changes.items():
        target = out / 'compact-system' / name
        if target.is_symlink():
            resolved = target.resolve(strict=True)
            relative = resolved.relative_to((out / 'compact-system').resolve()).as_posix()
            if relative not in changes or before[relative]['kind'] != 'file':
                raise ValueError('Symlink does not alias a reviewed file: ' + name)
            continue
        target.write_bytes(Path(row['source']).read_bytes())
        if sha(target) != row['candidate_sha256']:
            raise ValueError('Copied hash mismatch: ' + name)
    prop = out / 'compact-system/build.prop'
    prop_data = prop.read_bytes()
    if prop_data.count(b'ro.kaidroid.image=27\n') != 1:
        raise ValueError('Expected exact image27 revision property')
    prop.write_bytes(prop_data.replace(b'ro.kaidroid.image=27\n', b'ro.kaidroid.image=28\n'))
    changes['build.prop'] = dict(candidate_sha256=sha(prop))
    after = tree(out / 'compact-system')
    actual = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    expected = {name for name in changes if before[name]['kind'] == 'file'}
    if actual != expected:
        raise ValueError('Unexpected full-tree diff: ' + repr(actual ^ expected))
    for name, row in changes.items():
        if sha(out / 'compact-system' / name) != row['candidate_sha256']:
            raise ValueError('Final hash mismatch: ' + name)
    for name in changes:
        if before[name]['mode'] != after[name]['mode']:
            raise ValueError('Mode changed: ' + name)
    if tree(system) != before or tree(base / 'compact-root') != root_before:
        raise ValueError('Baseline mutated during staging')
    if tree(out / 'compact-root') != root_before:
        raise ValueError('Root tree differs')
    report = dict(base=str(base), inventory_sha256=INVENTORY, changes={n:r['candidate_sha256'] for n,r in changes.items()},
                  baseline_tree=before, candidate_tree=after, full_tree_diff=sorted(actual),
                  root_tree_unchanged=True, baseline_unchanged=True,
                  labels_sha256=sha(out / 'file_contexts.bin'),
                  image_identity='image28 UI runtime candidate derived from preserved image27',
                  built=False, installed=False)
    (out / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(stage=str(out), changed=len(actual), baseline_entries=len(before), baseline_unchanged=True)))


if __name__ == '__main__':
    main()
