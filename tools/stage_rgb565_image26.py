"""Stage image26 from preserved image25 inputs; never modify the baseline."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ORIGINAL = '68e3953edab90e6170b930474cb84824fa8e57a0de3ef2fbf459ab97aff1caa7'
CANDIDATE = '3f0d105fba18197628bd1183cfc92cb963feddb7c324264a76b9e75131b22639'
BUILD_PROP = 'a1f9a9c05290d51707485ef8abaeb881fe92a2c5cf729761b4b048e0ad380d91'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stage(base, library, output):
    base = base.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink() or base in output.resolve().parents:
        raise ValueError('Output must be new and outside baseline')
    system = base / 'compact-system'
    if digest(system / 'lib/libsurfaceflinger.so') != ORIGINAL:
        raise ValueError('Wrong baseline SurfaceFlinger')
    if digest(system / 'build.prop') != BUILD_PROP or digest(library) != CANDIDATE:
        raise ValueError('Unreviewed build property or candidate')
    prop = (system / 'build.prop').read_text()
    if prop.count('ro.kaidroid.image=25') != 1 or 'ro.kaidroid.rgb565_client_target=' in prop:
        raise ValueError('Unexpected property state')
    config = (base / 'system_image_info.compact.txt').read_text()
    old_root = '/build/' + base.name + '/compact-root'
    if config.count('root_dir=' + old_root) != 1:
        raise ValueError('Unexpected root directory configuration')
    output.mkdir()
    shutil.copytree(system, output / 'compact-system', symlinks=True)
    shutil.copytree(base / 'compact-root', output / 'compact-root', symlinks=True)
    (output / 'compact-image').mkdir()
    target = output / 'compact-system'
    shutil.copy2(library, target / 'lib/libsurfaceflinger.so')
    (target / 'build.prop').write_text(prop.replace('ro.kaidroid.image=25',
        'ro.kaidroid.image=26') + '\nro.kaidroid.rgb565_client_target=true\n')
    (output / 'system_image_info.compact.txt').write_text(config.replace(
        'root_dir=' + old_root, 'root_dir=/build/' + output.name + '/compact-root'))
    report = {'base': str(base), 'revision': 26, 'existing_files_deleted': False,
              'changes': {p: digest(target / p) for p in
                          ('build.prop', 'lib/libsurfaceflinger.so')}}
    (output / 'staging.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--library', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(stage(a.base, a.library, a.output), indent=2))
