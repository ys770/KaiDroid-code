"""Stage a system-only Bluetooth overlay from exact image26 inputs; never flash."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

EXPECTED = {
    'build.prop': 'c3b85e0ac1161a0640a1ef7f2ee295fdb8c25983b0eb5d60136a5c534046d88e',
    'lib/libsurfaceflinger.so': '3f0d105fba18197628bd1183cfc92cb963feddb7c324264a76b9e75131b22639',
    'etc/selinux/plat_sepolicy.cil': '9ef0bcf66f0d8da6eb586d0f8e48bd1ee16eda8a12547b0f998f2258517efc2c',
}
CANDIDATE = '7b430074d1fa1025a31cb1948d1e509a7262e1cd0ef58ea983e6b2f52954dd0a'
RULE = '(allow init vendor_file (file (mounton)))\n'
CONTEXT = '/system/etc/kaidroid-bluetooth(/.*)? u:object_r:vendor_file:s0\n'
RC = '''# Engineering system-only overlay; original vendor bytes remain intact.
on post-fs-data
    mount none /system/etc/kaidroid-bluetooth/libbt-vendor-brt.so /vendor/lib/libbt-vendor-brt.so bind
'''


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def stage(base, library, contexts, output):
    base = base.resolve(strict=True)
    output = output.resolve()
    if output.exists() or output == base or base in output.parents:
        raise ValueError('Use a new output outside baseline')
    system = base / 'compact-system'
    for name, digest in EXPECTED.items():
        if sha(system / name) != digest:
            raise ValueError('Wrong image26 input: ' + name)
    if sha(library) != CANDIDATE:
        raise ValueError('Wrong Bluetooth candidate')
    if not (system / 'vendor').is_symlink():
        raise ValueError('Expected preserved vendor symlink')
    text = contexts.read_text()
    if 'kaidroid-bluetooth' in text:
        raise ValueError('Overlay labeling already present')
    config = (base / 'system_image_info.compact.txt').read_text()
    old_root = 'root_dir=/build/' + base.name + '/compact-root'
    if config.count(old_root) != 1:
        raise ValueError('Unexpected image root config')
    output.mkdir()
    shutil.copytree(system, output / 'compact-system', symlinks=True)
    shutil.copytree(base / 'compact-root', output / 'compact-root', symlinks=True)
    (output / 'compact-image').mkdir()
    target = output / 'compact-system'
    prop = (target / 'build.prop').read_text()
    if prop.count('ro.kaidroid.image=26') != 1:
        raise ValueError('Unexpected image property')
    (target / 'build.prop').write_text(prop.replace('ro.kaidroid.image=26', 'ro.kaidroid.image=27'))
    overlay = target / 'etc/kaidroid-bluetooth'
    overlay.mkdir()
    shutil.copy2(library, overlay / 'libbt-vendor-brt.so')
    (overlay / 'libbt-vendor-brt.so').chmod(0o644)
    (target / 'etc/init/kaidroid-bluetooth.rc').write_text(RC)
    policy = target / 'etc/selinux/plat_sepolicy.cil'
    policy.write_bytes(policy.read_bytes() + b'\n' + RULE.encode())
    fc = target / 'etc/selinux/plat_file_contexts'
    fc.write_bytes(fc.read_bytes() + b'\n' + CONTEXT.encode())
    (output / 'file_contexts.txt').write_text(text + '\n' + CONTEXT)
    config = config.replace(old_root, 'root_dir=/build/' + output.name + '/compact-root')
    config = '\n'.join('system_selinux_fc=/build/' + output.name + '/file_contexts.bin'
                       if line.startswith('system_selinux_fc=') else line for line in config.splitlines()) + '\n'
    (output / 'system_image_info.compact.txt').write_text(config)
    names = ['build.prop', 'etc/init/kaidroid-bluetooth.rc', 'etc/kaidroid-bluetooth/libbt-vendor-brt.so',
             'etc/selinux/plat_sepolicy.cil', 'etc/selinux/plat_file_contexts']
    report = dict(revision=27, base=str(base), input_sha256=EXPECTED,
                  source_contexts_sha256=sha(contexts), changes={name:sha(target/name) for name in names},
                  compiled_contexts_pending=True, built=False, installed=False)
    (output / 'staging.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'library', 'contexts', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    a = p.parse_args()
    stage(a.base, a.library, a.contexts, a.output)
