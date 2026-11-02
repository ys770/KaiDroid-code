"""Collect bounded, read-only filesystem evidence using Linux debugfs.

Run under Linux/WSL. Images must be raw ext filesystems. Original files are
stored only in the selected output directory, which should be ignored by Git.
"""
import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


def query(image, command):
    result = subprocess.run(['debugfs', '-R', command, str(image)], capture_output=True)
    errors = result.stderr.decode('utf-8', errors='replace').splitlines()
    errors = [line for line in errors if line and not line.startswith('debugfs ')]
    if result.returncode or errors:
        raise RuntimeError('\n'.join(errors))
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = {'files': {}, 'missing': {}, 'properties': {}, 'hal_declarations': []}
    targets = {
        'vendor': ['/build.prop', '/etc/vintf/manifest.xml', '/etc/vintf/compatibility_matrix.xml',
                   '/etc/fstab.qcom', '/etc/selinux/plat_sepolicy_vers.txt',
                   '/etc/selinux/vendor_file_contexts', '/etc/selinux/vendor_sepolicy.cil',
                   '/etc/selinux/vendor_property_contexts',
                   '/etc/selinux/plat_pub_versioned.cil', '/ueventd.rc', '/bin/init.qti.ims.sh',
                   '/bin/init.qcom.class_core.sh', '/bin/init.class_main.sh',
                   '/bin/init.qcom.post_boot.sh'],
        'system': ['/system/build.prop', '/system/etc/prop.default', '/init.rc',
                   '/init.b2g.rc', '/init.environ.rc', '/ueventd.rc',
                   '/system/bin/move_wifi_data.sh', '/system/bin/move_time_data.sh',
                   '/system/etc/selinux/plat_file_contexts',
                   '/system/etc/selinux/plat_property_contexts',
                   '/system/etc/selinux/plat_sepolicy.cil',
                   '/system/etc/selinux/mapping/29.0.cil',
                   '/system/etc/selinux/mapping/29.0.compat.cil',
                   '/system/etc/ld.config.txt', '/system/etc/ld.config.29.txt',
                   '/system/usr/keylayout/matrix_keypad.kl', '/system/usr/keylayout/gpio-keys.kl',
                   '/system/usr/keylayout/Generic.kl'],
    }
    for kind, paths in targets.items():
        image = getattr(args, kind)
        for path in paths:
            name = kind + path
            try:
                data = query(image, 'cat ' + path)
            except RuntimeError as error:
                results['missing'][name] = str(error)
                continue
            output = args.output / kind / path.lstrip('/')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            results['files'][name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if path.endswith(('build.prop', 'prop.default')):
                props = {}
                for line in data.decode('utf-8', errors='replace').splitlines():
                    if '=' in line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        if key.startswith(('ro.product', 'ro.build', 'ro.vendor', 'ro.board', 'ro.vndk', 'ro.treble')):
                            props[key] = value
                results['properties'][name] = props
            if path == '/etc/vintf/manifest.xml':
                root = ET.fromstring(data)
                results['vintf_target_level'] = root.get('target-level')
                results['hal_declarations'] = [
                    {'name': hal.findtext('name'), 'versions': [version.text for version in hal.findall('version')],
                     'fqnames': [fq.text for fq in hal.findall('fqname')]}
                    for hal in root.findall('hal')]
    for kind, paths in {'vendor': ['/bin/hw', '/lib/hw', '/etc/init', '/usr/keylayout',
                                  '/usr/idc', '/odm/usr/keylayout', '/odm/usr/idc'],
                        'system': ['/system/framework', '/system/bin', '/system/usr/keylayout',
                                   '/system/usr/idc']}.items():
        for path in paths:
            name = kind + path
            try:
                data = query(getattr(args, kind), 'ls -p ' + path)
                output = args.output / (name.replace('/', '_') + '.listing.txt')
                output.write_bytes(data)
            except RuntimeError as error:
                results['missing'][name] = str(error)
    (args.output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'files': len(results['files']), 'hal_declarations': len(results['hal_declarations']),
                      'missing_paths': list(results['missing'])}, indent=2))


if __name__ == '__main__':
    main()
