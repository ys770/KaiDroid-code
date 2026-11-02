"""Map captured storage/USB configuration without mounting or changing a device."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--fstab', type=Path, required=True)
    parser.add_argument('--init-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture postflight failed')
    hashes = {}
    for name in ('device-tree.tar', 'properties.txt', 'mounts.txt'):
        entry = next(e for e in manifest['reads'] if e['file'] == name)
        hashes[name] = digest((args.capture / name).read_bytes())
        if entry['returncode'] or entry['stderr_bytes'] or hashes[name] != entry['sha256']:
            raise ValueError('Invalid captured read: ' + name)
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        props = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
    handles = {int.from_bytes(v, 'big'): k.rsplit('/', 1)[0]
               for k, v in props.items() if k.endswith('/phandle') and len(v) == 4}
    nodes = {}
    for path, data in props.items():
        parent, name = path.rsplit('/', 1)
        if not (parent.endswith(('/sdhci@7824900', '/sdhci@7864900', '/usb@78db000', '/sdcc1ice@7803000'))
                or '/firmware/android/fstab/' in parent):
            continue
        if name in ('compatible', 'status', 'device_type', 'dev', 'type', 'mnt_flags',
                    'fsmgr_flags', 'clock-names', 'pinctrl-names', 'dr_mode', 'phy_type'):
            value = data.rstrip(b'\0').decode().split('\0')
        elif name.endswith('-supply') and len(data) == 4:
            value = {'referenced_node': handles.get(int.from_bytes(data, 'big'), 'UNRESOLVED')}
        elif not data:
            value = {'boolean_property_present': True}
        else:
            value = {'raw_hex': data.hex()}
        nodes.setdefault(parent, {})[name] = value
    for suffix in ('/sdhci@7824900', '/sdhci@7864900', '/usb@78db000', '/sdcc1ice@7803000'):
        if not any(node.endswith(suffix) for node in nodes):
            raise ValueError('Expected controller absent: ' + suffix)
    fstab = []
    for number, line in enumerate(args.fstab.read_text().splitlines(), 1):
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 5:
            raise ValueError('Unexpected fstab row: ' + str(number))
        fstab.append(dict(zip(('source', 'mount', 'type', 'mount_options', 'fs_mgr_flags'), parts)))
    mountpoints = {'/', '/vendor', '/data', '/cache', '/sysdata', '/vendor/firmware_mnt',
                   '/vendor/dsp', '/mnt/vendor/persist', '/config', '/dev/usb-ffs/adb'}
    mounts = [line for line in (args.capture / 'mounts.txt').read_text().splitlines()
              if len(line.split()) >= 2 and line.split()[1] in mountpoints]
    allowed = {'ro.crypto.state', 'ro.crypto.type', 'ro.boot.usbconfigfs', 'sys.usb.config',
               'sys.usb.state', 'sys.usb.controller', 'sys.usb.configfs', 'sys.usb.ffs.ready',
               'persist.sys.usb.config', 'init.svc.vold', 'init.svc.keymaster-4-0',
               'vold.has_adoptable', 'vold.has_quota', 'vold.has_reserved'}
    properties = {}
    for line in (args.capture / 'properties.txt').read_text().splitlines():
        match = re.fullmatch(r'\[([^]]+)\]: \[(.*)\]', line)
        if match and match[1] in allowed:
            properties[match[1]] = match[2]
    init = []
    for name in ('init.target.rc', 'init.qcom.rc', 'init.qcom.usb.rc', 'init.msm.usb.configfs.rc'):
        file = args.init_root / name
        trigger = None
        selected = []
        for number, line in enumerate(file.read_text().splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if not line[0].isspace():
                trigger = stripped if stripped.startswith('on ') else None
            elif trigger and (stripped.startswith('mount_all ') or
                    re.match(r'setprop (?:sys|persist\.sys|vendor)\.usb\.(?:config|configfs|controller) ', stripped)):
                selected.append({'line': number, 'trigger': trigger, 'directive': stripped})
        init.append({'file': name, 'sha256': digest(file.read_bytes()), 'selected_actions': selected})
    result = {'scope': 'Engineering captured DT/properties/mounts; retail fstab/init. No USB changes, mounts, formatting or key access. Static triggers do not prove execution.',
              'capture_hashes': hashes, 'fstab_sha256': digest(args.fstab.read_bytes()),
              'fstab': fstab, 'captured_mounts': mounts, 'captured_properties': properties,
              'nodes': nodes, 'init': init}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'fstab_rows': len(fstab), 'mounts': len(mounts), 'nodes': len(nodes)}))


if __name__ == '__main__':
    main()
