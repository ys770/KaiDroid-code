"""Decode selected captured power DT bindings; never change charge or thermal controls."""
import argparse
import hashlib
import json
import struct
import tarfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--init-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture postflight failed')
    hashes = {}
    for name in ('device-tree.tar', 'hal-services.txt'):
        entry = next(e for e in manifest['reads'] if e['file'] == name)
        digest = hashlib.sha256((args.capture / name).read_bytes()).hexdigest()
        if entry['returncode'] or entry['stderr_bytes'] or digest != entry['sha256']:
            raise ValueError('Invalid captured read: ' + name)
        hashes[name] = digest
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        props = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
    handles = {int.from_bytes(v, 'big'): k.rsplit('/', 1)[0] for k, v in props.items()
               if k.endswith('/phandle') and len(v) == 4}
    nodes = {}
    strings = ('compatible', 'status', 'name', 'qcom,battery-type')
    refs = ('qcom,battery-data', 'qcom,pmic-revid', 'qcom,bms-vadc', 'qcom,bms-adc_tm', 'qcom,chg-vadc', 'qcom,chg-adc_tm')
    for path, data in props.items():
        parent, name = path.rsplit('/', 1)
        if not parent.endswith(('/qcom,charger', '/qcom,vmbms', '/qcom,FIH1500-batterydata')):
            continue
        if name in strings:
            value = data.rstrip(b'\0').decode().split('\0')
        elif name in refs and len(data) == 4:
            value = {'referenced_node': handles.get(int.from_bytes(data, 'big'), 'UNRESOLVED')}
        elif not data:
            value = {'boolean_property_present': True}
        elif len(data) % 4 == 0:
            value = {'raw_u32_cells': [v[0] for v in struct.iter_unpack('>I', data)]}
        else:
            value = {'raw_hex': data.hex()}
        nodes.setdefault(parent, {})[name] = value
    services = []
    for file in sorted(args.init_root.glob('android.hardware.*.rc')):
        if not any(n in file.name for n in ('health@', 'power@', 'thermal@', 'light@')):
            continue
        data = file.read_bytes()
        services.append({'file': file.name, 'sha256': hashlib.sha256(data).hexdigest(),
                         'directives': [s.strip() for s in data.decode().splitlines() if s.strip() and not s.lstrip().startswith('#')]})
    result = {'scope': 'Engineering captured tree and HAL registrations plus retail init definitions. DT cells are configuration, not measurements; no charging/thermal controls changed.',
              'capture_hashes': hashes, 'nodes': nodes, 'services': services,
              'registered_interfaces': [s for s in (args.capture / 'hal-services.txt').read_text().splitlines()
                  if s.startswith('DM,FC Y ') and any('android.hardware.' + n + '@' in s for n in ('health', 'power', 'thermal', 'light'))]}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'nodes': len(nodes), 'services': len(services), 'registrations': len(result['registered_interfaces'])}))


if __name__ == '__main__':
    main()
