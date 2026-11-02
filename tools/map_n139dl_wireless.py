"""Summarize wireless DT and service evidence from existing captures only."""
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
    parser.add_argument('--init-root', type=Path, required=True)
    parser.add_argument('--vendor-properties', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture failed identity postflight')
    hashes = {}
    for name in ('device-tree.tar', 'hal-services.txt', 'properties.txt', 'processes.txt'):
        entry = next(e for e in manifest['reads'] if e['file'] == name)
        data = (args.capture / name).read_bytes()
        if entry['returncode'] or entry['stderr_bytes'] or digest(data) != entry['sha256']:
            raise ValueError('Invalid capture input: ' + name)
        hashes[name] = digest(data)
    nodes = {}
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        properties = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
        handles = {int.from_bytes(data, 'big'): path.rsplit('/', 1)[0]
                   for path, data in properties.items() if path.endswith('/phandle') and len(data) == 4}
        for m in tree:
            if not m.isfile():
                continue
            node, prop = m.name.rsplit('/', 1)
            if any(token in node.lower() for token in ('wifi', 'wlan', 'wcnss', 'bluetooth', 'sdhci@')):
                data = tree.extractfile(m).read()
                item = nodes.setdefault(node, {})
                if prop in ('compatible', 'status', 'clock-names', 'pinctrl-names'):
                    item[prop] = data.rstrip(b'\0').decode().split('\0')
                elif (prop.endswith('-supply') or re.fullmatch(r'pinctrl-\d+', prop)) and len(data) % 4 == 0:
                    item[prop] = [handles.get(int.from_bytes(data[i:i+4], 'big'), 'UNRESOLVED') for i in range(0, len(data), 4)]
                elif prop in ('linux,min-uv', 'linux,max-uv') and len(data) == 4:
                    item[prop] = int.from_bytes(data, 'big')
                else:
                    item.setdefault('other_property_names', []).append(prop)
    services = []
    for p in sorted(args.init_root.rglob('*.rc')):
        raw = p.read_bytes()
        lines = raw.decode().splitlines()
        for i, line in enumerate(lines):
            if not line.startswith('service ') or not any(n in line.lower() for n in ('wifi', 'wcnss', 'bluetooth', 'wpa_supplicant')):
                continue
            block = [line]
            for following in lines[i + 1:]:
                if following and not following[0].isspace() and not following.startswith('#'):
                    break
                if following.strip() and not following.lstrip().startswith('#'):
                    block.append(following.strip())
            services.append({'file': str(p.relative_to(args.init_root)), 'file_sha256': digest(raw),
                             'line': i + 1, 'definition': block})
    keys = ('vendor.qcom.bluetooth.soc', 'ro.vendor.bluetooth.lazyhal',
            'persist.vendor.qcom.bluetooth.enable.splita2dp', 'wifi.interface',
            'wifi.direct.interface', 'wlan.driver.status')
    stock_data = args.vendor_properties.read_bytes()
    stock = dict(line.split('=', 1) for line in stock_data.decode().splitlines()
                 if '=' in line and not line.startswith('#'))
    live = dict(re.findall(r'^\[(.*?)\]: \[(.*?)\]$', (args.capture / 'properties.txt').read_text(), re.M))
    rows = [line for line in (args.capture / 'hal-services.txt').read_text().splitlines()
            if any(n in line.lower() for n in ('wifi', 'bluetooth')) and ' Y ' in line]
    result = {'scope': 'Engineering captured DT/properties/registration, retail init/properties; no current live or Android-port validation',
              'capture_hashes': hashes, 'tree_nodes': nodes, 'services': services,
              'vendor_properties_sha256': digest(stock_data),
              'selected_properties': {key: {'retail_file': stock.get(key), 'engineering_capture': live.get(key)} for key in keys},
              'registered_interfaces': rows,
              'bluetooth_hci_registered_in_capture': any('android.hardware.bluetooth@1.0::IBluetoothHci/default' in row for row in rows),
              'wireless_function_validated': False}
    with args.output.open('x', encoding='utf-8') as f:
        f.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'nodes': nodes, 'service_definitions': len(services),
                      'selected_properties': result['selected_properties'],
                      'bluetooth_hci_registered': result['bluetooth_hci_registered_in_capture']}, indent=2))


if __name__ == '__main__':
    main()
