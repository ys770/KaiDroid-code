"""Map captured audio interfaces without executing firmware or changing a phone."""
import argparse
import hashlib
import json
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from probe_android_filesystems import query


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        raise ValueError('Use a new output directory')
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture identity postflight failed')
    verified = {}
    for name in ('device-tree.tar', 'sound-cards.txt', 'sound-pcm.txt', 'hal-services.txt', 'processes.txt'):
        entry = next(e for e in manifest['reads'] if e['file'] == name)
        data = (args.capture / name).read_bytes()
        if entry['returncode'] or entry['stderr_bytes'] or sha(data) != entry['sha256']:
            raise ValueError('Invalid captured input: ' + name)
        verified[name] = sha(data)
    args.output.mkdir(parents=True)
    nodes = {}
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        for member in tree:
            if not member.isfile():
                continue
            node, prop = member.name.rsplit('/', 1)
            if ('sound' in node or 'codec' in node) and prop in ('compatible', 'status', 'qcom,model', 'qcom,audio-routing'):
                data = tree.extractfile(member).read()
                nodes.setdefault(node, {})[prop] = data.rstrip(b'\0').decode().split('\0')
    configs = []
    for line in query(args.vendor, 'ls -p /etc').decode().splitlines():
        fields = line.split('/')
        if len(fields) < 7 or not fields[2].startswith('100'):
            continue
        name = fields[5]
        if not name.endswith('.xml') or not (name == 'default_volume_tables.xml' or name.startswith(('audio_', 'mixer_paths', 'a2dp_audio_', 'r_submix_audio_', 'usb_audio_'))):
            continue
        data = query(args.vendor, 'cat /etc/' + name)
        (args.output / name).write_bytes(data)
        root = ET.fromstring(data)
        configs.append({'path': '/vendor/etc/' + name, 'sha256': sha(data),
                        'root': root.tag,
                        'modules': [dict(m.attrib) for m in root.iter('module')],
                        'device_ports': [m.attrib.get('type') for m in root.iter('devicePort')],
                        'mix_ports': len(list(root.iter('mixPort'))),
                        'routes': len(list(root.iter('route'))),
                        'mixer_paths': len(list(root.iter('path'))),
                        'includes': [m.attrib.get('href') for m in root.iter('{http://www.w3.org/2001/XInclude}include')]})
    included_names = {Path(c['path']).name for c in configs}
    missing_includes = sorted({href for c in configs for href in c['includes'] if href not in included_names})
    result = {'scope': 'Engineering runtime/tree and retail2216 configuration inventory; config presence is not selected-path or Android operation proof',
              'runtime_fingerprint': manifest['before']['fingerprint'],
              'capture_hashes': verified,
              'vendor_sha256': sha(args.vendor.read_bytes()),
              'sound_cards': (args.capture / 'sound-cards.txt').read_text().splitlines(),
              'pcm_endpoints': (args.capture / 'sound-pcm.txt').read_text().splitlines(),
              'registered_audio_interfaces': [line for line in (args.capture / 'hal-services.txt').read_text().splitlines()
                                              if 'audio' in line.lower() and line.startswith('DM,FC Y ')],
              'audio_processes': [line for line in (args.capture / 'processes.txt').read_text().splitlines()
                                  if line.split() and line.split()[0] == 'audioserver'],
              'tree_nodes': nodes, 'configs': configs, 'includes_outside_inventory': missing_includes,
              'android_audio_validated': False}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'tree_nodes': nodes, 'configuration_files': len(configs)}, indent=2))


if __name__ == '__main__':
    main()
