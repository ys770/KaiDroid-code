"""Inspect captured sensor, vibrator and GNSS boundaries without device operations."""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path
from probe_android_filesystems import query


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture postflight failed')
    hashes = {}
    for name in ('device-tree.tar', 'hal-services.txt'):
        e = next(e for e in manifest['reads'] if e['file'] == name)
        data = (args.capture / name).read_bytes()
        if e['returncode'] or e['stderr_bytes'] or sha(data) != e['sha256']:
            raise ValueError('Invalid capture: ' + name)
        hashes[name] = sha(data)
    args.output.mkdir(parents=True, exist_ok=False)
    files = []
    for path in ('/etc/sensors/hals.conf', '/lib/hw/sensors.WND.so', '/lib/sensors.ssc.so',
                 '/lib/hw/vibrator.default.so', '/etc/init/android.hardware.gnss@2.0-service-qti.rc',
                 '/etc/init/android.hardware.sensors@1.0-service.rc', '/etc/init/android.hardware.vibrator@1.0-service.rc'):
        data = query(args.vendor, 'cat ' + path)
        dest = args.output / path.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        item = {'path': '/vendor' + path, 'sha256': sha(data), 'bytes': len(data)}
        if path.endswith(('.conf', '.rc')):
            item['directives'] = [s for s in data.decode().splitlines() if s and not s.lstrip().startswith('#')]
        else:
            strings = [s.decode() for s in re.findall(rb'[\x20-\x7e]{6,}', data)]
            item['selected_path_strings'] = sorted({s for s in strings if s.startswith(('/sys/', '/dev/', '/vendor/etc/sensors/', '/system/etc/sensors/'))})
        files.append(item)
    nodes = {}
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        for m in tree:
            if not m.isfile():
                continue
            node, prop = m.name.rsplit('/', 1)
            if (node.endswith(('qcom,vibrator@c000', 'qcom,msm-ssc-sensors', 'hall_sensor')) or '/i2c@' in node) and prop in ('compatible', 'status', 'label'):
                nodes.setdefault(node, {})[prop] = tree.extractfile(m).read().rstrip(b'\0').decode().split('\0')
    result = {'scope': 'Stock file/configuration and captured registration evidence; not fitted-sensor enumeration, GNSS fix, vibrator test or Android support',
              'vendor_sha256': sha(args.vendor.read_bytes()), 'capture_hashes': hashes, 'nodes': nodes, 'files': files,
              'registrations': [s for s in (args.capture / 'hal-services.txt').read_text().splitlines()
                  if s.startswith('DM,FC Y ') and any(n in s for n in ('gnss@', 'sensors@', 'vibrator@'))]}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'files': len(files), 'nodes': len(nodes), 'registration_rows': len(result['registrations'])}))


if __name__ == '__main__':
    main()
