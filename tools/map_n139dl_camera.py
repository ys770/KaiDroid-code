"""Map configured camera candidates, not physically verified sensors."""
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
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--capture', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot'):
        raise ValueError('Capture postflight failed')
    hashes = {}
    for name in ('device-tree.tar', 'hal-services.txt'):
        entry = next(e for e in manifest['reads'] if e['file'] == name)
        data = (args.capture / name).read_bytes()
        if entry['returncode'] or entry['stderr_bytes'] or sha(data) != entry['sha256']:
            raise ValueError('Invalid captured input: ' + name)
        hashes[name] = sha(data)
    args.output.mkdir(parents=True, exist_ok=False)
    files = []

    def extract(path):
        data = query(args.vendor, 'cat ' + path)
        out = args.output / path.lstrip('/')
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        files.append({'path': '/vendor' + path, 'bytes': len(data), 'sha256': sha(data)})
        return data

    modules = []
    root = ET.fromstring(extract('/etc/camera/camera_config.xml'))
    for module in root.findall('CameraModuleConfig'):
        fields = {e.tag: e.text.strip() for e in module if len(e) == 0 and e.text}
        fields['csi'] = {e.tag: e.text.strip() for e in module.find('CSIInfo')}
        for tag, template in [('SensorName', '/lib/libmmcamera_{}.so'),
                              ('EepromName', '/lib/libmmcamera_{}_eeprom.so'),
                              ('FlashName', '/lib/libflash_{}.so')]:
            if tag in fields:
                value = fields[tag]
                if not value.replace('_', '').isalnum():
                    raise ValueError('Unsafe configuration library name')
                extract(template.format(value))
        tuning = fields['ChromatixName']
        if not tuning.replace('_', '').isalnum():
            raise ValueError('Unsafe tuning name')
        tuning_root = ET.fromstring(extract('/etc/camera/' + tuning + '.xml'))
        names = sorted({e.text.strip() for e in tuning_root.iter() if len(e) == 0 and e.text and e.text.strip()})
        for name in names:
            if not name.replace('_', '').isalnum():
                raise ValueError('Unsafe tuning library name')
            extract('/lib/libchromatix_' + name + '.so')
        fields['tuning_library_names'] = names
        modules.append(fields)
    with tarfile.open(args.capture / 'device-tree.tar') as tree:
        props = {m.name: tree.extractfile(m).read() for m in tree if m.isfile()}
    handles = {int.from_bytes(data, 'big'): path.rsplit('/', 1)[0] for path, data in props.items()
               if path.endswith('/phandle') and len(data) == 4}
    node = './soc/qcom,cci@1b0c000/qcom,camera@0'
    decoded = {}
    for path, data in props.items():
        parent, prop = path.rsplit('/', 1)
        if parent != node:
            continue
        if prop.endswith('-supply') or prop in ('qcom,eeprom-src', 'qcom,led-flash-src'):
            decoded[prop] = handles.get(int.from_bytes(data, 'big'), 'UNRESOLVED')
        elif prop in ('cell-index', 'qcom,mount-angle', 'qcom,cci-master', 'qcom,csid-sd-index', 'qcom,csiphy-sd-index'):
            decoded[prop] = int.from_bytes(data, 'big')
        elif prop in ('compatible', 'status', 'clock-names', 'qcom,cam-vreg-name'):
            decoded[prop] = data.rstrip(b'\0').decode().split('\0')
    result = {'scope': 'Retail configured sensor/tuning files plus engineering DT/registration; not actual sensor probing or Android camera validation',
              'vendor_sha256': sha(args.vendor.read_bytes()), 'capture_hashes': hashes,
              'configured_modules': modules, 'files': files, 'camera_node': node, 'camera_properties': decoded,
              'registration': [s for s in (args.capture / 'hal-services.txt').read_text().splitlines()
                               if 'camera.provider' in s and s.startswith('DM,FC Y ')]}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'modules': modules, 'verified_files': len(files), 'camera_properties': decoded}, indent=2))


if __name__ == '__main__':
    main()
