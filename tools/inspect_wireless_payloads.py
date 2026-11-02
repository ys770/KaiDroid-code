"""Hash selected vendor wireless payloads and inspect static metadata, never load them."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from probe_android_filesystems import query


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vendor', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    paths = ['/lib/modules/acc1340_wlan.ko', '/lib/modules/modules.dep',
             '/lib/libbt-vendor-brt.so', '/lib/libwifi-hal.so',
             '/lib/libwifi-hal-ctrl.so', '/lib/libwifi-hal-qcom.so',
             '/lib/hw/android.hardware.bluetooth@1.0-impl-qti.so',
             '/firmware/wlan/ampedrf/Acc1340_rf.sdd', '/firmware/wlan/ampedrf/wsm_6010.bin']
    for line in query(args.vendor, 'ls -p /firmware').decode().splitlines():
        fields = line.split('/')
        if len(fields) >= 7 and fields[2].startswith('100') and fields[5].endswith('.brbin'):
            paths.append('/firmware/' + fields[5])
    files = []
    for path in paths:
        data = query(args.vendor, 'cat ' + path)
        dest = args.output / path.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        item = {'path': '/vendor' + path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        if data.startswith(b'\x7fELF'):
            strings = [s.decode('ascii') for s in re.findall(rb'[\x20-\x7e]{6,}', data)]
            item['wireless_reference_strings'] = sorted(set(s for s in strings if
                not s.startswith('/work/') and
                any(token in s.lower() for token in ('acc1340', 'ampedrf', 'barrot', 'libbt-vendor-brt', '.brbin', 'wsm_6010')) and
                (any(ext in s for ext in ('.ko', '.so', '.bin', '.sdd', '.brbin')) or
                 s in ('acc1340_sdio_probe', 'acc1340_sdio_ids', 'acc1340_wlan') or
                 s.startswith(('author=', 'description=')))))
            if path.endswith('.ko'):
                item['modinfo'] = subprocess.run(['readelf', '-p', '.modinfo', str(dest)], check=True,
                                                capture_output=True, text=True).stdout.splitlines()
            else:
                dynamic = subprocess.run(['readelf', '-d', str(dest)], check=True,
                                          capture_output=True, text=True).stdout
                item['needed'] = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
                item['soname'] = re.findall(r'\(SONAME\).*?\[(.*?)\]', dynamic)
                symbols = subprocess.run(['readelf', '-sW', str(dest)], check=True,
                                         capture_output=True, text=True).stdout
                item['loader_imports'] = sorted(set(re.findall(
                    r'\bUND\s+((?:dlopen|android_dlopen_ext|dlsym))(?:@|\s|$)', symbols)))
                item['serial_device_literals'] = sorted(set(s for s in strings if s.startswith('/dev/tty')))
        files.append(item)
    report = {'vendor_sha256': hashlib.sha256(args.vendor.read_bytes()).hexdigest(), 'files': files,
              'scope': 'Retail2216 file existence, hashes and static metadata/strings; not runtime selection, successful firmware upload or physical chip identification'}
    (args.output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
