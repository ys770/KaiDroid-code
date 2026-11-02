"""Inspect captured vendor Binder services offline; never execute firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from probe_android_filesystems import query

SERVICES = {
    'dtseagleservice': 'dts_eagle_service',
    'fidodaemon': 'fidodaemon',
    'secotad': 'secotad',
    'seemp_health_daemon': 'seemp_healthd',
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--vendor', required=True, type=Path)
    p.add_argument('--system', type=Path, help='Optional captured SAR system image for alternate paths and platform contexts')
    p.add_argument('--init-root', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    init_files = sorted(a.init_root.rglob('*.rc'))
    if not a.init_root.is_dir() or not init_files:
        raise ValueError('Provide the populated captured init tree')
    if a.output.exists():
        raise ValueError('Use a new output directory')
    a.output.mkdir(parents=True)
    contexts = {}
    for name in ('vndservice_contexts', 'vendor_service_contexts', 'vendor_hwservice_contexts'):
        path = '/etc/selinux/' + name
        try:
            data = query(a.vendor, 'cat ' + path)
        except RuntimeError as error:
            if 'File not found' not in str(error):
                raise
            contexts[name] = {'present': False, 'error': str(error)}
            continue
        (a.output / name).write_bytes(data)
        contexts[name] = {'present': True, 'sha256': hashlib.sha256(data).hexdigest(),
                          'matches': [line for line in data.decode().splitlines()
                                      if any(n in line for n in SERVICES)]}
    rows = []
    for domain, binary in SERVICES.items():
        row = {'domain': domain, 'vendor_path': '/bin/' + binary, 'init_matches': []}
        for rc in init_files:
            data = rc.read_bytes()
            matches = [{'line': i, 'text': line.strip()} for i, line in enumerate(data.decode().splitlines(), 1)
                       if binary in line or domain in line]
            if matches:
                row['init_matches'].append({'path': rc.relative_to(a.init_root).as_posix(),
                                            'sha256': hashlib.sha256(data).hexdigest(), 'matches': matches})
        try:
            data = query(a.vendor, 'cat ' + row['vendor_path'])
        except RuntimeError as error:
            if 'File not found' not in str(error):
                raise
            row.update({'present': False, 'error': str(error)})
            rows.append(row)
            continue
        dest = a.output / binary
        dest.write_bytes(data)
        row.update({'present': True, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        elf = subprocess.run(['readelf', '-d', str(dest)], capture_output=True, text=True, check=True).stdout
        row['needed'] = re.findall(r'\(NEEDED\).*\[(.*?)\]', elf)
        strings = re.findall(rb'[ -~]{5,}', data)
        row['binder_device_strings'] = sorted({s.decode() for s in strings
                                               if s in (b'/dev/binder', b'/dev/vndbinder', b'/dev/hwbinder')})
        rows.append(row)
    system_checks = {}
    if a.system:
        paths = ['/system/bin/' + name for name in SERVICES.values()]
        paths += ['/system/etc/selinux/plat_service_contexts',
                  '/system/etc/selinux/plat_file_contexts']
        for path in paths:
            try:
                data = query(a.system, 'cat ' + path)
            except RuntimeError as error:
                if 'File not found' not in str(error):
                    raise
                system_checks[path] = {'present': False, 'error': str(error)}
                continue
            item = {'present': True, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            if path.endswith('_contexts'):
                item['matches'] = [line for line in data.decode().splitlines()
                                   if any(n in line for n in SERVICES)]
                (a.output / Path(path).name).write_bytes(data)
            system_checks[path] = item
    report = {'scope': 'Exact vendor filesystem paths and supplied captured init files; missing paths do not prove absence of renamed binaries. Strings/ELF imports do not prove runtime Binder selection or service use.',
              'vendor_sha256': hashlib.sha256(a.vendor.read_bytes()).hexdigest(),
              'init_source_sha256': {p.relative_to(a.init_root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in init_files},
              'contexts': contexts, 'services': rows, 'system_checks': system_checks,
              'system_sha256': hashlib.sha256(a.system.read_bytes()).hexdigest() if a.system else None}
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'services': [{'domain': r['domain'], 'present': r['present']} for r in rows]}))


if __name__ == '__main__':
    main()
