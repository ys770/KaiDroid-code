"""Inspect vendor ELF dependencies offline; existence is not ABI compatibility.

Uses Linux debugfs/readelf without mounting or running firmware. Output belongs
under ignored work/. Dynamic dlopen dependencies and linker visibility need
separate analysis even when every DT_NEEDED filename exists.
"""
import argparse
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from probe_android_filesystems import query


def inventory(image, roots):
    pending, result, visited = list(roots), [], set()
    while pending:
        folder = pending.pop()
        if folder in visited:
            continue
        visited.add(folder)
        if len(visited) > 1000:
            raise ValueError('Directory traversal limit exceeded')
        for line in query(image, 'ls -p ' + folder).decode().splitlines():
            fields = line.split('/')
            if len(fields) < 8 or fields[5] in ('.', '..'):
                continue
            path = folder.rstrip('/') + '/' + fields[5]
            mode = int(fields[2], 8)
            if mode & 0o170000 == 0o040000:
                pending.append(path)
            else:
                result.append({'path': path, 'mode': fields[2], 'bytes': fields[6]})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--include', action='append', default=[],
                        help='Additional exact vendor-image path to audit, e.g. /lib/libril-qc-hal-qmi.so')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    # Include ordinary daemons as candidates and explicit --include targets.
    # The default ELF audit below remains limited to HAL directories.
    vendor_roots = ['/lib', '/bin']
    vendor_files = inventory(args.vendor, vendor_roots)
    missing = set(args.include) - {item['path'] for item in vendor_files}
    if missing:
        raise ValueError('Requested vendor paths not inventoried: ' + ', '.join(sorted(missing)))
    system_files = inventory(args.system, ['/system/lib'])
    candidates = defaultdict(list)
    for kind, files in [('vendor', vendor_files), ('system', system_files)]:
        for item in files:
            candidates[Path(item['path']).name].append(kind + ':' + item['path'])
    binaries = []
    for item in vendor_files:
        path = item['path']
        if not (path.startswith('/bin/hw/') or path.startswith('/lib/hw/') or path in args.include):
            continue
        if int(item['mode'], 8) & 0o170000 != 0o100000:
            continue
        data = query(args.vendor, 'cat ' + path)
        if not data.startswith(b'\x7fELF'):
            continue
        destination = args.output / 'vendor' / path.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        parsed = subprocess.run(['readelf', '-h', '-d', str(destination)], check=True,
                                capture_output=True, text=True).stdout
        needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', parsed)
        binaries.append({'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                         'elf_class': data[4], 'machine': int.from_bytes(data[18:20], 'little'),
                         'needed': {name: candidates.get(name, []) for name in needed}})
    unresolved = sorted({name for binary in binaries for name, paths in binary['needed'].items() if not paths})
    result = {'vendor_inventory': vendor_files, 'system_inventory': system_files,
              'binaries': binaries, 'unresolved_filenames': unresolved,
              'extra_paths': args.include,
              'vendor_inventory_roots': vendor_roots,
              'scope': 'Direct DT_NEEDED for vendor bin/hw, lib/hw and explicitly included paths. Filename candidates only; not recursive symbol/ABI or namespace validation.'}
    (args.output / 'dependencies.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'vendor_files': len(vendor_files), 'system_files': len(system_files),
                      'elf_binaries': len(binaries), 'unresolved_filenames': unresolved}, indent=2))


if __name__ == '__main__':
    main()
