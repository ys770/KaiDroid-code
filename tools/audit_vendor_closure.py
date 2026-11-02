"""Walk vendor DT_NEEDED edges, recording system/VNDK boundaries without executing firmware.

Uses captured one-hop namespace routes. Does not emulate actual linker ordering,
resolve symlinks or expand dependencies beyond the vendor namespace boundary.
"""
import argparse
import collections
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from audit_linker_routes import read_section, routes
from probe_android_filesystems import query


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--root', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    inventory = json.loads(args.inventory.read_text())
    paths, candidates = {}, collections.defaultdict(list)
    for kind in ('vendor', 'system'):
        for item in inventory[kind + '_inventory']:
            tagged = kind + ':' + item['path']
            candidates[PurePosixPath(item['path']).name].append(tagged)
            paths[tagged] = item
    config = read_section(args.config.read_text(), 'vendor')
    pending, visited, binaries, errors = list(args.root), set(), [], []
    while pending:
        path = pending.pop(0)
        if path in visited:
            continue
        visited.add(path)
        if len(visited) > 500:
            raise ValueError('Vendor graph limit exceeded')
        item = paths.get('vendor:' + path)
        if not item or int(item['mode'], 8) & 0o170000 != 0o100000:
            errors.append({'path': path, 'error': 'Not an inventoried regular vendor file; symlinks are not resolved'})
            continue
        data = query(args.vendor, 'cat ' + path)
        if data[:6] != b'\x7fELF\x01\x01' or int.from_bytes(data[18:20], 'little') != 40:
            errors.append({'path': path, 'error': 'Not ARM32 little-endian ELF'})
            continue
        output = args.output / 'vendor' / path.lstrip('/')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        dynamic = subprocess.run(['readelf', '-d', str(output)], check=True, capture_output=True, text=True).stdout
        needed = {}
        for name in re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic):
            eligible = routes(config, name, candidates.get(name, []))
            needed[name] = {'filename_candidates': candidates.get(name, []), 'routes': eligible}
            for route in eligible:
                if route['namespace'] == 'default' and route['candidate'].startswith('vendor:'):
                    pending.append(route['candidate'][len('vendor:'):])
        binaries.append({'path': path, 'local_file': str(output), 'sha256': hashlib.sha256(data).hexdigest(),
                         'bytes': len(data), 'needed': needed,
                         'runpath': re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', dynamic),
                         'without_route': [n for n, item in needed.items() if not item['routes']]})
    result = {'roots': args.root, 'binaries': binaries, 'errors': errors,
              'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest(),
              'inventory_sha256': hashlib.sha256(args.inventory.read_bytes()).hexdigest(),
              'scope': 'Vendor-only DT_NEEDED traversal using captured route candidates. System/VNDK are boundaries; no symbols, actual resolution, dlopen, namespace ordering or runtime validation.'}
    (args.output / 'graph.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'vendor_elfs': len(binaries), 'edges': sum(len(b['needed']) for b in binaries),
                      'without_route': {b['path']:b['without_route'] for b in binaries if b['without_route']},
                      'errors': errors, 'runpaths': {b['path']:b['runpath'] for b in binaries if b['runpath']}}, indent=2))


if __name__ == '__main__':
    main()
