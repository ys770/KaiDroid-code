"""Inventory static ashmem indicators in a hash-checked vendor ELF graph.

Strings and imports identify inspection candidates, not executed call paths.
Run from the project root under Linux with readelf available.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from audit_apk_native import dynamic_symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--graph', type=Path)
    source.add_argument('--vndk-summary', type=Path,
                        help='summary.json from compare_vndk_exports.py')
    parser.add_argument('--captured-root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if bool(args.vndk_summary) != bool(args.captured_root):
        parser.error('--captured-root is required only with --vndk-summary')
    graph_bytes = (args.graph or args.vndk_summary).read_bytes()
    graph = json.loads(graph_bytes)
    if args.vndk_summary:
        nodes = []
        for item in graph['libraries']:
            parts = Path(item['path']).parts
            folder = {'vndk-29': 'vndk-core', 'vndk-sp-29': 'vndk-sp'}.get(parts[-2])
            if folder is None:
                raise ValueError('Unexpected VNDK path: ' + item['path'])
            nodes.append({'path': item['path'], 'sha256': item['captured_sha256'],
                          'local_file': str(args.captured_root / folder / parts[-1])})
        graph = {'binaries': nodes}
    if graph.get('errors') or not graph.get('binaries'):
        raise ValueError('Require a nonempty graph without extraction errors')
    results = []
    for node in graph['binaries']:
        path = Path(node['local_file'])
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != node['sha256']:
            raise ValueError('Graph hash mismatch: ' + str(path))
        raw = subprocess.run(['readelf', '--dyn-syms', '--wide', str(path)],
                             check=True, capture_output=True, text=True).stdout
        imports = sorted({s['name'] for s in dynamic_symbols(raw)
                          if s['section'] == 'UND' and 'ashmem' in s['name'].lower()})
        offsets = []
        start = 0
        while (offset := data.find(b'/dev/ashmem', start)) >= 0:
            offsets.append(offset)
            start = offset + 1
        results.append({'path': node['path'], 'sha256': digest,
                        'ashmem_imports': imports,
                        'legacy_path_prefix_file_offsets': offsets,
                        'boot_id_path_present': b'/proc/sys/kernel/random/boot_id' in data})
    result = {'source_sha256': hashlib.sha256(graph_bytes).hexdigest(),
              'source_kind': 'vndk-comparison' if args.vndk_summary else 'vendor-closure',
              'scope': 'Only files in the supplied inventory; not a full transitive system dependency traversal. Imports do not prove provider or execution; strings do not prove direct opens. Absence does not exclude dlopen, computed paths, inline ioctls or FD consumers.',
              'runtime_validated': False, 'binaries': results}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'scanned': len(results), 'candidates': [r for r in results
          if r['ashmem_imports'] or r['legacy_path_prefix_file_offsets']]}, indent=2))


if __name__ == '__main__':
    main()
