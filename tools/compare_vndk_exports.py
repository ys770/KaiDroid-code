"""Compare captured VNDK exports with pinned upstream references and selected consumers.

Name-level comparison only: symbol versions, object layout, calling convention,
transitive dependencies and dynamic loading remain separate checks.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from audit_apk_native import dynamic_symbols
from probe_android_filesystems import query


def symbols(path):
    raw = subprocess.run(['readelf', '--dyn-syms', '--wide', str(path)], check=True,
                         capture_output=True, text=True).stdout
    exported, imported = set(), set()
    for symbol in dynamic_symbols(raw):
        name = symbol['name'].split('@')[0]
        if symbol['section'] == 'UND' and symbol['binding'] == 'GLOBAL':
            imported.add(name)
        elif symbol['section'] != 'UND' and symbol['binding'] in ('GLOBAL', 'WEAK', 'UNIQUE') and symbol['visibility'] in ('DEFAULT', 'PROTECTED'):
            exported.add(name)
    return exported, imported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--system', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--consumer', type=Path, action='append', default=[])
    parser.add_argument('--consumer-graph', type=Path,
                        help='Hash-checked vendor graph from audit_vendor_closure.py')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((args.reference / 'manifest.json').read_text())
    if args.consumer_graph:
        graph = json.loads(args.consumer_graph.read_text())
        for node in graph['binaries']:
            path = Path(node['local_file'])
            if hashlib.sha256(path.read_bytes()).hexdigest() != node['sha256']:
                raise ValueError('Graph consumer hash mismatch: ' + str(path))
            args.consumer.append(path)
    if not args.consumer:
        parser.error('Supply consumers or a consumer graph')
    consumers = {str(path): {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                            'imports': sorted(symbols(path)[1])} for path in args.consumer}
    imports = {name for consumer in consumers.values() for name in consumer['imports']}
    results = []
    for item in manifest['files']:
        reference = args.reference / item['local_path']
        reference_data = reference.read_bytes()
        if hashlib.sha256(reference_data).hexdigest() != item['sha256']:
            raise ValueError('Upstream reference hash mismatch')
        path = item['captured_candidate'].removeprefix('system:')
        data = query(args.system, 'cat ' + path)
        if data[:6] != b'\x7fELF\x01\x01':
            raise ValueError('Expected captured ARM32 ELF')
        destination = args.output / 'captured' / item['local_path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        old, _ = symbols(destination)
        new, _ = symbols(reference)
        missing = old - new
        results.append({'path': path, 'captured_sha256': hashlib.sha256(data).hexdigest(),
                        'upstream_sha256': item['sha256'], 'identical_bytes': data == reference_data,
                        'captured_exports': len(old), 'upstream_exports': len(new),
                        'captured_names_absent_upstream': sorted(missing),
                        'absent_names_imported_by_selected_consumers': sorted(missing & imports)})
    result = {'upstream_revision': manifest['revision'], 'libraries': results, 'consumers': consumers,
              'scope': 'Unversioned dynamic-symbol names only; not full ABI, resolution, transitive closure, or runtime compatibility.'}
    (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'libraries': len(results), 'identical_bytes': sum(r['identical_bytes'] for r in results),
                      'libraries_with_removed_exports': sum(bool(r['captured_names_absent_upstream']) for r in results),
                      'selected_consumer_gaps': {r['path']:r['absent_names_imported_by_selected_consumers'] for r in results if r['absent_names_imported_by_selected_consumers']}}, indent=2))


if __name__ == '__main__':
    main()
