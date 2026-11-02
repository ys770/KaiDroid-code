"""Check direct ELF import candidates, including symbol versions, without loading code.

This is not linker namespace, ABI layout, transitive closure or runtime validation.
Run under Linux with readelf. Original inputs are never modified.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from audit_apk_native import dynamic_symbols


def inspect(path):
    data = path.read_bytes()
    raw = subprocess.run(['readelf', '--dyn-syms', '--wide', str(path)],
                         check=True, capture_output=True, text=True).stdout
    return {'path': str(path), 'sha256': hashlib.sha256(data).hexdigest(),
            'symbols': list(dynamic_symbols(raw))}


def split(name):
    pieces = name.replace('@@', '@').split('@', 1)
    return pieces[0], pieces[1] if len(pieces) == 2 else None


def exports(record):
    return {s['name'] for s in record['symbols'] if s['section'] != 'UND'
            and s['binding'] in ('GLOBAL', 'WEAK', 'UNIQUE')
            and s['visibility'] in ('DEFAULT', 'PROTECTED')}


def matches(required, provided):
    name, version = split(required)
    other, offered = split(provided)
    return name == other and (version == offered if version else
                             ('@' not in provided or '@@' in provided))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--dependency', type=Path, action='append', required=True)
    parser.add_argument('--consumer-graph', type=Path, action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Use a new output report')
    library, reference = inspect(args.library), inspect(args.reference)
    dependencies = [inspect(p) for p in args.dependency]
    provided = {d['path']: exports(d) for d in dependencies}
    imports = []
    for symbol in library['symbols']:
        if symbol['section'] != 'UND' or symbol['binding'] not in ('GLOBAL', 'WEAK'):
            continue
        candidates = [p for p, names in provided.items()
                      if any(matches(symbol['name'], n) for n in names)]
        imports.append({'name': symbol['name'], 'binding': symbol['binding'],
                        'candidates': candidates})
    missing_names = {split(n)[0] for n in exports(reference)} - {split(n)[0] for n in exports(library)}
    consumers, graph_records = [], []
    for path in args.consumer_graph:
        graph = json.loads(path.read_text())
        if graph.get('errors'):
            raise ValueError('Consumer graph contains errors')
        graph_records.append({'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                              'binaries_checked': len(graph['binaries'])})
        for node in graph['binaries']:
            item = inspect(Path(node['local_file']))
            if item['sha256'] != node['sha256']:
                raise ValueError('Consumer hash mismatch: ' + item['path'])
            hits = sorted({s['name'] for s in item['symbols'] if s['section'] == 'UND'
                           and split(s['name'])[0] in missing_names})
            if hits:
                consumers.append({'path': item['path'], 'sha256': item['sha256'], 'imports': hits})
    result = {'library': {k: v for k, v in library.items() if k != 'symbols'},
              'reference': {k: v for k, v in reference.items() if k != 'symbols'},
              'dependencies': [{k: v for k, v in d.items() if k != 'symbols'} for d in dependencies],
              'imports': imports, 'unresolved_strong_imports': [s['name'] for s in imports
                  if s['binding'] == 'GLOBAL' and not s['candidates']],
              'missing_reference_export_names': sorted(missing_names),
              'consumer_graphs': graph_records,
              'consumers_of_missing_names': consumers,
              'scope': 'Static direct symbol candidates only. Does not prove namespace reachability, symbol binding order, ABI layouts or runtime behavior.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'imports': len(imports), 'unresolved_strong_imports': result['unresolved_strong_imports'],
                      'consumer_hits': len(consumers)}))


if __name__ == '__main__':
    main()
