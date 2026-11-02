"""Match captured DT_NEEDED candidates to one-hop Android linker namespace routes.

This is a configuration audit, not a linker emulator: no symbols, RUNPATH,
already-loaded objects, symlink targets, dlopen or runtime search are resolved.
"""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path, PurePosixPath


def read_section(text, section):
    active = False
    result = {}
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if line.startswith('['):
            active = line == '[' + section + ']'
            continue
        if not active or not line:
            continue
        match = re.fullmatch(r'([\w.]+)\s*(\+=|=)\s*(.*)', line)
        if not match:
            raise ValueError('Unsupported linker configuration line: ' + line)
        key, op, value = match.groups()
        if op == '=':
            result[key] = [value]
        else:
            result.setdefault(key, []).append(value)
    if not result:
        raise ValueError('Linker section not found')
    return result


def values(config, key, separator=':'):
    return [item.strip() for value in config.get(key, []) for item in value.split(separator) if item.strip()]


def runtime_path(candidate):
    image, path = candidate.split(':', 1)
    if image == 'vendor':
        return '/vendor' + path
    if image == 'system':
        return path
    raise ValueError('Unsupported inventory image: ' + image)


def routes(config, name, candidates, namespace='default'):
    eligible = [(namespace, 'local search path')]
    for linked in values(config, 'namespace.' + namespace + '.links', ','):
        prefix = 'namespace.' + namespace + '.link.' + linked
        if name in values(config, prefix + '.shared_libs') or values(config, prefix + '.allow_all_shared_libs') == ['true']:
            eligible.append((linked, 'allowed namespace link'))
    found = []
    for ns, reason in eligible:
        directories = [p.replace('${LIB}', 'lib') for p in values(config, 'namespace.' + ns + '.search.paths')]
        for candidate in candidates:
            path = runtime_path(candidate)
            if path in [str(PurePosixPath(directory) / name) for directory in directories]:
                found.append({'candidate': candidate, 'namespace': ns, 'reason': reason})
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--dependencies', type=Path, required=True)
    parser.add_argument('--binary', action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = read_section(args.config.read_text(), 'vendor')
    dependencies = json.loads(args.dependencies.read_text())
    binaries = {b['path']: b for b in dependencies['binaries']}
    results = []
    for name in args.binary:
        binary = binaries[name]
        needed = {lib: {'filename_candidates': candidates, 'routes': routes(config, lib, candidates)}
                  for lib, candidates in binary['needed'].items()}
        results.append({'path': name, 'sha256': binary['sha256'], 'needed': needed,
                        'without_route': [lib for lib, detail in needed.items() if not detail['routes']]})
    result = {'config_sha256': hashlib.sha256(args.config.read_bytes()).hexdigest(),
              'dependency_report_sha256': hashlib.sha256(args.dependencies.read_bytes()).hexdigest(),
              'section': 'vendor', 'source_namespace': 'default', 'abi_directory': 'lib', 'binaries': results,
              'scope': 'One-hop static namespace/search-path candidates against captured inventory. Not actual resolution, symlink/ELF validation, recursive dependencies, symbol ABI, or Android 11 compatibility.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    for binary in results:
        counts = collections.Counter(route['namespace'] for item in binary['needed'].values() for route in item['routes'])
        print(json.dumps({'binary': binary['path'], 'needed': len(binary['needed']),
                          'candidate_routes': dict(counts), 'without_route': binary['without_route']}))


if __name__ == '__main__':
    main()
