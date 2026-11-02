"""Create expected name-based ID pairs from aapt2 dumps; not an idmap result."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def read_names(path):
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        match = re.match(r'\s*resource (0x[0-9a-fA-F]{8}) (\S+/\S+)(?:\s|$)', line)
        if match:
            resource_id, name = match.groups()
            if name in result and result[name] != resource_id:
                raise ValueError('Ambiguous name: ' + name)
            result[name] = resource_id
    if not result:
        raise ValueError('No resource records in ' + str(path))
    return result


def compare(target, overlay):
    target_names, overlay_names = read_names(target), read_names(overlay)
    return {
        'target_resource_names': len(target_names),
        'overlay_resource_names': len(overlay_names),
        'matching_names': [dict(name=name, target_id=target_names[name], overlay_id=value)
                           for name, value in sorted(overlay_names.items()) if name in target_names],
        'missing_target_names': sorted(set(overlay_names) - set(target_names)),
        'dump_sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                       for name, path in [('target', target), ('overlay', overlay)]},
        'scope': 'Expected legacy name lookup pairs from independent aapt2 dumps. Does not execute libandroidfw/idmap2, validate overlay policy, configuration selection or prove runtime application.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, type=Path)
    parser.add_argument('--overlay', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = compare(args.target, args.overlay)
    with args.output.open('x', encoding='utf-8') as dest:
        json.dump(result, dest, indent=2)
        dest.write('\n')
    print(json.dumps({'matched': len(result['matching_names']),
                      'missing': result['missing_target_names']}))
