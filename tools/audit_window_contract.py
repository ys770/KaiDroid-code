"""Collect observed donor window-extension references and pin source inputs.

Method-table references are not reachability proof. This bounded audit does
not discover all OEM methods, reflection, resource IDs or inlined constants.
"""
import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--references', required=True, type=Path)
    parser.add_argument('--platform-source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    found = defaultdict(set)
    inputs = {}
    owners = {'Landroid/app/Activity;', 'Landroid/app/Dialog;', 'Landroid/app/AlertDialog;',
              'Landroid/view/Window;', 'Lcom/android/internal/policy/DecorView;',
              'Lcom/android/internal/policy/PhoneWindow;'}
    for file in sorted(args.references.glob('*-method-refs.json')):
        data = file.read_bytes()
        inputs[file.name] = hashlib.sha256(data).hexdigest()
        for method in json.loads(data):
            if method['owner'] in owners and method['name'] in ('getMenuBar', 'removeMenuBar'):
                found[(method['owner'], method['name'], method['descriptor'])].add(
                    file.name.removesuffix('-method-refs.json'))
    if not inputs:
        raise ValueError('No input reference reports')
    source = json.loads((args.platform_source / 'manifest.json').read_text())
    for item in source['files']:
        data = (args.platform_source / item['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Changed platform source: ' + item['path'])
    report = {'scope': __doc__, 'reference_sha256': inputs,
              'platform_source': source,
              'methods': [{'owner': owner, 'name': name, 'descriptor': descriptor,
                           'consumers': sorted(consumers)}
                          for (owner, name, descriptor), consumers in sorted(found.items())]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('Observed window extension methods:', len(found))


if __name__ == '__main__':
    main()
