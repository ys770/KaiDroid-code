"""Stage hash-pinned sparse AAPT2 linking before APK signing; preserve original files."""
import argparse
import hashlib
import json
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists() or output == source or source in output.parents:
        raise ValueError('Use a new report directory outside the AOSP checkout')
    contract = Path(__file__).resolve().parents[1] / 'docs/contracts/resource-sparse-encoding.json'
    entries = json.loads(contract.read_text())['files']
    prepared = []
    for entry in entries:
        path = (source / entry['path']).resolve()
        if source not in path.parents:
            raise ValueError('Target escapes source')
        before = path.read_bytes()
        if digest(before) != entry['before_sha256']:
            raise ValueError('Source hash differs: ' + entry['path'])
        after = before
        for edit in entry.get('edits', [entry]):
            old, new = edit['old'].encode(), edit['new'].encode()
            if after.count(old) != 1:
                raise ValueError('Source match count differs: ' + entry['path'])
            after = after.replace(old, new)
        if digest(after) != entry['after_sha256']:
            raise ValueError('Unexpected patch result')
        prepared.append((entry, path, before, after))
    output.mkdir(parents=True)
    for entry, path, before, after in prepared:
        backup = output / 'originals' / entry['path']
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_bytes(before)
    report = {'contract_sha256': digest(contract.read_bytes()), 'files': entries,
              'applied': False, 'scope': 'Source build recipe only; full build, capacity and runtime checks still required.'}
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if args.apply:
        # Recheck every source before the first mutation, after preserving originals.
        if any(path.read_bytes() != before for _, path, before, _ in prepared):
            raise ValueError('Source changed after preflight')
        for _, path, _, after in prepared:
            path.write_bytes(after)
        report['applied'] = True
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'files': len(entries), 'applied': report['applied']}))


if __name__ == '__main__':
    main()
