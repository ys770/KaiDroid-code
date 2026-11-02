"""Find actual DEX class definitions across a bounded captured archive tree.

Reports reference-only archives separately. Absence is limited to the files
scanned, not proof of absence from the donor's runtime or dynamic class loaders.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from audit_tcl_target_api import parse


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--owner', action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if any(not re.fullmatch(r'L[^;\s]+;', name) for name in a.owner):
        raise ValueError('Expected class descriptors')
    inventories, providers, references = [], [], []
    for path in sorted(a.root.rglob('*')):
        if path.suffix not in ('.jar', '.apk') or not path.is_file():
            continue
        relative = path.relative_to(a.root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        inventories.append(dict(file=relative, sha256=digest))
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not re.fullmatch(r'classes\d*\.dex', name):
                    continue
                data = archive.read(name)
                hits = [owner for owner in a.owner if owner.encode() in data]
                if not hits:
                    continue
                classes, _, _, stale = parse(data)
                for owner in hits:
                    row = dict(owner=owner, file=relative, sha256=digest, dex=name,
                               stale_dex_sha1=stale)
                    if owner in classes:
                        row.update(methods=sorted(classes[owner]['methods']),
                                   superclass=classes[owner]['superclass'])
                        providers.append(row)
                    else:
                        references.append(row)
    report = dict(scope=__doc__, inputs=inventories, providers=providers,
                  reference_only=references,
                  absent_from_scanned_definitions=sorted(set(a.owner)-{r['owner'] for r in providers}),
                  runtime_loader_coverage_verified=False)
    with a.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(archives=len(inventories), providers=len(providers),
                          absent=report['absent_from_scanned_definitions'])))


if __name__ == '__main__':
    main()
