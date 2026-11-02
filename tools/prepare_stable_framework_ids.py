"""Prepare AAPT2 stable IDs from the installed-baseline framework resource table."""
import argparse
import hashlib
import json
from pathlib import Path
from compare_framework_resources import table

BASELINE = 'f1bad2e1e59543c5d7d2f437e33a41d443739ab39df7c10a4fd2731447a3adad'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('aapt', 'baseline', 'blueprint', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if a.output.exists():
        raise FileExistsError(a.output)
    if hashlib.sha256(a.baseline.read_bytes()).hexdigest() != BASELINE:
        raise ValueError('Unexpected baseline resource table')
    _, names = table(a.aapt, a.baseline)
    original = a.blueprint.read_bytes()
    anchor = b'    aaptflags: [\n'
    if original.count(anchor) != 1 or b'--stable-ids' in original:
        raise ValueError('Unexpected resource module definition')
    candidate = original.replace(anchor, anchor +
        b'        "--stable-ids",\n'
        b'        "frameworks/base/core/res/kaidroid-stable-resource-ids.txt",\n')
    stable = ''.join(f'{name} = 0x{number:08x}\n' for name, number in sorted(names.items())).encode()
    a.output.mkdir(parents=True)
    (a.output / 'Android.bp').write_bytes(candidate)
    (a.output / 'kaidroid-stable-resource-ids.txt').write_bytes(stable)
    report = dict(baseline_sha256=BASELINE, symbols=len(names),
                  original_blueprint_sha256=hashlib.sha256(original).hexdigest(),
                  candidate_blueprint_sha256=hashlib.sha256(candidate).hexdigest(),
                  stable_ids_sha256=hashlib.sha256(stable).hexdigest(),
                  scope='Preserve baseline resource identities; new symbols receive free IDs. Not built or installed.')
    (a.output / 'plan.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
