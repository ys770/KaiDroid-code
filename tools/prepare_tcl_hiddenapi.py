"""Prepare explicit observed TCL UI compatibility entries; never modify AOSP."""
import argparse
import hashlib
import json
from pathlib import Path

BASE_SHA256 = '6b3c8d2b964f7ad51148a70432e6d2e76bca4c08750753b8ae1b315bf3f42ab5'
# Reviewed 44-signature UI/window extension; retain it when adding the two
# accessibility methods exposed by image18 runtime testing.
UI_EXTENDED_SHA256 = '072924d04792de3373dcdc2951a6989ba536b1ce2cc5f31a099f726b1e082885'


def prepare(source, flags, methods):
    if hashlib.sha256(source).hexdigest() not in (BASE_SHA256, UI_EXTENDED_SHA256):
        raise ValueError('Unexpected baseline hidden API list')
    policy = {}
    for line in flags.splitlines():
        signature, *values = line.split(',')
        if signature in policy:
            raise ValueError('Duplicate policy signature')
        policy[signature] = values
    requested = sorted({m['owner'] + '->' + m['name'] + m['descriptor'] for m in methods})
    additions, unresolved, existing = [], [], []
    for signature in requested:
        values = policy.get(signature)
        if values is None:
            unresolved.append(signature)  # May be inherited; never infer resolution.
        elif values == ['blacklist']:
            additions.append(signature)
        else:
            existing.append({'signature': signature, 'flags': values})
    if not additions:
        raise ValueError('No blocked observed UI methods to adapt')
    old = set(source.decode().splitlines())
    if old.intersection(additions):
        raise ValueError('Candidate already present in baseline')
    result = source.rstrip(b'\n') + b'\n' + ('\n'.join(additions) + '\n').encode()
    return result, {'added': additions, 'unresolved_exact_owner': unresolved,
                    'existing_policy': existing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--flags', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.report.exists():
        raise ValueError('Output and report must be new files')
    root = Path(__file__).resolve().parents[1]
    methods = []
    contracts = {}
    for name in ('tcl-ui-methods.json', 'tcl-window-methods.json',
                 'tcl-accessibility-methods.json'):
        data = (root / 'docs/contracts' / name).read_bytes()
        contracts[name] = hashlib.sha256(data).hexdigest()
        methods.extend(json.loads(data)['methods'])
    source, flags = args.source.read_bytes(), args.flags.read_bytes()
    output, report = prepare(source, flags.decode(), methods)
    report.update(scope='Observed UI method signatures only. No global enforcement change. '
                  'Generated flags and inherited-owner resolution require verification; no runtime proof.',
                  source_sha256=hashlib.sha256(source).hexdigest(),
                  flags_sha256=hashlib.sha256(flags).hexdigest(),
                  output_sha256=hashlib.sha256(output).hexdigest(), contracts=contracts)
    with args.output.open('xb') as stream:
        stream.write(output)
    with args.report.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'added': len(report['added']),
                      'unresolved_exact_owner': len(report['unresolved_exact_owner'])}))


if __name__ == '__main__':
    main()
