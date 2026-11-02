"""Compile a CIL bundle offline with neverallow checking and recorded provenance."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('inputs', nargs='+', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    policy = args.output / 'policy.30'
    if policy.exists():
        raise ValueError('Use a new output directory; refusing stale policy output')
    command = [str(args.compiler.resolve()), '-m', '-M', 'true', '-G', '-c', '30']
    command += [str(p.resolve()) for p in args.inputs]
    command += ['-o', str(policy.resolve()), '-f', str((args.output / 'file_contexts').resolve())]
    result = subprocess.run(command, capture_output=True)
    (args.output / 'stdout.txt').write_bytes(result.stdout)
    (args.output / 'stderr.txt').write_bytes(result.stderr)
    record = {'argv': command, 'exit_code': result.returncode,
              'compiler_sha256': hashlib.sha256(args.compiler.read_bytes()).hexdigest(),
              'input_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in args.inputs},
              'policy_sha256': hashlib.sha256(policy.read_bytes()).hexdigest() if result.returncode == 0 else None,
              'scope': 'Offline CIL compilation only. Neverallow checks enabled; no policy load or device operation.'}
    (args.output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'exit_code': result.returncode, 'policy_sha256': record['policy_sha256']}))
    if result.returncode:
        print(result.stderr.decode(errors='replace')[:3000])
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
