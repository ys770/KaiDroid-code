"""Verify and assemble the fixed N139DL 796MiB system capture, preserving originals."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot') or any(r.get('returncode') != 0 for r in manifest['reads']):
        raise ValueError('Capture incomplete or identity/read gate failed')
    if (args.capture / 'preflight.txt').read_text().splitlines()[0] != '834666496':
        raise ValueError('Unexpected system partition size')
    expected = (args.capture / 'hash-before.txt').read_text().split()[0]
    if expected != (args.capture / 'hash-after.txt').read_text().split()[0]:
        raise ValueError('System changed during capture')
    entries = {r['file']: r for r in manifest['reads']}
    args.output.mkdir(parents=True, exist_ok=False)
    digest = hashlib.sha256()
    records = []
    with (args.output / 'system.img').open('xb') as out:
        for index in range(50):
            name = f'system.part{index:03d}'
            data = (args.capture / name).read_bytes()
            if hashlib.sha256(data).hexdigest() != entries[name]['sha256']:
                raise ValueError('Captured chunk altered: ' + name)
            count = 16 if index < 49 else 12
            size = count * 1048576
            payload, suffix = data[:size], data[size:]
            # Legacy adbd merges dd stderr with stdout. Keep the original file;
            # accept only its exact expected records/byte-count diagnostic suffix.
            pattern = (str(count) + r'\+0 records in\n' + str(count) +
                       r'\+0 records out\n' + str(size) + r' bytes [^\n]+\n').encode()
            if len(payload) != size or (suffix and not re.fullmatch(pattern, suffix)):
                raise ValueError('Unexpected chunk framing: ' + name)
            out.write(payload)
            digest.update(payload)
            records.append({'file': name, 'payload_bytes': size, 'diagnostic_suffix_bytes': len(suffix)})
    actual = digest.hexdigest()
    result = {'expected_sha256': expected, 'actual_sha256': actual,
              'verified': actual == expected, 'bytes': (args.output / 'system.img').stat().st_size,
              'chunks': records, 'scope': 'Verified readback backup, not a successful restore test'}
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    if actual != expected:
        raise ValueError('Assembled image differs from both device hashes')
    print(json.dumps({k:v for k,v in result.items() if k != 'chunks'}))


if __name__ == '__main__':
    main()
