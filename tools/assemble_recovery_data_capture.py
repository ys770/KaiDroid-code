"""Assemble verified unmounted engineering N139DL writable-partition backups.

No device operation. Input captures and failed outputs are preserved.
"""
import argparse
import hashlib
import json
from pathlib import Path

SIZES = {'userdata': 1901068288, 'sysdata': 8388608,
         'cache': 115343360, 'persist': 33554432}
CHUNK = 16 * 1048576


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text())
    if not manifest.get('same_identity_and_boot') or any(r.get('returncode') != 0 for r in manifest['reads']):
        raise ValueError('Incomplete or failed capture')
    entries = {r['file']: r for r in manifest['reads']}
    def verified(name):
        data = (args.capture / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != entries[name]['sha256']:
            raise ValueError('Capture bytes changed: ' + name)
        return data
    for name in ('mounts-before.txt', 'mounts-after.txt'):
        mounts = verified(name).decode()
        if '/dev/block/' in mounts or 'rootfs / rootfs ' not in mounts:
            raise ValueError('Expected unmounted recovery block partitions')
    args.output.mkdir(parents=True, exist_ok=False)
    results = {}
    for name, size in SIZES.items():
        expected = verified(name+'-hash-before.txt').decode().split()[0]
        if expected != verified(name+'-hash-after.txt').decode().split()[0]:
            raise ValueError('Partition changed: ' + name)
        digest = hashlib.sha256()
        with (args.output / (name+'.img')).open('xb') as out:
            for i, start in enumerate(range(0, size, CHUNK)):
                data = verified(f'{name}.part{i:03d}')
                if len(data) != min(CHUNK, size-start):
                    raise ValueError('Unexpected chunk size: ' + name)
                digest.update(data)
                out.write(data)
        results[name] = {'bytes': size, 'sha256': digest.hexdigest(),
                         'verified': digest.hexdigest() == expected}
        (args.output/'result.json').write_text(json.dumps(results, indent=2)+'\n')
        if digest.hexdigest() != expected:
            raise ValueError('Partition readback mismatch: ' + name)
    print(json.dumps(results))


if __name__ == '__main__':
    main()
