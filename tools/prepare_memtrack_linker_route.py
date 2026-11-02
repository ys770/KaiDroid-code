"""Prepare the pinned linkerconfig route for the system-root ODM supplement."""
import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_bytes().replace(b'\r\n', b'\n')
    expected = '455cf1a5baacefc04c263e2085133ecc419ab81d88f6fc54bb4a75e2a3e8445d'
    if hashlib.sha256(source).hexdigest() != expected:
        raise ValueError('Unreviewed linkerconfig source')
    anchor = b'      {"/odm/bin/", "vendor"},'
    if source.count(anchor) != 1:
        raise ValueError('Expected unique ODM route')
    output = source.replace(anchor, anchor + b'\n      {"/odm/kaidroid/bin/", "vendor"},')
    with args.output.open('xb') as stream:
        stream.write(output)
    print(hashlib.sha256(output).hexdigest())


if __name__ == '__main__':
    main()
