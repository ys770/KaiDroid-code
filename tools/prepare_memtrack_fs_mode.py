"""Pin the root ODM memtrack executable mode in AOSP image fs_config."""
import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_bytes().replace(b'\r\n', b'\n')
    expected = 'd4a106aadf16000c6e1ec9494c34a7776261e29fc89d0061909f8338a4de81cf'
    if hashlib.sha256(source).hexdigest() != expected:
        raise ValueError('Unreviewed fs_config source')
    anchor = b'    { 00755, AID_ROOT,      AID_SHELL,     0, "odm/bin/*" },'
    if source.count(anchor) != 1:
        raise ValueError('Expected unique ODM executable rule')
    rule = b'    { 00755, AID_ROOT,      AID_ROOT,      0, "odm/kaidroid/bin/kaidroid-memtrack-service" },'
    output = source.replace(anchor, rule + b'\n' + anchor)
    with args.output.open('xb') as stream:
        stream.write(output)
    print(hashlib.sha256(output).hexdigest())


if __name__ == '__main__':
    main()
