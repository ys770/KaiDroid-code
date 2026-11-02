"""Give engineering Bluetooth bring-up a bounded deadline after native startup."""
import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(source).hexdigest() != '289aadec04219845fe9329f5810cfba9b820cba4af8fb5d2f520ba8e96d2cc3e':
        raise ValueError('Unreviewed AdapterState source')
    anchor = b'    static final int BLE_START_TIMEOUT_DELAY = 4000;'
    if source.count(anchor) != 1:
        raise ValueError('Expected unique BLE startup deadline')
    replacement = (b'    // Lab bring-up: allow firmware initialization plus controller setup.\n'
                   b'    // Production builds retain the upstream four-second deadline.\n'
                   b'    static final int BLE_START_TIMEOUT_DELAY =\n'
                   b'            "eng".equals(android.os.Build.TYPE) ? 15000 : 4000;')
    output = source.replace(anchor, replacement)
    with args.output.open('xb') as stream:
        stream.write(output)
    print(hashlib.sha256(output).hexdigest())


if __name__ == '__main__':
    main()
