"""Allow a device to select userspace LMK despite a disabled legacy kernel module."""
import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_bytes().replace(b'\r\n', b'\n')
    if hashlib.sha256(source).hexdigest() != 'c21eb0487c87d250398824426b690184af57adf9ccc1581d5d162b1244b5cb4a':
        raise ValueError('Unreviewed lmkd source')
    anchor = b'    use_inkernel_interface = has_inkernel_module;'
    if source.count(anchor) != 1:
        raise ValueError('Expected unique interface selection')
    replacement = (b'    // Some vendor low-RAM scripts disable the kernel killer.\n'
                   b'    // Keep legacy selection unless the device explicitly opts out.\n'
                   b'    use_inkernel_interface = has_inkernel_module &&\n'
                   b'        property_get_bool("ro.lmk.use_inkernel_interface", true);')
    output = source.replace(anchor, replacement)
    with args.output.open('xb') as stream:
        stream.write(output)
    print(hashlib.sha256(output).hexdigest())


if __name__ == '__main__':
    main()
