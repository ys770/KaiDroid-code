"""Prepare image24 engineering packaging overlay; never edits inputs or a phone.

Apply after platform build: location_socket belongs to the retained vendor
policy, so validation must use the combined policy, not platform-only policy.
"""
import argparse
import hashlib
import json
from pathlib import Path

PINNED = {
    'plat_file_contexts': '264f0ac145a061593247e56b421ec4373b73ab138d62c66c0e124e51d648b912',
    'vendor_file_contexts': '94fd3b5b5d7800c8d6e3904e7855d412801d269ae1ca16b2fb04f282ddf85ee1',
    'kaidroid-data.rc': 'd7e72c62646c81d835b36d4f0064ea05d61ac26b6ee0f0b294cd02219135543f',
}
SOCKET = '/data/vendor/location/blp/sock-server'


def prepare(source, output):
    original = {name: (source / name).read_bytes() for name in PINNED}
    for name, expected in PINNED.items():
        if hashlib.sha256(original[name]).hexdigest() != expected:
            raise ValueError('Unreviewed input: ' + name)
    rule = SOCKET + ' -s u:object_r:location_socket:s0\n'
    contexts = original['plat_file_contexts'] + b'\n' + rule.encode()
    rc = original['kaidroid-data.rc'].decode()
    anchor = '    restorecon /data/misc/installd\n'
    if rc.count(anchor) != 1:
        raise ValueError('Unexpected init anchor')
    rc = rc.replace(anchor, anchor +
        '    # Correct the inherited location socket before boot-complete starts blpsvc.\n'
        '    restorecon ' + SOCKET + '\n')
    output.mkdir(parents=True, exist_ok=False)
    payload = {'plat_file_contexts': contexts, 'kaidroid-data.rc': rc.encode()}
    for name, data in payload.items():
        (output / name).write_bytes(data)
    (output / 'combined_file_contexts').write_bytes(
        contexts + b'\n' + original['vendor_file_contexts'])
    (output / 'manifest.json').write_text(json.dumps({
        'input_sha256': PINNED,
        'output_sha256': {n: hashlib.sha256(b).hexdigest() for n, b in payload.items()},
        'scope': 'Engineering image24 packaging overlay; requires combined-policy validation and reboot test',
        'destinations': {'plat_file_contexts': '/system/etc/selinux/plat_file_contexts',
                         'kaidroid-data.rc': '/system/etc/init/kaidroid-data.rc'},
        'permissions_added': False,
    }, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.source, args.output)
