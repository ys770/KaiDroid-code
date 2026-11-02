"""Prepare an offline engineering-only experiment; never installs or flashes.

Remove BuildLayerStack's forced RGB565 metadata store. Retain the actual
format populated by SetLayerBuffer. Driver support and panel output are unproven.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SOURCE_SHA = '63eabb0636f449f4f8f2c9ffd5c2f461838db06cd18bf1a966457f6176cb10cc'
STORE_VA = 0x26c1c


def prepare(source, output):
    data = source.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA:
        raise ValueError('Not the verified engineering composer')
    if data[:6] != b'\x7fELF\x01\x01':
        raise ValueError('Expected ELF32 little endian')
    phoff = struct.unpack_from('<I', data, 28)[0]
    ents, count = struct.unpack_from('<HH', data, 42)
    offset = None
    for i in range(count):
        kind, start, va, _, size, _, flags, _ = struct.unpack_from('<8I', data, phoff+i*ents)
        if kind == 1 and flags & 1 and va <= STORE_VA and STORE_VA+2 <= va+size:
            offset = start+STORE_VA-va
            break
    if offset is None or data[offset:offset+2] != bytes.fromhex('4161'):
        raise ValueError('Expected Thumb str r1,[r0,#0x14] not found')
    patched = bytearray(data)
    patched[offset:offset+2] = bytes.fromhex('00bf')  # Thumb NOP, same length.
    output.mkdir(parents=True, exist_ok=False)
    (output/source.name).write_bytes(patched)
    report = {'source_sha256': SOURCE_SHA,
              'candidate_sha256': hashlib.sha256(patched).hexdigest(),
              'virtual_address': hex(STORE_VA), 'file_offset': offset,
              'original_hex': '4161', 'replacement_hex': '00bf',
              'runtime_tested': False, 'physical_display_validated': False,
              'purpose': 'Preserve client target format instead of forced RGB565 metadata'}
    (output/'manifest.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
