"""Verify a hash-bound static ashmem call-site finding in captured ARM libcutils.

This is a specific binary audit, not a general ARM decoder or runtime test.
Run under Linux with readelf. Never executes the input library.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

EXPECTED = '67dc3302ec2671f519ecf310db623611e647803a8902bbb384d2c19209d57478'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    data = a.library.read_bytes()
    if hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError('Not the inspected captured ARM libcutils')
    if data[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<H', data, 18)[0] != 40:
        raise ValueError('Expected little-endian ELF32 ARM')
    phoff = struct.unpack_from('<I', data, 28)[0]
    width, count = struct.unpack_from('<HH', data, 42)

    def at(va, size):
        for i in range(count):
            kind, offset, address, _, length, _, _, _ = struct.unpack_from('<8I', data, phoff + i * width)
            if kind == 1 and address <= va and va + size <= address + length:
                return data[offset + va - address:offset + va - address + size]
        raise ValueError('Address not in file-backed PT_LOAD')

    displacement = struct.unpack('<i', at(0x855c, 4))[0]
    address = (0x84ac + displacement) & 0xffffffff
    if at(address, 12) != b'/dev/ashmem\0':
        raise ValueError('Unexpected path at inspected literal target')
    # Inspected Thumb mov r0,r5 / mov r1,r6 / blx 0xa160.
    if at(0x84b2, 8) != bytes.fromhex('2846314601f054ee'):
        raise ValueError('Unexpected inspected call sequence')
    reloc = subprocess.run(['readelf', '-rW', str(a.library)], capture_output=True, text=True, check=True).stdout
    lines = [line.strip() for line in reloc.splitlines() if line.startswith('0000ce50 ')]
    if len(lines) != 1 or '__open_2@LIBC' not in lines[0]:
        raise ValueError('Unexpected PLT target relocation')
    result = {'scope': __doc__, 'library_sha256': EXPECTED,
              'ashmem_create_region_fallback_call': '0x7ffe -> 0x8494',
              'path_literal_va': hex(address), 'path': '/dev/ashmem',
              'path_call_va': '0x84b6', 'plt_va': '0xa160',
              'got_va': '0xce50', 'relocation': lines[0],
              'runtime_reachability_tested': False,
              'conclusion': 'Inspected fallback helper opens legacy ashmem directly. Do not remove its permission based only on Android 11 libcutils using a suffixed node.'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'path': result['path'], 'relocation_verified': True}))


if __name__ == '__main__':
    main()
