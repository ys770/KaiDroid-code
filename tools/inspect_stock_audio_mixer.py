"""Hash-bound static inspection of Nokia's retained ARM audio mixer branch; never executes it."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = args.library.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != '5276afb3169fe7e8dc3af2a7ded5f901da7f855d170365c458441825b19f5f51':
        raise ValueError('Not the inspected stock primary audio HAL')
    phoff = struct.unpack_from('<I', data, 28)[0]
    width, count = struct.unpack_from('<HH', data, 42)

    def at(address, size):
        for i in range(count):
            kind, offset, va, _, length, _, _, _ = struct.unpack_from('<8I', data, phoff + i * width)
            if kind == 1 and va <= address and address + size <= va + length:
                return data[offset + address - va:offset + address - va + size]
        raise ValueError('Not file-backed: ' + hex(address))

    def string(address):
        return at(address, 100).split(b'\0', 1)[0].decode('ascii')

    specs = (
        ('card', 0x36dd0, 0x36168),
        ('default_revision', 0x37808, 0x3689c),
        ('revision_property', 0x3780c, 0x368a4),
        ('below_2', 0x37810, 0x368d8),
        ('at_least_2', 0x37820, 0x36920),
    )
    literals = {}
    for name, pool, pc in specs:
        target = (pc + struct.unpack('<i', at(pool, 4))[0]) & 0xffffffff
        literals[name] = {'pool_va': hex(pool), 'pc_base': hex(pc),
                          'target_va': hex(target), 'value': string(target)}
    report = {'library_sha256': digest,
              'scope': 'Exact retail binary static selection and audio_route_init call; not active engineering module or physical audio proof.',
              'literals': literals,
              'code': {hex(a): at(a, size).hex() for a, size in
                       ((0x36158, 28), (0x36878, 80), (0x368c4, 24),
                        (0x3690c, 36), (0x36e60, 28), (0x3724c, 52))},
              'plt_got': {'strncmp': {'plt': '0x657c0', 'got': '0x70078'},
                          'property_get': {'plt': '0x65000', 'got': '0x6fe88'},
                          'atof': {'plt': '0x655f0', 'got': '0x70004'},
                          'audio_route_init': {'plt': '0x657d0', 'got': '0x7007c'}}}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'literal_count': len(literals), 'route_init_call': '0x36e68'}))


if __name__ == '__main__':
    main()
