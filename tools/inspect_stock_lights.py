"""Hash-bound static inspection of Nokia's retained ARM Light HAL; never executes it."""
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
    if digest != '3d169c36e9b9919a77e7b7c1dc7ad88ee6cdaae057755664b78a861de4090788':
        raise ValueError('Not the inspected stock Light HAL')
    phoff = struct.unpack_from('<I', data, 28)[0]
    width, count = struct.unpack_from('<HH', data, 42)

    def at(address, size):
        for i in range(count):
            kind, offset, va, _, length, _, _, _ = struct.unpack_from('<8I', data, phoff + i * width)
            if kind == 1 and va <= address and address + size <= va + length:
                return data[offset + address - va:offset + address - va + size]
        raise ValueError('Not file-backed: ' + hex(address))

    def pointer(address):
        return struct.unpack('<I', at(address, 4))[0]

    def string(address):
        return at(address, 100).split(b'\0', 1)[0].decode('ascii')

    names = ('RED_LED_FILE', 'GREEN_LED_FILE', 'BLUE_LED_FILE', 'LCD_FILE', 'LCD_FILE2',
             'BUTTON_FILE', 'RED_BLINK_FILE', 'GREEN_BLINK_FILE', 'BLUE_BLINK_FILE', 'PERSISTENCE_FILE')
    paths = {name: {'object_va': hex(0x5008 + i * 4), 'string_va': hex(pointer(0x5008 + i * 4)),
                    'path': string(pointer(0x5008 + i * 4))} for i, name in enumerate(names)}
    # PC-relative literals inspected in Thumb disassembly. ASLR load bias cancels.
    primary = (0x21d8 + struct.unpack('<i', at(0x2214, 4))[0]) & 0xffffffff
    fallback = (0x21e4 + struct.unpack('<i', at(0x2218, 4))[0]) & 0xffffffff
    if string(primary) != paths['LCD_FILE']['path'] or string(fallback) != paths['LCD_FILE2']['path']:
        raise ValueError('Unexpected backlight literals')
    report = {'sha256': digest, 'scope': 'Exact binary pointers and inspected Thumb literals; no runtime path selection or physical lights test.',
              'paths': paths, 'hmi_methods_va': hex(pointer(0x401c)),
              'open_thumb_pointer': hex(pointer(pointer(0x401c))),
              'backlight_branch': {'primary': string(primary), 'fallback': string(fallback),
                                   'inspected_va_range': ['0x21cc', '0x21ee'],
                                   'bytes': at(0x21cc, 0x22).hex()},
              'contains_sublcd_literal': b'sublcd' in data}
    with args.output.open('x', encoding='utf-8') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'path_objects': len(paths), 'primary': string(primary), 'fallback': string(fallback)}))


if __name__ == '__main__':
    main()
