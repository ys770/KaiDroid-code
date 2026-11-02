"""Read embedded flattened device trees from a kernel payload or DTBO image.

Reports candidate trees and selected hardware properties; does not determine
which tree a bootloader actually selects. Never writes the input image.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = b'\xd0\x0d\xfe\xed'
INTERESTING = {'model', 'compatible', 'status', 'reg', 'qcom,msm-id',
               'qcom,board-id', 'qcom,pmic-id', 'bootargs', 'device_type'}


def decode(value):
    if not value:
        return True
    if value.endswith(b'\0') and all(byte in (0, 9, 10, 13) or 32 <= byte < 127 for byte in value):
        strings = value.rstrip(b'\0').decode('ascii').split('\0')
        return strings[0] if len(strings) == 1 else strings
    if len(value) % 4 == 0:
        return [f'0x{word:x}' for word in struct.unpack(f'>{len(value)//4}I', value)]
    return value.hex()


def parse_tree(blob):
    magic, size, structs, strings, reserve, version, compatible_version, cpu, strings_size, structs_size = struct.unpack_from('>10I', blob)
    if magic != 0xd00dfeed or version < 17 or size != len(blob):
        raise ValueError('Unsupported FDT header')
    if structs + structs_size > size or strings + strings_size > size:
        raise ValueError('FDT blocks exceed image')
    string_table = blob[strings:strings + strings_size]
    cursor, end, stack, nodes = structs, structs + structs_size, [], {}
    while cursor + 4 <= end:
        token, = struct.unpack_from('>I', blob, cursor)
        cursor += 4
        if token == 1:
            stop = blob.index(b'\0', cursor, end)
            stack.append(blob[cursor:stop].decode('ascii'))
            cursor = (stop + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            length, name_offset = struct.unpack_from('>II', blob, cursor)
            cursor += 8
            if cursor + length > end:
                raise ValueError('FDT property exceeds structure block')
            stop = string_table.index(b'\0', name_offset)
            name = string_table[name_offset:stop].decode('ascii')
            if name in INTERESTING:
                node = '/'.join(stack) or '/'
                nodes.setdefault(node, {})[name] = decode(blob[cursor:cursor+length])
            cursor = (cursor + length + 3) & ~3
        elif token == 4:
            pass
        elif token == 9:
            return nodes
        else:
            raise ValueError(f'Unexpected token {token}')
    raise ValueError('Missing FDT end token')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--extract-dir', type=Path)
    args = parser.parse_args()
    data = args.image.read_bytes()
    trees, cursor = [], 0
    while True:
        offset = data.find(MAGIC, cursor)
        if offset < 0:
            break
        cursor = offset + 4
        if offset + 40 > len(data):
            continue
        size, = struct.unpack_from('>I', data, offset + 4)
        if size < 40 or offset + size > len(data):
            continue
        blob = data[offset:offset + size]
        try:
            nodes = parse_tree(blob)
        except (ValueError, IndexError, struct.error, UnicodeDecodeError):
            continue
        trees.append({'offset': offset, 'bytes': size,
                      'sha256': hashlib.sha256(blob).hexdigest(), 'nodes': nodes})
        if args.extract_dir:
            args.extract_dir.mkdir(parents=True, exist_ok=True)
            (args.extract_dir / f'{offset:08x}.dtb').write_bytes(blob)
        cursor = offset + size
    result = {'image': args.image.name, 'bytes': len(data),
              'sha256': hashlib.sha256(data).hexdigest(), 'trees': trees,
              'selection': 'Offline candidates; active tree not measured.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'image': args.image.name, 'sha256': result['sha256'],
                      'trees': [{'offset': tree['offset'], 'bytes': tree['bytes'],
                                 'sha256': tree['sha256'], 'model': tree['nodes'].get('/', {}).get('model')}
                                for tree in trees]}, indent=2))


if __name__ == '__main__':
    main()
