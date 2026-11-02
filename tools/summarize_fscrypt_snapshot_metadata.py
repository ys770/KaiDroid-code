"""Compare fixed-layout F2FS dump.f2fs metadata, without extracting key files.

Input reports must be from the measured 3488-byte inline directories and the
15-byte inline mode file. Rejects other layouts rather than guessing offsets.
"""
import argparse
import json
import re
import struct
from pathlib import Path


def number(text, field):
    found = re.search(r'^'+re.escape(field)+r'\s+\[0x\s*([0-9a-f]+)\s*:', text, re.M)
    if not found:
        raise ValueError('Missing field: '+field)
    return int(found[1], 16)


def words(text):
    result = bytearray(923*4)
    seen = set()
    for index, value in re.findall(r'i_addr\[0x([0-9a-f]+)\].*?\[0x\s*([0-9a-f]+)', text):
        index = int(index, 16)
        if index >= 923 or index in seen:
            raise ValueError('Invalid address array')
        seen.add(index)
        struct.pack_into('<I', result, index*4, int(value, 16))
    return result


def directory(path, name, parent):
    text = path.read_text()
    if (number(text, 'i_size') != 3488 or number(text, 'i_inline') != 5 or
            number(text, 'i_pino') != parent or
            not re.search(r'^i_name\s+\['+re.escape(name)+r'\]$', text, re.M)):
        raise ValueError('Unexpected inline-directory layout: '+str(path))
    data = words(text)
    rows = {}
    index = 0
    while index < 182:
        if not data[4+index//8] & (1 << (index%8)):
            index += 1
            continue
        _, inode, length, kind = struct.unpack_from('<IIHB', data, 34+index*11)
        slots = (length+7)//8
        if not 1 <= length <= 255 or index+slots > 182 or kind not in (1, 2):
            raise ValueError('Invalid directory entry')
        if any(not data[4+j//8] & (1 << (j%8)) for j in range(index, index+slots)):
            raise ValueError('Missing continuation slot')
        entry = bytes(data[2036+index*8:2036+index*8+length]).decode('ascii')
        if entry in rows or '/' in entry or '\0' in entry:
            raise ValueError('Invalid entry name')
        rows[entry] = {'inode': inode, 'type': kind}
        index += slots
    if rows.get('..') != {'inode': parent, 'type': 2} or '.' not in rows:
        raise ValueError('Directory parent/self validation failed')
    return rows


def mode(path):
    text = path.read_text()
    if number(text, 'i_size') != 15 or number(text, 'i_inline') != 11 or number(text, 'i_pino') != 7:
        raise ValueError('Unexpected mode file layout')
    if not re.search(r'^i_name\s+\[mode\]$', text, re.M):
        raise ValueError('Not the mode file')
    return bytes(words(text)[4:19]).decode('ascii')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reports', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = {}
    for side in ('before', 'after'):
        result[side] = {
            'mode': mode(args.reports/(side+'-mode-hex.txt')),
            'unencrypted_entries': directory(args.reports/(side+'-unencrypted.txt'), 'unencrypted', 3),
            'key_directory_entries': directory(args.reports/(side+'-key-dir.txt'), 'key', 7),
        }
    result['scope'] = 'Directory entries and non-secret mode text only; no key-file contents or Keymaster operations'
    with args.output.open('x') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
