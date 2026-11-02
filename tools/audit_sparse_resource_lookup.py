"""Audit sparse resource slots against the pinned dense-only FindEntryByName loop.

Read-only structural reproduction, not execution of idmap2 or proof of the
specific resource name being looked up in a saved native crash.
"""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path


def audit(data):
    result = dict(type_chunks=0, sparse_chunks=0, sparse_entries=0,
                  dense_interpretation_outside_chunk=0, matching_0x40001=[], examples=[])

    def chunks(start, end):
        pos = start
        while pos < end:
            if pos + 8 > end:
                raise ValueError('Truncated resource header')
            kind, header, size = struct.unpack_from('<HHI', data, pos)
            if header < 8 or size < header or pos + size > end:
                raise ValueError('Invalid chunk bounds')
            if kind in (0x0002, 0x0200):
                chunks(pos + header, pos + size)
            if kind == 0x0201:
                result['type_chunks'] += 1
                if header < 20:
                    raise ValueError('Truncated type header')
                type_id, flags = struct.unpack_from('<BB', data, pos + 8)
                count, entries_start = struct.unpack_from('<II', data, pos + 12)
                if flags & 1:
                    result['sparse_chunks'] += 1
                    if pos + header + count * 4 > pos + entries_start or entries_start > size:
                        raise ValueError('Sparse index overlaps entry data')
                    last_id = -1
                    for slot in range(count):
                        index, units = struct.unpack_from('<HH', data, pos + header + slot * 4)
                        if index <= last_id:
                            raise ValueError('Unsorted sparse index')
                        last_id = index
                        offset = units * 4
                        if entries_start + offset + 8 > size:
                            raise ValueError('Invalid sparse entry offset')
                        encoded = index | units << 16
                        outside = entries_start + encoded + 8 > size
                        result['sparse_entries'] += 1
                        result['dense_interpretation_outside_chunk'] += int(outside)
                        sample = dict(chunk_offset=pos, type_id=type_id, slot=slot,
                                      resource_entry_index=index, sparse_byte_offset=offset,
                                      dense_misread_offset=encoded, chunk_size=size,
                                      entries_start=entries_start, dense_outside=outside)
                        if outside and len(result['examples']) < 3:
                            result['examples'].append(sample)
                        if encoded == 0x40001 and len(result['matching_0x40001']) < 3:
                            result['matching_0x40001'].append(sample)
            pos += size
        if pos != end:
            raise ValueError('Invalid chunk termination')

    chunks(0, len(data))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    with zipfile.ZipFile(a.apk) as archive:
        data = archive.read('resources.arsc')
    result = dict(apk_sha256=hashlib.sha256(a.apk.read_bytes()).hexdigest(),
                  resources_sha256=hashlib.sha256(data).hexdigest(),
                  **audit(data), native_execution_verified=False,
                  exact_crashing_resource_identified=False)
    a.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('examples', 'matching_0x40001')}))


if __name__ == '__main__':
    main()
