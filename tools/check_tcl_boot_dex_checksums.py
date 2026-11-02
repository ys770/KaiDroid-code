"""Compare framework OAT DEX location checksums to staged JAR ZIP entry CRCs.

Restricted structural check for this Android11 build. Does not validate ART
image relocation, all boot-image dependencies, verifier acceptance or a boot.
"""
import argparse
import hashlib
import json
import re
import struct
import zipfile
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--system', type=Path, required=True)
    a = p.parse_args()
    rows = []
    core = (a.system / 'apex/com.android.art.release/javalib/arm/boot.art').read_bytes()
    if core[:4] != b'art\n':
        raise ValueError('Missing core ART header')
    core_count = struct.unpack_from('<I', core, 12)[0]
    core_checksum = struct.unpack_from('<I', core, 24)[0]
    for path in sorted((a.system / 'framework/arm').glob('boot*.oat')):
        data = path.read_bytes()
        start = data.find(b'oat\n')
        if start < 0 or data[start+4:start+8] != b'183\0':
            raise ValueError('Expected Android11 OAT version183: ' + str(path))
        count = struct.unpack_from('<I', data, start + 20)[0]
        store_size = struct.unpack_from('<I', data, start + 56)[0]
        store = data[start+60:start+60+store_size]
        if len(store) != store_size or (store_size and not store.endswith(b'\0')):
            raise ValueError('Invalid OAT metadata size')
        parts = store[:-1].split(b'\0') if store_size else []
        if len(parts) % 2:
            raise ValueError('Invalid OAT metadata pairs')
        metadata = {parts[i].decode(): parts[i+1].decode() for i in range(0, len(parts), 2)}
        if 'bootclasspath-checksums' in metadata and metadata['bootclasspath-checksums'] != f'i;{core_count}/{core_checksum:08x}':
            raise ValueError('Core boot dependency checksum mismatch')
        art = path.with_suffix('.art').read_bytes()
        if art[:8] != core[:8] or struct.unpack_from('<I', art, 28)[0] != struct.unpack_from('<I', data, start+8)[0]:
            raise ValueError('ART/OAT header checksum mismatch: ' + str(path))
        matches = []
        for match in re.finditer(rb'/system/framework/[A-Za-z0-9_.-]+\.jar(?:!classes[0-9]*\.dex)?', data):
            location = match.group()
            if match.start() < 4 or struct.unpack_from('<I', data, match.start()-4)[0] != len(location):
                continue
            recorded = struct.unpack_from('<I', data, match.end())[0]
            jar, _, entry = location.decode().partition('!')
            jarpath = a.system / jar.removeprefix('/system/')
            with zipfile.ZipFile(jarpath) as z:
                expected = z.getinfo(entry or 'classes.dex').CRC
            if recorded != expected:
                raise ValueError('DEX checksum mismatch: ' + location.decode())
            matches.append(dict(location=location.decode(), checksum=recorded))
        if len(matches) != count or count == 0:
            raise ValueError('Not every OAT DEX record accounted for: ' + str(path))
        rows.append(dict(oat=str(path.relative_to(a.system)), version=data[start+4:start+7].decode(),
                         sha256=hashlib.sha256(data).hexdigest(), dex=matches,
                         metadata=metadata))
    if not rows:
        raise ValueError('No framework OAT files')
    print(json.dumps(dict(scope=__doc__, oats=rows, matched_dex_entries=sum(len(x['dex']) for x in rows),
                          core_component_count=core_count, core_image_checksum=f'{core_checksum:08x}',
                          art_oat_header_checksums_matched=True,
                          physical_boot_verified=False), indent=2))


if __name__ == '__main__':
    main()
