"""Change one structurally identified binary manifest versionCode, offline only."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from remap_tcl_app_resources import chunks
from compress_apk_dex import signature_entry


def rewrite(data, expected, replacement):
    if not 0 < expected < replacement < 0x7fffffff:
        raise ValueError('Expected a positive increasing Android versionCode')
    kind, header, length = struct.unpack_from('<HHI', data)
    if kind != 3 or length != len(data):
        raise ValueError('Expected complete binary XML')
    attributes = None
    result = bytearray(data)
    changes = []
    seen_element = False
    for off, kind, hs, size in chunks(data, header, length):
        if kind == 0x180:
            if attributes is not None or (size-hs) % 4:
                raise ValueError('Invalid resource map')
            attributes = struct.unpack_from('<' + 'I'*((size-hs)//4), data, off+hs)
        elif kind == 0x102 and not seen_element:
            seen_element = True
            if hs != 16 or size < 36 or attributes is None:
                raise ValueError('Invalid root element')
            start, width, count = struct.unpack_from('<HHH', data, off+24)
            if start != 20 or width != 20 or 16+start+width*count > size:
                raise ValueError('Unsupported attribute layout')
            for i in range(count):
                pos = off+16+start+i*width
                name, raw = struct.unpack_from('<II', data, pos+4)
                if name >= len(attributes) or attributes[name] != 0x0101021b:
                    continue
                length_value, reserved, typ, value = struct.unpack_from('<HBBI', data, pos+12)
                if (length_value,reserved,typ,value,raw) != (8,0,16,expected,0xffffffff):
                    raise ValueError('Unexpected versionCode representation/value')
                struct.pack_into('<I', result, pos+16, replacement)
                changes.append(pos+16)
    if len(changes) != 1:
        raise ValueError('Expected exactly one root versionCode')
    return bytes(result), changes[0]


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk',type=Path,required=True)
    p.add_argument('--sha256',required=True)
    p.add_argument('--expected',type=int,required=True)
    p.add_argument('--replacement',type=int,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if hashlib.sha256(a.apk.read_bytes()).hexdigest()!=a.sha256:
        raise ValueError('APK identity mismatch')
    with zipfile.ZipFile(a.apk) as src:
        manifest=src.read('AndroidManifest.xml')
        updated,offset=rewrite(manifest,a.expected,a.replacement)
        with zipfile.ZipFile(a.output,'x') as dst:
            for entry in src.infolist():
                if signature_entry(entry.filename):
                    continue
                dst.writestr(entry,updated if entry.filename=='AndroidManifest.xml' else src.read(entry.filename))
    print(json.dumps(dict(original=a.expected,replacement=a.replacement,offset=offset,
        sha256=hashlib.sha256(a.output.read_bytes()).hexdigest(),unsigned=True,
        database_compatibility_verified=False,installed=False)))
