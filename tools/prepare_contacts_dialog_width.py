"""Patch only two pinned Contacts dialog width attributes; output is unsigned."""
import argparse
import hashlib
import json
import struct
import zipfile
from pathlib import Path
from remap_tcl_app_resources import chunks

BASE_SHA = 'c31045c93317a5e1bbe43fd492573f445e57b08e44d425278fbafc113020c610'
LAYOUT = 'res/layout/vzw_preference_dialog.xml'


def transform(data):
    kind, head, size = struct.unpack_from('<HHI', data)
    if kind != 3 or size != len(data):
        raise ValueError('Invalid binary XML root')
    resource_ids = None
    output = bytearray(data)
    changes = []
    for off, kind, header, length in chunks(data, head, size):
        if kind == 0x180:
            if resource_ids is not None or (length - header) % 4:
                raise ValueError('Invalid resource map')
            resource_ids = struct.unpack_from('<' + 'I' * ((length - header) // 4), data, off + header)
        if kind != 0x102:
            continue
        if resource_ids is None or header != 16 or length < 36:
            raise ValueError('Invalid element')
        start, width, count = struct.unpack_from('<HHH', data, off + 24)
        if start < 20 or width != 20 or 16 + start + count * width > length:
            raise ValueError('Invalid attribute bounds')
        for i in range(count):
            pos = off + 16 + start + i * width
            name = struct.unpack_from('<I', data, pos + 4)[0]
            if name >= len(resource_ids) or resource_ids[name] != 0x010100f4:
                continue
            value_size, reserved, value_type, value = struct.unpack_from('<HBBI', data, pos + 12)
            if value_size != 8 or reserved:
                raise ValueError('Invalid typed value')
            if value_type == 5 and value == 0x0000f001:
                struct.pack_into('<I', output, pos + 8, 0xffffffff)  # no stale raw string
                struct.pack_into('<HBBI', output, pos + 12, 8, 0, 16, 0xffffffff)
                changes.append(dict(attribute_offset=pos, before='240dp', after='match_parent'))
    if len(changes) != 2:
        raise ValueError('Expected exactly root/title fixed-width attributes')
    return bytes(output), changes


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apk', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if hashlib.sha256(a.apk.read_bytes()).hexdigest() != BASE_SHA:
        raise ValueError('Wrong callback candidate')
    a.output.mkdir(parents=True, exist_ok=False)
    target = a.output / 'FPContacts.unsigned.apk'
    with zipfile.ZipFile(a.apk) as src, zipfile.ZipFile(target, 'x') as dst:
        if len(set(src.namelist())) != len(src.namelist()):
            raise ValueError('Duplicate ZIP entries')
        before = src.read(LAYOUT)
        after, changes = transform(before)
        for entry in src.infolist():
            if entry.filename.upper().startswith('META-INF/'):
                continue
            dst.writestr(entry, after if entry.filename == LAYOUT else src.read(entry))
    with zipfile.ZipFile(a.apk) as src, zipfile.ZipFile(target) as dst:
        differences = [n for n in dst.namelist() if src.read(n) != dst.read(n)]
        if differences != [LAYOUT]:
            raise ValueError('Unexpected APK payload differences')
    report = dict(base_sha256=BASE_SHA, unsigned_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                  changed_entries=differences, attributes=changes, dex_unchanged=True,
                  signed=False, installed=False, title_clipping_fixed_at_runtime=False)
    (a.output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
