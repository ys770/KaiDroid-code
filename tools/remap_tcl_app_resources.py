"""Remap reviewed, typed resource references in a pinned APK, offline only.

Does not patch DEX constants, raw XML or arbitrary integer bytes. Output APK is
unsigned and must be rebuilt/aligned/signed before any coordinated runtime test.
Reference identity is not resource-value equivalence or behavioral parity.
"""
import argparse
import hashlib
import io
import json
import re
import struct
import zipfile
from pathlib import Path

from compare_framework_resources import table


def chunks(data, start, end):
    while start < end:
        if start + 8 > end:
            raise ValueError('Truncated chunk header')
        kind, head, size = struct.unpack_from('<HHI', data, start)
        if head < 8 or size < head or start + size > end:
            raise ValueError('Invalid chunk extent')
        yield start, kind, head, size
        start += size
    if start != end:
        raise ValueError('Chunk boundary mismatch')


def references(data, xml):
    """Return only structurally typed reference offsets, with semantic kinds."""
    if len(data) < 8:
        raise ValueError('Truncated resource')
    kind, head, size = struct.unpack_from('<HHI', data)
    if kind != (3 if xml else 2) or size != len(data) or not 8 <= head <= size:
        raise ValueError('Unexpected top-level resource')
    found = {}

    def add(pos, label, limit):
        if pos < 0 or pos + 4 > limit:
            raise ValueError('Reference outside containing chunk')
        if pos in found and found[pos] != label:
            raise ValueError('Conflicting reference interpretation')
        found[pos] = label

    def value(pos, limit):
        if pos + 8 > limit:
            raise ValueError('Truncated typed value')
        length, reserved, typ, number = struct.unpack_from('<HBBI', data, pos)
        if length != 8 or reserved:
            raise ValueError('Unsupported typed value')
        if typ in (7, 8):
            raise ValueError('Dynamic references require explicit package resolution')
        if typ in (1, 2):
            add(pos + 4, 'reference' if typ == 1 else 'attribute', limit)

    if xml:
        for off, typ, hs, length in chunks(data, head, size):
            end = off + length
            if typ == 0x180:
                if (length - hs) % 4:
                    raise ValueError('Invalid XML resource map')
                for pos in range(off + hs, end, 4):
                    add(pos, 'attribute-name', end)
            elif typ == 0x102:
                if hs != 16 or length < 36:
                    raise ValueError('Invalid XML element')
                start, width, count = struct.unpack_from('<HHH', data, off + 24)
                if start < 20 or width < 20 or 16 + start + count * width > length:
                    raise ValueError('Invalid attribute extent')
                for i in range(count):
                    value(off + 16 + start + i * width + 12, end)
            elif typ == 0x104:
                if hs != 16 or length != 28:
                    raise ValueError('Invalid CDATA chunk')
                if data[off + 20:off + 28] != bytes(8):
                    value(off + 20, end)
            elif typ not in (1, 0x100, 0x101, 0x103):
                raise ValueError(f'Unsupported XML chunk {typ:#x}')
    else:
        for off, typ, hs, length in chunks(data, head, size):
            if typ == 1:
                continue  # string pool
            if typ != 0x200 or hs not in (284, 288):
                raise ValueError('Unsupported resource package')
            for toff, ttyp, ths, tlength in chunks(data, off + hs, off + length):
                if ttyp in (1, 0x202):
                    continue  # string pools and type specifications
                if ttyp != 0x201 or ths < 24:
                    raise ValueError(f'Unsupported package chunk {ttyp:#x}')
                end = toff + tlength
                flags = data[toff + 9]
                if flags & ~1:
                    raise ValueError('Unsupported type offset encoding')
                count, entry_start = struct.unpack_from('<II', data, toff + 12)
                if entry_start < ths + 4 * count or entry_start > tlength:
                    raise ValueError('Invalid entry offsets')
                offsets = []
                for i in range(count):
                    pos = toff + ths + i * 4
                    if flags & 1:
                        index, offset = struct.unpack_from('<HH', data, pos)
                        if offsets and index <= offsets[-1][0]:
                            raise ValueError('Sparse IDs not strictly ordered')
                        offsets.append((index, offset * 4))
                    else:
                        offset = struct.unpack_from('<I', data, pos)[0]
                        if offset != 0xffffffff:
                            offsets.append((i, offset))
                for _, offset in offsets:
                    pos = toff + entry_start + offset
                    if pos + 8 > end:
                        raise ValueError('Entry outside type chunk')
                    esize, eflags = struct.unpack_from('<HH', data, pos)
                    if eflags & ~7 or esize < 8 or pos + esize > end:
                        raise ValueError('Unsupported entry layout')
                    if eflags & 1:
                        if esize != 16:
                            raise ValueError('Unsupported map entry')
                        add(pos + 8, 'bag-parent', end)
                        n = struct.unpack_from('<I', data, pos + 12)[0]
                        if pos + esize + 12 * n > end:
                            raise ValueError('Map exceeds type chunk')
                        for j in range(n):
                            m = pos + esize + 12 * j
                            add(m, 'bag-key', end)
                            value(m + 4, end)
                    else:
                        if esize != 8:
                            raise ValueError('Unsupported simple entry')
                        value(pos + esize, end)
    return sorted(found.items())


def transform(data, xml, mapping):
    output = bytearray(data)
    changes = []
    for offset, kind in references(data, xml):
        old = struct.unpack_from('<I', data, offset)[0]
        if old in mapping:
            new = mapping[old]
            struct.pack_into('<I', output, offset, new)
            changes.append(dict(offset=offset, kind=kind, old=f'0x{old:08x}', new=f'0x{new:08x}'))
    # Reparse candidate and account for every changed byte; no structural edits.
    if references(bytes(output), xml) != references(data, xml):
        raise ValueError('Reference structure changed')
    allowed = {i for c in changes for i in range(c['offset'], c['offset'] + 4)}
    if any(i not in allowed for i, (a, b) in enumerate(zip(data, output)) if a != b):
        raise ValueError('Unaccounted byte change')
    return bytes(output), changes


def reorder_xml_attributes(data):
    """Keep attribute records and special indexes together after ID remapping."""
    references(data, True)  # Validate chunk extents before any edits.
    output = bytearray(data)
    resource_ids = []
    reordered = []
    for off, typ, hs, length in chunks(data, 8, len(data)):
        if typ == 0x180:
            resource_ids = list(struct.unpack_from('<' + 'I' * ((length - hs) // 4), data, off + hs))
        elif typ == 0x102:
            start, width, count = struct.unpack_from('<HHH', data, off + 24)
            base = off + 16 + start
            records = [data[base + i * width:base + (i + 1) * width] for i in range(count)]
            def key(index):
                name = struct.unpack_from('<I', records[index], 4)[0]
                return resource_ids[name] if name < len(resource_ids) else 0
            # Attributes without a resource ID retain their positions and order.
            known = [i for i in range(count) if key(i)]
            order = list(range(count))
            for position, original in zip(known, sorted(known, key=key)):
                order[position] = original
            if order == list(range(count)):
                continue
            for i, original in enumerate(order):
                output[base + i * width:base + (i + 1) * width] = records[original]
            for special in (off + 30, off + 32, off + 34):
                old = struct.unpack_from('<H', data, special)[0]
                if old > count:
                    raise ValueError('Invalid special attribute index')
                if old:
                    struct.pack_into('<H', output, special, order.index(old - 1) + 1)
            reordered.append(dict(element_offset=off, original_index_at_new_position=order))
    references(bytes(output), True)
    return bytes(output), reordered


def checked_target_name(row):
    target = row.get('target_name', row['name'])
    if target != row['name']:
        if not row['name'].startswith('android:attr/') or target != row['name'].replace(
                'android:attr/', 'android:^attr-private/', 1):
            raise ValueError('Only same-name framework attribute visibility mapping is supported')
    return target


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'donor', 'target', 'aapt', 'plan', 'output'):
        p.add_argument('--' + name, required=True, type=Path)
    a = p.parse_args()
    if a.output.exists() or a.output.is_symlink():
        raise FileExistsError(a.output)
    plan = json.loads(a.plan.read_text())
    for name, path in [('apk', a.apk), ('donor', a.donor), ('target', a.target)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != plan[name + '_sha256']:
            raise ValueError(f'Unexpected {name} SHA-256')
    donor_ids, _ = table(a.aapt, a.donor)
    target_ids, _ = table(a.aapt, a.target)
    mapping = {}
    for row in plan['mappings']:
        old, new = int(row['old'], 16), int(row['new'], 16)
        if old in mapping or not row.get('rationale'):
            raise ValueError('Missing review rationale or duplicate mapping')
        if donor_ids.get(old) != row['name'] or target_ids.get(new) != checked_target_name(row):
            raise ValueError('Plan disagrees with pinned resource names')
        mapping[old] = new
    buffer = io.BytesIO()
    report = dict(plan_sha256=hashlib.sha256(a.plan.read_bytes()).hexdigest(),
                  input_sha256=plan['apk_sha256'], target_sha256=plan['target_sha256'],
                  changes=[], attribute_reorders=[], unchanged_entries=[], removed_signature_entries=[],
                  signed=False, installed=False, parity_verified=False)
    with zipfile.ZipFile(a.apk) as source, zipfile.ZipFile(buffer, 'w') as dest:
        if len(source.namelist()) != len(set(source.namelist())):
            raise ValueError('Duplicate APK entry')
        for info in source.infolist():
            name = info.filename
            if re.fullmatch(r'META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))', name, re.I):
                report['removed_signature_entries'].append(name)
                continue
            data = source.read(name)
            xml = name == 'AndroidManifest.xml' or (
                name.startswith('res/') and name.endswith('.xml') and name.split('/')[1].split('-')[0] != 'raw')
            changes = []
            if xml or name == 'resources.arsc':
                data, changes = transform(data, xml, mapping)
                if xml and any(c['kind'] == 'attribute-name' for c in changes):
                    data, reorders = reorder_xml_attributes(data)
                    if reorders:
                        report['attribute_reorders'].append(dict(entry=name, elements=reorders))
            if changes:
                report['changes'].append(dict(entry=name, sites=changes))
            else:
                report['unchanged_entries'].append(name)
            dest.writestr(info, data)
    seen = {int(c['old'], 16) for e in report['changes'] for c in e['sites']}
    if seen != set(mapping):
        raise ValueError('Plan includes references not found in typed resource sites')
    data = buffer.getvalue()
    report['output_sha256'] = hashlib.sha256(data).hexdigest()
    report['mapped_ids'] = len(mapping)
    a.output.mkdir(parents=True)
    (a.output / a.apk.name).write_bytes(data)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('mapped_ids', 'output_sha256', 'signed', 'installed')}))


if __name__ == '__main__':
    main()
