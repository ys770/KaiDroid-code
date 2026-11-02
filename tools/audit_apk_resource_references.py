"""Inventory typed framework references in APK XML and aapt-decoded tables.

No integer byte scanning or rewriting. DEX, native and dynamic name lookups
are outside this inventory; name matching does not establish semantic parity.
"""
import argparse
from collections import defaultdict
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path
from compare_framework_resources import table


def xml_references(data, include_context=False):
    if len(data) < 8:
        raise ValueError('Truncated XML')
    kind, header, size = struct.unpack_from('<HHI', data)
    if kind != 3 or header < 8 or header > size or size != len(data):
        raise ValueError('Not complete compiled Android XML')
    chunks = []
    offset = header
    resources = []
    while offset < size:
        if offset + 8 > size:
            raise ValueError('Truncated chunk')
        kind, head, length = struct.unpack_from('<HHI', data, offset)
        if head < 8 or length < head or offset + length > size:
            raise ValueError('Invalid XML chunk extent')
        chunk = data[offset:offset + length]
        if kind == 0x180:
            if (length - head) % 4:
                raise ValueError('Invalid resource map')
            resources = list(struct.unpack_from('<' + 'I' * ((length - head) // 4), chunk, head))
        chunks.append((kind, head, chunk))
        offset += length
    result = []
    for kind, head, chunk in chunks:
        if kind == 0x102:
            if head != 16 or len(chunk) < 36:
                raise ValueError('Unexpected start element layout')
            start, width, count = struct.unpack_from('<HHH', chunk, 24)
            if start < 20 or width < 20 or 16 + start + count * width > len(chunk):
                raise ValueError('Invalid attribute extent')
            for i in range(count):
                pos = 16 + start + i * width
                name_index = struct.unpack_from('<I', chunk, pos + 4)[0]
                if name_index < len(resources):
                    result.append(('attribute-name', resources[name_index], resources[name_index]))
                value_size, _, value_type, value = struct.unpack_from('<HBBI', chunk, pos + 12)
                if value_size != 8:
                    raise ValueError('Unexpected typed value size')
                if value_type in (1, 2):
                    result.append(('reference' if value_type == 1 else 'attribute', value,
                                   resources[name_index] if name_index < len(resources) else None))
                elif value_type in (7, 8):
                    raise ValueError('Dynamic XML references require package-map resolution')
        elif kind == 0x104:
            if head != 16 or len(chunk) < 28:
                raise ValueError('Unexpected text chunk')
            value_size, _, value_type, value = struct.unpack_from('<HBBI', chunk, 20)
            # aapt can emit an empty all-zero typedData for string CDATA.
            if value_size != 8 and (value_size, value_type, value) != (0, 0, 0):
                raise ValueError('Unexpected text typed value size')
            if value_type in (1, 2):
                result.append(('text-reference', value, None))
            elif value_type in (7, 8):
                raise ValueError('Dynamic XML references require package-map resolution')
    return result if include_context else [(kind, value) for kind, value, _ in result]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--donor', required=True, type=Path)
    parser.add_argument('--reference', required=True, type=Path)
    parser.add_argument('--aapt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.apk.read_bytes()).hexdigest() != args.sha256:
        raise ValueError('APK identity mismatch')
    uses = defaultdict(list)

    def record(kind, number, source, attribute_id=None):
        if number >> 24 == 1:
            site = {'kind': kind, 'source': source}
            if attribute_id is not None:
                site['xml_attribute_id'] = f'0x{attribute_id:08x}'
            uses[number].append(site)

    internal_keys = defaultdict(int)
    raw_xml = []
    count = 0
    with zipfile.ZipFile(args.apk) as archive:
        for entry in archive.namelist():
            if entry == 'AndroidManifest.xml' or entry.startswith('res/') and entry.endswith('.xml'):
                if entry.startswith('res/') and entry.split('/')[1].split('-')[0] == 'raw':
                    raw_xml.append(entry)
                    continue
                for kind, number, attribute_id in xml_references(archive.read(entry), include_context=True):
                    record(kind, number, entry, attribute_id)
                count += 1
    output = subprocess.run([str(args.aapt), 'dump', '--values', 'resources', str(args.apk)],
                            capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", check=True, timeout=60).stdout
    if 'resource ' not in output:
        raise ValueError('Resource table dump was empty')
    current = 'resources.arsc'
    for line in output.splitlines():
        match = re.match(r'\s*resource (0x[0-9a-f]+) ([^ :]+:[^ :]+):', line)
        if match:
            current = match[2]
        for kind, pattern in (
                ('bag-parent', r'Parent=(0x[0-9a-f]+)'),
                ('bag-key', r'Key=(0x[0-9a-f]+)'),
                ('bag-reference', r'\((?:reference|attribute)\) (0x[0-9a-f]+)'),
                ('table-reference', r't=0x0[12] d=(0x[0-9a-f]+)')):
            for value in re.findall(pattern, line):
                number = int(value, 16)
                # ResTable_map metadata, array indices and plural selectors use
                # the reserved type-zero namespace, not framework resources.
                if kind == 'bag-key' and number & 0xffff0000 == 0x01000000:
                    internal_keys[value] += 1
                else:
                    record(kind, number, current)
    donor_ids, _ = table(args.aapt, args.donor)
    reference_ids, reference_names = table(args.aapt, args.reference)
    for sites in uses.values():
        for site in sites:
            if 'xml_attribute_id' in site:
                site['xml_attribute_donor_name'] = donor_ids.get(int(site['xml_attribute_id'], 16))
    rows = []
    for number, sites in sorted(uses.items()):
        name = donor_ids.get(number)
        target = reference_names.get(name)
        state = ('unknown-donor-id' if name is None else 'absent-reference-name' if target is None
                 else 'same-id' if target == number else 'different-id')
        rows.append({'id': f'0x{number:08x}', 'donor_name': name,
                     'reference_name_at_id': reference_ids.get(number),
                     'mapped_reference_id': None if target is None else f'0x{target:08x}',
                     'state': state, 'site_count': len(sites), 'sites': sites})
    report = {'scope': __doc__, 'apk_sha256': args.sha256,
              'donor_sha256': hashlib.sha256(args.donor.read_bytes()).hexdigest(),
              'reference_sha256': hashlib.sha256(args.reference.read_bytes()).hexdigest(),
              'excluded_raw_xml': raw_xml, 'compiled_xml_files': count, 'framework_ids': len(rows),
              'aapt_sha256': hashlib.sha256(args.aapt.read_bytes()).hexdigest(),
              'internal_bag_keys': dict(sorted(internal_keys.items())),
              'counts': {state: sum(row['state'] == state for row in rows) for state in
                         ('same-id', 'different-id', 'absent-reference-name', 'unknown-donor-id')},
              'references': rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('compiled_xml_files', 'framework_ids', 'counts')}))


if __name__ == '__main__':
    main()
