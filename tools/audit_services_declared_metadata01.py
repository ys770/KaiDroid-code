"""Count pinned services DEX class-data members and model initial array requests.

Offline only. Counts declared definitions, not loaded classes or physical pages.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import audit_services_dex_cache_capacity01 as cache

HEADERS_SHA = '18ae837f01b09cd929e42a3a7eedf356084028a0de84103c3627a54d24e112db'
GROUPS = ('static_fields', 'instance_fields', 'direct_methods', 'virtual_methods')


def uleb(data, offset):
    value = 0
    for i in range(5):
        if offset >= len(data):
            raise ValueError('Truncated ULEB128')
        byte = data[offset]
        offset += 1
        if i == 4 and byte > 15:
            raise ValueError('Overflow ULEB128')
        value |= (byte & 127) << (i * 7)
        if not byte & 128:
            return value, offset
    raise ValueError('Overlong ULEB128')


def class_data(data, offset, owner_type, counts):
    row = dict.fromkeys(GROUPS, 0)
    row.update(duplicate_fields=0, duplicate_methods=0, native_methods=0,
               abstract_methods=0, methods_with_code=0)
    if offset == 0:
        return row
    if offset < 112 or offset >= len(data):
        raise ValueError('Class data bounds')
    for group in GROUPS:
        row[group], offset = uleb(data, offset)
    minimum = 2 * (row['static_fields'] + row['instance_fields']) + 3 * (row['direct_methods'] + row['virtual_methods'])
    if minimum > len(data) - offset:
        raise ValueError('Class member count exceeds remaining bytes')
    for group in GROUPS:
        is_method = group.endswith('methods')
        size = counts['methods' if is_method else 'fields']
        table = struct.unpack_from('<I', data, 92 if is_method else 84)[0]
        index = 0
        for n in range(row[group]):
            diff, offset = uleb(data, offset)
            flags, offset = uleb(data, offset)
            index += diff
            if index >= size:
                raise ValueError('Member index outside ID table')
            declared_owner = struct.unpack_from('<H', data, table + 8 * index)[0]
            if declared_owner != owner_type:
                raise ValueError('Member declaring type differs from class')
            if n and diff == 0:
                row['duplicate_methods' if is_method else 'duplicate_fields'] += 1
            if is_method:
                code, offset = uleb(data, offset)
                row['native_methods'] += bool(flags & 0x100)
                row['abstract_methods'] += bool(flags & 0x400)
                if code:
                    if code < 112 or code % 4 or code + 16 > len(data):
                        raise ValueError('Code item bounds/alignment')
                    instructions = struct.unpack_from('<I', data, code + 12)[0]
                    if code + 16 + 2 * instructions > len(data):
                        raise ValueError('Instruction extent out of bounds')
                    row['methods_with_code'] += 1
    return row


def descriptor(data, type_index, counts):
    if type_index >= counts['types']:
        raise ValueError('Class type outside type table')
    type_offset = struct.unpack_from('<I', data, 68)[0]
    string_index = struct.unpack_from('<I', data, type_offset + 4 * type_index)[0]
    if string_index >= counts['strings']:
        raise ValueError('Descriptor string outside string table')
    string_table = struct.unpack_from('<I', data, 60)[0]
    string_offset = struct.unpack_from('<I', data, string_table + 4 * string_index)[0]
    if string_offset < 112 or string_offset >= len(data):
        raise ValueError('Descriptor string data bounds')
    utf16_count, start = uleb(data, string_offset)
    end = data.find(b'\0', start, min(len(data), start + 1048576))
    if end == -1:
        raise ValueError('Unterminated/oversized descriptor')
    raw = data[start:end]
    if any(byte >= 128 for byte in raw):
        # No invented UTF8 decoding of MUTF8/surrogate identifiers.
        return '<non-ascii-descriptor-sha256:' + hashlib.sha256(raw).hexdigest() + '>'
    if len(raw) != utf16_count:
        raise ValueError('ASCII descriptor UTF16 length differs')
    return raw.decode('ascii')


def initial_requests(row):
    fields = row['static_fields'] + row['instance_fields']
    methods = row['direct_methods'] + row['virtual_methods']
    field_arrays = bool(row['static_fields']) + bool(row['instance_fields'])
    # Retrieved source layout, ARM32: ArtField16/align4, ArtMethod28/align4,
    # and uint32 length-prefix4. AllocArt*Array returns null for zero length.
    return dict(initial_field_array_request_bytes=16 * fields + 4 * field_arrays,
                initial_method_array_request_bytes=28 * methods + (4 if methods else 0),
                field_array_count=int(field_arrays), method_array_count=int(bool(methods)))


def parse_dex(name, data):
    counts = cache.read_dex(data)
    table = struct.unpack_from('<I', data, 100)[0]
    rows = []
    for i in range(counts['class_definitions']):
        owner, flags, _, _, _, _, members, _ = struct.unpack_from('<8I', data, table + 32 * i)
        row = dict(dex=name, class_def_index=i, type_index=owner,
                   descriptor=descriptor(data, owner, counts), interface=bool(flags & 0x200),
                   abstract_class=bool(flags & 0x400), has_class_data=members != 0,
                   **class_data(data, members, owner, counts))
        row.update(initial_requests(row))
        rows.append(row)
    return rows


def run():
    # Revalidate the existing raw/JAR/DEX/source/object/header-capacity audit.
    baseline = json.loads((ROOT / 'experiments/memory/services-dex-cache-capacity02.json').read_text())
    if cache.sha(Path(cache.__file__).read_bytes()) != baseline['analyzer_sha256']:
        raise ValueError('Prior capacity analyzer changed')
    cache_result = cache.run()
    if cache_result['single_cache_set_per_dex_request_bytes'] != 81920:
        raise ValueError('Prior capacity constraint differs')
    headers = ROOT / 'work/memory/reconstruction-source-inputs04'
    receipt_data = (headers / 'acquisition.json').read_bytes()
    if cache.sha(receipt_data) != HEADERS_SHA:
        raise ValueError('Size-header receipt changed')
    receipt = json.loads(receipt_data)
    if receipt['errors'] or len(receipt['files']) != 6:
        raise ValueError('Incomplete size-header acquisition')
    sources = []
    for row in receipt['files']:
        if not row['stable_stat'] or cache.sha((headers / 'source' / row['relative_path']).read_bytes()) != row['sha256']:
            raise ValueError('Size source changed')
        sources.append({k: row[k] for k in ('relative_path', 'sha256', 'bytes', 'mtime_ns')})
    from dissect.extfs import ExtFS
    with (ROOT / 'work/engineering-system-55.raw.img').open('rb') as stream:
        jar = ExtFS(stream).get('/system/framework/services.jar').open().read()
    if cache.sha(jar) != cache.JAR_SHA:
        raise ValueError('Services JAR differs')
    rows = []
    with zipfile.ZipFile(io.BytesIO(jar)) as archive:
        for name in ('classes.dex', 'classes2.dex'):
            data = archive.read(name)
            expected = next(r for r in baseline['dex_files'] if r['name'] == name)
            if cache.sha(data) != expected['sha256']:
                raise ValueError('DEX differs')
            rows.extend(parse_dex(name, data))
    counters = (*GROUPS, 'duplicate_fields', 'duplicate_methods', 'native_methods',
                'abstract_methods', 'methods_with_code', 'initial_field_array_request_bytes',
                'initial_method_array_request_bytes', 'field_array_count', 'method_array_count')
    totals = {key: sum(r[key] for r in rows) for key in counters}
    full = json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()
    result = dict(classification='offline_declared_services_metadata_scenario', image='55_historical',
                  raw_sha256=cache.RAW_SHA, services_jar_sha256=cache.JAR_SHA,
                  size_headers_receipt_sha256=HEADERS_SHA, sources=sources,
                  classes_declared=len(rows), classes_with_data=sum(r['has_class_data'] for r in rows),
                  interface_class_definitions=sum(r['interface'] for r in rows), totals=totals,
                  full_class_rows_sha256=cache.sha(full),
                  top20_initial_declared_array_requests=sorted(rows, key=lambda r:
                      r['initial_field_array_request_bytes'] + r['initial_method_array_request_bytes'], reverse=True)[:20],
                  actual_loaded_class_count=None, actual_allocation_attempts=None,
                  physical_savings_proven=False, compiled_source_byte_binding_proven=False,
                  target_binary_changed=False,
                  limits=['Scenario loads every declared class once through ordinary LoadClass; this was not executed.',
                          'ID tables include references; only encoded class_data member definitions enter this model.',
                          'Initial requested field/method array bytes exclude arena rounding/overhead and physical backing.',
                          'Miranda/default/conflict/proxy/runtime methods and later reallocations are not counted.',
                          'Managed class objects, static field values, inherited vtables, IMTs/conflicts and dependency classes are excluded.',
                          'Duplicate fields reduce logical array size without shrinking the initial source allocation.',
                          'Class-data and code-item boundary checks are not complete DEX semantic/code verification.',
                          'Header source layout was reviewed; no new target compile or complete ABI/source-to-object proof.',
                          'Historical55 scenario is not a current59 baseline or a total physical working-set denominator.'])
    return result, full


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--classes-output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.classes_output.exists():
        raise FileExistsError('Fresh output paths required')
    result, full = run()
    result['analyzer_sha256'] = cache.sha(Path(__file__).read_bytes())
    args.classes_output.write_bytes(gzip.compress(full, mtime=0))
    result['full_class_rows_gzip_sha256'] = cache.sha(args.classes_output.read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(classes=result['classes_declared'], totals=result['totals']), indent=2))
