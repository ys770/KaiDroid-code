"""Offline source/DEX-bound capacity accounting; no target or build operations."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import struct
import sys
import zipfile
import zlib

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RAW_SHA = 'c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
JAR_SHA = '4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'
ACQUISITION_SHA = '07ab3bc9b54f9e22ef88155288a293858afa36ef872918c63afeca043961c5b1'
PROVENANCE_SHA = '46a74e0c02fc736b30afb99cb00392344e70545add59c171263ebc5c02fe4643'
IMAGE_AUDIT_SHA = '08059d6a608114000bc84bebd7d286c2c9b817aaa07e79cdbe8ecff5b366648d'
KINDS = ('types', 'methods', 'strings', 'fields', 'method_types')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_dex(data):
    if len(data) < 112 or not re.fullmatch(rb'dex\n0(?:35|37|38|39)\x00', data[:8]):
        raise ValueError('Standard reviewed DEX035/037/038/039 required')
    size, header, endian = struct.unpack_from('<III', data, 32)
    if size != len(data) or header != 112 or endian != 0x12345678:
        raise ValueError('DEX size/header/endian differs')
    if hashlib.sha1(data[32:]).digest() != data[12:32]:
        raise ValueError('DEX SHA1 mismatch')
    if zlib.adler32(data[12:]) & 0xffffffff != struct.unpack_from('<I', data, 8)[0]:
        raise ValueError('DEX Adler32 mismatch')
    result = {}
    for name, at, width in (('strings', 56, 4), ('types', 64, 4),
                            ('method_types', 72, 12), ('fields', 80, 8),
                            ('methods', 88, 8), ('class_definitions', 96, 32)):
        count, offset = struct.unpack_from('<II', data, at)
        if (count == 0 and offset != 0) or (count and (offset < 112 or offset + width * count > size)):
            raise ValueError('DEX ID table bounds: ' + name)
        result[name] = count
    map_offset = struct.unpack_from('<I', data, 52)[0]
    if map_offset < 112 or map_offset + 4 > size:
        raise ValueError('DEX map absent/out of bounds')
    count = struct.unpack_from('<I', data, map_offset)[0]
    if count > 1024 or map_offset + 4 + 12 * count > size:
        raise ValueError('DEX map bounds')
    seen = set()
    result['call_sites'] = 0
    for i in range(count):
        kind, unused, number, offset = struct.unpack_from('<HHII', data, map_offset + 4 + 12 * i)
        if kind in seen or unused:
            raise ValueError('Duplicate/malformed map type')
        seen.add(kind)
        if kind == 7:
            if offset < 112 or offset + 4 * number > size:
                raise ValueError('Call-site ID bounds')
            result['call_sites'] = number
    return result


def layout(counts, cap=1024, pointer_bytes=4):
    if pointer_bytes != 4 or cap <= 0 or cap & (cap - 1):
        raise ValueError('Only ARM32 and positive power-of-two model caps supported')
    if any(type(counts.get(k)) is not int or not 0 <= counts[k] <= 0xffffffff
           for k in (*KINDS, 'call_sites')):
        raise ValueError('Invalid counts')
    # Actual ARM32 layout: five 8-byte pairs; all boundary alignments8 except
    # types4 (offset always0). Call-site roots4; final requested size rounds8.
    offset = 0
    rows = []
    for kind in KINDS:
        slots = min(counts[kind], cap)
        rows.append(dict(kind=kind, offset=offset, slots=slots, element_bytes=8, bytes=slots * 8))
        offset += slots * 8
    rows.append(dict(kind='call_sites', offset=offset, slots=counts['call_sites'],
                     element_bytes=4, bytes=counts['call_sites'] * 4))
    unrounded = offset + counts['call_sites'] * 4
    size = (unrounded + 7) & ~7
    if size > 0xffffffff:
        raise ValueError('Layout exceeds ARM32 size_t; outside modeled valid domain')
    # InitializeDexCache enters its LinearAlloc site only for these four kinds.
    allocated = any(counts[k] for k in ('strings', 'types', 'methods', 'fields'))
    return dict(arrays=rows, layout_bytes=size, trailing_alignment_bytes=size - unrounded,
                initialization_array_request_bytes=size if allocated else 0)


def run():
    folder = ROOT / 'work/memory/reconstruction-source-inputs03'
    raw_receipt = (folder / 'acquisition.json').read_bytes()
    raw_provenance = (folder / 'provenance.json').read_bytes()
    if sha(raw_receipt) != ACQUISITION_SHA or sha(raw_provenance) != PROVENANCE_SHA:
        raise ValueError('Read-only acquisition changed')
    receipt = json.loads(raw_receipt)
    provenance = json.loads(raw_provenance)
    if receipt['errors'] or len(receipt['files']) != 5 or len(provenance['recipes']) != 2:
        raise ValueError('Incomplete acquisition')
    sources = []
    for row in receipt['files']:
        source = folder / 'source' / row['relative_path']
        if sha(source.read_bytes()) != row['sha256'] or receipt['source_recheck'][row['relative_path']]['sha256'] != row['sha256']:
            raise ValueError('Source changed')
        sources.append({k: row[k] for k in ('relative_path', 'sha256', 'size', 'mtime_ns')})
    cache = json.loads((ROOT / 'work/memory/libart-dryrun02/inputs/cache-before.json').read_text())
    objects = []
    prefix = 'out-eng-02/soong/.intermediates/art/runtime/libart/'
    for name, row in receipt['objects'].items():
        old = cache[row['relative_path'].removeprefix(prefix)]
        if row['sha256'] != old['sha256'] or row['after']['sha256'] != row['sha256']:
            raise ValueError('Cached object differs')
        modules = provenance['metadata'][name]
        if any(m['extract_rc'] or m['disassemble_rc'] or m['stderr'] for m in modules):
            raise ValueError('Metadata extraction failed')
        lines = [line for m in modules for line in m['debug_metadata']]
        if not any('!DIFile(' in line and name in line for line in lines):
            raise ValueError('Missing TU filename')
        if any('checksum:' in line for line in lines):
            raise ValueError('Unexpected checksum; reassess binding evidence')
        objects.append(dict(name=name, sha256=row['sha256'], frozen_cache_match=True,
                            source_filename_present=True, source_checksum_present=False))
    old_header = ROOT / 'work/memory/reconstruction-source-inputs01/source/art/runtime/mirror/dex_cache.h'
    header = old_header.read_text()
    constants = dict(re.findall(r'kDexCache(\w+)CacheSize = (\d+);', header))
    if constants != {k: '1024' for k in ('Type', 'String', 'Field', 'Method', 'MethodType')}:
        raise ValueError('Cache constants changed')
    if sha(old_header.read_bytes()) != '8366d7f9df1ca78fdbcfad605a93fa93efeab244e97e0b63d31b3a5a3736c228':
        raise ValueError('Cache header binding differs')
    raw = ROOT / 'work/engineering-system-55.raw.img'
    with raw.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != RAW_SHA:
            raise ValueError('Exact image55 raw required')
    sys.path.insert(0, str(ROOT / 'work/kyocera-extfs-python'))
    from dissect.extfs import ExtFS
    with raw.open('rb') as stream:
        jar = ExtFS(stream).get('/system/framework/services.jar').open().read()
    if sha(jar) != JAR_SHA:
        raise ValueError('Services JAR differs')
    rows = []
    with zipfile.ZipFile(io.BytesIO(jar)) as archive:
        names = [n for n in archive.namelist() if re.fullmatch(r'classes(?:[2-9][0-9]*)?\.dex', n)]
        if sorted(names) != ['classes.dex', 'classes2.dex']:
            raise ValueError('Accepted two-DEX set differs')
        for name in sorted(names):
            data = archive.read(name)
            counts = read_dex(data)
            rows.append(dict(name=name, sha256=sha(data), bytes=len(data), counts=counts,
                             baseline_1024=layout(counts), hypothetical_256=layout(counts, 256)))
    baseline = sum(x['baseline_1024']['initialization_array_request_bytes'] for x in rows)
    hypothetical = sum(x['hypothetical_256']['initialization_array_request_bytes'] for x in rows)
    prior_raw = (ROOT / 'experiments/memory/services-reconstruction-audit01-evidence.json').read_bytes()
    if sha(prior_raw) != IMAGE_AUDIT_SHA:
        raise ValueError('Serialized image audit changed')
    prior = json.loads(prior_raw)
    if prior['raw_sha256'] != RAW_SHA:
        raise ValueError('Serialized image audit has different raw input')
    serialized = next(x['bytes'] for x in prior['image']['sections'] if x['name'] == 'DexCacheArrays')
    return dict(classification='offline_exact_services_dex_cache_capacity', image='55_historical',
                raw_sha256=RAW_SHA, services_jar_sha256=JAR_SHA, acquisition_sha256=ACQUISITION_SHA,
                provenance_sha256=PROVENANCE_SHA, sources=sources, objects=objects, dex_files=rows,
                single_cache_set_per_dex_request_bytes=baseline,
                hypothetical_256_single_set_request_bytes=hypothetical,
                hypothetical_request_reduction_bytes=baseline - hypothetical,
                serialized_image_audit_sha256=IMAGE_AUDIT_SHA,
                serialized_image_cache_section_bytes=serialized,
                serialized_section_numerically_equals_single_set_model=baseline == serialized,
                source_to_object_bytes_proven=False, runtime_allocations_counted=False,
                physical_savings_proven=False, patch_prepared=False, built=False, installed=False,
                limits=['Only one array-allocation request per each of the two specific DEX files is modeled.',
                        'Multiple loaders/instances, failed allocations and RegisterDexFile races can create more requests.',
                        'Capacity and serialized section equality do not establish live entries or image cache-object count.',
                        'Requested LinearAlloc bytes exclude allocator overhead, managed DexCache, strings/classes, ArtMethods/Fields and liveness.',
                        'Compile-time cache constants/layout affect compiler, runtime, entrypoints and preopt; not a safe libart-only binary edit.',
                        'No 256-cap candidate or zero-cap feature removal is promoted; source contains modulo and power-of-two assumptions.',
                        'Historical55 JAR/preopt is not a current59 workload baseline or total physical working-set denominator.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = run()
    result['analyzer_sha256'] = sha(Path(__file__).read_bytes())
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('single_cache_set_per_dex_request_bytes',
          'hypothetical_request_reduction_bytes', 'source_to_object_bytes_proven', 'physical_savings_proven')}))
