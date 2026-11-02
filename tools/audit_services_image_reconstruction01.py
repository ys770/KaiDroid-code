"""Offline pinned services image layout and cached ART source provenance audit."""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
RAW_SHA = 'c3e9e8e5cf4af03aa053c98c509b2cbec6375e8bf6632bb7b0b57fa171894d88'
PINS = {
    'services.art': '06367ceca49dfd29ee2732a62b217f42399c04a631c07cb2a63226f822f17ff4',
    'services.odex': '7ccc2039785860155f161ba8a8583adf50ee64c8364553f3718c8d3774b1b608',
    'services.vdex': '55d079cc405a9eff0a8ec066af3f740dc4e3277ecaeebfde627a4c4eefd27035',
}
SECTIONS = ['Objects', 'ArtFields', 'ArtMethods', 'RuntimeMethods', 'ImTables',
            'IMTConflictTables', 'DexCacheArrays', 'InternedStrings', 'ClassTable',
            'StringReferenceOffsets', 'Metadata', 'ImageBitmap']


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(extfs_path):
    sys.path.insert(0, str(extfs_path.resolve()))
    from dissect.extfs import ExtFS
    raw = ROOT / 'work/engineering-system-55.raw.img'
    if sha(raw) != RAW_SHA:
        raise ValueError('Exact image 55 raw required')
    receipt_path = ROOT / 'work/memory/libart-compile03/compile-record.json'
    receipt = json.loads(receipt_path.read_text())
    records = []
    sources = [
        ('manager_original', 'work/memory/madvise-random01/source/art/runtime/oat_file_manager.cc', receipt['read_inputs']['/opt/kaidroid/kaidroid-build-20261023/aosp/art/runtime/oat_file_manager.cc'], 'compiled_manager_source_receipt'),
        ('manager_candidate', 'work/memory/services-image55-host02/apply/art/runtime/oat_file_manager.cc', receipt['candidate'], 'compiled_manager_candidate_receipt'),
        ('image_header', 'work/memory/oat-native-paging01/source/art/runtime/image.h', receipt['read_inputs']['/opt/kaidroid/kaidroid-build-20261023/aosp/art/runtime/image.h'], 'compiled_manager_header_receipt'),
        ('class_linker', 'work/memory/madvise-random01/source/art/runtime/class_linker.cc', '835d72cf5b25e4281bd4fb3efe6e19514888813a3b1c93c0b239f63d52f19729', 'cached_source_only_no_compiled_TU_receipt'),
        ('oat_file_assistant', 'work/memory/oat-native-paging01/source/art/runtime/oat_file_assistant.cc', None, 'newly_hashed_cached_source_only_no_compiled_TU_receipt'),
    ]
    for name, relative, pin, binding in sources:
        value = sha(ROOT / relative)
        if pin is not None and value != pin:
            raise ValueError('Source differs: ' + relative)
        records.append(dict(name=name, path=relative, sha256=value, binding=binding))
    blobs = {}
    with raw.open('rb') as stream:
        fs = ExtFS(stream)
        for name, pin in PINS.items():
            data = fs.get('/system/framework/oat/arm/' + name).open().read()
            if hashlib.sha256(data).hexdigest() != pin:
                raise ValueError('Preopt revision differs: ' + name)
            blobs[name] = data
        lib = fs.get('/system/apex/com.android.art.release/lib/libart.so').open().read()
        old_lib_sha = hashlib.sha256(lib).hexdigest()
        if old_lib_sha != 'cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62':
            raise ValueError('Baseline ART binary differs')
    candidate = ROOT / 'work/memory/libart-compile03/stripped.bin'
    new_lib_sha = sha(candidate)
    if new_lib_sha != '5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258':
        raise ValueError('Candidate ART binary differs')
    oat = blobs['services.odex']
    oat_offset = 4096
    if oat[oat_offset:oat_offset + 8] != b'oat\n183\0' or struct.unpack_from('<I', oat, oat_offset + 8)[0] != 307763368:
        raise ValueError('Accepted embedded OAT header differs')
    data = blobs['services.art']
    if data[:8] != b'art\n085\0':
        raise ValueError('Reviewed ART image version 085 required')
    fields = struct.unpack_from('<16I', data, 8)
    reservation, components, begin, size, checksum, oat_checksum = fields[:6]
    if components != 1 or fields[-1] != 4 or oat_checksum != 307763368:
        raise ValueError('App image / ARM32 / accepted OAT checksum differs')
    sections = [dict(name=name, offset=offset, bytes=length,
                     address_domain='file_bitmap' if name == 'ImageBitmap' else 'uncompressed_image')
                for i, name in enumerate(SECTIONS)
                for offset, length in [struct.unpack_from('<II', data, 72 + i * 8)]]
    ordinary = sorted(sections[:-1], key=lambda row: row['offset'])
    end = 0
    gaps = []
    for row in ordinary:
        if row['offset'] < end or row['offset'] + row['bytes'] > size:
            raise ValueError('Image sections overlap or exceed image')
        if row['offset'] > end:
            gaps.append(dict(offset=end, bytes=row['offset'] - end))
        end = row['offset'] + row['bytes']
    if end != size:
        raise ValueError('Final image section does not reach declared image size')
    data_size, blocks_offset, blocks_count = struct.unpack_from('<III', data, 240)
    if blocks_count != 1 or blocks_offset + blocks_count * 20 > len(data):
        raise ValueError('Reviewed single compression block layout required')
    mode, file_offset, compressed, image_offset, expanded = struct.unpack_from('<5I', data, blocks_offset)
    bitmap = sections[-1]
    if mode != 1 or image_offset != 256 or expanded + image_offset != size or file_offset + compressed > len(data) or bitmap['offset'] + bitmap['bytes'] > len(data):
        raise ValueError('Compression block / bitmap bounds differ')
    section_bytes = sum(row['bytes'] for row in ordinary)
    if section_bytes + sum(row['bytes'] for row in gaps) != size:
        raise ValueError('Layout bytes do not reconcile')
    return dict(
        classification='offline_layout_and_source_audit_only', raw_sha256=RAW_SHA,
        compile_record_sha256=sha(receipt_path), sources=records,
        binaries=dict(baseline_libart_sha256=old_lib_sha, candidate_libart_sha256=new_lib_sha,
                      services_oat_header_file_offset=oat_offset, services_oat_version='183',
                      services_oat_checksum=307763368,
                      services_oat_manager_gate_size=12699918,
                      services_oat_manager_gate_executable_offset=2895872,
                      gate_fields_are_not_whole_ELF_file_length=True),
        preopt={name: dict(sha256=PINS[name], file_bytes=len(value)) for name, value in blobs.items()},
        image=dict(version='085', pointer_bytes=4, header_bytes=256, image_begin=begin,
                   image_bytes=size, reservation_bytes=reservation, image_checksum=checksum,
                   oat_checksum=oat_checksum, sections=sections, unassigned_gaps=gaps,
                   nonbitmap_section_bytes=section_bytes, data_size_field=data_size,
                   compression=dict(mode='LZ4', file_offset=file_offset, file_bytes=compressed,
                                    image_offset=image_offset, expanded_bytes=expanded)),
        objects_walked=False, live_objects_counted=False, reconstructed_bytes_measured=False,
        cached_translation_units_proven_to_match_compiled_binary=False,
        savings_proven=False, ready_for_build=False,
        limits=['Header/layout bytes are not RSS, PSS, live heap, or replacement allocation cost.',
                'Objects section includes header/padding; serialized table capacity is not a count of live entries.',
                'Bitmap file offsets and expanded-image offsets occupy different address domains.',
                'No image objects decompressed or dereferenced; no unsupported object-layout assumptions.',
                'Only manager source/candidate and image header are bound by compile03 receipts; cached other translation units remain unproven.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extfs-path', type=Path, default=ROOT / 'work/kyocera-extfs-python')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = run(args.extfs_path)
    result['analyzer_sha256'] = sha(Path(__file__))
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(classification=result['classification'], image_bytes=result['image']['image_bytes'], savings_proven=False)))
