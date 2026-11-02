"""Future offline paired ELF/interface check; no linker, installer or target execution."""
import argparse
from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import zlib

sys.dont_write_bytecode = True
from elftools.elf.elffile import ELFFile
from audit_libart_surface54 import surface, compare, brief
from audit_services_phase_link_providers01 import sha

BASE = {'55': 'cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62',
        '56': '5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258'}
COUNTER = '_ZZN3art12_GLOBAL__N_119NextServicesPhaseIdEvE4next'
MARKER = b'KV_SERVICES_PHASE_V1 source=services55-oat125818a8\0'


def debuglink(raw, unstripped):
    elf = ELFFile(BytesIO(raw))
    section = elf.get_section_by_name('.gnu_debuglink')
    if section is None:
        raise ValueError('Missing GNU debuglink')
    data = section.data()
    zero = data.find(b'\0')
    if zero < 0 or data[:zero].decode('utf-8') != 'libart.so':
        raise ValueError('GNU debuglink filename differs')
    offset = (zero + 4) & ~3
    if len(data) != offset + 4:
        raise ValueError('GNU debuglink extent differs')
    crc = 0
    with unstripped.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            crc = zlib.crc32(block, crc)
    if struct.unpack_from('<I', data, offset)[0] != crc:
        raise ValueError('GNU debuglink CRC does not bind actual unstripped file')
    return dict(filename='libart.so', crc32=crc)


def build_id(raw):
    elf = ELFFile(BytesIO(raw))
    note = elf.get_section_by_name('.note.gnu.build-id')
    if note is None:
        raise ValueError('Missing build ID')
    return note.data().hex()


def allocated(raw):
    result = {}
    for section in ELFFile(BytesIO(raw)).iter_sections():
        if not section['sh_flags'] & 2:
            continue
        if section.name in result:
            raise ValueError('Duplicate allocated section name')
        result[section.name] = (section['sh_type'], section['sh_flags'], section['sh_addr'], section['sh_size'],
                               None if section['sh_type'] == 'SHT_NOBITS' else __import__('hashlib').sha256(section.data()).hexdigest())
    return result


def check(role, baseline, candidate, unstripped, candidate_pin, unstripped_pin):
    if role not in ('55-off', '55-on', '56-off', '56-on'):
        raise ValueError('Exact matrix role required')
    if sha(baseline) != BASE[role[:2]] or sha(candidate) != candidate_pin or sha(unstripped) != unstripped_pin:
        raise ValueError('Baseline or transferred candidate hash differs')
    before, after = baseline.read_bytes(), candidate.read_bytes()
    full = unstripped.read_bytes()
    after_surface = surface(after)
    failures = compare(surface(before), after_surface)
    failures += ['stripped/unstripped ' + value for value in compare(surface(full), after_surface)]
    if allocated(after) != allocated(full):
        failures.append('strip changed allocated section bytes/address/size/flags')
    if build_id(after) != build_id(full):
        failures.append('stripped/unstripped build IDs differ')
    link = debuglink(after, unstripped)
    full_elf = ELFFile(BytesIO(full))
    stripped_elf = ELFFile(BytesIO(after))
    if stripped_elf.get_section_by_name('.symtab') is None:
        failures.append('selected strip mode lost regular symbols')
    before_frame = full_elf.get_section_by_name('.debug_frame')
    after_frame = stripped_elf.get_section_by_name('.debug_frame')
    if (before_frame is None) != (after_frame is None) or (before_frame is not None and before_frame.data() != after_frame.data()):
        failures.append('selected strip mode changed/lost debug_frame')
    symbols = full_elf.get_section_by_name('.symtab')
    if symbols is None:
        raise ValueError('Unstripped symbol inventory missing')
    counters = [symbol for symbol in symbols.iter_symbols() if symbol.name.startswith(COUNTER)]
    enabled = role.endswith('-on')
    if bool(MARKER in after) != enabled or bool(counters) != enabled:
        failures.append('diagnostic flag/marker/counter mismatch')
    if enabled and (len(counters) != 1 or any(symbol['st_info']['bind'] != 'STB_LOCAL' or symbol['st_info']['type'] != 'STT_OBJECT' or symbol['st_size'] != 4 for symbol in counters)):
        failures.append('counter is not exactly one private four-byte object')
    if enabled:
        for symbol in counters:
            if not isinstance(symbol['st_shndx'], int):
                failures.append('counter lacks a concrete section')
                continue
            section = full_elf.get_section(symbol['st_shndx'])
            if section['sh_type'] != 'SHT_NOBITS' or section['sh_flags'] & 3 != 3 or symbol['st_value'] % 4:
                failures.append('counter is not aligned writable allocated BSS')
    if enabled and before == after:
        failures.append('enabled candidate identical to accepted baseline')
    return dict(classification='linked_ELF_interface_screen_only', role=role,
                candidate_sha256=candidate_pin, unstripped_sha256=unstripped_pin,
                baseline_sha256=BASE[role[:2]], debuglink=link,
                interface_screen_pass=not failures, failures=failures,
                surface=brief(after_surface), full_ABI_proven=False, code_scope_proven=False,
                relocation_unwind_review_complete=False, installed=False, runtime_accepted=False,
                savings_proven=False, analyzer_sha256=sha(Path(__file__)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', required=True)
    for name in ('baseline', 'candidate', 'unstripped', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--unstripped-sha256', required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    result = check(args.role, args.baseline, args.candidate, args.unstripped,
                   args.candidate_sha256, args.unstripped_sha256)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    if not result['interface_screen_pass']:
        raise SystemExit(1)
