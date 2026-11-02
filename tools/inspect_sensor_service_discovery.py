"""Inspect pinned captured sensor libraries and router listing; no device operations."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB


def inspect(root):
    pins = {
        'libsensor1.so': 'c5f72f5eadea6d344253fef4d55e73960fd8b7da7ce3ace9eae048084e954588',
        'libqmi_encdec.so': '77047d604a94e936cd2005fd650d8ea7c81c797eeb52dc4cc2de927c43159f80',
    }
    for name, pin in pins.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != pin:
            raise ValueError('Unreviewed library: ' + name)
    with (root / 'libsensor1.so').open('rb') as f:
        elf = ELFFile(f)
        symbols = {s.name: s for s in elf.get_section_by_name('.dynsym').iter_symbols()}
        def data(symbol, count):
            section = elf.get_section(symbol['st_shndx'])
            offset = symbol['st_value'] - section['sh_addr']
            return section.data()[offset:offset + count]
        table = symbols['svc_map']
        entry = struct.unpack('<4I', data(table, 16))
        targets = []
        for section in elf.iter_sections():
            if section['sh_type'] == 'SHT_REL':
                for relocation in section.iter_relocations():
                    if relocation['r_offset'] == table['st_value']:
                        targets.append(elf.get_section(section['sh_link']).get_symbol(relocation['r_info_sym']).name)
        if targets != ['SNS_SMGR_SVC_get_service_object_internal_v01'] or entry[1:] != (1, 27, 6):
            raise ValueError('Internal service zero mapping differs')
        obj = symbols['SNS_SMGR_SVC_qmi_idl_service_object_v01']
        header = struct.unpack('<4I', data(obj, 16))
        if header[:3] != (6, 1, 256):
            raise ValueError('SMGR service object differs')
    with (root / 'libqmi_encdec.so').open('rb') as f:
        elf = ELFFile(f)
        getter = next(s for s in elf.get_section_by_name('.dynsym').iter_symbols()
                      if s.name == 'qmi_idl_get_service_id')
        section = elf.get_section(getter['st_shndx'])
        address = getter['st_value'] & ~1
        offset = address - section['sh_addr']
        instructions = [(hex(i.address), i.mnemonic, i.op_str) for i in
                        Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(section.data()[offset:offset + getter['st_size']], address)]
        if ('0x2082', 'ldr', 'r0, [r2, #8]') not in instructions:
            raise ValueError('Service ID field offset not established')
    listing = (root / 'ipc-servers02.txt').read_text()
    rows = [tuple(int(v, 16) for v in values) for values in re.findall(
        r'^(0x[0-9a-f]+)\s*\|(0x[0-9a-f]+)\s*\|(0x[0-9a-f]+)\s*\|(0x[0-9a-f]+)\s*\|', listing, re.M)]
    if not rows:
        raise ValueError('Missing router service rows')
    return dict(library_hashes=pins, internal_service_index=0, getter=targets[0],
                service_object_address=hex(obj['st_value']), qmi_service_id=header[2],
                qmi_getter_instructions=instructions, router_service_rows=len(rows),
                matching_advertisements=[row for row in rows if row[0] == header[2]],
                router_listing_sha256=hashlib.sha256((root / 'ipc-servers02.txt').read_bytes()).hexdigest(),
                limits=['Snapshot of advertised services, not a transport trace or proof of fitted sensors.',
                        'Does not prove why the SMGR backend is absent or whether stock enumerates sensors.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.capture)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print(json.dumps(result))
