"""Inspect the pinned Nokia sensor daemon's pre-SMGR initialization table offline."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

PIN = '1992f0cf34bb5bb1902e3502bcee58b6acc915f2a0281c9fdd65ddc5badc8d25'


def inspect(path):
    if hashlib.sha256(path.read_bytes()).hexdigest() != PIN:
        raise ValueError('Unreviewed sensor daemon')
    with path.open('rb') as stream:
        elf = ELFFile(stream)

        def read(address, count):
            for section in elf.iter_sections():
                offset = address - section['sh_addr']
                if section['sh_type'] != 'SHT_NOBITS' and 0 <= offset and offset + count <= section['sh_size']:
                    return section.data()[offset:offset + count]
            raise ValueError('Address outside file-backed sections')

        def word(address):
            return struct.unpack('<I', read(address, 4))[0]

        def instructions(address, size):
            return [(hex(i.address), i.mnemonic, i.op_str) for i in
                    Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(read(address, size), address)]

        callback = (word(0x1e53c) + 0x1e4aa) & 0xffffffff
        table = (word(0x1e87c) + 0x1e5f2) & 0xffffffff
        if callback != 0x1e551 or table != 0x289ac:
            raise ValueError('Initialization binding differs')
        reloc = elf.get_section_by_name('.rel.plt')
        symbols = elf.get_section(reloc['sh_link'])
        plt = elf.get_section_by_name('.plt')['sh_addr']
        imports = {plt + 32 + 16 * n: symbols.get_symbol(r['r_info_sym']).name
                   for n, r in enumerate(reloc.iter_relocations())}
        if imports.get(0x259d0) != 'pthread_once' or imports.get(0x25a40) != 'sem_wait':
            raise ValueError('Initialization imports differ')
        entries = []
        for index in range(6):
            function, name = struct.unpack('<II', read(table + index * 8, 8))
            entries.append({'index': index, 'function': hex(function),
                            'name': read(name, 80).split(b'\0')[0].decode('ascii')})
        worker_slot = (word(0x1cb38) + 0x1caae) & 0xffffffff
        worker = word(worker_slot)
        service_header = struct.unpack('<4I', read(0x2691c, 16))
        if worker_slot != 0x291d8 or worker != 0x1c051 or service_header[:3] != (6, 2, 271):
            raise ValueError('Registry worker/service binding differs')
        if imports.get(0x257f0) != 'qmi_csi_register' or imports.get(0x25bc0) != 'pthread_create':
            raise ValueError('Registry server/thread imports differ')
        path_table = (word(0x21910) + 0x2154a) & 0xffffffff
        paths = [read(word(path_table + 4 * n), 120).split(b'\0')[0].decode('ascii')
                 for n in range(2)]
        create_mode = read((word(0x21938) + 0x215f6) & 0xffffffff, 8).split(b'\0')[0].decode()
        existing_mode = read((word(0x2191c) + 0x21672) & 0xffffffff, 8).split(b'\0')[0].decode()
        if (create_mode, existing_mode) != ('w+', 'r+'):
            raise ValueError('Registry file modes differ')
        return {
            'binary_sha256': PIN, 'method': 'Pinned ELF Thumb disassembly and PC-relative table resolution',
            'pthread_once_callback': hex(callback), 'initialization_table': hex(table),
            'entries': entries,
            'registry_file_operations': {
                'binary_sha256': PIN,
                'path_candidates': paths,
                'create_or_empty_file_mode': create_mode,
                'existing_nonempty_file_mode': existing_mode,
                'chmod_mode_octal': '0700',
                'finding': 'Registry startup is not read-only. The failed-stat or zero-length branch supplies w+; the nonempty branch supplies r+. The open wrapper reaches fopen after canonical-path checks, including an ENOENT branch.',
                'writes': 'Registry write helper calls fwrite; an optional flush path calls fflush then fdatasync.',
                'instruction_evidence': {
                    'stat_result_branch': instructions(0x21584, 10),
                    'create_open': instructions(0x215ee, 24),
                    'nonempty_branch': instructions(0x21662, 28),
                    'fopen': instructions(0x1dd6e, 20),
                    'chmod': instructions(0x21258, 22),
                    'write_helper': instructions(0x1e020, 8),
                    'flush_helper': instructions(0x1de64, 38),
                },
                'limits': ['Static paths do not establish successful execution on the current image.',
                           'No complete write-set or firmware-consumption proof; do not treat stop-service as filesystem rollback.',
                           'No live daemon execution or persistent data modification.'],
            },
            'registry': {
                'initializer': '0x1ca31', 'server_setup': '0x1b910',
                'service_object': 'SNS_REG2_SVC_qmi_idl_service_object_v02',
                'service_header_words': list(service_header), 'service_id': '0x10f',
                'worker_pointer_slot': hex(worker_slot), 'worker': hex(worker),
                'thread_wrapper': '0x1fa8c',
                'worker_initial_helper': '0x21520',
                'registry_path_candidates': paths,
                'path_selection': 'Two candidates passed to helper0x1e1b4, which uses dirname/realpath; selected path is copied before stat. Failure branches require further tracing.',
                'interpretation': 'Registry service registration precedes worker creation on the successful initialization path; it is distinct from SMGR service0x100.',
                'instruction_evidence': {
                    'initializer_server_call': instructions(0x1ca3e, 6),
                    'registry_getter_args': instructions(0x1b928, 10),
                    'server_registration': instructions(0x1b960, 8),
                    'worker_argument': instructions(0x1caa0, 20),
                    'pthread_create_args': instructions(0x1fab8, 12),
                    'worker_helper_call': instructions(0x1c0ba, 6),
                    'candidate_selection': instructions(0x2154c, 20),
                    'selected_path_copy': instructions(0x21560, 22),
                },
            },
            'instruction_evidence': {
                'main_before_smgr': instructions(0x1eb12, 4),
                'once_call': instructions(0x1e4a2, 16),
                'indirect_initializer': instructions(0x1e650, 12),
                'completion_wait': instructions(0x1e6bc, 6),
                'six_entry_loop': instructions(0x1e71a, 12),
            },
            'finding': 'A six-component initialization loop including sns_reg_init precedes the main SMGR discovery phase.',
            'limits': ['Static ordering does not prove successful runtime initialization.',
                       'Registry initializer thread bodies, file writes and firmware dependency remain to trace.',
                       'No daemon start, device operation, registry write or fitted sensor claim.'],
        }


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inspect(args.binary)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(result, indent=2) + '\n')
