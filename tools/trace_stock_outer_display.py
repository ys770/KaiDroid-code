"""Read-only, exact-image outer-display call/relocation audit (pyelftools/capstone)."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

EXPECTED = '26e8ce99d1218a79488e24aba80abf4eb1e726e38a2244d5ace3214df7b58a29'


def inspect(path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != EXPECTED:
        raise ValueError('Unrecognized stock libxul; no address reuse permitted')
    with path.open('rb') as stream:
        elf = ELFFile(stream)

        def read(address, length):
            for segment in elf.iter_segments():
                if (segment['p_type'] == 'PT_LOAD' and
                        segment['p_vaddr'] <= address and
                        address + length <= segment['p_vaddr'] + segment['p_filesz']):
                    stream.seek(segment['p_offset'] + address - segment['p_vaddr'])
                    return stream.read(length)
            raise ValueError(f'Unmapped VA {address:x}')

        references = []
        for literal, pc in [(0x37c37e4, 0x37c350e), (0x37c37ec, 0x37c352e),
                            (0x37c37f0, 0x37c3530), (0x37c3f50, 0x37c3ece),
                            (0x37c29d0, 0x37c2996)]:
            address = struct.unpack('<i', read(literal, 4))[0] + pc
            references.append(dict(literal=hex(literal), pc=hex(pc),
                                   address=hex(address),
                                   text=read(address, 180).split(b'\0')[0].decode('ascii')))
        imports = []
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        decoder.detail = True
        relocations = {r['r_offset']: r for r in elf.get_section_by_name('.rel.plt').iter_relocations()}
        for veneer, expected in [(0x317e4d8, 'ioctl'), (0x317e664, 'open'),
                                 (0x3180e50, 'property_get'), (0x317e834, 'mmap'),
                                 (0x317e25c, 'fsync')]:
            instructions = list(decoder.disasm(read(veneer, 12), veneer))
            if veneer == 0x317e834:
                arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                arm.detail = True
                branch = list(arm.disasm(read(veneer, 4), veneer))[0]
                if branch.mnemonic != 'b':
                    raise ValueError('Unexpected ARM veneer')
                target = branch.operands[0].imm
            else:
                if [i.mnemonic for i in instructions] != ['movw', 'movt', 'add', 'bx']:
                    raise ValueError('Unexpected veneer')
                offset = instructions[0].operands[1].imm | instructions[1].operands[1].imm << 16
                target = instructions[2].address + 4 + offset
            words = struct.unpack('<III', read(target, 12))
            if words[0] & 0xfffff000 != 0xe28fc000 or words[1] & 0xfffff000 != 0xe28cc000 or words[2] & 0xfffff000 != 0xe5bcf000:
                raise ValueError('Unexpected ARM PLT instructions')

            def immediate(word):
                value, shift = word & 255, ((word >> 8) & 15) * 2
                return ((value >> shift) | (value << ((32 - shift) % 32))) & 0xffffffff

            got = target + 8 + immediate(words[0]) + immediate(words[1]) + (words[2] & 0xfff)
            relocation = relocations[got]
            name = elf.get_section_by_name('.dynsym').get_symbol(relocation['r_info_sym']).name
            if name != expected:
                raise ValueError(f'Unexpected import {name}')
            imports.append(dict(veneer=hex(veneer), plt=hex(target), got=hex(got),
                                symbol=name, relocation_type=relocation['r_info_type']))
        path_table = struct.unpack('<i', read(0x37c37e8, 4))[0] + 0x37c3526
        paths = [read(p, 80).split(b'\0')[0].decode('ascii')
                 for p in struct.unpack('<II', read(path_table, 8))]
        anchors = []
        for start, size, meaning in [
                (0x37c3606, 40, 'Read framebuffer fixed and variable info into external object'),
                (0x37c36ac, 12, 'Write adjusted variable info'),
                (0x37c38ec, 78, 'Compute page-rounded mapping size and mmap external fd'),
                (0x37c3972, 38, 'Pass external dimensions and object to CreateFramebufferSurface'),
                (0x37c424e, 28, 'DisplayType 1 chooses separate native window and queue callback'),
                (0x37c4ef8, 46, 'Consumer obtains external object, locks it and requests source buffer access'),
                (0x37c4fa0, 68, 'Conditional conversion or bulk-copy path then fsync and ioctl 0x4601'),
                (0x37c51d4, 66, 'Eight-pixel vector conversion of four interleaved channels into packed RGB565')]:
            anchors.append(dict(address=hex(start), byte_count=size, interpretation=meaning,
                                sha256=hashlib.sha256(read(start, size)).hexdigest(),
                                instructions=[f'{i.address:x}: {i.mnemonic} {i.op_str}'
                                              for i in decoder.disasm(read(start, size), start)]))
        return dict(source_sha256=digest, provenance='retail stock B2G libxul; not current Android runtime',
                    references=references, resolved_imports=imports,
                    external_device_path_formats=paths, instruction_anchors=anchors,
                    switch_screen_request=hex(struct.unpack('<I', read(0x37c29c0, 4))[0]),
                    consumer_tables={
                        'surface_vtable': hex(struct.unpack('<i', read(0x37c344c, 4))[0] + 0x37c331a + 12),
                        'surface_callback_entry': hex(struct.unpack('<I', read(0x5161c98, 4))[0]),
                        'task_run_entry': hex(struct.unpack('<I', read(0x516201c, 4))[0])},
                    limitations=['Static call targets only; no ioctl executed',
                                 'Full switch command semantics and current-kernel compatibility remain unresolved',
                                 'Non-conversion copy helper and source-buffer lock wrapper not fully resolved'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('library', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = inspect(args.library)
    with args.output.open('x', encoding='utf-8') as out:
        json.dump(result, out, indent=2)
        out.write('\n')
