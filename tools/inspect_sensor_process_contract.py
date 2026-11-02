"""Offline, pinned ELF evidence for sensors.qti process and device paths."""
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
        raise ValueError('Unreviewed daemon')
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        def read(address, count):
            for section in elf.iter_sections():
                offset = address - section['sh_addr']
                if section['sh_type'] != 'SHT_NOBITS' and 0 <= offset and offset + count <= section['sh_size']:
                    return section.data()[offset:offset + count]
            raise ValueError('Address outside file-backed section')
        def resolved_string(literal, pc):
            address = (struct.unpack('<I', read(literal, 4))[0] + pc) & 0xffffffff
            return read(address, 150).split(b'\0')[0].decode('ascii')
        def instructions(address, size):
            return [[hex(i.address), i.mnemonic, i.op_str] for i in
                    Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(read(address, size), address)]
        reloc = elf.get_section_by_name('.rel.plt')
        symbols = elf.get_section(reloc['sh_link'])
        plt = elf.get_section_by_name('.plt')['sh_addr']
        imports = {plt + 32 + 16 * n: symbols.get_symbol(r['r_info_sym']).name
                   for n, r in enumerate(reloc.iter_relocations())}
        expected = {0x25a90:'getopt', 0x25aa0:'getppid', 0x25ab0:'puts',
                    0x25ac0:'fork', 0x25ae0:'setsid', 0x258f0:'__open_2', 0x25dd0:'ioctl'}
        if any(imports.get(a) != name for a, name in expected.items()):
            raise ValueError('Import binding changed')
        options = resolved_string(0x1f784, 0x1e9cc)
        background = resolved_string(0x1f788, 0x1ea2e)
        foreground = resolved_string(0x1f78c, 0x1ea38)
        device = resolved_string(0x22b08, 0x228ee)
        if (options, foreground, device) != ('d', 'Running in foreground...', '/dev/sensors'):
            raise ValueError('Process/device binding changed')
        return {'binary_sha256': PIN, 'method':'Pinned ELF imports, PC-relative literals and bounded Thumb instruction ranges',
                'getopt_options':options, 'background_message':background, 'foreground_message':foreground,
                'foreground_invocation':'/vendor/bin/sensors.qti (no arguments)',
                'lifetime_finding':'main compares getopt result with ASCII d. Non-d prints foreground messages and branches to 0x1eae0, reaching initialization at 0x1eb12. The d path can fork and setsid when parent is not PID1.',
                'device_path':device, 'device_open_flags':0, 'ioctl_request':'0x80046403',
                'device_finding':'The device open at 0x228ec stores its fd at object+0x3c; ioctl at 0x22096 loads an fd from that same field offset. Exact runtime object identity and successful execution are unproven.',
                'imports':{hex(a):n for a,n in expected.items()},
                'needed_libraries':[t.needed for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED'],
                'instruction_evidence':{'main_option_branch':instructions(0x1e9c4,0x18),'background_guard':instructions(0x1e9fe,8),'foreground_branch':instructions(0x1ea26,0x16),'fork_setsid':instructions(0x1ea3c,0x26),'common_init':instructions(0x1eae0,0x36),'device_open':instructions(0x228e2,0x12),'device_ioctl':instructions(0x22084,0x16)},
                'limits':['No daemon executed, no device or persistent data changed.', 'Static main foreground path does not prove dependencies never spawn descendants.', 'Read-only open flags do not prove ioctl has no side effects.', 'Dependent libraries and constructed paths are outside this bounded analysis; not a complete write-set.']}

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('binary',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=inspect(args.binary)
    with args.output.open('x',encoding='utf-8') as output:
        output.write(json.dumps(result,indent=2)+'\n')
