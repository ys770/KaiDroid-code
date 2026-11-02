"""Execute vendor PBM accumulation and response-object packing offline."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC


def run(blob, sessions):
    elf = ELFFile(io.BytesIO(blob))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    end = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
    uc.mem_map(0, (end + 4095) & ~4095)
    for s in segments:
        uc.mem_write(s['p_vaddr'], s.data())
    base, stack = 0x30000000, 0x30010000
    uc.mem_map(base, 0x20000)
    uc.reg_write(UC_ARM_REG_SP, stack)
    uc.reg_write(UC_ARM_REG_C1_C0_2, 0xf << 20)
    uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    symbols = elf.get_section_by_name('.dynsym')
    for relocation in elf.get_section_by_name('.rel.dyn').iter_relocations():
        if relocation['r_info_sym'] and symbols.get_symbol(relocation['r_info_sym']).name == '__stack_chk_guard':
            uc.mem_write(relocation['r_offset'], struct.pack('<I', base + 0x100))
    uc.mem_write(base + 0x100, struct.pack('<I', 0x12345678))
    lookups = []

    def hook(machine, address, size, unused):
        if address == 0x4c3f60:
            index = machine.reg_read(UC_ARM_REG_R1)
            if index >= len(sessions):
                raise ValueError('Unexpected session lookup')
            lookups.append(index)
            machine.reg_write(UC_ARM_REG_R0, base + 0x1000 + index * 40)
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif not any(lo <= address < hi for lo, hi in
                     [(0x4c33cc, 0x4c3512), (0x4c3c7a, 0x4c3ce8), (0x4c4f5c, 0x4c4ffa)]):
            raise ValueError('Unexpected execution ' + hex(address))

    uc.hook_add(UC_HOOK_CODE, hook)
    for index, row in enumerate(sessions):
        uc.mem_write(base + 0x1000 + index * 40, struct.pack('<10I', *row))
        uc.mem_write(stack + 0x240, struct.pack('<I', index))
        uc.emu_start(0x4c33cd, 0x4c3512, count=2000)
        if uc.reg_read(UC_ARM_REG_PC) != 0x4c3512:
            raise ValueError('Accumulation did not finish')
    expected = [sum(row[i] for row in sessions) & 0xffffffff for i in range(6)]
    expected += [max((row[i] for row in sessions), default=0) for i in range(6, 10)]
    actual = list(struct.unpack('<10I', uc.mem_read(stack + 0x2a4, 40)))
    if actual != expected:
        raise ValueError('Aggregation mismatch')
    # Execute the real caller and setter, preserving their AAPCS argument transfer.
    obj = base + 0x4000
    uc.reg_write(UC_ARM_REG_R0, obj)
    uc.emu_start(0x4c3c7b, 0x4c3ce8, count=2000)
    if uc.reg_read(UC_ARM_REG_PC) != 0x4c3ce8:
        raise ValueError('Response packing did not finish')
    packed = list(struct.unpack('<10I', uc.mem_read(obj + 4, 40)))
    if packed != actual or bytes(uc.mem_read(obj, 1)) != b'\x01':
        raise ValueError('Response object mismatch')
    return {'sessions': sessions, 'aggregated_words': actual,
            'response_object_words': packed, 'vector_lookup_count': len(lookups)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    blob = Path('work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != '47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd':
        raise ValueError('Unexpected library')
    fixtures = [[], [[100, 20, 50, 10, 40, 5, 14, 40, 60, 30]],
                [[100, 20, 50, 10, 40, 5, 14, 40, 60, 30],
                 [200, 30, 60, 20, 80, 15, 20, 30, 70, 20]],
                [[200, 30, 60, 20, 80, 15, 20, 30, 70, 20],
                 [100, 20, 50, 10, 40, 5, 14, 40, 60, 30]]]
    report = {'library_sha256': digest, 'passed': True,
              'cases': [run(blob, rows) for rows in fixtures],
              'limits': ['Vector lookup and initial zero accumulators modeled',
                         'Session discovery, modem queries and live subscription scope not tested',
                         'Length units and signed-negative behavior not established',
                         'Zero-session fixture does not prove live zero-session path is reachable']}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS: count sums, length maxima, caller arguments and response object packing')


if __name__ == '__main__':
    main()
