"""Bind PBM count fields to original vendor diagnostic labels offline.

Executes bounded original ARM blocks with synthetic stack markers; no modem IO.
Does not establish length units, card scope, or validity of live capacities.
"""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R2, UC_ARM_REG_LR, UC_ARM_REG_PC


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    blob = Path('work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so').read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != '47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd':
        raise ValueError('Unexpected library')
    elf = ELFFile(io.BytesIO(blob))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    labels = [
        (0x4c2170, 0x4c21c6, 0, ['max records', 'valid records']),
        (0x4c239a, 0x4c2400, 2, ['max email', 'valid email', 'max ad number', 'valid ad number']),
        (0x4c2542, 0x4c25a8, 6, ['max name len', 'max number len', 'max email len', 'max anr len']),
    ]
    results = []
    for start, stop, first, names in labels + [(0x4c28c6, 0x4c28ee, 0, [])]:
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        end = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
        uc.mem_map(0, (end + 4095) & ~4095)
        for segment in segments:
            uc.mem_write(segment['p_vaddr'], segment.data())
        stack = 0x30001000
        uc.mem_map(0x30000000, 0x10000)
        uc.reg_write(UC_ARM_REG_SP, stack)
        for index in range(10):
            uc.mem_write(stack + 0x340 - index * 4, struct.pack('<I', 101 + index))
        captured = []

        def hook(machine, address, size, unused):
            if address == 0xfd5340:  # model TLS address helper, irrelevant metadata only
                machine.reg_write(UC_ARM_REG_R0, 0x30000000)
                machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
            elif address == 0xfd5370:  # capture snprintf arguments, do not format private data
                ptr = machine.reg_read(UC_ARM_REG_R2)
                fmt = bytes(machine.mem_read(ptr, 256)).split(b'\0', 1)[0].decode('ascii')
                expected_suffix = ', '.join(name + ': %d' for name in names)
                if not fmt.endswith(expected_suffix):
                    raise ValueError('Unexpected diagnostic label: ' + fmt)
                values = list(struct.unpack('<' + 'I' * len(names), machine.mem_read(stack + 0x10, 4 * len(names))))
                if values != list(range(101 + first, 101 + first + len(names))):
                    raise ValueError('Label-to-value mapping changed')
                captured.append({'format': fmt, 'synthetic_values': values})
                machine.emu_stop()
            elif not start <= address < stop:
                raise ValueError('Unexpected executed address ' + hex(address))

        uc.hook_add(UC_HOOK_CODE, hook)
        uc.emu_start(start | 1, stop, count=1000)
        if names:
            if len(captured) != 1:
                raise ValueError('Missing diagnostic call')
            results.append({'start': hex(start), 'fields': names, **captured[0]})
        else:
            values = list(struct.unpack('<10I', uc.mem_read(stack + 0x368, 40)))
            if values != list(range(101, 111)) or uc.reg_read(UC_ARM_REG_PC) != stop:
                raise ValueError('Per-session structure packing mismatch')
    report = {
        'library_sha256': digest, 'passed': True,
        'labels': results, 'per_session_structure_words': values,
        'field_order': [name for row in labels for name in row[3]],
        'limits': ['Synthetic markers, not measured SIM capacities',
                   'Only diagnostic argument blocks and per-session packing executed',
                   'Aggregation, response wiring and length units not established by this harness',
                   'TLS helper modeled; modem and Android transport not executed'],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS: ten diagnostic labels bound to per-session structure fields')


if __name__ == '__main__':
    main()
