"""Emulate the pinned AEC caller with queue/free stubs, including immediate reclamation.

This validates the edited instruction path, not the real HAL or device behavior.
Requires pyelftools, keystone-engine and unicorn.
"""
import argparse
import io
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R4,
                              UC_ARM_REG_R6, UC_ARM_REG_SP, UC_ARM_REG_PC,
                              UC_ARM_REG_LR)
from prepare_camera_aec_message_lifetime import candidate, ADDRESS


def trial(blob, flag, result, reclaim):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(0, 0x100000)
    elf = ELFFile(io.BytesIO(blob))
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD':
            uc.mem_write(segment['p_vaddr'], segment.data())
    stack, message, queue = 0x20F000, 0x300000, 0x400000
    uc.mem_map(0x200000, 0x10000)
    uc.mem_map(message, 0x1000)
    uc.mem_write(message + 8, flag.to_bytes(4, 'little'))
    uc.mem_write(stack + 0x8C, message.to_bytes(4, 'little'))
    uc.reg_write(UC_ARM_REG_SP, stack)
    uc.reg_write(UC_ARM_REG_R4, message)
    uc.reg_write(UC_ARM_REG_R0, queue)
    calls, reached = [], []

    def hook(machine, address, size, data):
        if address == 0x80D90:
            assert machine.reg_read(UC_ARM_REG_R0) == queue
            assert machine.reg_read(UC_ARM_REG_R1) == message
            calls.append('enqueue')
            # Async ownership may already be consumed before the call returns.
            if reclaim and flag != 1:
                machine.mem_unmap(message, 0x1000)
            machine.reg_write(UC_ARM_REG_R0, result)
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif address == 0x80570:
            assert machine.reg_read(UC_ARM_REG_R0) == message
            calls.append('caller_free')
            machine.mem_unmap(message, 0x1000)
            machine.reg_write(UC_ARM_REG_PC, machine.reg_read(UC_ARM_REG_LR))
        elif address == 0x485FA:
            reached.append(True)
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    fault = None
    try:
        uc.emu_start(ADDRESS | 1, 0, count=100)
    except UcError as exc:
        fault = str(exc)
    return {'flag': flag, 'queue_result': result, 'reclaim': reclaim,
            'calls': calls, 'reached_join': bool(reached), 'fault': fault,
            'return_value': uc.reg_read(UC_ARM_REG_R6)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    original = args.source.read_bytes()
    patched = candidate(original)
    results = []
    for flag in (0, 1, 2):
        for result in (0, 1):
            for reclaim in (False, True):
                before = trial(original, flag, result, reclaim)
                after = trial(patched, flag, result, reclaim)
                assert after['fault'] is None and after['reached_join'], after
                assert after['return_value'] == result, after
                assert after['calls'] == ['enqueue'] + (['caller_free'] if flag == 1 else []), after
                if reclaim and flag != 1:
                    assert before['fault'] and not before['reached_join'], before
                else:
                    assert before == after, (before, after)
                results.append({'original': before, 'candidate': after})
    try:
        candidate(patched)
    except ValueError:
        pass
    else:
        raise AssertionError('Already-patched input accepted')
    print(json.dumps({'cases': results, 'already_patched_rejected': True,
                      'scope': 'Instruction-path emulation with stubbed queue/free only; no HAL or hardware success claim.'}, indent=2))


if __name__ == '__main__':
    main()
