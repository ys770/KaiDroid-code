"""Execute the original/edited count arithmetic; not a HAL pipeline simulation."""
import argparse
import io
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_PC, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R9
from prepare_camera_picture_buffers import candidate


def count(blob, mode_word, extra_flag):
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.mem_map(0, 0x200000)
    for s in ELFFile(io.BytesIO(blob)).iter_segments():
        if s['p_type'] == 'PT_LOAD':
            uc.mem_write(s['p_vaddr'], s.data())
    uc.mem_map(0x300000, 0x20000)
    stack, obj = 0x301000, 0x310000
    uc.reg_write(UC_ARM_REG_SP, stack)
    uc.mem_write(stack + 0x2C0, obj.to_bytes(4, 'little'))
    uc.mem_write(obj + 0x15C, mode_word.to_bytes(4, 'little'))
    uc.mem_write(stack + 0x294, extra_flag.to_bytes(4, 'little'))
    reached = []

    def hook(machine, address, size, data):
        # Skip unrelated allocation/pointer setup. Test the actual count
        # selection and extra-buffer decision only, with synthetic inputs.
        if address == 0x85800:
            machine.reg_write(UC_ARM_REG_PC, 0x85822 | 1)
        elif address == 0x85826:
            machine.reg_write(UC_ARM_REG_R5, mode_word)
            machine.reg_write(UC_ARM_REG_PC, 0x8585C | 1)
        elif address == 0x8586C:
            reached.append(True)
            machine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(0x857F2 | 1, 0x8586C, count=100)
    # End address may stop before the hook; either path must reach the same PC.
    if uc.reg_read(UC_ARM_REG_PC) != 0x8586C:
        raise AssertionError('Count path did not reach expected join')
    return {'base': uc.reg_read(UC_ARM_REG_R4), 'count': uc.reg_read(UC_ARM_REG_R9)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = args.source.read_bytes()
    patched = candidate(original)
    rows = []
    for mode in (0, 1, 2):
        for flag in (0, 1):
            before, after = count(original, mode, flag), count(patched, mode, flag)
            base_before, base_after = (6, 3) if mode == 1 else (4, 4)
            assert before == {'base': base_before, 'count': base_before + 3 * flag}
            assert after == {'base': base_after, 'count': base_after + 3 * flag}
            rows.append({'mode_word': mode, 'extra_flag': flag, 'before': before, 'after': after})
    for bad in (b'invalid', patched):
        try:
            candidate(bad)
        except ValueError:
            pass
        else:
            raise AssertionError('Unreviewed input accepted')
    with args.output.open('x') as stream:
        json.dump({'cases': rows, 'scope': 'Count arithmetic only; no allocation, buffer ownership, driver, pipeline or device validation.'}, stream, indent=2)
    print('Six arithmetic cases passed; unknown/already-patched inputs rejected')


if __name__ == '__main__':
    main()
