"""Emulate the candidate trampoline with a modeled cfmakeraw call boundary."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R6, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC

CANDIDATE_SHA = 'b0abb79396ca1bc05d047eed43027af28081edb7cd348f7bb8eb2a404ff4ee81'


def verify(path):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != CANDIDATE_SHA:
        raise ValueError('Unexpected trial candidate')
    cases = []
    for flags in (0, 0x1000, 0x40000000):
        u = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        u.mem_map(0, 0x10000)
        u.mem_write(0, data)
        u.mem_map(0x10000, 0x10000)
        u.reg_write(UC_ARM_REG_R0, 0x10004)
        u.reg_write(UC_ARM_REG_R6, 0x10000)
        u.reg_write(UC_ARM_REG_SP, 0x1f000)
        u.reg_write(UC_ARM_REG_LR, 0xdead)
        calls = []
        def hook(uc, address, size, _):
            if address == 0x158c:
                assert uc.reg_read(UC_ARM_REG_R0) == 0x10004
                assert uc.reg_read(UC_ARM_REG_SP) % 8 == 0
                calls.append(address)
                uc.mem_write(0x10004, struct.pack('<I', flags))
                # A void function may clobber caller-saved r0.
                uc.reg_write(UC_ARM_REG_R0, 0x87654321)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            if address == 0x2620:
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(0x261d, 0x3000, count=100)
        assert u.reg_read(UC_ARM_REG_PC) == 0x2620
        assert calls == [0x158c]
        assert struct.unpack('<I', u.mem_read(0x10004, 4))[0] == flags | 1
        assert u.reg_read(UC_ARM_REG_R0) == 0x10004
        assert u.reg_read(UC_ARM_REG_R6) == 0x10000
        assert u.reg_read(UC_ARM_REG_SP) == 0x1f000
        u.emu_start(0x2687, 0x269e, count=1)
        assert u.reg_read(UC_ARM_REG_PC) == 0x269e
        cases.append(dict(raw_result=hex(flags), patched_result=hex(flags | 1), passed=True))
    print(json.dumps(dict(cases=cases, scope='Trampoline ABI/control flow only; cfmakeraw modeled, no actual UART or live test'), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('candidate', type=Path)
    verify(p.parse_args().candidate)
