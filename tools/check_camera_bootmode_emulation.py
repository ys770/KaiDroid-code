"""Execute camera launchers' bootmode branch in bounded ARM emulation.

External calls are modeled; optional startup tests use fake Binder/service objects.
This proves launcher control flow only, not camera functionality or runtime ABI.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC

ORIGINAL_SHA = '3e5daad652ca65d83450c24c99c921f06162df550bbd217275ef7045a17f5512'
INIT = '_ZN7android12ProcessState14initWithDriverEPKc'


def run(path, mode, original=False, startup=False, provider_available=True,
        registration_status=0, join_returns=False):
    data = path.read_bytes()
    if original and hashlib.sha256(data).hexdigest() != ORIGINAL_SHA:
        raise ValueError('Unreviewed original binary')
    u = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    u.reg_write(UC_ARM_REG_C1_C0_2, 0xf << 20)
    u.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
    # Low ELF image, separate stack, and modeled external call space.
    u.mem_map(0, 0x100000)
    u.mem_map(0x1000000, 0x20000)
    u.mem_map(0x2000000, 0x10000)
    stubs = {}
    # Model RefBase-bearing objects with zero virtual-base adjustment. No real
    # vendor object or C++ ABI layout is validated by these deliberately fake objects.
    object_address, vtable = 0x200a100, 0x200a000
    u.mem_write(object_address, struct.pack('<I', vtable))
    next_allocation = [0x2008000]
    with path.open('rb') as stream:
        e = ELFFile(stream)
        if e.elfclass != 32 or e['e_machine'] != 'EM_ARM':
            raise ValueError('Expected ARM32')
        for segment in e.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                if segment['p_vaddr'] + segment['p_memsz'] >= 0x100000:
                    raise ValueError('Unexpected image size')
                u.mem_write(segment['p_vaddr'], segment.data())
        main = 0x1045 if original else None
        symtab = e.get_section_by_name('.symtab')
        if not original and symtab:
            symbols = symtab.get_symbol_by_name('main')
            if symbols:
                main = symbols[0]['st_value']
        if main is None:
            raise ValueError('Candidate main symbol missing')
        for section in e.iter_sections():
            if section['sh_type'] != 'SHT_REL':
                continue
            symbols = e.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                kind = rel['r_info_type']
                if kind == 23:  # R_ARM_RELATIVE, load bias zero.
                    continue
                if kind not in (21, 22):  # GLOB_DAT / JUMP_SLOT
                    raise ValueError('Unsupported relocation '+str(kind))
                symbol = symbols.get_symbol(rel['r_info_sym'])
                if symbol['st_shndx'] != 'SHN_UNDEF':
                    target = symbol['st_value']
                else:
                    name = symbol.name
                    if name == '__stack_chk_guard':
                        target = 0x200f000
                        u.mem_write(target, struct.pack('<I', 0x12345678))
                    else:
                        target = next((addr for addr, n in stubs.items() if n == name), None)
                        if target is None:
                            target = 0x2000000 + len(stubs)*0x100
                            stubs[target] = name
                            u.mem_write(target, b'\x1e\xff\x2f\xe1')  # ARM bx lr
                u.mem_write(rel['r_offset'], struct.pack('<I', target))
    sentinel = 0x200e000
    u.reg_write(UC_ARM_REG_SP, 0x101f000)
    u.reg_write(UC_ARM_REG_LR, sentinel)
    events = []
    result = {'mode': mode, 'events': events, 'outcome': None}

    def cstring(addr):
        value = bytes(u.mem_read(addr, 128)).split(b'\0', 1)[0]
        return value.decode()

    def cppstring(addr):
        first = bytes(u.mem_read(addr, 1))[0]
        if first & 1:
            length, pointer = struct.unpack('<II', bytes(u.mem_read(addr+4, 8)))
        else:
            length, pointer = first >> 1, addr+1
        if length > 128:
            raise ValueError('Unexpected string length')
        return bytes(u.mem_read(pointer, length)).decode()

    def hook(uc, address, size, unused):
        if address == sentinel:
            result['outcome'] = 'returned'
            result['return_value'] = uc.reg_read(UC_ARM_REG_R0)
            uc.emu_stop()
            return
        if address not in stubs:
            return
        name = stubs[address]
        a, b, c = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2)]
        value = 0
        if name == 'property_get':
            if cstring(a) != 'ro.bootmode':
                raise ValueError('Unexpected property')
            text = cstring(c) if mode in (None, '') else mode
            uc.mem_write(b, text.encode()+b'\0')
            events.append({'property': 'ro.bootmode', 'value': text})
            value = len(text)
        elif name == 'memcmp':
            left, right = bytes(uc.mem_read(a, c)), bytes(uc.mem_read(b, c))
            value = 0 if left == right else (-1 if left < right else 1)
        elif name == 'sleep':
            events.append({'sleep_seconds': a})
        elif name == '__android_log_print':
            pass
        elif name == INIT:
            # C++ sp<ProcessState> return uses hidden result storage in r0;
            # the explicit const char* driver argument is therefore in r1.
            driver = cstring(b)
            if driver != '/dev/vndbinder':
                raise ValueError('Unexpected Binder driver argument')
            events.append({'binder_driver': driver})
            if not startup:
                result['outcome'] = 'normal_binder_path'
                uc.emu_stop()
                return
            uc.mem_write(a, struct.pack('<I', object_address))
        elif startup and name == '_ZN7android8hardware22configureRpcThreadpoolEjb':
            events.append({'rpc_threads': a, 'caller_joins': bool(b)})
        elif startup and 'ICameraProvider10getService' in name:
            events.append({'get_service': cppstring(b), 'passthrough': bool(c)})
            uc.mem_write(a, struct.pack('<I', object_address if provider_available else 0))
        elif startup and ('ICameraProvider17registerAsService' in name or
                          'LazyServiceRegistrar15registerService' in name):
            lazy = 'LazyServiceRegistrar' in name
            events.append({'register': cppstring(c if lazy else b), 'lazy': lazy})
            value = registration_status
        elif startup and name == '_ZN7android8hardware17joinRpcThreadpoolEv':
            events.append({'join_rpc': True})
            if not join_returns:
                result['outcome'] = 'joined_rpc'
                uc.emu_stop()
                return
        elif startup and name == '_Znwj':
            if a > 1024 or next_allocation[0]+a >= 0x200a000:
                raise ValueError('Unexpected allocation')
            value = next_allocation[0]
            next_allocation[0] += (a+15) & ~15
        elif startup and name == '__cxa_guard_acquire':
            value = 1
        elif startup and (name in ('__cxa_guard_release', '__cxa_atexit', '_ZdlPv') or
                          'LazyServiceRegistrarC1Ev' in name or 'RefBase' in name):
            pass
        elif startup and name == 'memset':
            uc.mem_write(a, bytes([b & 255])*c)
            value = a
        else:
            raise ValueError('Unmodeled external call: '+name)
        uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
        # Let the stub's bx lr instruction perform ARM/Thumb interworking.

    u.hook_add(UC_HOOK_CODE, hook)
    u.emu_start(main, 0, timeout=1000000, count=10000)
    if result['outcome'] is None:
        raise RuntimeError('Instruction/time bound reached without an outcome')
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original', type=Path, required=True)
    p.add_argument('--candidate', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--startup', action='store_true', help='Also compare modeled startup and failure paths')
    a = p.parse_args()
    results = []
    for mode in (None, '', 'normal', 'ffbm-01', 'ffbm-02', 'ffbm-010', 'ffbm-03'):
        original = run(a.original, mode, True)
        candidate = run(a.candidate, mode)
        if original != candidate:
            raise AssertionError({'original': original, 'candidate': candidate})
        results.append(candidate)
    report = dict(original_sha256=hashlib.sha256(a.original.read_bytes()).hexdigest(),
                  candidate_sha256=hashlib.sha256(a.candidate.read_bytes()).hexdigest(),
                  cases=results, passed=True,
                  scope='Actual ARM instructions with modeled external calls. Stops before Binder initialization; no hardware, timing or camera lifecycle proof.')
    if a.startup:
        scenarios = [
            ('normal', {}, 'joined_rpc', None),
            ('provider-absent', {'provider_available': False}, 'returned', 1),
            ('registration-failed', {'registration_status': -5}, 'returned', 0xfffffffb),
            ('registration-busy', {'registration_status': -16}, 'returned', 0xfffffff0),
            ('join-returned', {'join_returns': True}, 'returned', 0x80000000),
        ]
        flows = []
        for name, options, outcome, code in scenarios:
            original = run(a.original, 'normal', True, startup=True, **options)
            candidate = run(a.candidate, 'normal', startup=True, **options)
            for item, lazy in ((original, False), (candidate, True)):
                assert item['outcome'] == outcome, (name, item)
                if code is not None:
                    assert item['return_value'] == code, (name, item)
                assert {'rpc_threads': 6, 'caller_joins': True} in item['events']
                assert {'get_service': 'legacy/0', 'passthrough': True} in item['events']
                registrations = [event for event in item['events'] if 'register' in event]
                assert registrations == ([] if name == 'provider-absent' else
                                          [{'register': 'legacy/0', 'lazy': lazy}])
            # The intended change is exactly the registrar choice.
            def normalized(item):
                return dict(item, events=[{k: v for k, v in event.items() if k != 'lazy'}
                                          for event in item['events']])
            assert normalized(original) == normalized(candidate), name
            flows.append(dict(scenario=name, original=original, candidate=candidate))
        report['startup_cases'] = flows
        report['scope'] = ('Actual launcher ARM instructions with modeled externals and fake C++ objects. '
                           'Startup flow, arguments and failure propagation only; '
                           'not vendor ABI layout, Binder/registrar implementation, client-count exit or hardware behavior.')
    with a.output.open('x') as f:
        f.write(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(passed=True, bootmode_cases=len(results),
                          startup_cases=len(report.get('startup_cases', [])),
                          candidate_sha256=report['candidate_sha256'])))


if __name__ == '__main__':
    main()
