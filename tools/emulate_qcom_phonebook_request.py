"""Trace original OEM request parsing to ADN dispatch without invoking modem code."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR


def trace(blob, payload):
    elf = ELFFile(io.BytesIO(blob))
    segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    end = max(s['p_vaddr'] + s['p_memsz'] for s in segments)
    uc.mem_map(0, (end+4095) & ~4095)
    for s in segments: uc.mem_write(s['p_vaddr'], s.data())
    base, stack = 0x30000000, 0x30010000
    uc.mem_map(base, 0x20000)
    uc.mem_write(base, payload)
    uc.reg_write(UC_ARM_REG_SP, stack)
    # Seed locals produced by HIDL vector size/data access and entry arguments.
    for offset, value in [(0x118,len(payload)),(0x110,base),(0x11c,base+0x1000),
                          (0x100,base+0x2000),(0x120,77)]:
        uc.mem_write(stack+offset,struct.pack('<I',value))
    result = {}
    def ret(value):
        uc.reg_write(UC_ARM_REG_R0,value)
        uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
    def hook(machine,address,size,unused):
        if address == 0xf1870e:
            result['route']='short-input-error-path'; machine.emu_stop()
        elif address == 0xc42b48:
            index=machine.reg_read(UC_ARM_REG_R1)
            if index >= len(payload): raise ValueError('Vector index outside input')
            ret(base+index)
        elif address == 0xfd4f80:
            dst,src,length,bound=[machine.reg_read(r) for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
            if length > bound or not base <= src <= src+length <= base+len(payload):
                raise ValueError('Copy outside input/bound')
            machine.mem_write(dst,bytes(machine.mem_read(src,length)));ret(dst)
        elif address == 0xff2620:
            result.update(route='getAdnRecord',serial=machine.reg_read(UC_ARM_REG_R2))
            machine.emu_stop()
        elif not (0xf18704 <= address < 0xf1870e or 0xf1884c <= address < 0xf18a1e
                  or 0xf18a54 <= address < 0xf18b48):
            raise ValueError('Unexpected execution '+hex(address))
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(0xf18705,0,count=2000)
    if not result: raise ValueError('No terminal route within instruction budget')
    result.update(input_hex=payload.hex(),bytes=len(payload),
                  parsed_length=struct.unpack('<I',uc.mem_read(stack+0x158,4))[0])
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    blob=Path('work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so').read_bytes()
    digest=hashlib.sha256(blob).hexdigest()
    if digest!='47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd':raise ValueError('Unexpected library')
    canonical=b'QOEMHOOK'+struct.pack('<II',0x800dd,0)
    fixtures=[canonical[:n] for n in range(12)]
    fixtures += [canonical[:12],canonical,canonical+b'\0',b'XXXXXXXX'+canonical[8:]]
    fixtures += [canonical[:12]+struct.pack('<I',123), canonical[:12]+struct.pack('<I',123)+b'\0']
    cases=[trace(blob,x) for x in fixtures]
    for c in cases:
        expected='short-input-error-path' if c['bytes']<12 else 'getAdnRecord'
        if c['route']!=expected:raise ValueError('Unexpected dispatch')
    if cases[-2]['parsed_length'] != 0 or cases[-1]['parsed_length'] != 123:
        raise ValueError('Length-read threshold differs')
    report={'library_sha256':digest,'passed':True,'cases':cases,
            'candidate_read_request_hex':canonical.hex(),
            'limits':['HIDL vector locals/access and checked memcpy modeled',
                      'Stops before getAdnRecord; no modem or callback registration executed',
                      'First eight bytes are not validated by the traced parser; canonical marker retained',
                      'Length word parsed only for inputs of at least 17 bytes; read route ignores payload',
                      'Short-input route observed, not its eventual error callback']}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+'\n')
    print('PASS: 18 original-parser fixtures; canonical no-payload read request reaches ADN dispatch')


if __name__=='__main__':main()
