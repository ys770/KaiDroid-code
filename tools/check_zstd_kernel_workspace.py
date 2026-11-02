"""Bounded offline execution of retained kernel compressor init allocation requests.

Allocator/context initialization calls are modeled successful. Parameter and
workspace-bound arithmetic executes real ARM code. This is not live RAM usage.
"""
import argparse
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
    UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_C1_C0_2,UC_ARM_REG_FPEXC)

KERNEL='5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561'
SYMBOLS='a5aa3100ceb9d9d46902d201656f5764ace591c797c5e392b005999bc3d88808'


def execute(image,syms,name):
    u=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    u.reg_write(UC_ARM_REG_C1_C0_2,0xf<<20);u.reg_write(UC_ARM_REG_FPEXC,1<<30)
    u.mem_map(0,0x10000);u.mem_map(0xc0000000,0x2000000)
    u.mem_write(0xc0008000,image)
    u.mem_map(0x20000000,0x100000);u.mem_map(0x30000000,0x1000000)
    u.reg_write(UC_ARM_REG_SP,0x20080000);u.reg_write(UC_ARM_REG_LR,0x1000)
    u.reg_write(UC_ARM_REG_R0,0x30000000)
    allocations=[];observed={};steps=0
    allocators={syms[n]:n for n in ('vzalloc','vmalloc','kmalloc_order_trace')}
    initializers={syms[n]:n for n in ('ZSTD_initCCtx','ZSTD_initDCtx')}
    def code(emu,address,size,_):
        nonlocal steps
        steps+=1
        if address==syms['ZSTD_getParams']:
            observed['compression_level_argument']=emu.reg_read(UC_ARM_REG_R1)
        if address==syms['ZSTD_CCtxWorkspaceBound']:
            observed['compression_parameter_words']=[emu.reg_read(r) for r in
                (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)] + list(
                struct.unpack('<III',emu.mem_read(emu.reg_read(UC_ARM_REG_SP),12)))
        if address in allocators:
            requested=emu.reg_read(UC_ARM_REG_R0)
            if requested<=0 or requested>8*1024*1024:raise ValueError('Unexpected allocation request')
            allocations.append(dict(function=allocators[address],requested_bytes=requested,
                                    call_return_address=hex(emu.reg_read(UC_ARM_REG_LR))))
            emu.reg_write(UC_ARM_REG_R0,0x30100000+len(allocations)*0x400000)
            emu.reg_write(UC_ARM_REG_PC,emu.reg_read(UC_ARM_REG_LR))
        elif address in initializers:
            # Return the supplied workspace as a nonnull opaque context. No
            # real kernel allocation/context initialization is performed.
            emu.reg_write(UC_ARM_REG_PC,emu.reg_read(UC_ARM_REG_LR))
    u.hook_add(UC_HOOK_CODE,code)
    u.emu_start(syms[name],0x1000,timeout=3_000_000,count=500_000)
    if u.reg_read(UC_ARM_REG_PC)!=0x1000 or u.reg_read(UC_ARM_REG_R0)!=0:
        raise ValueError('Compressor init did not complete its modeled success path')
    return dict(entry=hex(syms[name]),allocations=allocations,observed=observed,
        requested_workspace_bytes=sum(a['requested_bytes'] for a in allocations),
        page_rounded_workspace_bytes=sum((a['requested_bytes']+4095)//4096*4096 for a in allocations),
        instructions_executed=steps,return_value=0)


def inspect(kernel,symbols):
    data=kernel.read_bytes();s=symbols.read_bytes()
    if hashlib.sha256(data).hexdigest()!=KERNEL or hashlib.sha256(s).hexdigest()!=SYMBOLS:
        raise ValueError('Wrong retained kernel or captured symbol mapping')
    syms={n:int(a,16) for a,_,n in re.findall(r'^([0-9a-f]{8}) ([A-Za-z]) (\S+)$',s.decode().replace('\r\n','\n'),re.M)}
    image=None
    for m in re.finditer(b'\x1f\x8b\x08',data):
        try:decoded=zlib.decompress(data[m.start():],31)
        except zlib.error:continue
        if b'Linux version 4.9.268+-ab00.2211.12.01' in decoded:image=decoded;break
    if image is None or syms['_text']!=0xc0008000 or not image[syms['linux_banner']-syms['_text']:].startswith(b'Linux version 4.9.268+-ab00.2211.12.01'):
        raise ValueError('Kernel image/symbol mapping not established')
    rows={name:execute(image,syms,name) for name in ('lzo_init','zstd_init')}
    delta=rows['zstd_init']['page_rounded_workspace_bytes']-rows['lzo_init']['page_rounded_workspace_bytes']
    return dict(kernel_sha256=KERNEL,symbols_sha256=SYMBOLS,decompressed_sha256=hashlib.sha256(image).hexdigest(),
        results=rows,page_rounded_workspace_delta_per_stream_bytes=delta,
        conditional_four_stream_delta_bytes=4*delta,
        scope='Real retained ARM init/parameter/bound code with modeled successful allocators/context initializers. Allocation requests and 4KiB rounding only; excludes allocator metadata, crypto/zcomp structures, page tables, CPU hotplug/actual stream count and physical residency. No live kernel execution or performance claim.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('kernel','symbols','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=inspect(a.kernel,a.symbols)
    with a.output.open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
