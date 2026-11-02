"""Execute bounded retained ARM PIL capacity/relocation arithmetic offline.

Starts after metadata validation with modeled descriptor/allocated-region state.
No allocators, SCM calls, firmware execution or device accesses are performed.
"""
import argparse
import hashlib
import io
import json
import re
import struct
import zlib
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R2,UC_ARM_REG_R4,UC_ARM_REG_R5,
    UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,
    UC_ARM_REG_R11,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC)

KERNEL_SHA='5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561'
SYMBOLS_SHA='a5aa3100ceb9d9d46902d201656f5764ace591c797c5e392b005999bc3d88808'
START=0xc060de38
ACCEPT=0xc060e08c
TOO_SMALL=0xc060eea4


def machine(image):
    emu=Uc(UC_ARCH_ARM,UC_MODE_ARM)
    emu.mem_map(0xc0000000,0x2000000);emu.mem_write(0xc0008000,image)
    emu.mem_map(0x20000000,0x100000)
    return emu


def capacity(image,metadata,base,size):
    elf=ELFFile(io.BytesIO(metadata))
    if elf.elfclass!=32 or not elf.little_endian or elf['e_phoff']!=52 or elf['e_phentsize']!=32 or not 0<elf['e_phnum']<64:
        raise ValueError('Unexpected MDT program-header layout')
    emu=machine(image);header=0x20000000;desc=0x20010000;private=0x20011000;stack=0x20080000
    emu.mem_write(header,metadata);emu.mem_write(desc+0x1c,struct.pack('<I',private))
    for offset,value in ((0xd8,base),(0xdc,base+size),(0xe0,1)):
        emu.mem_write(private+offset,struct.pack('<I',value))
    for register,value in ((UC_ARM_REG_R10,desc),(UC_ARM_REG_R11,header),
                           (UC_ARM_REG_R2,elf['e_phnum']),(UC_ARM_REG_SP,stack),(UC_ARM_REG_LR,0)):
        emu.reg_write(register,value)
    steps=0
    def code(u,address,length,_):
        nonlocal steps
        steps+=1
        if address in (ACCEPT,TOO_SMALL):u.emu_stop();return
        if not START<=address<0xc060df68:raise ValueError('Unexpected departure from capacity slice')
    emu.hook_add(UC_HOOK_CODE,code)
    emu.emu_start(START,0,timeout=1_000_000,count=10000)
    pc=emu.reg_read(UC_ARM_REG_PC)
    if pc not in (ACCEPT,TOO_SMALL):raise ValueError('Capacity slice did not reach a terminal branch')
    minimum=struct.unpack('<I',emu.mem_read(stack+0x14,4))[0]
    return dict(required_bytes=emu.reg_read(UC_ARM_REG_R7),declared_minimum=minimum,
                allocated_base=base,allocated_bytes=size,capacity_accepted=pc==ACCEPT,
                terminal_pc=hex(pc),instructions_executed=steps)


def relocate(image,address,minimum,base,flags):
    emu=machine(image);segment=0x20000000;private=0x20010000;record=0x20020000;stack=0x20080000
    emu.mem_write(segment+0x40,struct.pack('<I',address))
    emu.mem_write(private+0xd4,struct.pack('<II',minimum,base))
    emu.mem_write(stack+0x10,struct.pack('<I',private))
    for register,value in ((UC_ARM_REG_R4,segment),(UC_ARM_REG_R5,record),
                           (UC_ARM_REG_R6,flags),(UC_ARM_REG_R8,private),
                           (UC_ARM_REG_R9,flags&0x8000000),(UC_ARM_REG_SP,stack)):
        emu.reg_write(register,value)
    emu.emu_start(0xc060e188,0xc060e1b0,timeout=100000,count=20)
    if emu.reg_read(UC_ARM_REG_PC)!=0xc060e1b0:raise ValueError('Relocation slice incomplete')
    return struct.unpack('<I',emu.mem_read(record,4))[0]


def inspect(kernel,symbols,metadata,loadmaps):
    data=kernel.read_bytes();symbol_data=symbols.read_bytes()
    if hashlib.sha256(data).hexdigest()!=KERNEL_SHA or hashlib.sha256(symbol_data).hexdigest()!=SYMBOLS_SHA:
        raise ValueError('Wrong retained kernel or symbol mapping')
    names={name:int(address,16) for address,_,name in re.findall(r'^([0-9a-f]{8}) ([A-Za-z]) (\S+)$',symbol_data.decode().replace('\r\n','\n'),re.M)}
    image=None
    for match in re.finditer(b'\x1f\x8b\x08',data):
        try:candidate=zlib.decompress(data[match.start():],31)
        except zlib.error:continue
        if b'Linux version 4.9.268+-ab00.2211.12.01' in candidate:image=candidate;break
    if image is None or names['_text']!=0xc0008000 or names['pil_boot']!=0xc060da90 or not image[names['linux_banner']-0xc0008000:].startswith(b'Linux version 4.9.268+-ab00.2211.12.01'):
        raise ValueError('Address mapping not established')
    mapping=loadmaps.read_bytes();rows=[]
    for row in json.loads(mapping)['firmwares']:
        mdt=(metadata/(row['name']+'.mdt')).read_bytes()
        if hashlib.sha256(mdt).hexdigest()!=row['mdt_sha256']:raise ValueError('MDT identity mismatch')
        elf=ELFFile(io.BytesIO(mdt))
        actual=[dict(index=i,type=s['p_type'],paddr=s['p_paddr'],vaddr=s['p_vaddr'],
                     filesz=s['p_filesz'],memsz=s['p_memsz'],flags=s['p_flags'],alignment=s['p_align'])
                for i,s in enumerate(elf.iter_segments())]
        if actual!=row['segments']:raise ValueError('Loadmap disagrees with actual ELF headers')
        region=row['reserved_region'];accepted=capacity(image,mdt,region['address'],region['bytes'])
        required=accepted['required_bytes']
        if not accepted['capacity_accepted'] or required<=4096:raise ValueError('Unexpected retained firmware capacity')
        rejected=capacity(image,mdt,region['address'],required-4096)
        exact=capacity(image,mdt,region['address'],required)
        if rejected['capacity_accepted'] or not exact['capacity_accepted']:
            raise ValueError('Capacity boundary controls failed')
        relocations=[]
        for segment in row['segments']:
            if segment['type']!='PT_LOAD' or not segment['memsz'] or (segment['flags']&0x7000000)==0x2000000:continue
            observed=relocate(image,segment['paddr'],accepted['declared_minimum'],region['address'],segment['flags'])
            expected=segment['paddr']-accepted['declared_minimum']+region['address'] if segment['flags']&0x8000000 else segment['paddr']
            if observed!=expected:raise ValueError('Relocation arithmetic disagreement')
            unchanged=relocate(image,segment['paddr'],accepted['declared_minimum'],region['address'],segment['flags']&~0x8000000)
            if unchanged!=segment['paddr']:raise ValueError('Non-relocatable control changed address')
            relocations.append(dict(segment=segment['index'],declared_paddr=segment['paddr'],modeled_allocated_paddr=observed,non_relocatable_control=unchanged))
        rows.append(dict(name=row['name'],mdt_sha256=row['mdt_sha256'],reserved_capacity=accepted,
                         exact_required_capacity=exact,one_page_below_required=rejected,relocations=relocations))
    release_start=names['dma_release_from_coherent'];release_end=release_start+128
    release_body=image[release_start-0xc0008000:release_end-0xc0008000]
    decoder=Cs(CS_ARCH_ARM,CS_MODE_ARM|CS_MODE_LITTLE_ENDIAN)
    instructions=list(decoder.disasm(release_body,release_start))
    expected_calls={names[name]:name for name in ('_raw_spin_lock_irqsave','bitmap_release_region','_raw_spin_unlock_irqrestore')}
    calls=[]
    for instruction in instructions:
        if instruction.mnemonic not in ('bl','blx'):continue
        if not instruction.op_str.startswith('#'):raise ValueError('Unknown indirect coherent-release call')
        target=int(instruction.op_str[1:],0)
        if target not in expected_calls:raise ValueError('Unexpected coherent-release callee')
        calls.append(dict(address=hex(target),name=expected_calls[target]))
    if len(calls)!=3 or sum(i.size for i in instructions)!=128:raise ValueError('Coherent-release closure differs')
    return dict(kernel_sha256=KERNEL_SHA,symbols_sha256=SYMBOLS_SHA,
                decompressed_sha256=hashlib.sha256(image).hexdigest(),loadmaps_sha256=hashlib.sha256(mapping).hexdigest(),
                capacity_slice_sha256=hashlib.sha256(image[START-0xc0008000:0xc060df68-0xc0008000]).hexdigest(),
                relocation_slice_sha256=hashlib.sha256(image[0xc060e188-0xc0008000:0xc060e1b0-0xc0008000]).hexdigest(),
                firmwares=rows,
                coherent_pool_release_disassembly=dict(start=hex(release_start),end=hex(release_end),bytes=128,sha256=hashlib.sha256(release_body).hexdigest()),
                coherent_pool_release_calls=calls,
                coherent_release_interpretation='On the inspected coherent-pool success path, dma_release_from_coherent clears pool bitmap slots under a spinlock and returns1; pil_free_memory then skips its fallback free. This path has no Linux buddy-page release call. Runtime selection and other free paths are not established.',
                scope='Offline execution of exact retained ARM arithmetic with modeled descriptor/already-allocated-region inputs, after assumed metadata validation. Proves this existing-allocation capacity comparison and address translation only. Does not execute secure authentication, first allocation, firmware, full boot path, shutdown, Linux page release or hardware; does not prove current runtime residency or reclaimability.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('kernel','symbols','metadata','loadmaps','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=inspect(args.kernel,args.symbols,args.metadata,args.loadmaps)
    with args.output.open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps([{key:row[key] for key in ('name','reserved_capacity','one_page_below_required')} for row in result['firmwares']]))
