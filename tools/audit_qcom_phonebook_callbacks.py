"""Verify callback slot assignments/getters in the handset-matched OEM service."""
import argparse
import hashlib
import io
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args()
blob=Path('work/radio-vendor-closure/vendor/lib/libril-qc-hal-qmi.so').read_bytes()
digest=hashlib.sha256(blob).hexdigest()
if digest!='47965523c6b7ca56d9c930198c4f9acc6a9c7b34d12100b0ff068f9305b293dd':
    raise ValueError('Unexpected library')
elf=ELFFile(io.BytesIO(blob))
symbols=elf.get_section_by_name('.dynsym')
relocations={r['r_offset']:symbols.get_symbol(r['r_info_sym']).name for r in elf.get_section_by_name('.rel.plt').iter_relocations()}

def read(address,length):
    for s in elf.iter_segments():
        if s['p_type']=='PT_LOAD' and s['p_vaddr']<=address and address+length<=s['p_vaddr']+s['p_filesz']:
            offset=s['p_offset']+address-s['p_vaddr'];return blob[offset:offset+length]
    raise ValueError('Address outside file-backed segments')

def code(address,length,mode):
    decoder=Cs(CS_ARCH_ARM,mode);decoder.detail=True
    rows=list(decoder.disasm(read(address,length),address))
    if sum(i.size for i in rows)!=length:raise ValueError('Incomplete disassembly')
    return rows

rows=[]
for name,start,call,slot_instruction,slot_operands,plt,suffix in [
    ('assign-response',0xf18304,0xf18310,0xf18308,'r2, r0, #8',0xff25c0,'19IQtiOemHookResponseEEaSERKS8_'),
    ('assign-indication',0xf18314,0xf18320,0xf18318,'lr, r2, #0xc',0xff25d0,'21IQtiOemHookIndicationEEaSERKS8_'),
    ('get-response',0xf18564,0xf1856c,0xf18566,'r1, r0, #8',0xff25e0,'19IQtiOemHookResponseEEC2ERKS8_'),
    ('get-indication',0xf18608,0xf18610,0xf1860a,'r1, r0, #0xc',0xff25f0,'21IQtiOemHookIndicationEEC2ERKS8_'),
]:
    block=code(start,call+4-start,CS_MODE_THUMB)
    slot=next(i for i in block if i.address==slot_instruction)
    if slot.mnemonic!='add.w' or slot.op_str!=slot_operands:raise ValueError('Unexpected callback slot')
    if block[-1].mnemonic!='blx' or block[-1].operands[0].imm!=plt:raise ValueError('Unexpected helper call')
    thunk=code(plt,12,CS_MODE_ARM)
    if [i.mnemonic for i in thunk]!=['add','add','ldr'] or thunk[0].op_str!='ip, pc, #0, #12':raise ValueError('Unexpected PLT')
    if not thunk[1].op_str.startswith('ip, ip,') or not thunk[2].op_str.startswith('pc, [ip,'):raise ValueError('Unexpected PLT registers')
    got=plt+8+thunk[1].operands[2].imm+thunk[2].operands[1].mem.disp
    symbol=relocations[got]
    if not symbol.endswith(suffix):raise ValueError('Unexpected smart-pointer operation')
    rows.append({'operation':name,'start':hex(start),'slot_instruction':slot.op_str,
                 'resolved_symbol':symbol,'block_hex':read(start,call+4-start).hex()})
report={'library_sha256':digest,'passed':True,'operations':rows,
        'finding':'setCallback assigns one response slot at object+8 and one indication slot at object+12; getters copy those same slots',
        'integration_constraint':'Do not independently replace callbacks while another OEM client owns them; integrate with or multiplex the existing owner',
        'limits':['Static instruction/relocation audit, not live callback registration',
                  'Current owner, death handling and Binder transport still require investigation'],
        'device_mutated':False}
a.output.parent.mkdir(parents=True,exist_ok=True)
a.output.write_text(json.dumps(report,indent=2)+'\n')
print('PASS: callback assignments and getters share two fixed slots')
