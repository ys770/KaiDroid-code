"""Execute retained ARM page-table accounting with bounded synthetic kernel objects."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR,
                               UC_ARM_REG_PC)

KERNEL = '5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561'
SYMBOLS = 'a5aa3100ceb9d9d46902d201656f5764ace591c797c5e392b005999bc3d88808'
FUNCTIONS = {'task_mem': '4b3df0cac9e891169b54936d390f21f178d721cbc78b642763c887d1921bae30',
             '__pte_alloc': '9d2e32533ea67e794b7753d816f3921770c0737494b2b7dc85300d80a0963d7d',
             'meminfo_proc_show': '82a116419103dc337227cef23e3c558b18d377249d53a13c1cbf4dc47c5da735',
             'show_val_kb': '3bfbcbdc95e1bb749c155dba602f6383e5c462859f7a4df22b7c7917a769707a'}


def load(kernel, symbols):
    data = kernel.read_bytes()
    raw = symbols.read_bytes()
    if hashlib.sha256(data).hexdigest() != KERNEL or hashlib.sha256(raw).hexdigest() != SYMBOLS:
        raise ValueError('Wrong retained kernel/symbol identity')
    image = None
    for match in re.finditer(b'\x1f\x8b\x08', data):
        try:
            decoded = zlib.decompress(data[match.start():], 31)
        except zlib.error:
            continue
        if b'Linux version 4.9.268+-ab00.2211.12.01' in decoded:
            image = decoded
            break
    rows = [(int(a,16),kind,name) for a,kind,name in
            re.findall(r'^([0-9a-f]{8}) ([A-Za-z]) (\S+)$', raw.decode().replace('\r\n','\n'), re.M)]
    syms = {name:address for address,_,name in rows}
    base = syms['_text']
    if image is None or base != 0xc0008000 or not image[syms['linux_banner']-base:].startswith(b'Linux version 4.9.268+-ab00.2211.12.01'):
        raise ValueError('Address mapping not established')
    ranges = {}
    for name,pin in FUNCTIONS.items():
        start = syms[name]
        end = min(a for a,kind,_ in rows if a>start and kind in 'tT')
        if hashlib.sha256(image[start-base:end-base]).hexdigest() != pin:
            raise ValueError('Function extent/body changed: '+name)
        ranges[name] = (start,end)
    return image,syms,ranges


def execute(image,syms,ranges,mode,count,case='success'):
    u = Uc(UC_ARCH_ARM,UC_MODE_ARM)
    for address,size in [(0,0x10000),(0xc0000000,0x2000000),(0x20000000,0x100000),(0x30000000,0x100000)]:
        u.mem_map(address,size)
    u.mem_write(0xc0008000,image)
    mm,page,pmd = 0x30000000,0x30010000,0x30020000
    def write32(address,value): u.mem_write(address,struct.pack('<I',value&0xffffffff))
    def read32(address): return struct.unpack('<I',u.mem_read(address,4))[0]
    def return_call(value=0):
        u.reg_write(UC_ARM_REG_R0,value&0xffffffff)
        u.reg_write(UC_ARM_REG_PC,u.reg_read(UC_ARM_REG_LR))
    def string(address): return bytes(u.mem_read(address,1024)).split(b'\0',1)[0].decode('ascii')
    u.reg_write(UC_ARM_REG_SP,0x20080000)
    u.reg_write(UC_ARM_REG_LR,0x1000)
    observed = dict(mode=mode,input_count=count,case=case,calls=[])
    steps = 0
    current_label = ''
    if mode == 'task_mem':
        write32(mm+0x30,count)
        u.reg_write(UC_ARM_REG_R0,0x30030000)
        u.reg_write(UC_ARM_REG_R1,mm)
        allowed = ['task_mem']
    elif mode == '__pte_alloc':
        write32(mm+0x30,count)
        write32(page,0x40000000)  # Modeled highmem zone skips cache-maintenance callback.
        write32(syms['mem_map'],page)
        write32(syms['__pv_phys_pfn_offset'],0x80000)
        if case == 'already_populated': write32(pmd,1)
        u.reg_write(UC_ARM_REG_R0,mm)
        u.reg_write(UC_ARM_REG_R1,pmd)
        allowed = ['__pte_alloc']
    elif mode == 'meminfo_proc_show':
        # NR_PAGETABLE is index10 in the retained allocator's zone counter call.
        write32(syms['vm_zone_stat']+10*4,count)
        u.reg_write(UC_ARM_REG_R0,0x30030000)
        allowed = ['meminfo_proc_show','show_val_kb']
    else: raise ValueError(mode)
    def hook(emu,address,size,_):
        nonlocal steps,current_label
        steps += 1
        if steps>5000: raise ValueError('Instruction bound exceeded')
        if address==0x1000:
            emu.emu_stop();return
        if mode=='task_mem' and address==syms['seq_printf']:
            fmt=string(emu.reg_read(UC_ARM_REG_R1))
            labels=re.findall(r'(\w+):\t%8lu kB',fmt)
            args=[emu.reg_read(UC_ARM_REG_R2),emu.reg_read(UC_ARM_REG_R3)]
            args+=list(struct.unpack('<'+'I'*(len(labels)-2),emu.mem_read(emu.reg_read(UC_ARM_REG_SP),4*(len(labels)-2))))
            if len(labels)!=16 or labels[13:15]!=['VmPTE','VmPMD']: raise ValueError('Unexpected task format')
            observed.update(vm_pte_KiB=args[13],vm_pmd_KiB=args[14])
            return_call();return
        if mode=='__pte_alloc':
            external={syms[name]:name for name in ['__alloc_pages_nodemask','inc_zone_page_state',
                'dec_zone_page_state','_raw_spin_lock','_raw_spin_unlock','__free_pages']}
            if address in external:
                name=external[address]
                args=[emu.reg_read(r) for r in [UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3]]
                observed['calls'].append(dict(name=name,args=args))
                return_call(0 if name!='__alloc_pages_nodemask' or case=='allocation_failure' else page)
                return
        if mode=='meminfo_proc_show':
            if address==syms['show_val_kb']:
                current_label=string(emu.reg_read(UC_ARM_REG_R1)).strip()
                if current_label=='PageTables:': observed['page_table_counter_pages']=emu.reg_read(UC_ARM_REG_R2)
            if address==syms['num_to_str']:
                if current_label=='PageTables:':
                    observed['page_tables_KiB']=emu.reg_read(UC_ARM_REG_R2)
                    emu.emu_stop();return
                emu.mem_write(emu.reg_read(UC_ARM_REG_R0),b'0');return_call(1);return
            if address in [syms[n] for n in ['si_meminfo','si_swapinfo','total_swapcache_pages','si_mem_available','seq_write','seq_printf']]:
                return_call();return
        if not any(ranges[name][0]<=address<ranges[name][1] for name in allowed):
            raise ValueError('Unmodeled execution at '+hex(address))
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(syms[mode],0,count=5001)
    observed['instructions']=steps
    if mode=='meminfo_proc_show':
        if observed.get('page_table_counter_pages')!=count or observed.get('page_tables_KiB')!=count*4:
            raise ValueError('Global accounting mismatch')
    else:
        if u.reg_read(UC_ARM_REG_PC)!=0x1000: raise ValueError('Did not return')
        if mode=='task_mem':
            if observed.get('vm_pte_KiB')!=count*2 or observed.get('vm_pmd_KiB')!=0: raise ValueError('Task accounting mismatch')
        else:
            observed['returned_u32']=u.reg_read(UC_ARM_REG_R0)
            observed['mm_count_after']=read32(mm+0x30)
            alloc=[c for c in observed['calls'] if c['name']=='__alloc_pages_nodemask']
            if len(alloc)!=1 or alloc[0]['args'][1]!=0: raise ValueError('Expected order0 allocation')
            observed['allocation_order']=alloc[0]['args'][1]
            observed['zone_counter_operations']=[dict(name=c['name'],index=c['args'][1]) for c in observed['calls'] if c['name'] in ['inc_zone_page_state','dec_zone_page_state']]
            expected_ops=[] if case=='allocation_failure' else [dict(name='inc_zone_page_state',index=10)]
            if case=='already_populated': expected_ops.append(dict(name='dec_zone_page_state',index=10))
            if observed['zone_counter_operations']!=expected_ops or observed['mm_count_after']!=count+(case=='success') or observed['returned_u32']!=(0xfffffff4 if case=='allocation_failure' else 0):
                raise ValueError('Allocation accounting path mismatch')
    observed.pop('calls')  # Synthetic pointers are not meaningful evidence.
    return observed


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ['kernel','symbols','output']: parser.add_argument('--'+key,type=Path,required=True)
    args=parser.parse_args()
    image,syms,ranges=load(args.kernel,args.symbols)
    runs=[execute(image,syms,ranges,mode,count) for mode in ['task_mem','meminfo_proc_show'] for count in [0,1,3,285,1024,1536]]
    runs += [execute(image,syms,ranges,'__pte_alloc',285,case) for case in ['success','allocation_failure','already_populated']]
    report=dict(kernel_sha256=KERNEL,symbols_sha256=SYMBOLS,decompressed_sha256=hashlib.sha256(image).hexdigest(),
                function_sha256=FUNCTIONS,
                function_ranges={name:dict(start=hex(lo),end=hex(hi),bytes=hi-lo) for name,(lo,hi) in ranges.items()},
                checker_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),runs=runs,
                limits=['Real retained ARM arithmetic/control flow, synthetic mm/page/PMD objects and modeled external allocation/locking/counter operations.',
                        'Allocator uses a modeled highmem page; cache-maintenance path, actual mappings and physical allocation are not executed.',
                        'Global meminfo uses modeled zero helper inputs and stops after actual show_val_kb converts PageTables to KiB.',
                        'Not live kernel execution, atomic census, page ownership/reclaimability, target rewrite or memory saving.'])
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(cases=len(runs),task_KiB_per_table=2,global_KiB_per_table=4,allocation_order=0),indent=2))
