"""Trace the installed sensor listener without executing vendor code."""
import argparse,hashlib,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
PIN='83899f619cb63f1f7bf2510d2088ed870cd093a5b6085953b5c799c7bb1699f8'
def inspect(path):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=PIN:raise ValueError('Unreviewed listener')
    with path.open('rb') as stream:
        elf=ELFFile(stream)
        def read(a,n):
            for seg in elf.iter_segments():
                off=a-seg['p_vaddr']
                if seg['p_type']=='PT_LOAD' and 0<=off and off+n<=seg['p_filesz']:return seg.data()[off:off+n]
            raise ValueError('Outside file-backed load segments')
        def string(a):
            value=bytearray()
            for i in range(256):
                b=read(a+i,1)
                if b==b'\0':return value.decode('ascii')
                value.extend(b)
            raise ValueError('Unterminated string')
        def literal(a,pc):return string((struct.unpack('<I',read(a,4))[0]+pc)&0xffffffff)
        def ins(a,n):return [[hex(i.address),i.mnemonic,i.op_str] for i in Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(read(a,n),a)]
        needed=[t.needed for t in elf.get_section_by_name('.dynamic').iter_tags() if t.entry.d_tag=='DT_NEEDED']
        assert 'libsdsprpc.so' in needed
        constants={'static_prefix':literal(0x111c,0x104e),'fallback':literal(0x1118,0x106e),'environment_name':literal(0x1120,0x107a),'environment_value':literal(0x1124,0x107c),'listener':literal(0x1128,0x109c),'eventfd':literal(0x112c,0x10b2)}
        assert constants['static_prefix'].endswith('createstaticpd:') and constants['eventfd'].endswith('geteventfd')
        rel=elf.get_section_by_name('.rel.plt');sy=elf.get_section(rel['sh_link']);plt=elf.get_section_by_name('.plt')['sh_addr']
        imports={plt+32+16*n:sy.get_symbol(r['r_info_sym']).name for n,r in enumerate(rel.iter_relocations())}
        assert imports[0x13c0]=='remote_handle_open' and imports[0x13e0]=='__poll_chk'
        return {'binary_sha256':PIN,'needed':needed,'entry':'adsp_default_listener_start at0x1015','abi_evidence':'Entry compares r0 with2 and reads argv[1] from saved r1+4; consistent with int entry(int argc,char **argv).','constants':constants,'sequence':['argc>=2: concatenate static prefix and argv[1]; otherwise attachguestos','setenv cache-size1048576 with overwrite0','remote_handle_open(configured static-PD string)','remote_handle_open(adsp_default_listener)','adsp_default_listener_register helper0x11b0','remote_handle_open(geteventfd special string)','poll/eventfd_read loop until event or error'],'instruction_evidence':{'argument_branch':ins(0x101a,28),'static_name':ins(0x1044,24),'environment':ins(0x1070,16),'open_sequence':ins(0x1088,48),'wait':ins(0x10de,38)},'limits':['Offline only; no DSP or RPC call executed.','Library existence and call trace do not establish successful sensor-PD startup.','Entry receives argc/argv; one-shot test must avoid the outer adsprpcd retry loop.','libsdsprpc domain2 mapping to this kernel/board remains to verify.']}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=inspect(a.binary)
    with a.output.open('x',encoding='utf-8') as f:f.write(json.dumps(r,indent=2)+'\n')
