"""Pinned offline RPC sensor-PD interface trace; never executes a vendor library."""
import argparse,hashlib,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
PINS={'libadsprpc.so':'76ff49ede4fe564d96cf17255f7b0baec2e3ce33a240ac004fcb658601fd87b5','libsdsprpc.so':'b3e804ecf235bf4f60bc2883cc867c47b7b62540ad69730b39a985195be77091'}

def inspect(directory):
    receipts=json.loads((directory/'report.json').read_text())
    expected={r['name']:r['sha256'] for r in receipts}
    result={'method':'Live-hash-bound ELF imports, PC-relative literals and Thumb instructions','libraries':[]}
    for name in ('libadsprpc.so','libsdsprpc.so'):
        path=directory/name;digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=expected[name]:raise ValueError('Live receipt mismatch')
        if digest!=PINS[name]:raise ValueError('Unreviewed static trace')
        with path.open('rb') as stream:
            elf=ELFFile(stream)
            def read(a,n):
                for sec in elf.iter_sections():
                    off=a-sec['sh_addr']
                    if sec['sh_type']!='SHT_NOBITS' and 0<=off and off+n<=sec['sh_size']:return sec.data()[off:off+n]
                raise ValueError('Address outside file')
            def ins(a,n):return [[hex(i.address),i.mnemonic,i.op_str] for i in Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(read(a,n),a)]
            symbol=next(s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s.name=='remote_handle_open')
            if symbol['st_value']!=0xeeb1:raise ValueError('Unexpected entry')
            domain=0 if name=='libadsprpc.so' else 2
            entry=ins(0xeeb0,22)
            if ['0xeeb8','movs',f'r0, #{domain}'] not in entry:raise ValueError('Domain mismatch')
            item={'name':name,'sha256':digest,'remote_handle_open_domain_argument':domain,'entry_instructions':entry}
            if name=='libsdsprpc.so':
                a=(struct.unpack('<I',read(0xee84,4))[0]+0xed22)&0xffffffff
                prefix=read(a,50).split(b'\0')[0].decode()
                sensor=(struct.unpack('<I',read(0xeea4,4))[0]+0xee2c)&0xffffffff
                if read(sensor,10)!=b'sensorspd\0':raise ValueError('Sensor literal mismatch')
                rel=elf.get_section_by_name('.rel.plt');sy=elf.get_section(rel['sh_link']);plt=elf.get_section_by_name('.plt')['sh_addr']
                imports={plt+32+16*n:sy.get_symbol(r['r_info_sym']).name for n,r in enumerate(rel.iter_relocations())}
                if imports.get(0x1e270)!='ioctl':raise ValueError('ioctl binding mismatch')
                item.update({'static_pd_prefix':prefix,'sensor_name':'sensorspd','name_stored_at_domain_state_offset':'0x14','sensor_mode_value':2,'mode_stored_at_domain_state_offset':'0x10','device_init_ioctl':'0xc01c5206','device_init_argument_first_word':2,'instruction_evidence':{'prefix_branch':ins(0xed18,14),'name_skip':ins(0xede0,16),'sensor_compare':ins(0xee22,14),'sensor_mode':ins(0xee60,14),'mode_store':ins(0xed48,6),'static_pd_ioctl':ins(0xe6b2,28)}})
            result['libraries'].append(item)
    result['limits']=['No library or DSP call executed.','The createstaticpd branch configures per-domain state; it does not itself prove a DSP starts.','The observed open_dev ioctl block is a separate later operation; a complete loader sequence remains to be reconstructed.','Domain integer differences alone do not prove board-specific device mapping or fitted sensors.']
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    result=inspect(a.directory)
    with a.output.open('x',encoding='utf-8') as f:f.write(json.dumps(result,indent=2)+'\n')
