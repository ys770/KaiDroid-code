"""Offline whole-text/symbol change inventory; normalization is diagnostic, never ABI proof."""
import argparse,bisect,difflib,hashlib,json,os,re,subprocess
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile

def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def inventory(path):
    raw=path.read_bytes();e=ELFFile(BytesIO(raw));s=e.get_section_by_name('.symtab')
    if s is None:raise ValueError('Require unstripped symbols')
    funcs={};objects={}
    for x in s.iter_symbols():
        if not x.name or not isinstance(x['st_shndx'],int):continue
        section=e.get_section(x['st_shndx']);address=int(x['st_value']);size=int(x['st_size'])
        row=dict(address=address,size=size,section=section.name,binding=x['st_info']['bind'],visibility=x['st_other']['visibility'])
        if x['st_info']['type']=='STT_FUNC' and size:
            offset=(address&~1)-int(section['sh_addr']);row['sha256']=sha(section.data()[offset:offset+size]);funcs.setdefault(x.name,[]).append(row)
        elif x['st_info']['type'] in ('STT_OBJECT','STT_TLS') and size:objects.setdefault(x.name,[]).append(row)
    for group in (funcs,objects):
        for rows in group.values():rows.sort(key=lambda r:(r['size'],r['address']))
    sections={s.name:dict(size=int(s['sh_size']),type=s['sh_type'],flags=int(s['sh_flags']),sha256=sha(s.data()) if s['sh_type']!='SHT_NOBITS' else None) for s in e.iter_sections() if s['sh_flags']&2}
    return dict(sha256=sha(raw),functions=funcs,objects=objects,allocated_sections=sections)
def native(p):
    p=p.resolve();return '/mnt/'+p.drive[0].lower()+'/'+p.as_posix()[3:] if os.name=='nt' else str(p)
def disassemble(path,out):
    argv=(['wsl.exe','--exec'] if os.name=='nt' else [])+['arm-linux-gnueabi-objdump','-d','-w','--no-show-raw-insn','--section=.text',native(path)]
    with out.open('xb') as f:r=subprocess.run(argv,stdout=f,stderr=subprocess.PIPE,timeout=180)
    if r.returncode or r.stderr:raise ValueError('Disassembler failure '+repr(r.stderr))
    blocks={};name=None
    for line in out.read_text().splitlines():
        m=re.match(r'^[0-9a-f]+ <(.*)>:$',line)
        if m:name=m[1];blocks.setdefault(name,[]);continue
        if name and re.match(r'^\s+[0-9a-f]+:',line):
            instruction=re.sub(r'^\s+[0-9a-f]+:\s*','',line)
            # Only erase explicit address text when objdump also names its target.
            instruction=re.sub(r'(?<![\w])(?:0x)?[0-9a-f]+(?= <[^>]+>)','ADDR',instruction)
            blocks[name].append(instruction)
    if len(blocks)<1000:raise ValueError('Unexpectedly small text inventory')
    return blocks,argv

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('baseline','candidate','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();out=a.output_dir;out.mkdir(exist_ok=False)
    before=inventory(a.baseline);after=inventory(a.candidate);dump(out/'baseline-inventory.json',before);dump(out/'candidate-inventory.json',after)
    changes={}
    def body(rows):return sorted((r['size'],r['sha256']) for r in rows)
    for name in before['functions'].keys()|after['functions'].keys():
        old=before['functions'].get(name,[]);new=after['functions'].get(name,[])
        if body(old)!=body(new):changes[name]=dict(before=old,after=new)
    b,cmd0=disassemble(a.baseline,out/'baseline-objdump.txt');c,cmd1=disassemble(a.candidate,out/'candidate-objdump.txt')
    normalized=[n for n in b.keys()|c.keys() if b.get(n)!=c.get(n)]
    with (out/'normalized-text.diff').open('w') as f:
        for name in sorted(normalized):f.writelines(difflib.unified_diff([x+'\n' for x in b.get(name,[])],[x+'\n' for x in c.get(name,[])],fromfile='baseline/'+name,tofile='candidate/'+name))
    dump(out/'function-body-changes.json',changes)
    object_changes={}
    for name in before['objects'].keys()|after['objects'].keys():
        fields=lambda rows:sorted((r['size'],r['section'],r['binding'],r['visibility']) for r in rows)
        if fields(before['objects'].get(name,[]))!=fields(after['objects'].get(name,[])):object_changes[name]=dict(before=before['objects'].get(name),after=after['objects'].get(name))
    report=dict(baseline_sha256=before['sha256'],candidate_sha256=after['sha256'],baseline_function_names=len(before['functions']),candidate_function_names=len(after['functions']),raw_changed_function_names=len(changes),normalized_text_changed_block_count=len(normalized),normalized_text_changed_blocks=sorted(normalized),object_shape_changes=object_changes,
        allocated_section_changes={n:dict(before=before['allocated_sections'].get(n),after=after['allocated_sections'].get(n)) for n in before['allocated_sections'].keys()|after['allocated_sections'].keys() if before['allocated_sections'].get(n)!=after['allocated_sections'].get(n)},disassembler_argv=[cmd0,cmd1],abi_proven=False,code_scope_proven=False,ready_for_image=False,
        limits=['Every sized STT_FUNC is inventoried byte-for-byte; symbol aliases and address movement can inflate changes.','Entire .text is disassembled; normalization erases only explicit address text with a named objdump target. Literal pools/PC-relative offsets/layout shifts remain diagnostic differences.','No relocation or semantic equivalence is inferred from normalized text. ARM exidx/relocations/data and full actual changes require review before image promotion.','No class-layout, execution, GC, hardware or memory proof.'])
    dump(out/'result.json',report);print(json.dumps({k:report[k] for k in ('baseline_function_names','candidate_function_names','raw_changed_function_names','normalized_text_changed_block_count','ready_for_image')}))
if __name__=='__main__':main()
