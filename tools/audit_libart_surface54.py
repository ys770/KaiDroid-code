"""Offline ELF interface/protection screen for a future ARM32 libart; not full ABI proof."""
import argparse,hashlib,json
from io import BytesIO
from pathlib import Path
from elftools.elf.elffile import ELFFile
from prepare_oat_rx_image50 import LIBART

def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return digest(json.dumps(value,sort_keys=True,separators=(',',':')).encode())

def surface(raw):
    elf=ELFFile(BytesIO(raw));dynamic=elf.get_section_by_name('.dynamic');symbols=elf.get_section_by_name('.dynsym')
    if dynamic is None or symbols is None:raise ValueError('Require dynamic ELF and symbols')
    versions={0:'LOCAL',1:'GLOBAL'}
    need=elf.get_section_by_name('.gnu.version_r')
    if need:
        strings=elf.get_section(need['sh_link'])
        for version,auxiliary in need.iter_versions():
            library=strings.get_string(version['vn_file'])
            for aux in auxiliary:
                index=int(aux['vna_other'])&0x7fff
                if index in versions:raise ValueError('Duplicate version index')
                versions[index]=library+'@'+aux.name
    definitions=elf.get_section_by_name('.gnu.version_d')
    if definitions:
        for definition,auxiliary in definitions.iter_versions():
            names=[a.name for a in auxiliary];index=int(definition['vd_ndx'])&0x7fff
            if not names or index in versions:raise ValueError('Duplicate/empty defined version')
            versions[index]='DEFINED@'+names[0]
    versym=elf.get_section_by_name('.gnu.version');imports=[];exports=[]
    for index,symbol in enumerate(symbols.iter_symbols()):
        if not symbol.name:continue
        ndx=versym.get_symbol(index)['ndx'] if versym else 1
        if isinstance(ndx,str):ndx={'VER_NDX_LOCAL':0,'VER_NDX_GLOBAL':1}[ndx]
        ndx=int(ndx);key=ndx&0x7fff
        if key not in versions:raise ValueError('Unresolved symbol version')
        row=dict(name=symbol.name,binding=symbol['st_info']['bind'],type=symbol['st_info']['type'],visibility=symbol['st_other']['visibility'],version=versions[key],version_hidden=bool(ndx&0x8000))
        if row['type'] in ('STT_OBJECT','STT_TLS'):row['size']=int(symbol['st_size'])
        (imports if symbol['st_shndx']=='SHN_UNDEF' else exports).append(row)
    sort=lambda rows:sorted(rows,key=lambda r:json.dumps(r,sort_keys=True))
    tags=list(dynamic.iter_tags())
    def names(kind,field):return [getattr(t,field) for t in tags if t.entry.d_tag==kind]
    def values(kind):return [int(t.entry.d_val) for t in tags if t.entry.d_tag==kind]
    segments=list(elf.iter_segments());attributes=elf.get_section_by_name('.ARM.attributes')
    return dict(elfclass=elf.elfclass,little_endian=elf.little_endian,machine=elf['e_machine'],type=elf['e_type'],flags=int(elf['e_flags']),
        soname=names('DT_SONAME','soname'),needed=names('DT_NEEDED','needed'),rpath=names('DT_RPATH','rpath'),runpath=names('DT_RUNPATH','runpath'),
        dynamic_flags=values('DT_FLAGS'),dynamic_flags1=values('DT_FLAGS_1'),arm_attributes_sha256=digest(attributes.data()) if attributes else None,
        load_flags=[int(s['p_flags']) for s in segments if s['p_type']=='PT_LOAD'],stack_flags=[int(s['p_flags']) for s in segments if s['p_type']=='PT_GNU_STACK'],relro_flags=[int(s['p_flags']) for s in segments if s['p_type']=='PT_GNU_RELRO'],
        writable_executable_loads=sum(bool(s['p_flags']&2 and s['p_flags']&1) for s in segments if s['p_type']=='PT_LOAD'),imports=sort(imports),exports=sort(exports))

def compare(before,after):
    failures=[]
    for name,row in [('baseline',before),('candidate',after)]:
        if (row['elfclass'],row['little_endian'],row['machine'],row['type'])!=(32,True,'EM_ARM','ET_DYN'):failures.append(name+' is not ARM32 little-endian shared ELF')
        if row['writable_executable_loads'] or not row['relro_flags'] or row['stack_flags']!=[6]:failures.append(name+' W^X/RELRO/stack screen failed')
    for key in before:
        if before[key]!=after.get(key):failures.append('Changed '+key)
    return failures

def brief(row):
    return {**{k:v for k,v in row.items() if k not in ('imports','exports')},**{n:dict(count=len(row[n]),canonical_sha256=canonical(row[n])) for n in ('imports','exports')}}

def audit(baseline,candidate,candidate_sha):
    old=baseline.read_bytes();new=candidate.read_bytes()
    if digest(old)!=LIBART or digest(new)!=candidate_sha:raise ValueError('Input transfer/baseline hash differs')
    before=surface(old);after=surface(new);failures=compare(before,after)
    if old==new:failures.append('Candidate identical to baseline; changed function not established')
    return dict(baseline_sha256=LIBART,candidate_sha256=candidate_sha,interface_protection_screen_pass=not failures,failures=failures,baseline=brief(before),candidate=brief(after),
        analyzer_sha256=digest(Path(__file__).read_bytes()),abi_proven=False,code_scope_proven=False,ready_for_image=False,
        limits=['Exact dynamic symbol names/binding/type/visibility/versions and exported object/TLS sizes; function sizes/addresses may change and are not compared.','Mangled names and ELF surfaces do not prove class layouts, inline contracts, implementation correctness or ABI compatibility.','Normalized changed-function/body/relocation audit against stripped+unstripped objects remains mandatory; identical binary rejects the screen.','Unchanged protection flags do not prove all layout ranges or runtime APEX selection. Full ELF/code/image/boot/functional/performance checks remain separate.','No build, host/phone action, installation, runtime acceptance or saving claim.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('baseline','candidate','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True);a=p.parse_args();r=audit(a.baseline,a.candidate,a.candidate_sha256)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(screen_pass=r['interface_protection_screen_pass'],failures=r['failures'],abi_proven=False)))
    if not r['interface_protection_screen_pass']:raise SystemExit(1)
