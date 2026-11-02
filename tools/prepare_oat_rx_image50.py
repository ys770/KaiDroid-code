"""Prepare an unbuilt RX-only ART paging patch bound to immutable image50, offline."""
import argparse,difflib,hashlib,json,struct
from io import BytesIO
from pathlib import Path
from prepare_oat_rx_candidate import generate,ORIGINAL

RAW='4b876a7a4d1800fda46b43f96808125431ec72e2b6a2380e6ff209a42c30a1b9'
LIBART='cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62'
SOURCES={'art/runtime/oat.h':'47bf486dac1069ba5c602b571d3bf5a0f14eed235f6a5a68282570cb5ec4c245',
         'art/runtime/oat.cc':'8fa6f56b601a7c51ac6af31da16007b64ab60b6988d1b336350d9c8f39596488'}
TARGETS={
 '/system/framework/oat/arm/services.odex':dict(sha256='439f6185911f8deec64012c61c7ebf95709cc0ba5fc98db58af64b39de03ad1f',checksum=368253102,oat_size=12699918,code_offset=2895872,logical='/system/framework/oat/arm/services.odex'),
 '/system/framework/arm/boot-framework.oat':dict(sha256='5179aa73828270c5696c0e6e87352c861ea712196b14657cbd43cdee88b7513b',checksum=936917115,oat_size=9436998,code_offset=2023424,logical='/system/framework/boot-framework.oat')}

def sha(raw):return hashlib.sha256(raw).hexdigest()

def generate50(original):
    candidate=generate(original).decode()
    for old,new in [('1705782879u','368253102u'),('3542819386u','936917115u'),('9437174u','9436998u')]:
        if candidate.count(old)!=1:raise ValueError('Original44 candidate anchor changed')
        candidate=candidate.replace(old,new,1)
    return candidate.encode()

def inspect_oat(raw):
    from elftools.elf.elffile import ELFFile
    elf=ELFFile(BytesIO(raw))
    if elf.elfclass!=32 or not elf.little_endian or elf['e_machine']!='EM_ARM':raise ValueError('Require ARM32 little-endian ELF')
    symbols={}
    for section in elf.iter_sections():
        if section['sh_type']=='SHT_DYNSYM':
            for symbol in section.iter_symbols():
                if symbol.name in ('oatdata','oatexec','oatlastword'):
                    if symbol.name in symbols:raise ValueError('Duplicate OAT symbol')
                    symbols[symbol.name]=int(symbol['st_value'])
    if set(symbols)!={'oatdata','oatexec','oatlastword'}:raise ValueError('Missing OAT bounds')
    base=symbols['oatdata'];end=symbols['oatlastword']+4
    loads=[dict(vaddr=int(s['p_vaddr']),offset=int(s['p_offset']),filesz=int(s['p_filesz']),memsz=int(s['p_memsz']),flags=int(s['p_flags'])) for s in elf.iter_segments() if s['p_type']=='PT_LOAD']
    header_load=[s for s in loads if s['vaddr']<=base and base+32<=s['vaddr']+s['filesz']]
    if len(header_load)!=1:raise ValueError('OAT header ownership differs')
    s=header_load[0];offset=s['offset']+base-s['vaddr']
    if raw[offset:offset+8]!=b'oat\n183\0':raise ValueError('Only source-reviewed OAT183 supported')
    checksum=struct.unpack_from('<I',raw,offset+8)[0];code=struct.unpack_from('<I',raw,offset+28)[0]
    start=base+code;aligned_start=(start+4095)//4096*4096;aligned_end=end//4096*4096
    if start!=symbols['oatexec'] or not base<start<end or aligned_start>=aligned_end:raise ValueError('Header/symbol bounds differ')
    # Require a single fully file-backed RX segment, and no overlapping load.
    owners=[s for s in loads if s['vaddr']<=aligned_start and aligned_end<=s['vaddr']+min(s['filesz'],s['memsz']) and s['flags']==5]
    overlap=[s for s in loads if s['vaddr']<aligned_end and s['vaddr']+s['memsz']>aligned_start]
    if len(owners)!=1 or overlap!=owners:raise ValueError('RX span has hole/writable/anonymous/overlapping ownership')
    return dict(sha256=sha(raw),checksum=checksum,oat_size=end-base,code_offset=code,symbols=symbols,load_segments=loads,
        aligned_rx_start=aligned_start,aligned_rx_end=aligned_end,aligned_rx_virtual_bytes=aligned_end-aligned_start,
        header_magic_version='oat183',single_file_backed_rx_segment=True)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('image','source','header-source-root','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();before=(a.image.stat().st_size,a.image.stat().st_mtime_ns)
    with a.image.open('rb') as f:actual=hashlib.file_digest(f,'sha256').hexdigest()
    if before[0]!=834666496 or actual!=RAW:raise ValueError('Require exact raw50')
    for name,pin in SOURCES.items():
        if sha((a.header_source_root/name).read_bytes())!=pin:raise ValueError('Header layout source changed')
    original=a.source.read_bytes();candidate=generate50(original)
    from dissect.extfs import ExtFS
    artifacts={}
    with a.image.open('rb') as f:
        fs=ExtFS(f)
        if fs.get('/system/build.prop').open().read().splitlines().count(b'ro.kaidroid.image=50')!=1:raise ValueError('Wrong revision')
        if sha(fs.get('/system/apex/com.android.art.release/lib/libart.so').open().read())!=LIBART:raise ValueError('Baseline libart changed')
        for path,expected in TARGETS.items():
            row=inspect_oat(fs.get(path).open().read())
            if any(row[k]!=expected[k] for k in ('sha256','checksum','oat_size','code_offset')):raise ValueError('Reviewed50 artifact differs')
            artifacts[path]={**row,'logical_location':expected['logical']}
    if (a.image.stat().st_size,a.image.stat().st_mtime_ns)!=before:raise ValueError('Raw image changed during preparation')
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep output in workspace')
    out.mkdir(parents=True,exist_ok=False)
    patch=''.join(difflib.unified_diff(original.decode().splitlines(True),candidate.decode().splitlines(True),fromfile='a/art/runtime/oat_file.cc',tofile='b/art/runtime/oat_file.cc')).encode()
    for name,raw in [('original.cc',original),('candidate.cc',candidate),('candidate.patch',patch)]:out.joinpath(name).write_bytes(raw)
    result=dict(image=50,image_sha256=RAW,baseline_libart_sha256=LIBART,original_sha256=ORIGINAL,candidate_sha256=sha(candidate),patch_sha256=sha(patch),header_source_sha256=SOURCES,artifacts=artifacts,
        scope=['cerrno include','one existing OatDexFile function; existing DEX/layout behavior retained','two exact50 RX artifacts only'],built_target_libart=False,installed=False,
        limits=['Fingerprint gates bind an experiment; CRC/size is not authentication.','Logical default boot location is source/helper reviewed, not a live OatFile observation.','Virtual advised bytes are not resident pages or RAM savings.','No target compile, ABI/code diff, runtime hint/performance or hardware acceptance.','Original44 candidate remains separate; future preopt changes require another exact rebind.'])
    (out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
