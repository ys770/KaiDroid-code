"""Prepare an isolated lazy-camera module with verified Q HIDL API headers."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from elftools.elf.elffile import ELFFile

HEADERS={
    'HidlLazyUtils.h':'c0608b4943117a69c102e57242d77406d9a83fdc7ef49a7da19dabf59e0e6c10',
    'LegacySupport.h':'8d45ab2807833ee0a57a7c279352d117ce17df72758589acbd55b324bc65dafd',
}
CTOR='_ZN7android8hardware20LazyServiceRegistrarC1Ev'
REGISTER='_ZN7android8hardware20LazyServiceRegistrar15registerServiceERKNS_2spINS_4hidl4base4V1_05IBaseEEERKNSt3__112basic_stringIcNSA_11char_traitsIcEENSA_9allocatorIcEEEE'
GET_INSTANCE='_ZN7android8hardware20LazyServiceRegistrar11getInstanceEv'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--headers',required=True,type=Path)
    p.add_argument('--libhidlbase',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    for name,digest in HEADERS.items():
        if hashlib.sha256((a.headers/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('Wrong pinned Q header: '+name)
    with a.libhidlbase.open('rb') as f:
        elf=ELFFile(f)
        if elf.elfclass!=32 or elf['e_machine']!='EM_ARM': raise ValueError('Need ARM32 library')
        exports={s.name for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
    if not {CTOR,REGISTER}<=exports: raise ValueError('Required Q registrar ABI absent')
    a.output.mkdir(parents=True,exist_ok=False)
    includes=a.output/'include/hidl'; includes.mkdir(parents=True)
    for name in HEADERS: shutil.copyfile(a.headers/name,includes/name)
    source=Path(__file__).resolve().parents[1]/'experiments/memory/lazy-camera'
    for name in ('service.cpp','Android.bp'): shutil.copyfile(source/name,a.output/name)
    report=dict(headers=HEADERS,libhidlbase_sha256=hashlib.sha256(a.libhidlbase.read_bytes()).hexdigest(),
                constructor_export=True,register_export=True,R_getInstance_export=GET_INSTANCE in exports,
                built=False,installed=False,scope='Source preparation and symbol-presence audit only, not complete ABI or camera lifecycle validation.')
    (a.output/'preparation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':
    main()
