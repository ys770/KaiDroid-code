"""Run exact image50 paging function and original helper in local host models."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from check_oat_location_helpers import extract
from check_oat_rx_candidate import HELPER,SIGNATURE
from prepare_oat_rx_image50 import generate50,RAW,LIBART

FIXTURE='54f187ba1553ade78148afa870a40e565ba28779d17659241dd9fdec84f7b4aa'

def fixture50(raw):
    if hashlib.sha256(raw).hexdigest()!=FIXTURE:raise ValueError('Original host fixture changed')
    text=raw.decode()
    for old,new,count in [('1705782879u','368253102u',1),('3542819386u','936917115u',1),('9437174u','9436998u',1)]:
        if text.count(old)!=count:raise ValueError('Fixture tuple anchor changed')
        text=text.replace(old,new)
    anchor='  run("repeated-services",noop,true);'
    if text.count(anchor)!=1:raise ValueError('Fixture case anchor changed')
    extra='''  run("old44-services",[](auto& f,auto&,auto&,auto&) { f.header.checksum=1705782879u; },false);
  run("old44-framework",[](auto& f,auto&,auto&,auto&) { f.location="/system/framework/boot-framework.oat";f.header.checksum=3542819386u;f.header.offset=2023424u;f.size=9437174u; },false);
'''
    return text.replace(anchor,extra+anchor,1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('candidate-dir','layout-source','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();original=(a.candidate_dir/'original.cc').read_bytes();candidate=(a.candidate_dir/'candidate.cc').read_bytes()
    report=json.loads((a.candidate_dir/'candidate.json').read_text())
    if candidate!=generate50(original) or report['image_sha256']!=RAW or report['baseline_libart_sha256']!=LIBART or report['candidate_sha256']!=hashlib.sha256(candidate).hexdigest():raise ValueError('Unreviewed50 source/binding')
    if hashlib.sha256((a.candidate_dir/'candidate.patch').read_bytes()).hexdigest()!=report['patch_sha256']:raise ValueError('Patch changed')
    baseline_body=extract(original.decode(),SIGNATURE);candidate_body=extract(candidate.decode(),SIGNATURE)
    if candidate.decode().replace(candidate_body,baseline_body).replace('#include <cerrno>\n','',1)!=original.decode():raise ValueError('Changes outside one function/include')
    helper=a.layout_source.read_bytes()
    if hashlib.sha256(helper).hexdigest()!=HELPER:raise ValueError('Layout helper changed')
    body=extract(helper.decode(),'int DexLayoutSection::MadviseLargestPageAlignedRegion(')
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures/memory_oat_rx_host01.cc';template=fixture50(fixture.read_bytes())
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep output in workspace')
    out.mkdir(parents=True,exist_ok=False)
    def native(path):
        path=path.resolve();return '/mnt/'+path.drive[0].lower()+'/'+path.as_posix()[3:] if os.name=='nt' else str(path)
    prefix=['wsl.exe','--exec'] if os.name=='nt' else [];runs=[]
    for name,function,expect in [('baseline',baseline_body,0),('candidate',candidate_body,1)]:
        source=out/(name+'.cc');binary=out/name
        source.write_bytes(template.replace('// @EXACT_ADVICE_HELPER@',body).replace('// @EXACT_OAT_FUNCTION@',function).encode())
        command=prefix+['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-DEXPECT_RX='+str(expect),native(source),'-o',native(binary)]
        compile_result=subprocess.run(command,capture_output=True,timeout=60)
        for label,raw in [('stdout',compile_result.stdout),('stderr',compile_result.stderr)]:(out/(name+'-compile.'+label)).write_bytes(raw)
        compile_result.check_returncode()
        result=subprocess.run(prefix+[native(binary)],capture_output=True,timeout=15)
        for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:(out/(name+'-run.'+label)).write_bytes(raw)
        result.check_returncode();lines=result.stdout.decode().splitlines()
        if len(lines)!=20 or lines[-1]!='cases=19' or any(not line.endswith(' PASS') for line in lines[:-1]) or result.stderr:raise ValueError('Incomplete host controls')
        runs.append(dict(name=name,cases=19,compile_exit=0,run_exit=0,generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),compile_argv=command,output=lines))
    apply_root=out/'apply';target=apply_root/'art/runtime/oat_file.cc';target.parent.mkdir(parents=True);target.write_bytes(original)
    patch_runs=[]
    for name,flags in [('dry-run',['--dry-run']),('apply',[]),('reverse-dry-run',['--reverse','--dry-run'])]:
        command=prefix+['patch','--batch','--fuzz=0','--no-backup-if-mismatch','--directory',native(apply_root),'-p1','--input',native(a.candidate_dir/'candidate.patch'),*flags]
        result=subprocess.run(command,capture_output=True,timeout=15)
        for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:(out/(name+'.'+label)).write_bytes(raw)
        result.check_returncode()
        if result.stderr:raise ValueError('Patch emitted stderr')
        if target.read_bytes()!=(original if name=='dry-run' else candidate):raise ValueError('Patch application content differs')
        patch_runs.append(dict(name=name,argv=command,exit=0,stdout_sha256=hashlib.sha256(result.stdout).hexdigest()))
    r=dict(image=50,image_sha256=RAW,candidate_sha256=hashlib.sha256(candidate).hexdigest(),scope_gate_pass=True,patch_fuzz0_controls=patch_runs,
        helper_sha256=HELPER,original_fixture_sha256=FIXTURE,generated_fixture_sha256=hashlib.sha256(template.encode()).hexdigest(),runs=runs,built_target_libart=False,installed=False,
        limits=['Exact extracted baseline/candidate/helper run against modeled ART dependencies, not target ABI.','Intercepted madvise always fails; covers gating, inward bounds, existing calls, errno and repeated same owner, not real kernel behavior.','Old44 tuples explicitly rejected; exact50 positives and owner/path/header/state/lowRAM/option negatives tested.','No compile/link of Android libart, live owner selection, VM hints, RAM or latency acceptance.'])
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

if __name__=='__main__':main()
