"""Execute exact ART app-image gate bodies locally; no Android binary or device use."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
from prepare_services_image53 import generate,SIGNATURE,SOURCE
from check_oat_location_helpers import extract

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('candidate-dir','output-dir'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();before=(a.candidate_dir/'original.cc').read_bytes();after=(a.candidate_dir/'candidate.cc').read_bytes();report=json.loads((a.candidate_dir/'candidate.json').read_text())
    if sha(a.candidate_dir/'original.cc')!=SOURCE or after!=generate(before) or sha(a.candidate_dir/'candidate.patch')!=report['patch_sha256']:raise ValueError('Unreviewed source/patch')
    body0=extract(before.decode(),SIGNATURE);body1=extract(after.decode(),SIGNATURE)
    caller='std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat('
    if extract(before.decode(),caller)!=extract(after.decode(),caller):raise ValueError('OAT acceptance/fallback caller changed')
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures/services_image53_host01.cc';template=fixture.read_text()
    if template.count('// @EXACT_FUNCTION@')!=1:raise ValueError('Fixture marker changed')
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep output in workspace')
    out.mkdir(parents=True,exist_ok=False)
    def native(path):
        path=path.resolve();return '/mnt/'+path.drive[0].lower()+'/'+path.as_posix()[3:] if os.name=='nt' else str(path)
    prefix=['wsl.exe','--exec'] if os.name=='nt' else [];runs=[]
    for name,body,flag in [('baseline',body0,0),('candidate',body1,1)]:
        source=out/(name+'.cc');binary=out/name;source.write_bytes(template.replace('// @EXACT_FUNCTION@',body).encode())
        cmd=prefix+['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-DEXPECT_SKIP='+str(flag),native(source),'-o',native(binary)]
        result=subprocess.run(cmd,capture_output=True,timeout=60)
        for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:(out/(name+'-compile.'+label)).write_bytes(raw)
        result.check_returncode()
        result=subprocess.run(prefix+[native(binary)],capture_output=True,timeout=15)
        for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:(out/(name+'-run.'+label)).write_bytes(raw)
        result.check_returncode();expected='cases=3456 gated='+('96 changed=15' if flag else '0 changed=0')+' PASS'
        if result.stdout.decode().strip()!=expected or result.stderr:raise ValueError('Host cases incomplete')
        runs.append(dict(name=name,cases=3456,compile_exit=0,run_exit=0,source_sha256=sha(source),compile_argv=cmd,output=result.stdout.decode().strip()))
    apply_root=out/'apply';target=apply_root/'art/runtime/oat_file_manager.cc';target.parent.mkdir(parents=True);target.write_bytes(before);patch_runs=[]
    for name,flags in [('dry-run',['--dry-run']),('apply',[]),('reverse-dry-run',['--reverse','--dry-run'])]:
        cmd=prefix+['patch','--batch','--fuzz=0','--no-backup-if-mismatch','--directory',native(apply_root),'-p1','--input',native(a.candidate_dir/'candidate.patch'),*flags]
        result=subprocess.run(cmd,capture_output=True,timeout=15)
        for label,raw in [('stdout',result.stdout),('stderr',result.stderr)]:(out/(name+'.'+label)).write_bytes(raw)
        result.check_returncode()
        if result.stderr or target.read_bytes()!=(before if name=='dry-run' else after):raise ValueError('Patch application differs')
        patch_runs.append(dict(name=name,argv=cmd,exit=0,stdout_sha256=hashlib.sha256(result.stdout).hexdigest()))
    r=dict(candidate_sha256=sha(a.candidate_dir/'candidate.cc'),patch_sha256=report['patch_sha256'],fixture_sha256=sha(fixture),unchanged_caller_sha256=report['unchanged_open_dex_function_sha256'],runs=runs,patch_fuzz0_controls=patch_runs,scope_gate_pass=True,android_libart_built=False,installed=False,
        limits=['Exact helper bodies with modeled ART types/runtime; not target ABI, class loading, GC or memory execution.','3456cases vary lowRAM/debug/executable/app-image-enable, all six retained-source collision states and exact/stale/bad artifact/null-heap controls.','96exact-artifact lowRAM executable cases enter the bypass gate;15return values change, while81were already false. Other artifact cases preserve original collision-dependent image behavior.','Caller acceptance/fallback source is unchanged, but actual Android fallback functionality, cost, startup and hardware require future testing.'])
    (out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))

if __name__=='__main__':main()
