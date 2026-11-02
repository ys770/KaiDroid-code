"""Execute exact baseline/candidate advice bodies with modeled ART owners on host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from check_oat_location_helpers import extract
from prepare_oat_rx_candidate import ORIGINAL, generate

HELPER='c16d23699d20714a927dd7d52598f246357f818d2ce85d4a75b0223426d5cd79'
SIGNATURE='void OatDexFile::MadviseDexFile('


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--candidate-dir',type=Path,required=True);p.add_argument('--layout-source',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True);a=p.parse_args()
    before=(a.candidate_dir/'original.cc').read_bytes();after=(a.candidate_dir/'candidate.cc').read_bytes()
    if hashlib.sha256(before).hexdigest()!=ORIGINAL or after!=generate(before):raise ValueError('Unreviewed candidate')
    baseline=extract(before.decode(),SIGNATURE);candidate=extract(after.decode(),SIGNATURE)
    reverted=after.decode().replace(candidate,baseline).replace('#include <cerrno>\n','',1)
    if reverted!=before.decode():raise ValueError('Changes outside one function and include')
    helper_raw=a.layout_source.read_bytes()
    if hashlib.sha256(helper_raw).hexdigest()!=HELPER:raise ValueError('Layout helper source changed')
    helper=extract(helper_raw.decode(),'int DexLayoutSection::MadviseLargestPageAlignedRegion(')
    fixture=Path(__file__).resolve().parents[1]/'tests/fixtures/memory_oat_rx_host01.cc'
    template=fixture.read_text()
    out=a.output_dir.resolve()
    if not out.is_relative_to(Path.cwd().resolve()):raise ValueError('Keep outputs inside workspace')
    out.mkdir(parents=True,exist_ok=False)
    def native(path):
        path=path.resolve()
        return '/mnt/'+path.drive[0].lower()+'/'+path.as_posix()[3:] if os.name=='nt' else str(path)
    prefix=['wsl.exe','--exec'] if os.name=='nt' else []
    runs=[]
    for name,body,expect in [('baseline',baseline,0),('candidate',candidate,1)]:
        source=out/(name+'.cc');binary=out/name
        source.write_bytes(template.replace('// @EXACT_ADVICE_HELPER@',helper).replace('// @EXACT_OAT_FUNCTION@',body).encode())
        command=prefix+['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-DEXPECT_RX='+str(expect),native(source),'-o',native(binary)]
        result=subprocess.run(command,capture_output=True,timeout=60)
        (out/(name+'-compile.stdout')).write_bytes(result.stdout);(out/(name+'-compile.stderr')).write_bytes(result.stderr);result.check_returncode()
        result=subprocess.run(prefix+[native(binary)],capture_output=True,timeout=15)
        (out/(name+'-run.stdout')).write_bytes(result.stdout);(out/(name+'-run.stderr')).write_bytes(result.stderr);result.check_returncode()
        lines=result.stdout.decode().splitlines()
        if lines[-1]!='cases=17':raise ValueError('Incomplete host controls')
        runs.append(dict(name=name,cases=17,compile_exit=0,run_exit=0,generated_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),output=lines))
    report=dict(original_sha256=ORIGINAL,candidate_sha256=hashlib.sha256(after).hexdigest(),
        original_helper_sha256=HELPER,fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(),
        scope_gate_pass=True,runs=runs,built_target_libart=False,installed=False,
        limits=['Host executable uses exact extracted functions/helper; owner/runtime/layout dependencies are modeled, not target ART ABI.',
                'madvise is intercepted and always fails: tests arithmetic/gating/errno/legacy call order, not real kernel flags or Android latency.',
                'Two positive artifact tuples and negative owner/location/header/size/offset/state/low-RAM/option cases are covered.',
                'Repeated invocation uses same expected range; no claim about Android mmap lock/VMA overhead.',
                'Target compile, symbol/import/ABI/code-diff, immutable image closure and hardware validation remain required.'])
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
