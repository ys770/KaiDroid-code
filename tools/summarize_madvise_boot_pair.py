"""Compare timed43/44 arms, full retained APK guards and recorded VMA hints."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from capture_data_apk_guard import parse_manifest
from summarize_dex_vma_hints import summarize as vmas
from summarize_memory_boot_pair import compare

SOURCES={
    'trial_memory_boot.py':'f077ed78bed56b1472bf56174bcb2ccfa7df2065f6a4b85acb39ec74d7b8b8d0',
    'observe_startup_light.py':'e82dfc84cd9916b02faee994f8cf4868ea3ce4b952053be03f9421312e07af9b',
    'capture_timed_memory_audit.py':'4fe2f4b37392c92c232c75eab4b15d3c4e3e3855cbbb14d44682892d8ba87e67',
    'audit_memory.py':'495b87d1cb74e6be78fdb8352629c1a76ce5e14dccd9ad22e104e8b0e87c7509'}


def startup(root):
    root=root/'startup'
    samples=root/'samples.jsonl'
    rows=[json.loads(line) for line in samples.read_text().splitlines()]
    successful=[r for r in rows if r.get('returncode')==0 and len(r.get('output',[]))>=6 and r['output'][2]=='1']
    if not successful:raise ValueError('No fully successful boot-complete observation')
    logs=sorted(root.glob('logcat*.txt'))
    lines=set(line for path in logs for line in path.read_text(errors='replace').splitlines())
    def events(tag,process):
        return sorted(line for line in lines if re.search(r'\b'+tag+r'\s*:',line) and process in line)
    return dict(first_fully_successful_boot_complete_uptime=float(successful[0]['output'][3].split()[0]),
        first_fully_successful_observer_elapsed=successful[0]['elapsed'],
        partial_boot_complete_samples=[dict(observer_elapsed=r['elapsed'],returncode=r.get('returncode'),output=r.get('output')) for r in rows if r.get('output',[])[2:3]==['1'] and r.get('returncode')!=0],
        systemui_anrs=events('am_anr','com.android.systemui'),
        systemui_deaths=events('am_proc_died','com.android.systemui'),
        bluetooth_deaths=events('am_proc_died','com.android.bluetooth'),
        raw_sha256={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in [samples]+logs},
        limits=['Coarse polling/partial transport output does not give exact boot-completion latency.',
                'Logcat segment overlap is deduplicated by exact event line; absence of events is bounded to captured logs.'])


def apk_guard(root,image,boot):
    report=json.loads((root/'result.json').read_text())
    if not report['complete'] or report['image']!=image or report['boot']!=boot:
        raise ValueError('Wrong/incomplete retained APK guard')
    for command in report['commands']:
        if command['returncode'] or hashlib.sha256((root/(command['label']+'.stdout')).read_bytes()).hexdigest()!=command['stdout_sha256']:
            raise ValueError('APK guard raw hash/exit mismatch')
    for label in ('initial-identity','terminal-identity'):
        if (root/(label+'.stdout')).read_text().splitlines()!=[image,boot,'0','Enforcing']:
            raise ValueError('APK guard raw identity mismatch')
    raw=(root/'manifest.txt').read_bytes()
    rows=parse_manifest(raw.decode())
    if hashlib.sha256(raw).hexdigest()!=report['manifest_sha256'] or len(rows)!=report['apk_count']:
        raise ValueError('APK guard manifest changed')
    if rows!=parse_manifest((root/'all-data-apks.stdout').read_text()):
        raise ValueError('APK guard normalized/raw rows differ')
    return rows,report


def analyze(args):
    result=compare(args.baseline,args.candidate,baseline_image='43',candidate_image='44',expected_apk_changes={})
    failures=result['comparison_failures']
    manifests=[]
    guards=[]
    advice=[]
    for name,image,before,after,maps in (
        ('baseline','43',args.baseline_apks_before,args.baseline_apks_after,args.baseline_vmas),
        ('candidate','44',args.candidate_apks_before,args.candidate_apks_after,args.candidate_vmas)):
        arm=result[name]
        if arm['protocol']['source_sha256']!=SOURCES:failures.append(name+' is not frozen protocol03')
        hint=arm['protocol'].get('expected_madvise_random')
        if (image=='43' and hint not in ('unset','false')) or (image=='44' and hint!='true'):
            failures.append(name+' has wrong VM-property guard')
        for root,boot in ((before,arm['protocol']['initial_boot']),(after,arm['protocol']['boot'])):
            rows,report=apk_guard(root,image,boot);manifests.append(rows);guards.append(report)
        for path,digest in arm['apk_hashes'].items():
            if path.startswith('/data/app/') and manifests[-1].get(path)!=digest:
                failures.append(name+' core APK is absent/different in full manifest')
        mapping=vmas(maps)
        if mapping['image']!=image or mapping['boot']!=arm['protocol']['boot']:
            raise ValueError('VMA capture belongs to another arm')
        processes={p['command']:p for p in mapping['processes']}
        for index,command in enumerate(('system_server','com.android.systemui')):
            if command not in processes or processes[command]['start_ticks']!=arm['timing']['process_start_ticks'][index]:
                raise ValueError('VMA process lifetime differs from census')
            target=[p for p in arm['census']['processes'] if p['command'].strip()==command]
            if len(target)!=1 or target[0]['pid']!=processes[command]['pid']:
                raise ValueError('VMA PID differs from census')
        advice.append(mapping)
    if any(manifest!=manifests[0] for manifest in manifests[1:]):failures.append('Full retained APK set/path/hash differs within/across arms')
    advice_rows=[]
    for command in ('system_server','com.android.systemui'):
        pair=[next(p for p in mapping['processes'] if p['command']==command)['backings'] for mapping in advice]
        for path in sorted(pair[0].keys()|pair[1].keys()):
            advice_rows.append(dict(command=command,path=path,baseline=pair[0].get(path),candidate=pair[1].get(path)))
    result.update(experiment='Single property dalvik.vm.madvise-random=false/unset -> true',
        eligible_for_descriptive_timed_idle_comparison=not failures,retained_data_apk_count=len(manifests[0]),
        full_data_apk_guards=guards,post_census_vma_captures=advice,vma_advice_comparison=advice_rows,
        hint_virtual_coverage_is_not_ram_saving=True)
    result['startup_observations']=dict(baseline=startup(args.baseline),candidate=startup(args.candidate))
    result['analysis_source_sha256']={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in
        ('summarize_madvise_boot_pair.py','summarize_memory_boot_pair.py','summarize_memory_audit.py','summarize_dex_vma_hints.py','capture_data_apk_guard.py')}
    result['limits'].append('Full APK hashes/paths are frozen, but complete mutable app data/thermal state is not. VMA rr coverage is not reduced resident RAM or eliminated I/O.')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','baseline-apks-before','baseline-apks-after',
                 'candidate-apks-before','candidate-apks-after','baseline-vmas','candidate-vmas','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();result=analyze(args)
    with args.output.open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(eligible=result['eligible_for_descriptive_timed_idle_comparison'],failures=result['comparison_failures'],
        totals=result['census_attribution_delta_KiB'],targets=[dict(command=p['command'],delta=p['delta']) for p in result['target_processes']]),indent=2))
