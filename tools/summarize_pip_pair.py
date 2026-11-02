"""Offline comparison of complete protocol05 image49/50 arms and post-census controls."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from capture_data_apk_guard import parse_manifest
from capture_timed_memory_audit import start_ticks
from guard_pip_trial import BASE_UI, NEW_UI, FRAMEWORK, pip_dump
from summarize_memory_boot_pair import APK, compare
from summarize_madvise_boot_pair import apk_guard, startup
from summarize_dma_ion_capture import dma_buffers

SOURCES={
    'trial_memory_boot.py':'8beed3f63b0a2a1529182c9976c1ec8b0fb790ae8cd7624d3dacc4aa39af7f46',
    'observe_startup_light.py':'669de76d5b5e28333a55f47d4f3c48245bd5979d8efd813b29daa2b3361eeb33',
    'capture_timed_memory_audit.py':'4fe2f4b37392c92c232c75eab4b15d3c4e3e3855cbbb14d44682892d8ba87e67',
    'audit_memory.py':'495b87d1cb74e6be78fdb8352629c1a76ce5e14dccd9ad22e104e8b0e87c7509',
    'capture_data_apk_guard.py':'0af168694eaa5d44e60ee9a6e032ea5e5b40dec157c0e6b85869663c41b5a76a'}
FREEZE='185a28dd1a44b1a7543b8ec726a9670ccf1976e8bf54daee6a1ef181883b89d8'
ASSETS={
    '/system/framework/framework.jar':FRAMEWORK,
    '/system/framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
    '/system/framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d',
    '/system/priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
    '/data/system/users/0/wallpaper_info.xml':'52c1295a96020f70fe68bbed8ef3f7884730a0c17845b1187179d1467040a2db'}

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def asset_manifest(text):
    rows={}
    for line in text.splitlines():
        pin,path=line.split(None,1)
        if not re.fullmatch('[a-f0-9]{64}',pin) or path in rows or not path.startswith('/'):
            raise ValueError('Invalid/duplicate asset hash row')
        rows[path]=pin
    return rows

def full_apks(root,image,boot,expected):
    rows,report=apk_guard(root,image,boot)
    if rows!=expected or len(rows)!=19 or report.get('expected_match') is not True:
        raise ValueError('Full19 data APK paths/hashes differ')
    if len(report['commands'])!=3 or {c['label'] for c in report['commands']}!={'initial-identity','all-data-apks','terminal-identity'}:
        raise ValueError('APK command closure differs')
    for command in report['commands']:
        if (root/(command['label']+'.stderr')).read_bytes():raise ValueError('APK guard stderr')
    return dict(root=str(root),result_sha256=sha(root/'result.json'),manifest_sha256=report['manifest_sha256'])

def postguard(root,arm,image,configuration,expected):
    report=json.loads((root/'result.json').read_text());protocol=arm['protocol'];timing=arm['timing'];boot=protocol['boot']
    if not report['complete'] or not report['read_only'] or not report['post_census'] or report['image']!=image or report['boot']!=boot:
        raise ValueError('Incomplete/wrong postguard')
    names={'before','after','configuration','assets','feature','wallpaper-paths','wallpaper-properties','pip-service'}
    if set(report['files'])!={n+'.txt' for n in names}:raise ValueError('Postguard file closure differs')
    commands=report['commands']
    if len(commands)!=len(names) or {c['name'] for c in commands}!=names:raise ValueError('Postguard command closure differs')
    for command in commands:
        if command['exit']!=(1 if command['name']=='feature' else 0):raise ValueError('Postguard exit differs')
    for name in names:
        if sha(root/(name+'.txt'))!=report['files'][name+'.txt'] or (root/(name+'.stderr')).read_bytes():raise ValueError('Postguard raw hash/stderr mismatch')
    pids=list(map(int,protocol['measurement_pids']));ages=[]
    for name in ('before','after'):
        rows=(root/(name+'.txt')).read_text().splitlines()
        if len(rows)!=9 or rows[:6]!=[image,boot,'0','Enforcing',*map(str,pids)] or [start_ticks(rows[i+7],pids[i]) for i in range(2)]!=timing['process_start_ticks']:
            raise ValueError('Postguard process identity/lifetime differs')
        ages.append(float(rows[6].split()[0]))
    if ages[0]<timing['actual_snapshot_uptime']['after'] or ages[1]<ages[0] or report['guard_uptime']!=ages or report['processes']!=pids or report['start_ticks']!=timing['process_start_ticks']:
        raise ValueError('Postguard census ordering differs')
    if (root/'configuration.txt').read_text().splitlines()!=configuration:raise ValueError('Frozen configuration differs')
    assets=asset_manifest((root/'assets.txt').read_text())
    if assets!={**ASSETS,APK:BASE_UI if image=='49' else NEW_UI}:raise ValueError('Protected inputs differ')
    if (root/'feature.txt').read_text().strip()!='false':raise ValueError('PiP feature is not false')
    if (root/'wallpaper-paths.txt').read_text().splitlines()!=['/data/system/users/0/wallpaper_info.xml'] or (root/'wallpaper-properties.txt').read_text().strip():raise ValueError('Wallpaper selection differs')
    count=pip_dump((root/'pip-service.txt').read_text(),image)
    if count!=report['pip_manager_dump_count']:raise ValueError('PiP raw/reported count differs')
    if (root/'data-guard.stderr').read_bytes():raise ValueError('Nested APK helper stderr')
    data=full_apks(root/'data-apks',image,boot,expected)
    return dict(root=str(root),result_sha256=sha(root/'result.json'),raw_sha256=report['files'],guard_uptime=ages,pip_manager_dump_count=count,full_data_apks=data)

def analyze(a):
    if sha(a.freeze/'manifest.json')!=FREEZE:raise ValueError('Wrong freeze manifest')
    freeze=json.loads((a.freeze/'manifest.json').read_text())
    for name,pin in freeze['files'].items():
        if Path(name).name!=name or sha(a.freeze/name)!=pin:raise ValueError('Freeze file changed')
    bundle=json.loads((a.bundle/'protocol.json').read_text())
    if bundle['source05_sha256']!=SOURCES or bundle['freeze_manifest_sha256']!=FREEZE:raise ValueError('Wrong protocol05 bundle')
    for name,pin in SOURCES.items():
        if sha(a.bundle/'tools'/name)!=pin:raise ValueError('Protocol05 source changed')
    expected=parse_manifest((a.freeze/'data-apks.txt').read_text())
    if len(expected)!=19 or parse_manifest((a.bundle/'retained-data-apks.txt').read_text())!=expected:raise ValueError('Wrong frozen APK set')
    configuration=(a.freeze/'configuration.txt').read_text().splitlines()
    if len(configuration)!=13:raise ValueError('Wrong configuration schema')
    result=compare(a.baseline,a.candidate,baseline_image='49',candidate_image='50',expected_apk_changes={APK:(BASE_UI,NEW_UI)})
    failures=result['comparison_failures'];guards=[];post=[]
    for name,image,root,control in [('baseline','49',a.baseline,a.baseline_postguard),('candidate','50',a.candidate,a.candidate_postguard)]:
        arm=result[name];protocol=arm['protocol']
        if protocol['source_sha256']!=SOURCES or protocol.get('expected_madvise_random')!='true':raise ValueError('Wrong frozen05 arm/VM hint')
        config=protocol['initial_configuration'].splitlines()
        if len(config)!=8 or any(configuration[g]!=config[p] for g,p in [(0,4),(1,5),(2,6),(5,3),(7,7)]):raise ValueError('Protocol/freeze configuration differs')
        for label,boot in [('data-apks-before',protocol['initial_boot']),('data-apks-after',protocol['boot'])]:guards.append(full_apks(root/label,image,boot,expected))
        for path,digest in arm['apk_hashes'].items():
            if path.startswith('/data/app/') and expected.get(path)!=digest:raise ValueError('Core APK absent from full set')
        post.append(postguard(control,arm,image,configuration,expected))
        allocator=(root/'timed/census/allocators.txt').read_text()
        if allocator.count('\nDMA\n')!=1 or allocator.count('\nSLAB\n')!=1:raise ValueError('Allocator section closure differs')
        buffers=dma_buffers(allocator.split('\nDMA\n',1)[1].split('\nSLAB\n',1)[0])
        arm['dma_exported_objects']=len(buffers);arm['dma_exported_capacity_bytes']=sum(r['size_bytes'] for r in buffers)
    population=result['process_population_difference']
    if population['baseline_only'] or population['candidate_only']:failures.append('Process population differs')
    result.update(experiment='Unsupported-PiP SystemUI manager lazy construction; only reviewed49/50 APK change',
        eligible_for_descriptive_timed_idle_comparison=not failures,full_data_apk_guards=guards,post_census_controls=post,
        startup_observations={name:startup(root) for name,root in [('baseline',a.baseline),('candidate',a.candidate)]},
        freeze_manifest_sha256=FREEZE,retained_data_apk_count=19,
        analysis_source_sha256={n:sha(Path(__file__).with_name(n)) for n in ('summarize_pip_pair.py','guard_pip_trial.py','summarize_memory_boot_pair.py','summarize_memory_audit.py','summarize_madvise_boot_pair.py','capture_data_apk_guard.py')})
    result['limits'].extend(['PiP dump/lifecycle occur after the census; null manager control is mechanism evidence, not a RAM saving measurement. Lifecycle screenshots require owner visual review.',
        'DMA exported capacity is not proven physical allocation and may overlap other views. Do not add it to PSS or global occupied RAM.'])
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','baseline-postguard','candidate-postguard','freeze','bundle','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=analyze(a)
    with a.output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(eligible=result['eligible_for_descriptive_timed_idle_comparison'],failures=result['comparison_failures'],targets=[dict(command=r['command'],delta=r['delta']) for r in result['target_processes']]),indent=2))
