"""Compare one timed42/43 warmboot pair; attribution deltas are not whole-phone savings."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from summarize_memory_audit import summarize
from trial_memory_boot import hashes

OLD='f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'
NEW='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
APK='/system/system_ext/priv-app/SystemUI/SystemUI.apk'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def arm(root,image):
    root=Path(root);protocol=json.loads((root/'protocol.json').read_text());timing=json.loads((root/'timed/timing.json').read_text())
    if protocol['image']!=image or timing['image']!=image:raise ValueError('Wrong arm image')
    if not protocol['complete'] or protocol.get('error') or protocol.get('observer_exit')!=0 or protocol.get('timed_exit')!=0 or timing['state']!='complete' or timing.get('collector_exit')!=0:
        raise ValueError('Arm is incomplete or failed; do not compare partial data')
    if protocol['boot']!=timing['boot'] or not protocol['no_gc'] or not timing['no_gc']:
        raise ValueError('Wrong boot or GC policy')
    if protocol['source_sha256']['audit_memory.py']!=timing['collector_sha256']:
        raise ValueError('Collector source disagreement')
    def step(label):
        rows=[row for row in protocol['steps'] if row['label']==label]
        if len(rows)!=1 or rows[0]['returncode']!=0:raise ValueError('Missing/failed '+label)
        row=rows[0];name=row['stdout']
        if Path(name).name!=name:raise ValueError('Invalid evidence path')
        data=(root/name).read_bytes()
        if hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('Protocol output hash mismatch')
        return data.decode().replace('\r\n','\n').strip()
    initial=hashes(step('initial-apks'));terminal=hashes(step('terminal-apks'))
    if initial!=terminal or step('initial-configuration')!=step('terminal-configuration') or step('initial-configuration')!=protocol['initial_configuration']:
        raise ValueError('APK/configuration changed within arm')
    census=root/'timed/census';manifest=json.loads((census/'manifest.json').read_text())
    if manifest['image']!=image or manifest['boot']!=protocol['boot']:raise ValueError('Census identity disagreement')
    names={row['name'] for row in manifest['captures']}
    if names!={'identity-before','identity-middle','identity-after','system-before','system-after','processes','services','allocators'}:
        raise ValueError('Incomplete or unexpected census closure')
    for row in manifest['captures']:
        if row['returncode']!=0 or digest(census/(row['name']+'.txt'))!=row['sha256']:
            raise ValueError('Census command/hash failure')
    for name in ('identity-before','identity-middle','identity-after'):
        if (census/(name+'.txt')).read_text().splitlines()!=[image,protocol['boot'],'0']:raise ValueError('Census identity changed')
    result=summarize(census)
    for phase in ('before','after'):
        actual=float((census/('system-'+phase+'.txt')).read_text().split('UPTIME\n')[1].split()[0])
        if actual!=timing['actual_snapshot_uptime'][phase]:raise ValueError('Recorded census age differs')
    return dict(protocol=protocol,timing=timing,census=result,apk_hashes=initial,
                raw_manifest_sha256=digest(census/'manifest.json'),protocol_sha256=digest(root/'protocol.json'),
                timing_sha256=digest(root/'timed/timing.json'))


def compare(baseline,candidate,*,baseline_image='42',candidate_image='43',expected_apk_changes=None):
    if expected_apk_changes is None:expected_apk_changes={APK:(OLD,NEW)}
    before=arm(baseline,baseline_image);after=arm(candidate,candidate_image);failures=[]
    if before['protocol']['source_sha256']!=after['protocol']['source_sha256']:failures.append('Frozen source bundle differs')
    if before['protocol']['initial_configuration']!=after['protocol']['initial_configuration']:failures.append('Configuration differs across arms')
    if before['apk_hashes'].keys()!=after['apk_hashes'].keys():failures.append('APK paths differ')
    changed={key for key in before['apk_hashes'].keys()|after['apk_hashes'].keys() if before['apk_hashes'].get(key)!=after['apk_hashes'].get(key)}
    if changed!=set(expected_apk_changes) or any(before['apk_hashes'].get(path)!=old or after['apk_hashes'].get(path)!=new for path,(old,new) in expected_apk_changes.items()):failures.append('APK change differs from the reviewed candidate')
    for name,row in [('baseline',before),('candidate',after)]:
        if row['census']['omitted']:failures.append(name+' has omitted process reads')
        if row['timing']['target_launch_uptime']!=300 or abs(row['timing']['guard_uptime_before_collector']-300)>2:failures.append(name+' missed census timing')
        for target in (200,220,230):
            if abs(row['protocol']['intervention_ages'][str(target)]-target)>2:failures.append(name+' missed intervention timing')
    ages={phase:after['timing']['actual_snapshot_uptime'][phase]-before['timing']['actual_snapshot_uptime'][phase] for phase in ('before','after')}
    if abs(ages['before'])>2:failures.append('Snapshot start ages differ by more than2seconds')
    target=[]
    for name in ('com.android.systemui','system_server'):
        pairs=[]
        for row in (before,after):
            matched=[p for p in row['census']['processes'] if p['command'].strip()==name]
            if len(matched)!=1:raise ValueError('Missing/ambiguous target process')
            pairs.append(matched[0])
        old,new=pairs;delta={key:new[key]-old[key] for key in ('Pss','USS','SwapPss','Threads')}
        target.append(dict(command=name,baseline=old,candidate=new,delta=delta,
                           Pss_attribution_change_percent=100*(new['Pss']/old['Pss']-1)))
    population={}
    old_pop=Counter(p['command'].strip() for p in before['census']['processes']);new_pop=Counter(p['command'].strip() for p in after['census']['processes'])
    population['baseline_only']=list((old_pop-new_pop).elements());population['candidate_only']=list((new_pop-old_pop).elements())
    totals={key:after['census']['census_totals_KiB'][key]-before['census']['census_totals_KiB'][key] for key in ('Pss','USS','SwapPss')}
    snapshots=[]
    for i,phase in enumerate(('before','after')):
        old,new=before['census']['snapshots'][i],after['census']['snapshots'][i]
        snapshots.append(dict(phase=phase,baseline=old,candidate=new,delta={key:new[key]-old[key] for key in ('occupied_visible_KiB','zram_physical_KiB','logical_swap_used_KiB')}))
    return dict(eligible_for_descriptive_timed_idle_comparison=not failures,comparison_failures=failures,
                baseline=before,candidate=after,snapshot_age_differences_seconds=ages,target_processes=target,
                process_population_difference=population,census_attribution_delta_KiB=totals,global_snapshots=snapshots,
                whole_physical_working_set_denominator_frozen=False,savings_proven=False,
                limits=['One warmboot arm per image; no causal or tail-latency proof.',
                        'PSS/USS are sequential resident attribution, SwapPss is logical swap attribution, not physical RAM.',
                        'Occupied RAM includes reclaimable cache and observer perturbation; never add PSS/kernel/zram to it again.',
                        'Tool/config/APK/timing agreement does not prove complete app-data, thermal, driver or workload comparability.',
                        'Reserved memory and driver overlap coverage remain separate. No80percent whole-device result.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',type=Path,required=True);parser.add_argument('--candidate',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=compare(args.baseline,args.candidate)
    with args.output.open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(eligible=result['eligible_for_descriptive_timed_idle_comparison'],failures=result['comparison_failures'],targets=[dict(command=p['command'],delta=p['delta'],Pss_percent=p['Pss_attribution_change_percent']) for p in result['target_processes']]),indent=2))
