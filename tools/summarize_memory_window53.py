"""Revalidate the bounded image53 census/maps lease and keep accounting views separate."""
import argparse,hashlib,json,re
from pathlib import Path
from summarize_guarded_memory_maps import analyze as maps
from summarize_memory_audit import summarize
from summarize_kernel_attribution import slabs
from summarize_dma_ion_capture import dma_buffers
BOOT='00000000-0000-0000-0000-000000000009'
FRAMEWORK='78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2'
UI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def analyze(root):
    window=json.loads((root/'window.json').read_text())
    if not window['complete'] or not window['read_only'] or window['changes_requested'] or window['image']!='53' or window['boot']!=BOOT or window['elapsed_seconds']>120:raise ValueError('Wrong/incomplete window')
    commands=window['commands']
    if [r['name'] for r in commands]!=['before','census','maps','after']:raise ValueError('Wrong command closure')
    for row in commands:
        name=row['name']
        if row['returncode'] or sha(root/(name+'.stdout'))!=row['stdout_sha256'] or (root/(name+'.stderr')).read_bytes():raise ValueError('Window hash/exit/stderr differs')
    identities=[]
    for name in ('before','after'):
        rows=(root/(name+'.stdout')).read_text().splitlines()
        if len(rows)!=11 or rows[:4]!=['53',BOOT,'0','Enforcing'] or rows[5].split()!=[FRAMEWORK,'/system/framework/framework.jar'] or rows[6].split()!=[UI,'/system/system_ext/priv-app/SystemUI/SystemUI.apk'] or list(map(int,rows[7:]))!=window['pids']:raise ValueError('Wrong identity/assets/PIDs')
        identities.append(float(rows[4].split()[0]))
    if identities!=[window['uptime_before'],window['uptime_after']]:raise ValueError('Wrong window uptime')
    root_c=root/'census';manifest=json.loads((root_c/'manifest.json').read_text());records=manifest['captures']
    names={'identity-before','identity-middle','identity-after','system-before','system-after','processes','services','allocators'}
    if manifest['image']!='53' or manifest['boot']!=BOOT or len(records)!=8 or {r['name'] for r in records}!=names:raise ValueError('Census closure differs')
    for row in records:
        if row.get('returncode')!=0 or sha(root_c/(row['name']+'.txt'))!=row['sha256'] or (root_c/(row['name']+'.stderr')).read_bytes():raise ValueError('Census hash/exit/stderr differs')
    for name in ('identity-before','identity-middle','identity-after'):
        if (root_c/(name+'.txt')).read_text().splitlines()!=['53',BOOT,'0']:raise ValueError('Census identity differs')
    census=summarize(root_c);mapping=maps(root/'maps','53',BOOT)
    if census['omitted']:raise ValueError('Census omitted process reads')
    processes=mapping['processes']
    if [p['process']['pid'] for p in processes]!=window['pids']:raise ValueError('Maps/census PIDs differ')
    raw=(root_c/'processes.txt').read_text();blocks={int(b.splitlines()[0]):b for b in re.split(r'^PROCESS ',raw,flags=re.M)[1:]}
    for p in processes:
        identity=p['process'];block=blocks[identity['pid']];first=block.splitlines()[1];last=block.split('STAT_AFTER\n',1)[1].splitlines()[0]
        if any(int(stat.rsplit(')',1)[1].split()[19])!=identity['start_ticks'] for stat in (first,last)):raise ValueError('Census/maps process lifetime differs')
        matches=[r for r in census['processes'] if r['pid']==identity['pid']]
        if len(matches)!=1 or matches[0]['command'].strip()!=identity['command']:raise ValueError('Census/maps command differs')
    ages=[float((root_c/('system-'+phase+'.txt')).read_text().split('UPTIME\n')[1].split()[0]) for phase in ('before','after')]
    meta=mapping['runtime_metadata']
    if not meta or not identities[0]<=ages[0]<=ages[1]<=meta['before']<=meta['after']<=identities[1]:raise ValueError('Diagnostic ordering differs')
    allocator=(root_c/'allocators.txt').read_text();cache=slabs(allocator);dma=dma_buffers(allocator.split('\nDMA\n',1)[1].split('\nSLAB\n',1)[0])
    return dict(image='53',boot=BOOT,complete=True,read_only=True,window_sha256=sha(root/'window.json'),framework_sha256=FRAMEWORK,systemui_sha256=UI,
        host_elapsed_seconds=window['elapsed_seconds'],device_uptime_bracket=identities,census_uptime_bracket=ages,map_uptime_bracket=[meta['before'],meta['after']],command_durations_seconds={r['name']:r['seconds'] for r in commands},
        census_manifest_sha256=sha(root_c/'manifest.json'),map_capture=mapping,census=census,slab_object_capacity_top12=cache[:12],dma_exported_objects=len(dma),dma_exported_capacity_bytes=sum(r['size_bytes'] for r in dma),
        analyzer_sha256=sha(Path(__file__)),source_sha256={n:sha(Path(__file__).with_name(n)) for n in ('audit_memory.py','capture_memory_maps.py','summarize_guarded_memory_maps.py','summarize_memory_maps.py','summarize_memory_audit.py')},
        limits=['Single exploratory state at~2506s boot age after prior UI work, not matched idle/coldboot/workload comparison.','Collection durations bound diagnostic time, not its isolated CPU/RAM cost; page faults/cache/swap drift include background and collector effects.','Census and four maps are sequential, even with guarded same-boot/lifetimes and explicit uptime ordering.','Managed/native/ART/graphics labels are attribution, not reachability, free allocator slack or achievable savings.','Logical SwapPss cannot be converted to process physical zram with a global compression ratio.','Slab object capacity and exported DMA capacity overlap other views and do not establish reclaimable or unique physical pages.','No input, GC, heapdump, service/policy/property/swap change, reboot or install. Read-only lease returned immediately after9.36s capture.','No whole-physical denominator or80percent saving established.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();r=analyze(a.capture)
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(complete=r['complete'],uptime=r['device_uptime_bracket'],processes=[dict(identity=p['process'],totals=p['total_KiB']) for p in r['map_capture']['processes']],dma_capacity=r['dma_exported_capacity_bytes']),indent=2))
