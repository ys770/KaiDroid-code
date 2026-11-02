"""Compare only complete frozen46/47 wallpaper arms; never equate PSS/buffers with total RAM."""
import argparse
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re

from summarize_memory_boot_pair import compare
from summarize_madvise_boot_pair import apk_guard,startup
from summarize_dma_ion_capture import dma_buffers

APK='/system/system_ext/priv-app/SystemUI/SystemUI.apk'
OLD='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
NEW='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
SOURCES={'trial_memory_boot.py':'3c2fed19b7610d25acdd654972c659e82fbb5eec0ab4d7add727fcad50582728',
 'observe_startup_light.py':'89a3a82bc75ebd2aea017f08d79687260f8005210dd0ae5a038c75e350207290',
 'capture_timed_memory_audit.py':'4fe2f4b37392c92c232c75eab4b15d3c4e3e3855cbbb14d44682892d8ba87e67',
 'audit_memory.py':'495b87d1cb74e6be78fdb8352629c1a76ce5e14dccd9ad22e104e8b0e87c7509',
 'capture_data_apk_guard.py':'c4f545dc31fd419c769b9facb7a3dcf9cf56250e04e9417b45c2157248db2073'}
ASSETS={'/system/framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
 '/system/framework/framework.jar':'11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1',
 '/data/system/users/0/wallpaper_info.xml':'52c1295a96020f70fe68bbed8ef3f7884730a0c17845b1187179d1467040a2db'}


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def surface_rows(text):
    pattern=r'^\S+:\s+([\d.]+) KiB \|\s+(\d+)\s+\(\s*(\d+)\) x\s*(\d+) \|\s+(\d+) \|\s+(\d+) \| (\S+) \| com.android.systemui.ImageWallpaper#(\d+)$'
    rows=[]
    for kib,w,stride,h,layers,fmt,usage,suffix in re.findall(pattern,text,re.M):
        row=dict(reported_KiB=kib,width=int(w),height=int(h),stride_pixels=int(stride),layers=int(layers),format=int(fmt),usage=usage,surface_generation=int(suffix))
        center=Decimal(kib)*1024
        row['reported_byte_rounding_interval']=[str(center-Decimal('0.005')*1024),str(center+Decimal('0.005')*1024)]
        row['conditional_RGB888_layout_bytes']=int(stride)*int(h)*int(layers)*3 if int(fmt)==3 else None
        rows.append(row)
    if not rows:raise ValueError('No named ImageWallpaper allocation')
    return rows


def capture(root,arm,image):
    report=json.loads((root/'result.json').read_text())
    protocol=arm['protocol'];timing=arm['timing'];pids=list(map(int,protocol['measurement_pids']))
    if not report['complete'] or not report.get('read_only') or not report.get('post_census') or report['image']!=image or report['boot']!=protocol['boot']:
        raise ValueError('Post-census capture identity/completion differs')
    required={'before.txt','after.txt','window.txt','wallpaper.txt','surfaceflinger.txt','dmabuf.txt','power.txt','launcher.png'}
    if set(report['files'])!=required:raise ValueError('Post-census file closure differs')
    for name,pin in report['files'].items():
        if sha(root/name)!=pin or (root/(name+'.stderr')).read_bytes():raise ValueError('Post-census raw hash/stderr mismatch')
    ages=[]
    for name in ['before.txt','after.txt']:
        lines=(root/name).read_text().splitlines()
        if len(lines)!=9 or lines[:6]!=[image,protocol['boot'],'0','Enforcing',*map(str,pids)]:raise ValueError('Post-census raw identity differs')
        for line,pid,start in zip(lines[7:],pids,timing['process_start_ticks']):
            if not line.startswith(str(pid)+' (') or int(line.rsplit(')',1)[1].split()[19])!=start:raise ValueError('Post-census PID lifetime differs')
        ages.append(float(lines[6].split()[0]))
    if ages[0]<timing['actual_snapshot_uptime']['after'] or ages[1]<ages[0]:raise ValueError('Capture not after census')
    window=(root/'window.txt').read_text()
    if not any('mCurrentFocus=' in line and 'com.android.launcher3/com.android.launcher3.Launcher' in line for line in window.splitlines()):raise ValueError('Post-census Launcher focus differs')
    displays=re.findall(r'^\s*mDisplayInfo=(.*displayId 0.*)$',window,re.M)
    if len(displays)!=1 or 'real 240 x 320' not in displays[0] or 'rotation 0, state ON' not in displays[0]:raise ValueError('Default display state differs')
    modes=re.search(r'modes \[([^]]*)\]',displays[0])
    if not modes or re.findall(r'width=(\d+), height=(\d+)',modes[1])!=[('240','320')]:raise ValueError('Physical display modes differ')
    power=(root/'power.txt').read_text();power_state={}
    for key,expected in {'mWakefulness':'Awake','mIsPowered':'true','mPlugType':'2','mStayOn':'true','mDisplayReady':'true'}.items():
        values=re.findall(r'^\s+'+key+r'=(\S+)',power,re.M)
        if not values or set(values)!={expected}:raise ValueError('Power state differs: '+key)
        power_state[key]=expected
    if 'Display Power: state=ON' not in power:raise ValueError('Display power not ON')
    wallpaper=(root/'wallpaper.txt').read_text()
    if not all(value in wallpaper for value in ['User 0: id=2','mWidth=480  mHeight=320','mWallpaperComponent=ComponentInfo{com.android.systemui/com.android.systemui.ImageWallpaper}']):raise ValueError('Wallpaper state differs')
    rows=surface_rows((root/'surfaceflinger.txt').read_text());expected=(1243,1024) if image=='46' else (429,353)
    if any((r['width'],r['height'])!=expected for r in rows):raise ValueError('Wrong or mixed wallpaper buffer geometry for arm')
    dma=dma_buffers((root/'dmabuf.txt').read_text())
    return dict(root=str(root),result_sha256=sha(root/'result.json'),file_sha256=report['files'],capture_uptime=ages,power_state=power_state,wallpaper_buffers=rows,
        summed_conditional_RGB888_layout_bytes=sum(r['conditional_RGB888_layout_bytes'] for r in rows) if all(r['conditional_RGB888_layout_bytes'] is not None for r in rows) else None,
        dma_exported_objects=len(dma),dma_exported_capacity_bytes=sum(r['size_bytes'] for r in dma),
        limits=['SF capacity text is rounded and conditional layout arithmetic is not physical allocation.',
                'DMA exported capacities may overlap physical mappings/other driver views; no cross-view object identity is established.',
                'Post-census capture is sequential and later than the PSS/global snapshots.'])


def asset_guard(root,arm,image):
    report=json.loads((root/'result.json').read_text());boot=arm['protocol']['boot']
    if not report['complete'] or not report['read_only'] or report['image']!=image or report['boot']!=boot:raise ValueError('Asset guard identity/completion differs')
    names=['before','after','assets','configuration','wallpaper-paths','wallpaper-property']
    for name in names:
        if (root/(name+'.stderr')).read_bytes():raise ValueError('Asset guard stderr')
    for name in ['before','after']:
        if (root/(name+'.txt')).read_text().splitlines()!=[image,boot,'0','Enforcing']:raise ValueError('Asset guard raw identity differs')
    assets={line.split(None,1)[1]:line.split(None,1)[0] for line in (root/'assets.txt').read_text().splitlines()}
    if assets!=ASSETS or (root/'wallpaper-paths.txt').read_text().splitlines()!=['/data/system/users/0/wallpaper_info.xml'] or (root/'wallpaper-property.txt').read_text().splitlines()!=['','']:
        raise ValueError('Default asset/info/user-file/property guards differ')
    config=(root/'configuration.txt').read_text().splitlines()
    protocol_config=arm['protocol']['initial_configuration'].splitlines()
    # Guard indices3/4 are rotation controls,6 is low_power; radios are instead
    # captured by protocol indices0/1. Compare only fields common to both schemas.
    if len(config)<10 or len(protocol_config)!=8 or config[8:10]!=['true','true'] or any(config[g]!=protocol_config[p] for g,p in [(0,4),(1,5),(2,6),(5,3),(7,7)]):
        raise ValueError('Asset guard configuration differs from protocol')
    return dict(root=str(root),assets=assets,configuration=config,result_sha256=sha(root/'result.json'),
                raw_sha256={name:sha(root/(name+'.txt')) for name in names},
                limit='Asset guard producer has no per-file hash manifest; raw hashes here bind the files inspected by this analysis.')


def analyze(a):
    required=[a.baseline/'protocol.json',a.candidate/'protocol.json',a.baseline_post/'result.json',a.candidate_post/'result.json',a.baseline_guard/'result.json',a.candidate_guard/'result.json']
    if not all(p.is_file() for p in required):raise ValueError('Complete46 AND47 protocol/post-census/asset-guard artifacts required; no partial comparison')
    result=compare(a.baseline,a.candidate,baseline_image='46',candidate_image='47',expected_apk_changes={APK:(OLD,NEW)})
    failures=result['comparison_failures'];manifests=[];full_guards=[];posts=[];assets=[]
    for image,root,post,guard,name in [('46',a.baseline,a.baseline_post,a.baseline_guard,'baseline'),('47',a.candidate,a.candidate_post,a.candidate_guard,'candidate')]:
        arm=result[name]
        if arm['protocol']['source_sha256']!=SOURCES or arm['protocol'].get('expected_madvise_random')!='true':failures.append(name+' is not frozen04/trueVMhint')
        for label,boot in [('data-apks-before',arm['protocol']['initial_boot']),('data-apks-after',arm['protocol']['boot'])]:
            rows,report=apk_guard(root/label,image,boot);manifests.append(rows);full_guards.append(report)
            if len(rows)!=19 or not report.get('expected_match'):failures.append(name+' full19guard absent/mismatch')
        for path,pin in arm['apk_hashes'].items():
            if path.startswith('/data/app/') and manifests[-1].get(path)!=pin:failures.append(name+' core APK absent from full19')
        posts.append(capture(post,arm,image));assets.append(asset_guard(guard,arm,image))
    if any(rows!=manifests[0] for rows in manifests[1:]):failures.append('Full retained data APK paths/content differ')
    if any(result['process_population_difference'].values()):failures.append('Process command population differs')
    if assets[0]['configuration']!=assets[1]['configuration']:failures.append('Full post-guard/display configuration differs')
    profiles=[{(r['format'],r['layers'],r['usage']) for r in post['wallpaper_buffers']} for post in posts]
    if profiles[0]!=profiles[1]:failures.append('Wallpaper pixel/layer/usage profile differs; visual review required')
    result.update(experiment='Only bounded wallpaper SystemUI APK plus image revision46->47',
        eligible_for_descriptive_timed_idle_comparison=not failures,full_data_apk_guards=full_guards,post_census_captures=posts,asset_guards=assets,
        startup_observations=dict(baseline=startup(a.baseline),candidate=startup(a.candidate)),
        allocator_deltas=dict(post_dma_exported_capacity_bytes=posts[1]['dma_exported_capacity_bytes']-posts[0]['dma_exported_capacity_bytes'],
             conditional_RGB888_layout_bytes=(posts[1]['summed_conditional_RGB888_layout_bytes']-posts[0]['summed_conditional_RGB888_layout_bytes']) if all(p['summed_conditional_RGB888_layout_bytes'] is not None for p in posts) else None),
        analysis_source_sha256={name:sha(Path(__file__).with_name(name)) for name in ['summarize_wallpaper_pair.py','summarize_memory_boot_pair.py','summarize_memory_audit.py','summarize_madvise_boot_pair.py','summarize_dma_ion_capture.py']})
    result['limits']+=['Named buffer dimensions/capacity changes do not independently prove unique physical savings; never add buffer/PSS/CMA/zram values.',
                       'Post capture has explicit uptime/PID linkage. Separate asset guard has boot/config linkage but no raw uptime, so its exact ordering is not independently proved by this tool.',
                       'One pair is descriptive, not p50/p95 or causal latency/whole-phone working-set proof. Visual/crop/zoom/GL lifecycle and all hardware remain separate.',
                       'Source image closure/install/bootchain verification is external to this pair tool. Default resource selection remains inferred, not API-observed.']
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['baseline','candidate','baseline-post','candidate-post','baseline-guard','candidate-guard','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=analyze(a)
    with a.output.open('x') as file:file.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(eligible=result['eligible_for_descriptive_timed_idle_comparison'],failures=result['comparison_failures'],attribution_delta_KiB=result['census_attribution_delta_KiB'],allocator_deltas=result['allocator_deltas']),indent=2))
