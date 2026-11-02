"""Offline image50 smaps attribution and conservative exact RX subrange bounds."""
import argparse,hashlib,json,re
from pathlib import Path
from summarize_guarded_memory_maps import analyze as guarded
from summarize_memory_boot_pair import arm as timed_arm
from prepare_oat_rx_image50 import RAW,TARGETS
from rank_memory_image50 import PAIR

BOOT='00000000-0000-0000-0000-000000000015'
CANDIDATE='c92c6ec08fedd626dff6d1ae398203c6831180d77325dc5869a6ea1b953f5484'
PATCH='9b16f49e865f98f209b2a8c23f36ebfcaa6b1fbcbc3a10f17c34ba5d3341742b'
PREPARATION='e64af889a304b1438b1a288cac9e820fc62f13b4772fee24c3fb8841aa3f7c5e'
CAPTURE='893f56f6dcd8379692047088a139d3bc9a0ace5b6f13638db705584b960014da'
HEADER=re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+([0-9a-f]+)\s+([0-9a-f]+:[0-9a-f]+)\s+(\d+)(?:\s+(.*))?$')
METRICS=('Size','KernelPageSize','MMUPageSize','Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Swap','SwapPss','Referenced','Anonymous','Locked')

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def parse(text):
    rows=[]
    for line in text.splitlines():
        m=HEADER.fullmatch(line)
        if m:
            lo,hi=int(m[1],16),int(m[2],16)
            if hi<=lo or lo%4096 or hi%4096 or (rows and lo<rows[-1]['end']):raise ValueError('Invalid/overlapping VMA')
            rows.append(dict(start=lo,end=hi,permissions=m[3],file_offset=int(m[4],16),device=m[5],inode=int(m[6]),path=m[7] or '',metrics={}))
        elif rows:
            if line.startswith('VmFlags:'):
                if 'vm_flags' in rows[-1]:raise ValueError('Duplicate VmFlags')
                rows[-1]['vm_flags']=line.split()[1:]
            m=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
            if m and m[1] in METRICS:
                if m[1] in rows[-1]['metrics']:raise ValueError('Duplicate metric')
                rows[-1]['metrics'][m[1]]=int(m[2])
    if not rows:raise ValueError('Empty smaps')
    for row in rows:
        values=row['metrics'];size=(row['end']-row['start'])//1024
        if set(values)!=set(METRICS) or 'vm_flags' not in row or values['Size']!=size or values['KernelPageSize']!=4 or values['MMUPageSize']!=4:raise ValueError('Incomplete/non4KiB VMA')
        if values['Rss']>size or values['Pss']>values['Rss'] or values['Private_Clean']+values['Private_Dirty']>values['Rss']:raise ValueError('Invalid resident metrics')
    return rows

def bounds(metric_kib,overlap_bytes,vma_bytes,*,fractional=False):
    if not 0<overlap_bytes<=vma_bytes or overlap_bytes%4096 or vma_bytes%4096 or metric_kib<0 or metric_kib>vma_bytes//1024:raise ValueError('Invalid range/metric bound')
    inside=overlap_bytes//1024;outside=(vma_bytes-overlap_bytes)//1024
    # smaps PSS/SwapPss truncate fractional KiB; retain a conservative1KiB guard.
    return [max(0,metric_kib-outside),min(inside,metric_kib+(1 if fractional else 0))]

def target(rows,path,artifact):
    named=[r for r in rows if r['path']==path]
    if not named:return dict(path=path,mapped=False,whole_file=None,range=None)
    if len({(r['device'],r['inode']) for r in named})!=1 or named[0]['inode']<=0:raise ValueError('Mixed/unbacked file identity')
    lo,hi=artifact['aligned_rx_start'],artifact['aligned_rx_end']
    loads=[s for s in artifact['load_segments'] if s['flags']==5 and s['vaddr']<=lo and hi<=s['vaddr']+min(s['filesz'],s['memsz'])]
    if len(loads)!=1:raise ValueError('Prepared RX owner differs')
    load=loads[0];file_lo=load['offset']+lo-load['vaddr'];file_hi=file_lo+hi-lo
    segments=[]
    for row in named:
        vma_bytes=row['end']-row['start'];left=max(file_lo,row['file_offset']);right=min(file_hi,row['file_offset']+vma_bytes)
        if left>=right:continue
        if row['permissions']!='r-xp':raise ValueError('Proposed code intersects nonRX mapping')
        overlap=right-left;metrics=row['metrics']
        segments.append(dict(vma_start=hex(row['start']),vma_end=hex(row['end']),permissions=row['permissions'],vm_flags=row['vm_flags'],vma_file_offset=row['file_offset'],vma_bytes=vma_bytes,overlap_file_start=left,overlap_file_end=right,overlap_bytes=overlap,excluded_vma_bytes=vma_bytes-overlap,
            runtime_range=[hex(row['start']+left-row['file_offset']),hex(row['start']+right-row['file_offset'])],vma_metrics_KiB=metrics,
            exact_range_Rss_bounds_KiB=bounds(metrics['Rss'],overlap,vma_bytes),exact_range_Pss_bounds_KiB=bounds(metrics['Pss'],overlap,vma_bytes,fractional=True),
            exact_range_USS_bounds_KiB=bounds(metrics['Private_Clean']+metrics['Private_Dirty'],overlap,vma_bytes),
            exact_range_SwapPss_bounds_KiB=bounds(metrics['SwapPss'],overlap,vma_bytes,fractional=True)))
    segments.sort(key=lambda s:s['overlap_file_start']);cursor=file_lo
    for segment in segments:
        if segment['overlap_file_start']!=cursor:raise ValueError('Target has hole or duplicate mapping')
        cursor=segment['overlap_file_end']
    if cursor!=file_hi:raise ValueError('Target range not fully mapped')
    whole={k:sum(r['metrics'][k] for r in named) for k in ('Rss','Pss','Private_Clean','Private_Dirty','Swap','SwapPss')}
    range_report=dict(file_offset_range=[file_lo,file_hi],virtual_bytes=file_hi-file_lo,segments=segments,rr_virtual_bytes=sum(s['overlap_bytes'] for s in segments if 'rr' in s['vm_flags']))
    for key in ('Rss','Pss','USS','SwapPss'):range_report[key+'_bounds_KiB']=[sum(s['exact_range_'+key+'_bounds_KiB'][i] for s in segments) for i in (0,1)]
    return dict(path=path,mapped=True,artifact_sha256=artifact['sha256'],device=named[0]['device'],inode=named[0]['inode'],whole_file=dict(mapping_count=len(named),virtual_bytes=sum(r['end']-r['start'] for r in named),metrics_KiB=whole),range=range_report)

def analyze(a):
    if sha(a.pair)!=PAIR:raise ValueError('Require exact reviewed pair')
    if sha(a.preparation)!=PREPARATION or sha(a.capture/'manifest.json')!=CAPTURE:raise ValueError('Require exact candidate/capture evidence')
    pair=json.loads(a.pair.read_text());root=Path(pair['full_data_apk_guards'][2]['root']).parent
    arm=timed_arm(root,'50');manifest=guarded(a.capture,'50',BOOT)
    expected=[dict(pid=1173,command='system_server',start_ticks=2481),dict(pid=1368,command='com.android.systemui',start_ticks=3705)]
    if [p['process'] for p in manifest['processes']]!=expected or arm['protocol']['boot']!=BOOT or list(map(int,arm['protocol']['measurement_pids']))!=[1173,1368] or arm['timing']['process_start_ticks']!=[2481,3705]:raise ValueError('Different50 process lifetimes')
    preparation=json.loads(a.preparation.read_text())['preparation']
    if preparation['image_sha256']!=RAW or preparation['candidate_sha256']!=CANDIDATE or preparation['patch_sha256']!=PATCH:raise ValueError('Wrong frozen candidate')
    artifacts=preparation['artifacts']
    if set(artifacts)!=set(TARGETS):raise ValueError('Different target closure')
    for path,pins in TARGETS.items():
        if any(artifacts[path][key]!=pins[key] for key in ('sha256','checksum','oat_size','code_offset')):raise ValueError('Different prepared artifact')
    processes=[]
    for process in manifest['processes']:
        rows=parse((a.capture/(str(process['process']['pid'])+'-smaps.txt')).read_text())
        targets=[target(rows,path,artifact) for path,artifact in artifacts.items()]
        processes.append(dict(identity=process['process'],smaps_sha256=process['smaps_sha256'],process_total_KiB=process['total_KiB'],groups_KiB=process['groups_KiB'],targets=targets))
    return dict(image='50',boot=BOOT,source_capture=str(a.capture),manifest_sha256=manifest['manifest_sha256'],preparation_sha256=sha(a.preparation),timed_protocol_sha256=arm['protocol_sha256'],same_process_lifetime_as_timed_arm=True,candidate_sha256=CANDIDATE,candidate_patch_sha256=PATCH,processes=processes,
        analysis_source_sha256={n:sha(Path(__file__).with_name(n)) for n in ('analyze_oat_rx_residency50.py','summarize_guarded_memory_maps.py','summarize_memory_maps.py','summarize_memory_boot_pair.py')},
        limits=manifest['limits']+['Capture has no uptime; same boot/PID lifetime does not link these later values to the300s census or establish workload equality.','Live VMA path/device/inode identify mappings, not file content hashes; exact source ranges are conditional on the independently bound installed50 artifacts.','smaps gives VMA totals, not page-level residency: range bounds subtract at most the excluded page capacity and retain1KiB fractional PSS/SwapPss rounding guard.','Whole-file metrics include metadata/relro/other mappings; they are not exact proposed-range metrics.','RSS overlaps shared physical pages; PSS is proportional attribution. Cross-process sums are sequential and not unique whole-phone allocation.','rr flags describe VMA advice only; current absence is a baseline control, not proof of future selection or performance.','Resident code can be needed; these bounds are not removable bytes or a saving forecast. No candidate advice/build/phone operation occurs in this analysis.'],
        next_measurements=['Image50 candidate remains held; no build or capture is requested. A successor framework/preopt invalidates these tuples: rebind any future target to the actually accepted current image before considering a build.','Only after rebind/build/acceptance gates, owner-controlled matched warmboots with unchanged full19APK/config/collectors and300s noGC census.','After census, same-lifetime maps must establish exact file/range ownership, target rr coverage and untouched DEX/otherOAT/native/writable controls.','For exact sub-VMA RSS, bounded page-presence data for the same process ranges; record permissions and identity. Presence alone cannot give exact PSS or cross-process unique bytes: sharing/mapcount and PFN availability need separate treatment.','Keep kernel/cache/zram/global/resident/logicalswap views separate; compare faults/I/O/CPU and actual app/input/dialog/camera/recording latency; repeated rollback before promotion.'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('capture','pair','preparation','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();result=analyze(a)
    with a.output.open('x') as f:f.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps([dict(command=p['identity']['command'],targets=[dict(path=t['path'],mapped=t['mapped'],range={k:t['range'][k] for k in ('virtual_bytes','rr_virtual_bytes','Rss_bounds_KiB','Pss_bounds_KiB')} if t['mapped'] else None,whole_file=t['whole_file']) for t in p['targets']]) for p in result['processes']],indent=2))
