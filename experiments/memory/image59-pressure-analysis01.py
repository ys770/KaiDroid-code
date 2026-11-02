"""Analyze terminal saved startup samples; never connect to a phone or host."""
import sys
sys.dont_write_bytecode=True
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from summarize_startup_process_io import parse_processes

COUNTERS=('pswpin','pswpout','pgmajfault','pgscan_direct','pgsteal_direct')
PROCESS_COUNTERS=('minor_faults','major_faults','user_ticks','system_ticks','read_bytes','write_bytes')


def sha(raw):return hashlib.sha256(raw).hexdigest()


def difference(before,after,keys):
    delta={key:after[key]-before[key] for key in keys}
    if any(value<0 for value in delta.values()):raise ValueError('Cumulative counter decreased')
    return delta


def metrics(records,expected_image,expected_boot):
    valid=[];invalid=[];tracks=defaultdict(list);incomplete=[]
    for index,row in enumerate(records):
        output=row.get('output',[])
        if row.get('returncode')!=0 or len(output)<4:
            invalid.append(index);continue
        if output[:2]!=[expected_image,expected_boot]:raise ValueError('Image/boot identity differs')
        values={}
        for line in row.get('pressure',[]):
            fields=line.split()
            if len(fields)>1 and fields[0].rstrip(':') in COUNTERS+('MemFree','MemAvailable','SwapTotal','SwapFree'):
                values[fields[0].rstrip(':')]=int(fields[1])
        if not all(key in values for key in COUNTERS+('MemFree','MemAvailable','SwapTotal','SwapFree')):
            raise ValueError('Incomplete pressure sample')
        sample=dict(index=index,uptime=float(output[3].split()[0]),observer_elapsed=row['elapsed'],boot_completed=output[2]=='1',**values)
        if valid and sample['uptime']<=valid[-1]['uptime']:raise ValueError('Uptime did not increase')
        valid.append(sample)
        for process in parse_processes(row.get('process_io',[])):
            if 'start_ticks' not in process or not all(key in process for key in PROCESS_COUNTERS):
                incomplete.append(dict(index=index,process=process));continue
            key=(process['name'],process['pid'],process['start_ticks'])
            tracks[key].append(dict(**process,uptime=sample['uptime'],sample_index=index))
    if len(valid)<2:raise ValueError('At least two complete samples required')
    intervals=[]
    for before,after in zip(valid,valid[1:]):
        seconds=after['uptime']-before['uptime'];delta=difference(before,after,COUNTERS)
        intervals.append(dict(start_uptime=before['uptime'],end_uptime=after['uptime'],seconds=round(seconds,3),delta=delta,
                              per_second={key:round(value/seconds,3) for key,value in delta.items()},
                              spans_unavailable_sample=after['index']!=before['index']+1))
    first,last=valid[0],valid[-1]
    processes=[]
    for (name,pid,start),rows in sorted(tracks.items()):
        before,after=rows[0],rows[-1]
        for p,q in zip(rows,rows[1:]):difference(p,q,PROCESS_COUNTERS)
        duration=after['uptime']-before['uptime']
        processes.append(dict(name=name,pid=pid,start_ticks=start,samples=len(rows),first_uptime=before['uptime'],last_uptime=after['uptime'],seconds=round(duration,3),
                              first={key:before[key] for key in PROCESS_COUNTERS+('VmRSS','VmSwap') if key in before},
                              last={key:after[key] for key in PROCESS_COUNTERS+('VmRSS','VmSwap') if key in after},
                              observed_delta=difference(before,after,PROCESS_COUNTERS),
                              read_MiB_per_second=round((after['read_bytes']-before['read_bytes'])/1048576/duration,3) if duration else None))
    complete=[row for row in valid if row['boot_completed']]
    bound=complete[0] if complete else None
    return dict(raw_samples=len(records),connected_pressure_samples=len(valid),unavailable_sample_indices=invalid,
                first_uptime=first['uptime'],last_uptime=last['uptime'],seconds=round(last['uptime']-first['uptime'],3),
                first_boot_completed_sample=bound,first_pressure=first,last_pressure=last,pressure_samples=valid,
                pressure_delta=difference(first,last,COUNTERS),pressure_intervals=intervals,
                minimum_mem_available=min(valid,key=lambda row:row['MemAvailable']),minimum_swap_free=min(valid,key=lambda row:row['SwapFree']),
                peak_rates={key:max(intervals,key=lambda interval:interval['per_second'][key]) for key in COUNTERS},
                after_first_boot_completed_delta=difference(bound,last,COUNTERS) if bound else None,
                processes=processes,incomplete_process_samples=incomplete,page_size_captured=False,clock_ticks_per_second_captured=False)


def logs(paths):
    seen=set();kills=[];bad=[];raw_lines=0;markers=[];dates=set();dexopt=[]
    for path in sorted(paths,key=lambda p:(p.name!='logcat.txt',p.name)):
        for number,line in enumerate(path.read_bytes().decode('utf-8',errors='replace').splitlines(),1):
            raw_lines+=1
            if line in seen:continue
            seen.add(line)
            if re.match(r'^\d\d-\d\d ',line):dates.add(line[:5])
            item=dict(file=path.name,line=number,text=line)
            match=re.search(r"lowmemorykiller\s*:\s*Kill '([^']+)' \((\d+)\), uid (\d+), oom_adj (-?\d+) to free (\d+)kB",line)
            if match:kills.append(dict(**item,name=match[1],pid=int(match[2]),adj=int(match[4]),reported_kib=int(match[5])))
            if re.search(r'\bam_anr\s*:|\bam_crash\s*:|ActivityManager:\s*ANR in |FATAL EXCEPTION|Fatal signal',line):bad.append(item)
            if re.search(r'boot_progress_ams_ready:|boot_progress_enable_screen:',line):markers.append(item)
            if 'dex2oat32:' in line and ('--compilation-reason=server-dexopt' in line or 'dex2oat took ' in line):dexopt.append(item)
    return dict(raw_lines=raw_lines,unique_full_lines=len(seen),duplicate_full_lines=raw_lines-len(seen),wall_date_labels=sorted(dates),
                LMK_events=kills,LMK_count=len(kills),LMK_adj_counts=dict(Counter(k['adj'] for k in kills)),LMK_package_counts=dict(Counter(k['name'] for k in kills)),
                retained_crash_ANR_fatal_matches=bad,boot_markers=markers,server_dexopt_events=dexopt,complete_startup_log_proven=False)


def analyze(output):
    if output.exists():raise FileExistsError(output)
    root=ROOT/'artifacts/runtime/image59-boot01';other=ROOT/'artifacts/runtime/image58-boot01/observation'
    # A terminal receipt is mandatory. Stable file sizes alone are insufficient.
    terminal=json.loads((root/'observation-result.json').read_text())
    paths=[root/'observation-result.json',root/'samples.jsonl',*sorted(root.glob('logcat*.txt')),
           other/'observation-result.json',other/'samples.jsonl',ROOT/'tools/summarize_startup_process_io.py',
           ROOT/'docs/evidence/image59-pack-terminal01.json']
    captured={p:p.read_bytes() for p in paths}
    terminal=json.loads(captured[root/'observation-result.json'])
    rows=[json.loads(line) for line in captured[root/'samples.jsonl'].splitlines() if line]
    result=metrics(rows,'59','00000000-0000-0000-0000-000000000002')
    if terminal['expected_image']!='59' or terminal['samples']!=len(rows) or terminal['connected_samples']!=result['connected_pressure_samples']:
        raise ValueError('Terminal receipt does not describe these samples')
    result.update(classification='terminal_partial_startup_pressure_observation',image=59,boot='00000000-0000-0000-0000-000000000002',
                  observer_terminal=terminal,logs=logs(list(root.glob('logcat*.txt'))),
                  capture_hashes={p.relative_to(ROOT).as_posix():dict(sha256=sha(raw),bytes=len(raw)) for p,raw in captured.items()},
                  observed_logcat_restarts=[dict(sample=index,previous_exit=row['previous_logcat_exit']) for index,row in enumerate(rows) if row.get('previous_logcat_exit') is not None],
                  physical_acceptance=False,matched_comparison_accepted=False,causal_regression_or_improvement_proven=False,savings_proven=False,phone_or_host_access=False)
    previous_rows=[json.loads(line) for line in captured[other/'samples.jsonl'].splitlines() if line]
    previous=metrics(previous_rows,'58','00000000-0000-0000-0000-000000000013')
    result['comparison_screen']=dict(candidate=str(other.relative_to(ROOT)),same_counter_fields=True,
        candidate_observed_uptime=[previous['first_uptime'],previous['last_uptime']],
        candidate_terminal=json.loads(captured[other/'observation-result.json']),
        full_match_proven=False,accepted=False,reasons=['No matched cold/data/cache/process-population baseline',
        'Single installation/startup observation per image, no counterbalanced repetition','Both log streams incomplete',
        'Associated boot/framework/services preopt files changed'],comparative_delta_computed=False)
    result['packaged_changed_file_closure']=json.loads(captured[ROOT/'docs/evidence/image59-pack-terminal01.json'])['outputs']['changed_file_closure']
    if any(sha(p.read_bytes())!=sha(raw) for p,raw in captured.items()):raise ValueError('Capture changed during offline analysis')
    result['source_post_hashes_match']=True;result['analyzer_sha256']=sha(Path(__file__).read_bytes())
    with output.open('x',encoding='utf-8',newline='\n') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps({key:result[key] for key in ('first_uptime','last_uptime','pressure_delta','after_first_boot_completed_delta','processes','observed_logcat_restarts')},indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);analyze(p.parse_args().output)
