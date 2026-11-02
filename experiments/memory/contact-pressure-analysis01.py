"""Offline image58 Contacts evidence extraction. No subprocess, host or phone access."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
LOG=ROOT/'artifacts/runtime/image58-contacts-list01/people-logs.stdout'
WORKFLOW=ROOT/'docs/evidence/image58-contacts-workflows01.json'
ARTIFACTS=LOG.parent
LINE=re.compile(r'(?P<date>\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF]) (?P<tag>[^:]+): (?P<message>.*)')
KILL=re.compile(r"Kill '(?P<name>[^']+)' \((?P<pid>\d+)\), uid (?P<uid>\d+), oom_adj (?P<adj>-?\d+) to free (?P<reported_kib>\d+)kB")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def milliseconds(time):
    hour,minute,second=time.split(':')
    return int(hour)*3600000+int(minute)*60000+round(float(second)*1000)


def extract(raw):
    lines=raw.decode('utf-8',errors='replace').splitlines()
    events=[]
    for number,text in enumerate(lines,1):
        match=LINE.fullmatch(text)
        if match:
            row=match.groupdict()
            row.update(line=number,tag=row['tag'].strip(),pid=int(row['pid']),tid=int(row['tid']),raw=text)
            events.append(row)
    kills=[];starts=[];deaths=[]
    for row in events:
        if row['tag']=='lowmemorykiller':
            match=KILL.fullmatch(row['message'])
            if match:
                kill=match.groupdict()
                kill.update({key:int(kill[key]) for key in ('pid','uid','adj','reported_kib')})
                kill.update(line=row['line'],time=row['time'])
                kills.append(kill)
        elif row['tag']=='am_proc_start':
            fields=row['message'].strip('[]').split(',')
            if len(fields)>=6:
                starts.append(dict(line=row['line'],time=row['time'],pid=int(fields[1]),uid=int(fields[2]),name=fields[3],reason=fields[4]))
        elif row['tag']=='am_proc_died':
            fields=row['message'].strip('[]').split(',')
            if len(fields)==5:
                deaths.append(dict(line=row['line'],time=row['time'],pid=int(fields[1]),name=fields[2],adj=int(fields[3]),state=int(fields[4])))
    for kill in kills:
        started=[start for start in starts if start['pid']==kill['pid'] and start['name']==kill['name'] and start['line']<kill['line']]
        if started:
            kill['start']=started[-1]
            kill['start_to_kill_ms']=milliseconds(kill['time'])-milliseconds(started[-1]['time'])
        died=[death for death in deaths if death['pid']==kill['pid'] and death['name']==kill['name'] and death['line']>kill['line']]
        kill['death']=died[0] if died else None
        next_start=[start for start in starts if start['name']==kill['name'] and start['line']>kill['line']]
        if next_start:
            kill['next_same_name_start']=next_start[0]
            kill['kill_to_next_start_ms']=milliseconds(next_start[0]['time'])-milliseconds(kill['time'])
    evidence=[row for row in events if '12:37:13.000'<=row['time']<='12:38:36.999' and (
        row['tag'] in ('lowmemorykiller','killinfo','am_proc_start','am_proc_died','am_low_memory','am_pss')
        or (row['tag']=='ActivityManager' and ('12:37:16.059'<=row['time']<='12:37:16.060'))
        or any(term in row['message'] for term in ('startActivity called from finishing','No package: null','WAL enabled for','updateUseStrictPhoneNumberComparison','GrantPermissionsActivity','people','PeopleActivity','RequestPermissionsActivity')))]
    bad_patterns={name:[row['line'] for row in events if re.search(pattern,row['message'])] for name,pattern in {
        'ANR':r'^ANR in ', 'fatal_java':r'^FATAL EXCEPTION:', 'native_fatal':r'^Fatal signal ',
        'SQLite_corruption':r'SQLITE_CORRUPT|database disk image is malformed'}.items()}
    bad_patterns['am_anr']=[row['line'] for row in events if row['tag']=='am_anr']
    bad_patterns['provider_lost_process']=[row['line'] for row in events if row['tag']=='am_provider_lost_process']
    samples=[]
    for row in events:
        if row['tag']=='am_pss':
            fields=row['message'].strip('[]').split(',')
            if len(fields)==10 and fields[2]=='android.process.acore':
                samples.append(dict(line=row['line'],time=row['time'],pid=int(fields[0]),pss_bytes=int(fields[3]),
                                    uss_bytes=int(fields[4]),swap_pss_bytes=int(fields[5]),rss_bytes=int(fields[6]),process_state=int(fields[8])))
    pressure={}
    number=lambda text:int(text.replace(',',''))
    for row in events:
        if row['tag']!='ActivityManager' or not '12:37:16.059'<=row['time']<='12:37:16.060':
            continue
        message=row['message']
        match=re.search(r'ZRAM:\s+([\d,]+)K RAM,\s+([\d,]+)K swap total,\s+([\d,]+)K swap free',message)
        if match:
            pressure.update(time=row['time'],source_line=row['line'],zram_physical_kib=number(match[1]),swap_total_kib=number(match[2]),swap_free_kib=number(match[3]))
        match=re.search(r'([\d,]+)K free$',message)
        if match:pressure['meminfo_free_kib']=number(match[1])
        match=re.search(r'Free RAM:\s+([\d,]+)K',message)
        if match:pressure['reported_free_ram_kib']=number(match[1])
    if pressure:
        pressure.update(swap_used_kib=pressure['swap_total_kib']-pressure['swap_free_kib'],
                        swap_used_fraction=1-pressure['swap_free_kib']/pressure['swap_total_kib'],exact_LMK_trigger_proven=False)
        if kills:pressure['post_first_kill_delay_ms']=milliseconds(pressure['time'])-milliseconds(kills[0]['time'])
    return dict(total_lines=len(lines),parsed_events=len(events),kills=kills,selected_evidence=evidence,negative_screen_matches=bad_patterns,
                pressure_snapshot=pressure,later_acore_pss_samples=samples)


def analyze(output):
    if output.exists():
        raise FileExistsError(output)
    paths=[LOG,WORKFLOW,ARTIFACTS/'result.json',ARTIFACTS/'before-boot.stdout',ARTIFACTS/'after-boot.stdout',
           ARTIFACTS/'before-image.stdout',ARTIFACTS/'after-image.stdout']
    captured={path:path.read_bytes() for path in paths}
    result=extract(captured[LOG])
    workflow=json.loads(captured[WORKFLOW])
    result.update(classification='offline_contacts_pressure_observation',inputs={path.relative_to(ROOT).as_posix():dict(sha256=sha(raw),size=len(raw)) for path,raw in captured.items()},
                  boot=captured[ARTIFACTS/'before-boot.stdout'].decode().strip(),image=captured[ARTIFACTS/'before-image.stdout'].decode().strip(),
                  same_boot=captured[ARTIFACTS/'before-boot.stdout']==captured[ARTIFACTS/'after-boot.stdout'],
                  same_image=captured[ARTIFACTS/'before-image.stdout']==captured[ARTIFACTS/'after-image.stdout'],
                  trial=json.loads(captured[ARTIFACTS/'result.json']),provider_delta=workflow['provider_delta'],
                  no_phone_or_host_access=True,UI_fix_implemented_by_this_lane=False,LMK_caused_database_delta_proven=False,
                  resumed_foreground_process_kill_proven=False,foreground_startup_churn_observed=True,savings_proven=False)
    if [(kill['pid'],kill['adj'],kill['reported_kib']) for kill in result['kills']]!=[(328,905,19904),(401,905,21124),(748,905,12364),(844,905,19832)]:
        raise ValueError('Actual input differs from the reviewed four-kill capture')
    if any(sha(path.read_bytes())!=sha(raw) for path,raw in captured.items()):
        raise ValueError('Source input changed during offline analysis')
    result['source_post_hashes_match']=True
    result['analyzer_sha256']=sha(Path(__file__).read_bytes())
    with output.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(kills=result['kills'],same_boot=result['same_boot'],same_image=result['same_image'],source_post_hashes_match=True),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    analyze(parser.parse_args().output)
