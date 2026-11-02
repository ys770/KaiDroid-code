"""Offline epoch-bounded candidate lifecycle/LMK analysis; no device or host APIs."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[2]
SESSION=ROOT/'artifacts/runtime/image58-contacts-permission-session01'
TRIAL=ROOT/'artifacts/runtime/image58-contacts-permission-list01'
LINE=re.compile(r'\s*(?P<epoch>\d+\.\d{3})\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s+(?P<level>[VDIWEF])\s+(?P<tag>[^:]+): (?P<message>.*)')
START=re.compile(r'Start proc (\d+):([^/]+)/\S+ for (.*?) \{')
KILL=re.compile(r"Kill '([^']+)' \((\d+)\), uid (\d+), oom_adj (-?\d+) to free (\d+)kB")
DEATH=re.compile(r'Process ([^ ]+) \(pid (\d+)\) has died: (.*)')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def epoch_ms(value):
    whole,fraction=str(value).split('.') if '.' in str(value) else (str(value),'0')
    return int(whole)*1000+int(fraction.ljust(3,'0'))


def extract(raw,lower_bound):
    fresh=[];prefix=[];headers=[]
    for number,line in enumerate(raw.splitlines(keepends=True),1):
        text=line.decode('utf-8',errors='replace').rstrip('\r\n')
        match=LINE.fullmatch(text)
        if not match:
            headers.append(number)
            continue
        row=match.groupdict();row.update(line=number,tag=row['tag'].strip(),raw=text,epoch_ms=epoch_ms(row['epoch']))
        row['session_ms']=row['epoch_ms']-epoch_ms(lower_bound)
        if row['epoch_ms']<epoch_ms(lower_bound):
            prefix.append(number)
        else:fresh.append((row,line))
    events=[row for row,line in fresh]
    starts=[];kills=[];deaths=[];stops=[];manual_kills=[]
    for row in events:
        message=row['message']
        if row['tag']=='ActivityManager':
            match=START.match(message)
            if match:starts.append(dict(line=row['line'],epoch=row['epoch'],pid=int(match[1]),name=match[2],reason=match[3]))
            match=DEATH.fullmatch(message)
            if match:deaths.append(dict(line=row['line'],epoch=row['epoch'],name=match[1],pid=int(match[2]),reported_importance=match[3].strip()))
            match=re.match(r'Force stopping (\S+) appid=\d+ user=0: from pid (\d+)',message)
            if match:stops.append(dict(line=row['line'],epoch=row['epoch'],name=match[1],requester_pid=int(match[2])))
            if message.startswith('Killing '):manual_kills.append(row)
        if row['tag']=='lowmemorykiller':
            match=KILL.fullmatch(message)
            if match:kills.append(dict(line=row['line'],epoch=row['epoch'],name=match[1],pid=int(match[2]),uid=int(match[3]),LMK_reported_adj=int(match[4]),LMK_reported_kib=int(match[5])))
    for kill in kills:
        prior=[row for row in starts if row['pid']==kill['pid'] and row['name']==kill['name'] and row['line']<kill['line']]
        if prior:
            kill['start']=prior[-1];kill['start_to_kill_ms']=epoch_ms(kill['epoch'])-epoch_ms(prior[-1]['epoch'])
        death=[row for row in deaths if row['pid']==kill['pid'] and row['name']==kill['name'] and row['line']>kill['line']]
        if death:
            kill['AMS_death']=death[0];kill['kill_to_AMS_death_ms']=epoch_ms(death[0]['epoch'])-epoch_ms(kill['epoch'])
        later=[row for row in starts if row['name']==kill['name'] and row['line']>kill['line']]
        if later:
            kill['next_same_name_start']=later[0];kill['kill_to_next_same_name_start_ms']=epoch_ms(later[0]['epoch'])-epoch_ms(kill['epoch'])
    negative={name:[r['line'] for r in events if re.search(pattern,r['message'],re.I)] for name,pattern in {
        'finishing_activity_start':r'startActivity called from finishing',
        'no_package_null':r'No package:\s*null',
        'fatal_java':r'^FATAL EXCEPTION',
        'ANR':r'^ANR in ',
        'native_fatal':r'^Fatal signal ',
        'SQLite_corruption':r'SQLITE_CORRUPT|database disk image is malformed'}.items()}
    duplicates=[r for r in events if 'Duplicate finish request' in r['message']]
    selected=[r for r in events if r['tag']=='lowmemorykiller' or (r['tag']=='ActivityManager' and any(term in r['message'] for term in ('Start proc ',' has died:','Force stopping ','Killing ','Low on memory:','ZRAM:','Free RAM:'))) or
              any(term in r['message'] for term in ('PeopleActivity > onCreate','PeopleActivity > onResume','GrantPermissionsActivity:','Permission grant result','Logged buttons presented','Duplicate finish request','Displayed com.android.permissioncontroller','WAL enabled for','updateUseStrictPhoneNumberComparison','START u0'))]
    return dict(lower_bound_epoch=str(lower_bound),raw_lines=len(raw.splitlines()),fresh_lines=len(fresh),excluded_prebound_event_lines=prefix,non_event_lines=headers,
                filtered_raw_sha256=sha(b''.join(line for row,line in fresh)),starts=starts,kills=kills,AMS_deaths=deaths,force_stops=stops,
                manual_AMS_kills=manual_kills,negative_screen_matches=negative,duplicate_finish_events=duplicates,selected_evidence=selected,
                pressure_counters_present=any('ZRAM:' in r['message'] or 'MemInfo:' in r['message'] or 'Low on memory:' in r['message'] for r in events))


def analyze(output):
    if output.exists():raise FileExistsError(output)
    paths=[SESSION/'start.json',SESSION/'logcat.stdout',TRIAL/'result.json',ROOT/'docs/evidence/image58-contacts-permission-list01.json',
           ROOT/'tools/trial_contacts_list.py',ROOT/'experiments/memory/contact-pressure-image58-03.json']
    captures={p:p.read_bytes() for p in paths}
    start=json.loads(captures[paths[0]])
    result=extract(captures[paths[1]],start['device_epoch'])
    evidence=json.loads(captures[paths[3]])
    original=json.loads(captures[paths[5]])
    if evidence['fresh_log_sha256']!=sha(captures[paths[1]]):raise ValueError('UI receipt and raw log hashes differ')
    expected=[(3877,905,14800),(3851,905,24052),(3897,905,21240),(4012,905,20752),(4041,905,10400)]
    if [(k['pid'],k['LMK_reported_adj'],k['LMK_reported_kib']) for k in result['kills']]!=expected:raise ValueError('Not the reviewed five-kill candidate capture')
    result.update(classification='candidate_contacts_functional_replay_and_pressure_observation',
                  inputs={p.relative_to(ROOT).as_posix():dict(sha256=sha(raw),bytes=len(raw)) for p,raw in captures.items()},
                  installed_apk_sha256=evidence['installed_apk_sha256'],image=evidence['image'],boot=evidence['boot'],trial=json.loads(captures[paths[2]]),
                  logical_provider_comparison=evidence['logical_provider_comparison'],
                  original_descriptive_counts=dict(kills=len(original['kills']),finishing_caller_warning_observed=True,no_package_null_observed=True),
                  comparison_is_matched=False,pressure_benefit_proven=False,LMK_selected_foreground_adj0_proven=False,
                  importance_transition_window_observed=True,phone_or_host_access=False,fix_implemented_by_memory_lane=False,savings_proven=False,
                  analyzer_sha256=sha(Path(__file__).read_bytes()))
    if any(sha(p.read_bytes())!=sha(raw) for p,raw in captures.items()):raise ValueError('Input changed during offline extraction')
    result['source_post_hashes_match']=True
    with output.open('x',encoding='utf-8',newline='\n') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(fresh_lines=result['fresh_lines'],kills=result['kills'],force_stops=result['force_stops'],negative_screen_matches=result['negative_screen_matches']),indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    analyze(parser.parse_args().output)
