"""Identity-bound, read-only tracefs capability inspection. No trace data or control writes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

SERIAL='DEVICE_SERIAL_REQUIRED'
IMAGE='59'
ROOTS=('/sys/kernel/tracing','/sys/kernel/debug/tracing')
EVENTS=('oom:oom_score_adj_update','sched:sched_process_fork','sched:sched_process_exec','sched:sched_process_exit',
        'sched:sched_switch','lowmemorykiller:lowmemory_kill','binder:binder_transaction','binder:binder_transaction_received')
STATE_FILES=('tracing_on','current_tracer','trace_clock','buffer_size_kb','buffer_total_size_kb','events/enable')
MAX_RAW=65536
MAX_REPORT=32768
IDENTITY_SCRIPT='getprop ro.kaidroid.image\ncat /proc/sys/kernel/random/boot_id\nid -u\n'


def boot_id(value):
    if str(uuid.UUID(value))!=value:
        raise ValueError('Explicit canonical boot UUID required')
    return value


def script(expected_boot):
    boot_id(expected_boot)
    # The only interpolated caller value has passed canonical UUID validation.
    prefix='''[ "$(getprop ro.kaidroid.image)" = '59' ] || exit 73
[ "$(cat /proc/sys/kernel/random/boot_id)" = 'BOOT_UUID' ] || exit 74
'''.replace('BOOT_UUID',expected_boot)
    helpers='''tc_begin() {
  printf 'TC_BEGIN %s\nTC_STATUS %s\n' "$1" "$2"
}
tc_end() {
  printf '\nTC_RC %s\nTC_END %s\n' "$2" "$1"
}
tc_value() {
  tc_begin "$1" read
  printf '%s' "$2"
  tc_end "$1" 0
}
tc_file() {
  tc_key="$1"; tc_path="$2"; tc_limit="$3"
  if [ ! -e "$tc_path" ]; then
    tc_begin "$tc_key" absent_or_not_visible
    tc_end "$tc_key" 0
  elif [ ! -r "$tc_path" ]; then
    tc_begin "$tc_key" not_readable
    tc_end "$tc_key" 0
  else
    tc_begin "$tc_key" read
    head -c "$tc_limit" "$tc_path"
    tc_rc=$?
    tc_end "$tc_key" "$tc_rc"
  fi
}
tc_events() {
  tc_key="$1"; tc_path="$2"
  if [ ! -e "$tc_path" ]; then
    tc_begin "$tc_key" absent_or_not_visible
    tc_end "$tc_key" 0
  elif [ ! -r "$tc_path" ]; then
    tc_begin "$tc_key" not_readable
    tc_end "$tc_key" 0
  else
    tc_begin "$tc_key" read
    grep -E 'EVENT_PATTERN' "$tc_path"
    tc_rc=$?
    if [ "$tc_rc" = 1 ]; then tc_rc=0; fi
    tc_end "$tc_key" "$tc_rc"
  fi
}
tc_begin mounts read
grep -E ' - (tracefs|debugfs) ' /proc/self/mountinfo
tc_rc=$?
if [ "$tc_rc" = 1 ]; then tc_rc=0; fi
tc_end mounts "$tc_rc"
'''.replace('EVENT_PATTERN','^('+'|'.join(EVENTS)+')$')
    sections=[]
    for index,root in enumerate(ROOTS):
        lines=[f'tc_root=\'{root}\'',f'if [ -d "$tc_root" ]; then',f'  tc_value root{index}.visibility visible']
        for name in STATE_FILES:
            lines.append(f'  tc_file root{index}.state.{name.replace("/","_")} "$tc_root/{name}" 256')
        lines.append(f'  tc_events root{index}.available_events "$tc_root/available_events"')
        for event_index,event in enumerate(EVENTS):
            path=event.replace(':','/')
            lines.append(f'  tc_file root{index}.event{event_index}.enable "$tc_root/events/{path}/enable" 64')
        lines.append(f'  tc_file root{index}.oom_format "$tc_root/events/oom/oom_score_adj_update/format" 4096')
        lines += ['  tc_count=0; tc_more=0',
                  '  if [ -r "$tc_root/instances" ] && [ -x "$tc_root/instances" ]; then',
                  '    for tc_instance in "$tc_root"/instances/*; do',
                  '      [ -d "$tc_instance" ] || continue',
                  '      if [ "$tc_count" -ge 4 ]; then tc_more=1; break; fi',
                  f'      tc_value "root{index}.instance$tc_count.name" "${{tc_instance##*/}}"']
        for name in ('tracing_on','current_tracer','events/enable'):
            lines.append(f'      tc_file "root{index}.instance$tc_count.{name.replace("/","_")}" "$tc_instance/{name}" 256')
        lines += ['      tc_count=$((tc_count+1))','    done',
                  f'    tc_value root{index}.instances_state "inspected=$tc_count additional=$tc_more"','  else',
                  f'    tc_value root{index}.instances_state absent_or_not_readable','  fi','else',
                  f'  tc_value root{index}.visibility absent_or_not_visible','fi']
        sections.append('\n'.join(lines))
    return prefix+helpers+'\n'.join(sections)+'\n'


def valid_key(key):
    return bool(key=='mounts' or re.fullmatch(r'root[01]\.(visibility|available_events|oom_format|instances_state|state\.(tracing_on|current_tracer|trace_clock|buffer_size_kb|buffer_total_size_kb|events_enable)|event[0-7]\.enable|instance[0-3]\.(name|tracing_on|current_tracer|events_enable))',key))


def parse_frames(raw):
    if len(raw)>MAX_RAW:raise ValueError('Capability output exceeds bound')
    lines=raw.decode('utf-8',errors='replace').splitlines();result={};index=0
    while index<len(lines):
        if not lines[index].strip():index+=1;continue
        if not lines[index].startswith('TC_BEGIN '):raise ValueError('Unframed capability output')
        key=lines[index][9:];index+=1
        if not valid_key(key) or key in result:raise ValueError('Unexpected/duplicate capability key')
        if index>=len(lines) or not lines[index].startswith('TC_STATUS '):raise ValueError('Missing capability status')
        status=lines[index][10:];index+=1;data=[]
        if status not in ('read','not_readable','absent_or_not_visible'):raise ValueError('Unexpected capability status')
        while index<len(lines) and not lines[index].startswith('TC_RC '):data.append(lines[index]);index+=1
        if index>=len(lines) or not re.fullmatch(r'TC_RC \d+',lines[index]):raise ValueError('Missing read return code')
        rc=int(lines[index][6:]);index+=1
        if index>=len(lines) or lines[index]!='TC_END '+key:raise ValueError('Unclosed capability frame')
        index+=1
        value='\n'.join(data).rstrip('\n')
        limit=4096 if key.endswith('oom_format') else 64 if '.event' in key else 256
        result[key]=dict(status='read_error' if rc else status,returncode=rc,value=value,
                         potentially_truncated=len(value.encode('utf-8'))+2>=limit if key not in ('mounts','root0.available_events','root1.available_events') else False)
    if not all(key in result for key in ('mounts','root0.visibility','root1.visibility')):
        raise ValueError('Root/mount capability frames missing')
    for index in range(2):
        prefix='root'+str(index)
        visibility=result[prefix+'.visibility']
        if visibility['status']!='read' or visibility['value'] not in ('visible','absent_or_not_visible'):
            raise ValueError('Unrecognized trace-root visibility')
        if visibility['value']=='visible':
            required=[prefix+'.state.'+name.replace('/','_') for name in STATE_FILES]
            required += [prefix+'.available_events',prefix+'.oom_format',prefix+'.instances_state']
            required += [prefix+'.event'+str(i)+'.enable' for i in range(len(EVENTS))]
            if any(key not in result for key in required):raise ValueError('Visible root metadata frames missing')
            instance_state=result[prefix+'.instances_state']['value']
            match=re.fullmatch(r'inspected=([0-4]) additional=([01])',instance_state)
            if match:
                for instance in range(int(match[1])):
                    if any(prefix+'.instance'+str(instance)+'.'+name not in result for name in ('name','tracing_on','current_tracer','events_enable')):
                        raise ValueError('Instance metadata frames missing')
            elif instance_state!='absent_or_not_readable':raise ValueError('Unknown instance inspection state')
    return result


def identity(raw,expected_boot):
    rows=raw.decode('utf-8',errors='replace').splitlines()
    if len(rows)!=3 or rows[:2]!=[IMAGE,expected_boot] or not re.fullmatch(r'\d{1,10}',rows[2]):
        raise ValueError('Exact image/boot identity not verified')
    return dict(image=rows[0],boot_id=rows[1],uid=int(rows[2]))


def summarize_metadata(reads):
    def value(key):
        row=reads.get(key)
        return row['value'] if row and row['status']=='read' and not row['potentially_truncated'] else None
    roots=[];active=[];unknown=[];configured=[]
    for index,path in enumerate(ROOTS):
        prefix='root'+str(index);visible=value(prefix+'.visibility')=='visible'
        listed_row=reads.get(prefix+'.available_events')
        listed=(EVENTS[0] in listed_row['value'].splitlines()) if listed_row and listed_row['status']=='read' else None
        format_text=value(prefix+'.oom_format')
        readable=bool(format_text) if format_text is not None else None
        if listed is True and readable is True:availability='available_metadata_observed'
        elif listed is False:availability='absent_from_readable_event_list' if not readable else 'unknown_inconsistent_sequential_metadata'
        else:availability='unknown_not_readable_or_visible'
        if listed is True and readable is not True:availability='unknown_format_unreadable_or_incomplete'
        tracing=value(prefix+'.state.tracing_on')
        tracer=value(prefix+'.state.current_tracer');enabled=value(prefix+'.state.events_enable')
        root=dict(path=path,root_observed=visible,oom_event_listed=listed,oom_format_readable=readable,
                  oom_availability=availability,tracing_on=tracing,current_tracer=tracer,events_enable=enabled,instances=[])
        if tracing=='1':active.append(prefix)
        elif tracing!='0':unknown.append(prefix+'.tracing_state')
        if tracer is None or enabled is None:unknown.append(prefix+'.configuration_state')
        if tracer not in (None,'nop') or enabled in ('1','X'):
            configured.append(prefix)
        state=value(prefix+'.instances_state')
        match=re.fullmatch(r'inspected=([0-4]) additional=([01])',state or '')
        if match:
            root['additional_instances_uninspected']=match[2]=='1'
            if match[2]=='1':unknown.append(prefix+'.additional_instances')
            for instance in range(int(match[1])):
                key=prefix+'.instance'+str(instance)
                on=value(key+'.tracing_on');instance_tracer=value(key+'.current_tracer');instance_enabled=value(key+'.events_enable')
                root['instances'].append(dict(index=instance,name=value(key+'.name'),tracing_on=on,current_tracer=instance_tracer,events_enable=instance_enabled))
                if on=='1':active.append(key)
                elif on!='0':unknown.append(key+'.tracing_state')
                if instance_tracer is None or instance_enabled is None:unknown.append(key+'.configuration_state')
                if instance_tracer not in (None,'nop') or instance_enabled in ('1','X'):configured.append(key)
        else:
            root['additional_instances_uninspected']=None
            unknown.append(prefix+'.instances_state')
        roots.append(root)
    status='active_tracing_observed_conflict' if active else 'unknown' if unknown else 'no_active_tracing_observed_in_inspected_scope'
    return dict(roots=roots,conflict_summary=dict(status=status,active_locations=active,configured_locations=configured,unknown_locations=unknown),
                actual_tracing_readiness_proven=False,sequential_metadata_only=True)


def inspect(adb,expected_boot,runner=None):
    body=script(expected_boot)
    if runner is None:runner=subprocess.run
    result=dict(classification='read_only_trace_capability_inspection',expected=dict(serial=SERIAL,image=IMAGE,boot_id=expected_boot),
                trace_started=False,trace_controls_written=False,trace_buffers_read=False,permissions_changed=False,apps_launched=False,
                identity_verified=False,inspection_valid=False,probe_script_sha256=hashlib.sha256(body.encode()).hexdigest(),
                analyzer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    def call(args,payload=None):
        response=runner([str(adb),'-s',SERIAL]+args,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
        if len(response.stdout)>MAX_RAW:raise ValueError('ADB output exceeds bound')
        if response.returncode:raise ValueError('ADB read failed, exit '+str(response.returncode))
        return response.stdout
    try:
        if call(['get-serialno']).decode().strip()!=SERIAL:raise ValueError('ADB serial differs')
        result['identity_before']=identity(call(['shell','-T','sh','-s'],IDENTITY_SCRIPT.encode()),expected_boot)
        raw=call(['shell','-T','sh','-s'],body.encode())
        result['identity_after']=identity(call(['shell','-T','sh','-s'],IDENTITY_SCRIPT.encode()),expected_boot)
        result['identity_verified']=True
        result['reads']=parse_frames(raw)
        result['inspection_valid']=True
        result['status']='completed_metadata_reads'
        result['trace_root_observed']=any(result['reads']['root'+str(index)+'.visibility']['value']=='visible' for index in range(2))
        result['oom_event_observation']={}
        for index in range(2):
            key='root'+str(index)
            row=result['reads'].get(key+'.available_events')
            result['oom_event_observation'][key]=('listed' if EVENTS[0] in row['value'].splitlines() else 'not_listed') if row and row['status']=='read' else 'unknown_not_readable_or_visible'
        result['event_names']=list(EVENTS)
        result['roots']=list(ROOTS)
        result['capability_summary']=summarize_metadata(result['reads'])
        result['limits']=['Existing ADB namespace only; absent_or_not_visible is not global absence',
                          'At most four instances per root; additional instances are explicitly marked',
                          'Roots may alias the same tracefs; do not sum them',
                          'No trace buffer content or pending-top/LMKd transition history was collected',
                          'No authorization to start tracing or interfere with another observer']
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        # No raw transport stderr, environment, credential material or unverified capabilities are printed.
        result['status']='identity_or_probe_unverified';result['error']=str(error)[:256]
        result.pop('reads',None)
    if len(json.dumps(result,indent=2).encode())+1>MAX_REPORT:
        result.pop('reads',None);result['inspection_valid']=False;result['status']='report_bound_exceeded'
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb',type=Path,required=True)
    parser.add_argument('--serial',choices=(SERIAL,),required=True)
    parser.add_argument('--image',choices=(IMAGE,),required=True)
    parser.add_argument('--boot-id',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--plan-only',action='store_true',help='Write the reviewable query plan without invoking ADB')
    args=parser.parse_args();boot_id(args.boot_id)
    if args.output.exists():raise FileExistsError(args.output)
    if args.plan_only:
        body=script(args.boot_id)
        result=dict(classification='offline_read_only_capability_plan',serial=SERIAL,image=IMAGE,boot_id=args.boot_id,
                    script=body,script_sha256=hashlib.sha256(body.encode()).hexdigest(),
                    inspector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),executed=False)
    else:
        if not args.adb.is_absolute() or not args.adb.is_file():raise ValueError('Explicit existing absolute ADB executable required')
        result=inspect(args.adb,args.boot_id)
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=result.get('status',result['classification']),output=str(args.output),executed=not args.plan_only)))
    return 0 if args.plan_only or result.get('inspection_valid') else 2


if __name__=='__main__':raise SystemExit(main())
