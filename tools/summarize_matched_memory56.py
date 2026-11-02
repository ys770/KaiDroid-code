"""Verify one frozen arm or strict55/56/55/56 capture set offline; never infer savings."""
import argparse,collections,json,re,sys
from pathlib import Path
sys.dont_write_bytecode=True
import matched_memory56_contract as c
from summarize_memory_audit import summarize as census_summary
from summarize_guarded_memory_maps import analyze as map_summary
from capture_timed_memory_audit import require_identity

def safe_file(root,name):
 rel=Path(name)
 if rel.is_absolute() or '..' in rel.parts or (root/rel).is_symlink():raise ValueError('Unsafe evidence path')
 return root/rel

def census(root,target,arm):
 timing=json.loads((root/'timing.json').read_text());folder=root/'census';manifest=json.loads((folder/'manifest.json').read_text());e=arm['expected'];image=e['image'];boot=e['boot']
 if timing['state']!='complete' or timing['collector_exit']!=0 or timing['image']!=image or timing['boot']!=boot or timing['target_launch_uptime']!=target or not timing['no_gc'] or timing['collector_sha256']!=arm['source_sha256']['audit_memory.py'] or timing['process_start_ticks']!=[e['server_start'],e['ui_start']]:raise ValueError('Wrong/incomplete/frozen census')
 names={'identity-before','identity-middle','identity-after','system-before','system-after','processes','services','allocators'}
 if manifest['image']!=image or manifest['boot']!=boot or len(manifest['captures'])!=8 or {x['name'] for x in manifest['captures']}!=names:raise ValueError('Census command closure differs')
 for row in manifest['captures']:
  file=folder/(row['name']+'.txt')
  if row['returncode']!=0 or c.sha(file)!=row['sha256'] or (folder/(row['name']+'.stderr')).read_bytes():raise ValueError('Census hash/exit/stderr differs')
 for n in ('identity-before','identity-middle','identity-after'):
  if (folder/(n+'.txt')).read_text().splitlines()!=[image,boot,'0']:raise ValueError('Census identity differs')
 for n in ('initial-guard','before-collector','after-collector'):
  _,starts=require_identity((root/(n+'.txt')).read_text().splitlines(),image,boot,e['server_pid'],e['ui_pid'])
  if list(starts)!=[e['server_start'],e['ui_start']]:raise ValueError('Census process lifetime differs')
 ages={}
 for n in ('before','after'):
  age=float((folder/('system-'+n+'.txt')).read_text().split('UPTIME\n')[1].split()[0]);ages[n]=age
  if age!=timing['actual_snapshot_uptime'][n]:raise ValueError('Census age record differs')
 result=census_summary(folder)
 if result['omitted'] or len({p['pid'] for p in result['processes']})!=len(result['processes']):raise ValueError('Omitted/duplicate process census')
 for command,key in [('system_server','server_pid'),('com.android.systemui','ui_pid')]:
  found=[p for p in result['processes'] if p['command'].strip()==command]
  if len(found)!=1 or found[0]['pid']!=e[key]:raise ValueError('Target census PID/name differs')
 return result,ages,c.timing_failures('census_'+str(target),ages['before'],ages['after'],target)

def step_labels():
 labels=['initial-identity','age-log-start']
 def binding(t):labels.extend(['age-binding-'+str(t),'bindings-'+str(t),'post-binding-'+str(t)])
 def collect(t):labels.extend(['age-arm-census-'+str(t),'window-pre-census-'+str(t),'post-census-'+str(t),'window-post-census-'+str(t)])
 def maps(t):labels.extend(['age-maps-'+str(t),'post-maps-'+str(t)])
 binding(120);binding(150);collect(180);binding(195);maps(225);binding(270);collect(300);binding(315);maps(345);binding(360);labels.append('final-identity');return labels

def verify_arm(root,allow_unfinalized=False):
 from run_matched_memory56 import packet_check,guard_command,checkpoint_command,child_command
 arm=json.loads((root/'arm.json').read_text());m,bindings=packet_check(root/'inputs',arm['packet_sha256']);failures=list(arm.get('failures',[]));e=arm['expected']
 if arm['schema_version']!=1 or arm['experiment']!=bindings['experiment'] or arm['image']!=e['image'] or arm['boot']!=e['boot'] or not 1<=arm['slot']<=4 or arm['image']!=c.ORDER[arm['slot']-1] or arm['source_sha256']!=m['sources_sha256'] or arm['bindings_sha256']!=m['bindings_sha256'] or arm['schedule']!=m['schedule'] or not arm['no_gc'] or arm['state_changed']:raise ValueError('Arm/packet/policy contract differs')
 if not allow_unfinalized:
  recorded=arm.get('raw_files_sha256',{});actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p!=root/'arm.json'}
  if set(recorded)!=actual or any(p.is_symlink() for p in root.rglob('*')):raise ValueError('Final raw evidence coverage differs')
  for name,pin in recorded.items():
   if c.sha(safe_file(root,name))!=pin:raise ValueError('Final raw evidence hash differs '+name)
 if not arm.get('complete') or arm.get('error'):return dict(classification='failed',eligible_for_matched_comparison=False,failures=failures+[arm.get('error','Incomplete arm')],measurements={})
 if [r['label'] for r in arm['steps']]!=step_labels():raise ValueError('Ordered read ledger differs')
 checkpoints=[];windows={};ages={}
 for record in arm['steps']:
  stdout=safe_file(root,record['stdout']);stderr=safe_file(root,record['stderr'])
  if record['returncode']!=0 or c.sha(stdout)!=record['stdout_sha256'] or c.sha(stderr)!=record['stderr_sha256'] or stderr.read_bytes():raise ValueError('Read ledger hash/exit/stderr differs')
  label=record['label'];raw=stdout.read_text()
  if label.startswith('bindings-'):
   target=int(label.rsplit('-',1)[1])
   if record['command']!=checkpoint_command(bindings,arm['image']):raise ValueError('Binding command changed')
   parsed=c.checkpoint(raw,bindings,arm['image']);checkpoints.append(parsed)
   failures+=['binding_'+str(target)+'_'+x for x in parsed['failures']]
   if abs(parsed['uptime_before']-target)>c.TOLERANCE:failures.append('binding_'+str(target)+'_missed_age')
  elif label.startswith('window-'):
   command='echo KV_UPTIME; cat /proc/uptime; echo KV_WINDOW; dumpsys window; echo KV_END_UPTIME; cat /proc/uptime'
   if record['command']!=command:raise ValueError('Window command differs')
   s=c.parse_sections(raw)
   if set(s)!={'KV_UPTIME','KV_WINDOW','KV_END_UPTIME'}:raise ValueError('Window read incomplete')
   result=c.window_status('\n'.join(s['KV_WINDOW']),bindings['foreground_component']);windows[label]=dict(before=float(s['KV_UPTIME'][0].split()[0]),after=float(s['KV_END_UPTIME'][0].split()[0]))
   failures += [label+'_'+x for x in result['failures']]
  else:
   if record['command']!=guard_command(e):raise ValueError('Identity guard command differs')
   age=c.identity(raw.splitlines(),e);ages[label]=age
   if label.startswith('age-'):
    target=c.LOG_START if label=='age-log-start' else int(label.rsplit('-',1)[1])-(5 if label.startswith('age-arm-census-') else 0)
    if abs(age-target)>c.TOLERANCE:failures.append(label+'_missed_age')
 if ages['initial-identity']>c.LOG_START-2 or ages['final-identity']<358:failures.append('arm_observation_window_incomplete')
 children=arm['children']
 if [r['label'] for r in children]!=['census-180','maps-225','census-300','maps-345']:raise ValueError('Child execution order/closure differs')
 for record in children:
  kind,age=record['label'].split('-');original=Path(arm['capture_root']);expected_argv=child_command(kind,int(age),original/'inputs/sources',original/record['label'],e,arm['host']['adb_executable'],arm['host']['python_executable'])
  if [v.replace('\\','/') for v in record['argv']]!=[v.replace('\\','/') for v in expected_argv]:raise ValueError('Collector argv differs from frozen read-only plan')
  if record['exit']!=0 or c.sha(safe_file(root,record['stdout']))!=record['stdout_sha256'] or c.sha(safe_file(root,record['stderr']))!=record['stderr_sha256']:raise ValueError('Child stdout/exit differs')
 measured={};populations=[];census_ages={}
 for target in c.CENSUSES:
  result,age,flags=census(root/('census-'+str(target)),target,arm);failures+=flags;pop=c.population(result['processes']);populations.append(pop);census_ages[target]=age
  if bindings['expected_process_commands'] is not None and pop!=dict(sorted(collections.Counter(bindings['expected_process_commands']).items())):failures.append('census_'+str(target)+'_reference_process_set_drift')
  pre=windows['window-pre-census-'+str(target)];post=windows['window-post-census-'+str(target)]
  if pre['after']>age['before'] or post['before']<age['after']:raise ValueError('Foreground reads overlap census')
  targets={name:next(p for p in result['processes'] if p['command'].strip()==name) for name in ('system_server','com.android.systemui')}
  measured[str(target)]=dict(targets=targets,population=pop,total_KiB=result['census_totals_KiB'],global_snapshots=result['snapshots'],vm_delta=result['vm_delta'],actual_uptime=age)
 if populations[0]!=populations[1]:failures.append('within_arm_process_set_drift')
 fullmaps={}
 for target,census_target in zip(c.MAPS,c.CENSUSES):
  result=map_summary(root/('maps-'+str(target)),arm['image'],arm['boot']);metadata=result['runtime_metadata'];failures+=c.timing_failures('maps_'+str(target),metadata['before'],metadata['after'],target)
  if metadata['before']<=census_ages[census_target]['after']+10:raise ValueError('Full maps overlap census/quiet gap')
  expected=[(e['server_pid'],'system_server',e['server_start']),(e['ui_pid'],'com.android.systemui',e['ui_start'])]
  if [(p['process']['pid'],p['process']['command'],p['process']['start_ticks']) for p in result['processes']]!=expected:raise ValueError('Full-map target lifetimes differ')
  ss=result['processes'][0]
  raw=(root/('maps-'+str(target))/(str(e['server_pid'])+'-smaps.txt')).read_text();image_present='[anon:dalvik-/system/framework/oat/arm/services.art]' in raw
  if image_present!=(arm['image']=='55'):failures.append('maps_'+str(target)+'_services_image_mechanism_mismatch')
  if not any('/system/framework/oat/arm/services.odex' in line and line.split()[1]=='r-xp' for line in raw.splitlines() if re.match('^[0-9a-f]+-[0-9a-f]+ ',line)):failures.append('maps_'+str(target)+'_services_oat_not_executable')
  if not any('/apex/com.android.art/lib/libart.so' in line and line.split()[1]=='r-xp' and line.split()[-1]=='/apex/com.android.art/lib/libart.so' for line in raw.splitlines() if re.match('^[0-9a-f]+-[0-9a-f]+ ',line)):failures.append('maps_'+str(target)+'_selected_art_runtime_not_executable')
  fullmaps[str(target)]=result
 events=c.log_events((root/'natural-logcat.txt').read_text(errors='replace'))
 if events['fatal']:failures.append('natural_fatal_exception')
 if events['anr']:failures.append('natural_anr')
 if (root/'natural-logcat.stderr').read_bytes() or arm.get('log_stopped_by_harness')!='completed':failures.append('natural_log_incomplete')
 if (root/'natural-logcat.txt').stat().st_size>c.MAX_LOG_BYTES:failures.append('natural_log_size_bound')
 failures=sorted(set(failures));return dict(classification='matched_eligible_arm' if not failures else 'descriptive_only',eligible_for_matched_comparison=not failures,failures=failures,measurements=measured,fullmaps=fullmaps,natural_events=events,savings_proven=False)

def compare(roots):
 if len(roots)!=4 or len({p.resolve() for p in roots})!=4:raise ValueError('Four distinct55/56/55/56 arms required')
 arms=[json.loads((p/'arm.json').read_text()) for p in roots];checked=[verify_arm(p) for p in roots];failures=[]
 if [a['slot'] for a in arms]!=[1,2,3,4] or tuple(a['image'] for a in arms)!=c.ORDER:failures.append('crossover_order_differs')
 if len({a['boot'] for a in arms})!=4:failures.append('boot_reused')
 for key in ('experiment','packet_sha256','bindings_sha256'):
  if len({a[key] for a in arms})!=1:failures.append(key+'_differs')
 if any(a['host']!=arms[0]['host'] for a in arms):failures.append('host_python_or_adb_differs')
 if any(a['source_sha256']!=arms[0]['source_sha256'] for a in arms):failures.append('frozen_sources_differ')
 if any(not r['eligible_for_matched_comparison'] for r in checked):failures.append('arm_not_matched_eligible')
 if all(r['measurements'] for r in checked):
  for age in c.CENSUSES:
   populations=[r['measurements'][str(age)]['population'] for r in checked]
   if any(p!=populations[0] for p in populations):failures.append('cross_arm_process_set_drift_'+str(age))
 eligible=not failures;descriptive=[]
 for arm,result in zip(arms,checked):descriptive.append(dict(slot=arm['slot'],image=arm['image'],boot=arm['boot'],classification=result['classification'],failures=result['failures'],measurements=result['measurements'],fullmaps=result.get('fullmaps',{}),natural_event_counts={k:len(v) for k,v in result.get('natural_events',{}).items()}))
 aggregates=None
 if eligible:
  aggregates={}
  for age in c.CENSUSES:
   rows={}
   for image in ('55','56'):
    samples=[r['measurements'][str(age)] for a,r in zip(arms,checked) if a['image']==image]
    metrics={'total_Pss':[x['total_KiB']['Pss'] for x in samples],'total_SwapPss':[x['total_KiB']['SwapPss'] for x in samples],'server_Pss':[x['targets']['system_server']['Pss'] for x in samples], 'total_USS':[x['total_KiB']['USS'] for x in samples], 'server_USS':[x['targets']['system_server']['USS'] for x in samples], 'server_logical_SwapPss':[x['targets']['system_server']['SwapPss'] for x in samples], 'SystemUI_Pss':[x['targets']['com.android.systemui']['Pss'] for x in samples], 'physical_zram_after':[x['global_snapshots'][1]['zram_physical_KiB'] for x in samples], 'occupied_visible_after':[x['global_snapshots'][1]['occupied_visible_KiB'] for x in samples], 'MemAvailable_after':[x['global_snapshots'][1]['meminfo']['MemAvailable'] for x in samples]}
    rows[image]={k:dict(values=v,mean=sum(v)/len(v),minimum=min(v),maximum=max(v)) for k,v in metrics.items()}
   aggregates[str(age)]=rows
 return dict(classification='matched_eligible_crossover' if eligible else 'descriptive_only',eligible_for_matched_comparison=eligible,comparison_failures=sorted(set(failures)),arms=descriptive,matched_replicate_summaries=aggregates,savings_proven=False,full_hardware_or_ABI_acceptance=False,limits=['Two runs per image establish only initial repeatability; no statistical savings or latency claim is automatic.','PSS and logical SwapPss remain separate. Physical zram/global occupied/cache/kernel views overlap and must not be double-counted.','Bindings and window/error checks observe checkpoints; they cannot prove unchanged hidden app data, thermal state, external events or every intervening instant.','Natural logs are not forcedGC/heap evidence. MissingGC messages do not prove zeroGC cost.'])

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True)
 s=sub.add_parser('arm');s.add_argument('--capture',type=Path,required=True);s.add_argument('--output',type=Path,required=True)
 s=sub.add_parser('compare');s.add_argument('--arm',type=Path,action='append',required=True);s.add_argument('--output',type=Path,required=True)
 a=p.parse_args()
 if a.output.exists():raise FileExistsError(a.output)
 result=verify_arm(a.capture) if a.mode=='arm' else compare(a.arm);result['analyzer_sha256']=c.sha(Path(__file__));c.dump(a.output,result);print(json.dumps(dict(classification=result['classification'],savings_proven=False)))
