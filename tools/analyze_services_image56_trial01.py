"""Offline first55/56 memory accounting; one confounded pair never proves savings."""
import argparse,collections,hashlib,json,re
from pathlib import Path
from summarize_memory_audit import summarize as census_summary
from summarize_memory_maps import summarize as map_summary
from summarize_guarded_memory_maps import analyze as guarded_maps
from summarize_startup_pressure import summarize as pressure_summary
from summarize_startup_process_io import summarize as io_summary
from check_memory_image56 import mapping_checks,FILES,start_ticks

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,v):
 with path.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def read_arm(root,image):
 timing=json.loads((root/'timed/timing.json').read_text());capture=root/'timed/census';m=json.loads((capture/'manifest.json').read_text());expected={'identity-before','identity-middle','identity-after','system-before','system-after','processes','services','allocators'}
 if timing['state']!='complete' or timing['collector_exit']!=0 or not timing['no_gc'] or timing['image']!=image or m['image']!=image or m['boot']!=timing['boot']:raise ValueError('Incomplete/wrong census arm')
 if len(m['captures'])!=8 or {r['name'] for r in m['captures']}!=expected:raise ValueError('Census closure incomplete')
 for r in m['captures']:
  p=capture/(r['name']+'.txt')
  if r['returncode']!=0 or sha(p)!=r['sha256'] or (capture/(r['name']+'.stderr')).read_bytes():raise ValueError('Capture hash/exit/stderr differs')
 for n in ('identity-before','identity-middle','identity-after'):
  if (capture/(n+'.txt')).read_text().splitlines()!=[image,timing['boot'],'0']:raise ValueError('Identity changed')
 for n in ('before','after'):
  text=(capture/('system-'+n+'.txt')).read_text();age=float(text.split('UPTIME\n')[1].split()[0])
  if age!=timing['actual_snapshot_uptime'][n]:raise ValueError('Snapshot age differs')
 guard=[]
 for name in ('before-collector','after-collector'):
  lines=(root/'timed'/(name+'.txt')).read_text().splitlines()
  if lines[:3]!=[image,timing['boot'],'0'] or lines[6]!='1':raise ValueError('Timed guard differs')
  stats=[line for line in lines if re.match(r'^\d+ \(',line)]
  if len(stats)!=2 or [start_ticks(s) for s in stats]!=timing['process_start_ticks']:raise ValueError('Target lifetime changed')
  guard.append(stats)
 result=census_summary(capture)
 if result['omitted'] or len({p['pid'] for p in result['processes']})!=len(result['processes']):raise ValueError('Omitted or duplicate process')
 samples=[json.loads(x) for x in (root/'observation/samples.jsonl').read_text().splitlines() if x];valid=[x for x in samples if len(x.get('output',[]))>=4]
 if {(x['output'][0],x['output'][1]) for x in valid}!={(image,timing['boot'])}:raise ValueError('Observer identity differs')
 first=next(i for i,x in enumerate(valid) if x['output'][2]=='1');completion=dict(last_not_complete_uptime=float(valid[first-1]['output'][3].split()[0]) if first else None,first_observed_complete_uptime=float(valid[first]['output'][3].split()[0]))
 lines=set()
 for p in (root/'observation').glob('logcat*.txt'):lines.update(p.read_text(errors='replace').splitlines())
 fatal=sorted(x for x in lines if 'FATAL EXCEPTION' in x);pressure=pressure_summary(root/'observation/samples.jsonl');proc_io=io_summary(root/'observation/samples.jsonl')
 first,last=pressure['samples'][0],pressure['samples'][-1];seconds=last['uptime']-first['uptime'];counters={k:last[k]-first[k] for k in ('pswpin','pswpout','pgmajfault','pgscan_direct','pgsteal_direct') if k in first}
 io=[]
 for name in ('system_server','com.android.systemui','com.android.bluetooth'):
  rows=[x for x in proc_io['snapshots'] if x['name']==name];keys={(r['pid'],r['start_ticks']) for r in rows}
  if len(keys)!=1:raise ValueError('Observer process lifetime changed')
  lo,hi=rows[0],rows[-1];secs=hi['uptime']-lo['uptime'];delta={k:hi[k]-lo[k] for k in ('minor_faults','major_faults','user_ticks','system_ticks','read_bytes','write_bytes')};io.append(dict(name=name,window=[lo['uptime'],hi['uptime']],delta=delta,per_second={k:v/secs for k,v in delta.items()}))
 return dict(image=image,boot=timing['boot'],timing=timing,census=result,boot_completed_interval=completion,observer_window=[first['uptime'],last['uptime']],observer_error_count=sum(x.get('returncode',0)!=0 for x in samples),fatal_exception_lines=fatal,startup_pressure=dict(window_seconds=seconds,counter_delta=counters,counter_per_second={k:v/seconds for k,v in counters.items()},minimum_MemAvailable_KiB=pressure['minimum_mem_available_kib'],minimum_SwapFree_KiB=pressure['minimum_swap_free_kib']),startup_process_io=io,
 hashes={str(p):sha(p) for p in [capture/'manifest.json',root/'timed/timing.json',root/'observation/samples.jsonl',*sorted((root/'observation').glob('logcat*.txt'))]})
def group(result):
 rows={}
 for p in result['processes']:
  name=p['command'].strip();v=rows.setdefault(name,dict(count=0,Pss=0,USS=0,SwapPss=0));v['count']+=1
  for k in ('Pss','USS','SwapPss'):v[k]+=p[k]
 return rows

def analyze(baseline,candidate,maps55,maps56):
 old=read_arm(baseline,'55');new=read_arm(candidate,'56');a,b=group(old['census']),group(new['census']);process_delta=[]
 for name in a.keys()|b.keys():
  before=a.get(name,{});after=b.get(name,{});process_delta.append(dict(command=name,baseline=before,candidate=after,delta={k:after.get(k,0)-before.get(k,0) for k in ('Pss','USS','SwapPss')}))
 totals={k:new['census']['census_totals_KiB'][k]-old['census']['census_totals_KiB'][k] for k in ('Pss','USS','SwapPss')}
 if {k:sum(r['delta'][k] for r in process_delta) for k in totals}!=totals:raise ValueError('Process deltas do not reconcile')
 rm=json.loads((maps56/'result.json').read_text())
 if not rm['passed'] or rm['boot']!=new['boot']:raise ValueError('Mechanism arm differs')
 for n,pin in rm['capture_hashes'].items():
  if Path(n).name!=n or sha(maps56/n)!=pin:raise ValueError('Mechanism capture changed')
 identity=(maps56/'identity-before.stdout').read_text().splitlines()
 if identity!=(maps56/'identity-after.stdout').read_text().splitlines() or identity[1:6]!=['56',new['boot'],'0','Enforcing','1']:raise ValueError('Mechanism identity differs')
 if [start_ticks((maps56/(n+'.stdout')).read_text()) for n in ('stat-before','stat-after')]!=[rm['start_ticks']]*2:raise ValueError('Mechanism lifetime differs')
 if rm['start_ticks']!=new['timing']['process_start_ticks'][0]:raise ValueError('Mechanism/census server lifetime differs')
 for i,(path,pin) in enumerate(FILES.items()):
  fields=(maps56/('file-'+str(i)+'.stdout')).read_text().split()
  if fields!=[pin,path]:raise ValueError('Mechanism file binding differs')
 raw=(maps56/'smaps.stdout').read_text();mechanism=mapping_checks(raw);current=map_summary(raw)
 older=guarded_maps(maps55,'55','00000000-0000-0000-0001-000000000001');oldmap=next(x for x in older['processes'] if x['process']['command']=='system_server')
 mapping=[]
 for cat in oldmap['groups_KiB'].keys()|current['groups_KiB'].keys():
  x=oldmap['groups_KiB'].get(cat,{});y=current['groups_KiB'].get(cat,{});mapping.append(dict(category=cat,baseline_Pss=x.get('Pss',0),candidate_Pss=y.get('Pss',0),baseline_SwapPss=x.get('SwapPss',0),candidate_SwapPss=y.get('SwapPss',0)))
 global_rows=[]
 for i,label in enumerate(('before','after')):
  x,y=old['census']['snapshots'][i],new['census']['snapshots'][i];keys=('occupied_visible_KiB','zram_physical_KiB','logical_swap_used_KiB');delta={k:y[k]-x[k] for k in keys};delta.update({k:y['meminfo'][k]-x['meminfo'][k] for k in ('MemAvailable','MemFree','Cached','AnonPages','Slab','PageTables','KernelStack','CmaFree')});global_rows.append(dict(phase=label,baseline=x,candidate=y,delta=delta))
 return dict(status='mechanism_confirmed_single_pair_confounded',baseline=old,candidate=new,target_deltas=[x for x in process_delta if x['command'] in ('system_server','com.android.systemui')],process_population=dict(baseline_only=sorted(a.keys()-b.keys()),candidate_only=sorted(b.keys()-a.keys()),same_process_count=len(old['census']['processes'])==len(new['census']['processes'])),process_deltas=sorted(process_delta,key=lambda x:x['delta']['Pss'],reverse=True),census_attribution_delta_KiB=totals,global_snapshots=global_rows,
 mechanism=mechanism,mapping_composition=dict(baseline_boot=older['boot'],baseline_window=older['runtime_metadata'],candidate_boot=new['boot'],candidate_window=[float((maps56/(n+'.stdout')).read_text().split()[0]) for n in ('uptime-before','uptime-after')],same_age_or_workload=False,groups=mapping,baseline_total=oldmap['total_KiB'],candidate_total=current['total_KiB'],mapping_replacement_cost_established=False),
 eligible_for_matched_performance_comparison=False,savings_proven=False,full_hardware_or_ABI_accepted=False,
 quality_findings=[dict(severity='high',finding='MMS crash/error-dialog baseline and different process population confound performance attribution',evidence='MMS appears only in55census; Dialer appears only in56census; fatal counts differ',remediation='Same fixed Messaging package/config/foreground and repeated matched workload on both images'),dict(severity='high',finding='Full mapping captures are not a matched pair',evidence='55maps are older44ecboot2000s;56maps197s. Cold180s census contains rollups only.',remediation='Same-age full smaps on each arm outside the fixed census, with identical order and lifetime guards'),dict(severity='medium',finding='One boot per image with different observer endpoints and sampling-bounded completion',evidence='No replicate variance, exact boot timestamp or atomic physical total',remediation='Crossover repeats and fixed observation/workload windows')],
 limits=['PSS/USS are sequential resident attribution; logical SwapPss is not physical zram. Do not sum RSS across shared mappings.','Occupied visible RAM already contains cache/kernel/zram; do not add these again. MemAvailable is an estimate, not a unique physical working-set denominator.','Lower server PSS plus absent image does not prove net whole-phone RAM savings or lower replacement heap/GC cost.','Fullmap categories are labels, not object liveness. Old55mapping values are context only, not a same-age delta.','Startup pressure counters cover different sampled intervals, omit early boot and use page events; rates remain descriptive.','No host/device commands, new capture, forcedGC, policy change, reboot, install or80percent result.'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','baseline-maps','candidate-maps','output-dir'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();out=a.output_dir;out.mkdir(parents=True,exist_ok=False);r=analyze(a.baseline,a.candidate,a.baseline_maps,a.candidate_maps);r['analyzer_sha256']=sha(Path(__file__));dump(out/'result.json',r)
 print(json.dumps(dict(status=r['status'],census_delta=r['census_attribution_delta_KiB'],population=r['process_population'],savings_proven=False)))
