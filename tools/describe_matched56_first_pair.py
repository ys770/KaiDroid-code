"""Offline descriptive slots1/2 only; never relax the four-arm eligibility gate."""
import argparse,collections,json,sys
from pathlib import Path
sys.dont_write_bytecode=True
import matched_memory56_contract as c
from summarize_matched_memory56 import verify_arm
from summarize_memory_audit import summarize as raw_census

def describe(oldroot,newroot):
 roots=[oldroot,newroot];arms=[json.loads((p/'arm.json').read_text()) for p in roots];checks=[verify_arm(p) for p in roots]
 if [a['slot'] for a in arms]!=[1,2] or [a['image'] for a in arms]!=['55','56'] or arms[0]['boot']==arms[1]['boot']:raise ValueError('Distinct terminal slots1/image55 and2/image56 required')
 if any(not r['eligible_for_matched_comparison'] for r in checks):raise ValueError('Both arms must independently verify; preserve invalid arms separately')
 equal={k:arms[0][k]==arms[1][k] for k in ('packet_sha256','bindings_sha256','source_sha256','host','experiment','schedule')}
 rows={}
 for age in ('180','300'):
  old,new=[r['measurements'][age] for r in checks];a,b=collections.Counter(old['population']),collections.Counter(new['population']);population=dict(baseline_count=sum(a.values()),candidate_count=sum(b.values()),equal=a==b,baseline_only=list((a-b).elements()),candidate_only=list((b-a).elements()))
  extra=[]
  for root,pop,other,image in [(oldroot,a,b,'55'),(newroot,b,a,'56')]:
   names=set((pop-other).elements())
   if names:
    full=raw_census(root/('census-'+age)/'census')
    extra.extend(dict(image=image,command=p['command'].strip(),metrics_KiB={k:p[k] for k in ('Pss','USS','SwapPss')}) for p in full['processes'] if p['command'].strip() in names)
  targets={}
  for name in ('system_server','com.android.systemui'):
   x,y=old['targets'][name],new['targets'][name];targets[name]=dict(baseline={k:x[k] for k in ('Pss','USS','SwapPss','Threads')},candidate={k:y[k] for k in ('Pss','USS','SwapPss','Threads')},candidate_minus_baseline={k:y[k]-x[k] for k in ('Pss','USS','SwapPss','Threads')})
  global_rows=[]
  for i,phase in enumerate(('before','after')):
   x,y=old['global_snapshots'][i],new['global_snapshots'][i];metrics=('occupied_visible_KiB','zram_physical_KiB','logical_swap_used_KiB');before={k:x[k] for k in metrics};after={k:y[k] for k in metrics}
   for key in ('MemAvailable','Cached','AnonPages','Slab','PageTables','KernelStack'):before[key]=x['meminfo'][key];after[key]=y['meminfo'][key]
   global_rows.append(dict(phase=phase,baseline=before,candidate=after,candidate_minus_baseline={k:after[k]-before[k] for k in before}))
  rows[age]=dict(actual_uptime_before=old['actual_uptime'],actual_uptime_after=new['actual_uptime'],snapshot_age_offset_seconds={k:new['actual_uptime'][k]-old['actual_uptime'][k] for k in ('before','after')},population=population,exclusive_process_metrics=extra,targets=targets,all_userspace_KiB=dict(baseline={k:old['total_KiB'][k] for k in ('Pss','USS','SwapPss')},candidate={k:new['total_KiB'][k] for k in ('Pss','USS','SwapPss')},candidate_minus_baseline={k:new['total_KiB'][k]-old['total_KiB'][k] for k in ('Pss','USS','SwapPss')}),global_snapshots=global_rows)
 maps={}
 for age in ('225','345'):
  old,new=[r['fullmaps'][age] for r in checks];x,y=[p['processes'][0] for p in (old,new)];groups=[]
  for name in sorted(x['groups_KiB'].keys()|y['groups_KiB'].keys()):
   a,b=x['groups_KiB'].get(name,{}),y['groups_KiB'].get(name,{});metrics=('Pss','Private_Clean','Private_Dirty','SwapPss');groups.append(dict(category=name,baseline={k:a.get(k,0) for k in metrics},candidate={k:b.get(k,0) for k in metrics},candidate_minus_baseline={k:b.get(k,0)-a.get(k,0) for k in metrics}))
  delta={k:y['total_KiB'][k]-x['total_KiB'][k] for k in ('Pss','Private_Clean','Private_Dirty','SwapPss')}
  if any(sum(g['candidate_minus_baseline'][k] for g in groups)!=value for k,value in delta.items()):raise ValueError('Mapping groups do not reconcile')
  maps[age]=dict(baseline_window=old['runtime_metadata'],candidate_window=new['runtime_metadata'],system_server_total_delta_KiB=delta,groups=groups,baseline_services_image=next(v for v in x['largest_backings_KiB'] if v['name']=='[anon:dalvik-/system/framework/oat/arm/services.art]'),candidate_services_image_absent=True,executable_services_oat_retained=True)
 return dict(classification='descriptive_first_pair_only',individual_arm_eligibility=[r['classification'] for r in checks],protocol_equalities=equal,cross_arm_population_match=all(v['population']['equal'] for v in rows.values()),censuses=rows,maps=maps,natural_unwindowed_event_counts=[{k:len(v) for k,v in r['natural_events'].items()} for r in checks],inputs=[dict(capture=str(p),image=a['image'],boot=a['boot'],arm_sha256=c.sha(p/'arm.json')) for p,a in zip(roots,arms)],four_arm_series_complete=False,four_arm_eligibility_evaluated=False,matched_replicate_summaries=None,savings_proven=False,causal_effect_established=False,full_hardware_or_ABI_accepted=False,
 limits=['One observation per image; observed age-aligned differences are descriptive and are not a four-arm matched result.','A changed process population alters proportional sharing. Do not drop the extra providers or subtract them to manufacture a counterfactual saving.','Population differences can be workload/cache history or a pressure outcome; this first pair cannot identify the explanation.','Managed-heap/ART-metadata mapping labels and naturalGC timing are not object-liveness or causal replacement-allocation measurements.','PSS/USS are resident attribution; SwapPss is logical swap. Physical zram and occupied/cache/kernel views overlap and must not be double-counted.','Natural event counts include buffered boot history; device wall-clock dates do not delimit the measurement interval.','The fixed55/56/55/56 protocol and its strict population gate are unchanged. Retain all arms, no automatic retry or intervention.'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('baseline','candidate','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 if a.output.exists():raise FileExistsError(a.output)
 r=describe(a.baseline,a.candidate);r['analyzer_sha256']=c.sha(Path(__file__));c.dump(a.output,r);print(json.dumps(dict(classification=r['classification'],population_match=r['cross_arm_population_match'],savings_proven=False)))
