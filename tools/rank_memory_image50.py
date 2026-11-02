"""Rank resident, logical-swap and kernel consumers from revalidated49/50 captures."""
import argparse,hashlib,json
from pathlib import Path
from types import SimpleNamespace
from summarize_pip_pair import analyze
from summarize_kernel_attribution import slabs

PAIR='b6684a3293817d31ccc975502f84d3515d43e9784cbde4911cf6fe8c24769f1d'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('pair','freeze','bundle','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();raw=a.pair.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=PAIR:raise ValueError('Require reviewed49/50 pair')
    previous=json.loads(raw)
    guards=previous['full_data_apk_guards'];controls=previous['post_census_controls']
    roots=[Path(guards[i]['root']).parent for i in (0,2)]
    current=analyze(SimpleNamespace(baseline=roots[0],candidate=roots[1],baseline_postguard=Path(controls[0]['root']),candidate_postguard=Path(controls[1]['root']),freeze=a.freeze,bundle=a.bundle))
    for field in ('eligible_for_descriptive_timed_idle_comparison','comparison_failures','census_attribution_delta_KiB','global_snapshots','target_processes'):
        if current[field]!=previous[field]:raise ValueError('Recomputed pair disagrees: '+field)
    if not current['eligible_for_descriptive_timed_idle_comparison']:raise ValueError('Ineligible pair')
    arm=current['candidate'];processes=arm['census']['processes']
    def rank(key):return [{k:row[k] for k in ('pid','command','Pss','USS','SwapPss','Threads')} for row in sorted(processes,key=lambda r:r[key],reverse=True)]
    caches=slabs((roots[1]/'timed/census/allocators.txt').read_text())
    phases=[]
    for phase,snapshot in zip(('before','after'),arm['census']['snapshots']):
        info=snapshot['meminfo']
        phases.append(dict(phase=phase,meminfo_KiB={k:info[k] for k in ('MemTotal','MemFree','MemAvailable','Cached','AnonPages','Slab','SReclaimable','SUnreclaim','KernelStack','PageTables','CmaTotal','CmaFree')},zram_physical_KiB=snapshot['zram_physical_KiB'],logical_swap_used_KiB=snapshot['logical_swap_used_KiB']))
    r=dict(image='50',boot=arm['protocol']['boot'],source_pair_sha256=PAIR,source_pair_revalidated=True,
        protocol_sha256=arm['protocol_sha256'],census_manifest_sha256=arm['raw_manifest_sha256'],
        resident_PSS_ranking_KiB=rank('Pss'),resident_USS_ranking_KiB=rank('USS'),logical_SwapPss_ranking_KiB=rank('SwapPss'),thread_ranking=rank('Threads'),
        snapshots=phases,slab_object_capacity_ranking=caches,dma_exported_capacity_bytes=arm['dma_exported_capacity_bytes'],
        next_candidate='Exact50 services/boot-framework RX-only ART paging; unbuilt source experiment',
        limits=['Resident PSS/USS and logical SwapPss are separate rankings; their sum is not physical working set.','Slab object capacity and inactive capacity are not reclaimable/wasted physical RAM; no addition to global occupied RAM.','CMA is reusable reserved capacity, not an independent fixed allocation to add to MemTotal.','Current census does not attribute specific VMAs; image47 smaps is historical and cannot establish50 RX resident bytes.','Largest consumer does not mean removable functionality or achievable saving.','No prediction of80percent reduction or established whole-device denominator.'])
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(dict(resident_top5=r['resident_PSS_ranking_KiB'][:5],logical_swap_top5=r['logical_SwapPss_ranking_KiB'][:5],slab_capacity_top5=caches[:5]),indent=2))

if __name__=='__main__':main()
