"""Summarize the bounded synthetic ART trial; do not infer whole-device savings."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path


def summarize(root,terminal_directory=None):
    source=root/'result.json'
    result=json.loads(source.read_text())
    if not result['complete']:
        raise ValueError('Incomplete trial')
    expected=['baseline','candidate','candidate','baseline','baseline','candidate','baseline']
    if [s['phase'] for s in result['samples']]!=expected:
        raise ValueError('Unexpected trial order')
    low_modes={'-XX:LowMemoryMode' in s['command'].split() for s in result['samples']}
    if len(low_modes)!=1: raise ValueError('Mixed low-memory modes invalidate comparison')
    samples=[]
    for i,s in enumerate(result['samples']):
        if s['boot']!=result['boot'] or s['image']!=result['image']:
            raise ValueError('Identity mismatch')
        mapped={k:int(v) for k,v in re.findall(r'^(\w+):\s+(\d+) kB$',s['end_smaps_rollup'],re.M)}
        row=dict(index=i,phase=s['phase'],round_p50_ms=s['p50_round_ms'],round_p95_ms=s['p95_round_ms'],
                 cpu_ms=s['process_cpu_ticks']*1000/result['clock_ticks_per_second'],
                 sampled_managed_used_peak_KiB=s['sampled_peak_managed_used_bytes']/1024,
                 end_Pss_KiB=mapped['Pss'],end_SwapPss_KiB=mapped['SwapPss'],
                 gc_count=int(s['gc_after']['art.gc.gc-count'])-int(s['gc_before']['art.gc.gc-count']),
                 gc_time_ms=int(s['gc_after']['art.gc.gc-time'])-int(s['gc_before']['art.gc.gc-time']))
        before=(root/f'system-{i}-before.txt').read_text()
        after=(root/f'system-{i}-after.txt').read_text()
        def counters(text):
            return {k:int(v) for k,v in re.findall(r'^(\w+) (\d+)$',text,re.M)}
        b,a=counters(before),counters(after)
        row['system_counter_delta']={k:a[k]-b[k] for k in ('pgfault','pgmajfault','pswpin','pswpout','pgscan_kswapd','pgsteal_kswapd')}
        samples.append(row)
    metrics=['round_p50_ms','round_p95_ms','cpu_ms','sampled_managed_used_peak_KiB','end_Pss_KiB','end_SwapPss_KiB','gc_count','gc_time_ms']
    medians={phase:{key:statistics.median(s[key] for s in samples if s['phase']==phase) for key in metrics}
             for phase in ('baseline','candidate')}
    changes={key:100*(medians['candidate'][key]/medians['baseline'][key]-1)
             for key in metrics if medians['baseline'][key]}
    props=(root/'properties.txt').read_bytes().strip()
    unchanged=(root/'properties-after.txt').read_bytes().strip()==props
    if terminal_directory is None:
        unchanged=unchanged and (root/'terminal-properties.txt').read_bytes().strip()==props
        terminal=(root/'terminal-processes.txt').read_text()
        no_probe=not any('dalvikvm' in line or 'HeapSlackProbe' in line for line in terminal.splitlines())
        identity=(root/'terminal-identity.txt').read_text().splitlines()
        process_check='Retained terminal process inventory'
    else:
        no_probe=not (terminal_directory/'remaining-vms.txt').read_bytes().strip()
        identity=(terminal_directory/'after.txt').read_text().splitlines()
        if identity[:3]!=[result['image'],result['boot'],'0']:
            raise ValueError('Wrong terminal device identity')
        process_check='pidof dalvikvm dalvikvm32 after all seven commands exited; raw terminal stdout empty'
    if not unchanged or not no_probe: raise ValueError('Terminal verification failed')
    return dict(image=result['image'],boot=result['boot'],raw=root.as_posix(),
                result_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                samples=samples,phase_medians=medians,candidate_change_percent=changes,
                explicit_low_memory_mode=next(iter(low_modes)),
                terminal=dict(no_probe_processes=no_probe,dalvik_properties_unchanged=unchanged,
                              identity=identity,process_check=process_check),
                disposition='Not promoted: this synthetic process trial does not establish whole-device physical memory, latency, hardware or power benefit.',
                limitations=['Synthetic allocation churn, no UI, boot or hardware workload.',
                             'Check explicit_low_memory_mode: the first trial omitted AndroidRuntime LowMemoryMode and is not a matched low-RAM app baseline.',
                             'Ending PSS is GC-phase dependent and not a physical peak or steady-state measurement.',
                             'Median of per-run p95 values, not pooled p95; only12rounds per run, so p95 is each run maximum.',
                             'No warmup exclusion, first-run effects and system-wide pressure confound timing.',
                             'System counter deltas include instrumentation and unrelated kernel activity.',
                             'Zero global property changes; no battery/power benefit demonstrated.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('--output',required=True,type=Path)
    p.add_argument('--terminal-directory',type=Path,
                   help='Separate hardware-window preflight directory with after.txt and remaining-vms.txt')
    a=p.parse_args()
    result=summarize(a.capture,a.terminal_directory)
    with a.output.open('x') as f: f.write(json.dumps(result,indent=2)+'\n')
