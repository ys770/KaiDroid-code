"""Summarize a memory census without treating RSS or swap as physical totals."""
import argparse
import json
import re
from pathlib import Path


def kib(text):
    return {k: int(v) for k, v in re.findall(r'^([A-Za-z_]+):\s+(\d+) kB$', text, re.M)}


def summarize(root):
    before = (root/'system-before.txt').read_text()
    after = (root/'system-after.txt').read_text()
    raw = (root/'processes.txt').read_text()
    if not raw.rstrip().endswith('END_CENSUS'):
        raise ValueError('Incomplete census')
    processes, omitted = [], []
    for block in re.split(r'^PROCESS ', raw, flags=re.M)[1:]:
        if '\nMAPTOTALS\n' not in block:
            continue
        head, tail = block.split('\nMAPTOTALS\n', 1)
        lines = head.splitlines()
        pid = int(lines[0])
        maps, end = tail.split('STAT_AFTER\n', 1)
        first = lines[1].rsplit(')', 1)[1].split()
        lastline = end.splitlines()[0]
        if not lastline or ')' not in lastline:
            omitted.append(dict(pid=pid, reason='exited during read'))
            continue
        last = lastline.rsplit(')', 1)[1].split()
        if first[19] != last[19]:
            omitted.append(dict(pid=pid, reason='PID reused'))
            continue
        values = kib(maps)
        if not values:
            if 'VmSize:' in head:
                omitted.append(dict(pid=pid, reason='missing userspace smaps'))
            continue
        status = kib(head)
        processes.append(dict(pid=pid, command=lines[2], **values,
                              USS=values.get('Private_Clean',0)+values.get('Private_Dirty',0),
                              VmPTE=status.get('VmPTE'), Threads=int(re.search(r'^Threads:\s+(\d+)',head,re.M)[1])))
    snapshots=[]
    for text in (before, after):
        m = kib(text.split('VMSTAT')[0])
        z = [int(v) for v in text.split('ZRAM\n')[1].splitlines()[0].split()]
        snapshots.append(dict(meminfo=m, zram_original_KiB=z[0]/1024,
                              zram_compressed_KiB=z[1]/1024, zram_physical_KiB=z[2]/1024,
                              occupied_visible_KiB=m['MemTotal']-m['MemFree'],
                              logical_swap_used_KiB=m['SwapTotal']-m['SwapFree']))
    def vm(text):
        return {k:int(v) for k,v in re.findall(r'^(\w+) (\d+)$',text.split('VMSTAT\n')[1].split('ZRAM\n')[0],re.M)}
    v0,v1=vm(before),vm(after)
    return dict(snapshots=snapshots, userspace_processes=len(processes), omitted=omitted,
                census_totals_KiB={k:sum(x.get(k,0) for x in processes) for k in ('Pss','USS','Rss','SwapPss')},
                processes=sorted(processes,key=lambda x:x['Pss'],reverse=True),
                vm_delta={k:v1[k]-v0[k] for k in ('pgfault','pgmajfault','pswpin','pswpout','pgscan_kswapd','pgsteal_kswapd') if k in v0 and k in v1},
                limits=['Sequential PSS samples are attribution estimates, not an atomic physical total.',
                        'Occupied visible RAM includes reclaimable cache, kernel, zram and some driver allocations; do not add these again.',
                        'CMA allocation and DMA-BUF sizes can overlap mapped pages and each other.',
                        'Reserved RAM outside MemTotal and unmapped driver coverage require separate reconciliation.',
                        'This inventory perturbs the workload and is not a latency benchmark or frozen comparable baseline.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    a.output.write_text(json.dumps(summarize(a.capture),indent=2)+'\n')


if __name__=='__main__':
    main()
