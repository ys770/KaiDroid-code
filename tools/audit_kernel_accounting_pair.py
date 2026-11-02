"""Reconcile saved all-process page-table attribution using exact retained-kernel controls."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from check_kernel_page_table_accounting import KERNEL, SYMBOLS, FUNCTIONS
from summarize_kernel_attribution import analyze


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def verified_census(root):
    manifest=json.loads((root/'manifest.json').read_text())
    records=manifest['captures']
    if len({r['name'] for r in records})!=len(records): raise ValueError('Duplicate capture name')
    by_name={r['name']:r for r in records}
    required={'identity-before','system-before','processes','identity-middle','allocators','system-after','identity-after'}
    if not required.issubset(by_name): raise ValueError('Required capture missing')
    for name,record in by_name.items():
        if record.get('returncode')!=0 or record.get('sha256')!=sha(root/(name+'.txt')):
            raise ValueError('Saved capture hash/exit mismatch: '+name)
    for name in ['identity-before','identity-middle','identity-after']:
        if (root/(name+'.txt')).read_text().splitlines()!=[manifest['image'],manifest['boot'],'0']:
            raise ValueError('Saved image/boot/root guard mismatch')
    report=analyze(root)
    if report['omitted'] or report['observed_processes']!=94:
        raise ValueError('Expected complete retained94-process census')
    parents={}
    for block in re.split(r'^PROCESS ',(root/'processes.txt').read_text(),flags=re.M)[1:]:
        head=block.split('\nMAPTOTALS\n',1)[0]
        match=re.search(r'^PPid:\s+(\d+)$',head,re.M)
        if match: parents[int(head.splitlines()[0])]=int(match[1])
    processes=report['processes_by_VmPTE']
    if set(parents)!={p['pid'] for p in processes}: raise ValueError('Parent graph coverage mismatch')
    zygotes=[p['pid'] for p in processes if p['command'].strip()=='zygote']
    if len(zygotes)!=1: raise ValueError('Expected one captured zygote')
    zygote=zygotes[0]
    def below_zygote(pid):
        seen=set()
        while pid in parents and pid not in seen:
            if pid==zygote: return True
            seen.add(pid);pid=parents[pid]
        return False
    for p in processes:
        if p['VmPTE'] is None or p['VmPTE']%2: raise ValueError('Unexpected task PTE units')
        p['captured_zygote_or_descendant']=below_zygote(p['pid'])
        p['conditional_physical_PTE_KiB']=p['VmPTE']*2
    doubled=report['sum_process_VmPTE_KiB']*2
    slab=report.pop('slab_caches')
    report.update(image=manifest['image'],boot=manifest['boot'],
        raw_sha256={name:by_name[name]['sha256'] for name in by_name},
        conditional_sum_physical_PTE_KiB=doubled,
        global_minus_converted_process_KiB=[s['PageTables']-doubled for s in report['snapshots']],
        ancestry_groups=[dict(captured_zygote_or_descendant=group,
            processes=sum(p['captured_zygote_or_descendant']==group for p in processes),
            conditional_physical_PTE_KiB=sum(p['conditional_physical_PTE_KiB'] for p in processes if p['captured_zygote_or_descendant']==group)) for group in [True,False]],
        slab_cache_count=len(slab),slab_object_capacity_bytes=sum(s['object_capacity_bytes'] for s in slab),
        inactive_slab_object_capacity_bytes=sum(s['inactive_object_capacity_bytes'] for s in slab),
        largest_object_capacity_caches=slab[:8])
    return report


def audit(control_path):
    controls=json.loads(control_path.read_text())
    if controls['kernel_sha256']!=KERNEL or controls['symbols_sha256']!=SYMBOLS or controls['function_sha256']!=FUNCTIONS:
        raise ValueError('Kernel controls identity mismatch')
    if controls['checker_sha256']!=sha(Path(__file__).with_name('check_kernel_page_table_accounting.py')) or len(controls['runs'])!=15:
        raise ValueError('Stale/incomplete kernel controls')
    baseline=verified_census(Path('artifacts/runtime/image43-memory-madvise-baseline300-01/timed/census'))
    candidate=verified_census(Path('artifacts/runtime/image44-memory-madvise300-01/timed/census'))
    if Counter(p['command'].strip() for p in baseline['processes_by_VmPTE'])!=Counter(p['command'].strip() for p in candidate['processes_by_VmPTE']):
        raise ValueError('Process command multisets differ')
    config=Path('work/profiles/engineering/kernel.config')
    text=config.read_text()
    if '# CONFIG_ARM_LPAE is not set' not in text or 'CONFIG_ARM=y' not in text:
        raise ValueError('Configuration assumption changed')
    return dict(retained_kernel_controls=controls,control_report_sha256=sha(control_path),
        configuration=dict(path=str(config),sha256=sha(config),ARM=True,ARM_LPAE=False),
        baseline=baseline,candidate=candidate,
        conclusion='Retained vendor ARM code verifies2KiB task VmPTE versus4KiB physical/global accounting per PTE-table allocation. The factor2 is not a missing allocation or saving.',
        next_action='Do not treat the raw VmPTE/global gap as an unowned pool. Trace actual mapping/table ownership before changing binary layout; driver/physical overlaps remain separate.',
        limits=['Kernel is retained original engineering binary; no fresh image45 kernel acquisition or phone operation.',
                'Converted per-process values assume these captures use the retained kernel; original-bootchain validation is external to this tool.',
                'All94userspace process lifetimes pass, but observations are sequential; residual signs can change and are not assigned a cause.',
                'Captured parent ancestry is not full Java/native classification or proof of binary ownership.',
                'No per-VMA PTE physical attribution, unique driver-page reconciliation, reclaimability, measured optimization or80percent completion.',
                'Slab capacity/nominal geometry/inactive objects are not reclaimable physical pages. Kernel values already lie inside occupied RAM.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--controls',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=audit(args.controls)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({name:{key:report[name][key] for key in ['conditional_sum_physical_PTE_KiB','global_minus_converted_process_KiB','ancestry_groups']} for name in ['baseline','candidate']},indent=2))
