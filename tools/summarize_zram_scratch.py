"""Summarize a completed scratch trial without treating synthetic compression as phone savings."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path


def online_cpus(text):
    if not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*',text):
        raise ValueError('Malformed CPU online list')
    cpus=set()
    for part in text.split(','):
        ends=list(map(int,part.split('-')));first,last=ends[0],ends[-1]
        if not 0<=first<=last<1024:raise ValueError('Invalid CPU range')
        values=set(range(first,last+1))
        if cpus & values:raise ValueError('Duplicate CPU range')
        cpus |= values
    return sorted(cpus)


def kernel_snapshot(text,mm_stat=False):
    text=text.replace('\r\n','\n')
    lines=text.strip().splitlines()
    if not lines:raise ValueError('Empty kernel snapshot')
    result={'online_cpus':online_cpus(lines[-1])}
    if mm_stat:
        words=lines[0].split()
        if len(words)<3 or not all(word.isdigit() for word in words):
            raise ValueError('Malformed mm_stat')
        original,compressed,physical=map(int,words[:3])
        result['zram']={'logical_bytes':original,'compressed_payload_bytes':compressed,
                        'zsmalloc_physical_bytes':physical,'raw_mm_stat':list(map(int,words))}
    mem={key:int(value)*1024 for key,value in re.findall(r'^(\w+):\s+(\d+) kB$',text,re.M)}
    if not {'MemTotal','MemFree','MemAvailable'}<=mem.keys():raise ValueError('Missing meminfo coverage')
    if not 0<=mem['MemFree']<=mem['MemTotal']:raise ValueError('Impossible meminfo')
    result['occupied_visible_bytes']=mem['MemTotal']-mem['MemFree']
    result['mem_available_bytes']=mem['MemAvailable']
    allocations=re.findall(r'^0x[0-9a-f]+-0x[0-9a-f]+\s+(\d+)\s+.*$',text,re.M)
    if not allocations:raise ValueError('Missing vmallocinfo allocations')
    result['vmalloc_virtual_allocated_bytes']=sum(map(int,allocations))
    result['vmalloc_allocation_count']=len(allocations)
    workspace=[]
    for line in lines:
        if ' zstd_init+' not in line:continue
        match=re.match(r'^0x[0-9a-f]+-0x[0-9a-f]+\s+(\d+)\s+zstd_init\+\S+\s+pages=(\d+)\s+vmalloc(?:\s|$)',line)
        if not match:raise ValueError('Unrecognized zstd workspace allocation')
        workspace.append(dict(virtual_extent_bytes=int(match[1]),reported_backing_pages=int(match[2])))
    result['zstd_init_allocations']=workspace
    result['zstd_init_reported_backing_bytes']=sum(row['reported_backing_pages'] for row in workspace)*4096
    return result


def summarize(directory):
    directory=Path(directory)
    state=json.loads((directory/'result.json').read_text())
    if (not state.get('complete') or not state.get('apply') or state.get('uncertain_operation')
        or state.get('owned_device_pending') or state.get('allocation_pending')
        or state.get('removal_pending') or state.get('active_swap_changed')):
        raise ValueError('Only a completed, cleaned-up applied trial can be summarized')
    phases=state['phases']
    if [p['algorithm'] for p in phases]!=['lzo','zstd','zstd','lzo']:
        raise ValueError('Expected four balanced phases')
    if [p['phase'] for p in phases]!=list(range(4)):
        raise ValueError('Phase identities differ')
    if len({p['result']['checksum'] for p in phases})!=1:
        raise ValueError('Corpus checksum differs')
    journal=[json.loads(line) for line in (directory/'journal.jsonl').read_text().splitlines()]
    records=[item for item in journal if 'returncode' in item]
    hashes={}
    def raw(record):
        if record['returncode']!=0:raise ValueError('Failed snapshot command')
        name=record['stdout_file']
        if Path(name).name!=name:raise ValueError('Snapshot path escapes evidence directory')
        data=(directory/name).read_bytes();digest=hashlib.sha256(data).hexdigest()
        if digest!=record['sha256']:raise ValueError('Snapshot hash mismatch')
        hashes[name]=digest
        return data.decode()
    def snapshot(label,mm_stat=False):
        matches=[r for r in records if r['label']==label]
        if len(matches)!=1:raise ValueError('Missing/ambiguous snapshot '+label)
        return kernel_snapshot(raw(matches[0]),mm_stat)
    workspace_path=Path(__file__).resolve().parents[1]/'docs/evidence/memory-zstd-kernel-workspace01.json'
    workspace_data=workspace_path.read_bytes();workspace_evidence=json.loads(workspace_data)
    if workspace_evidence['kernel_sha256']!='5567e19c38b4d3a8a8d09104def474c44b1b8842e682a4a1d2ac28f0b5d1f561':
        raise ValueError('Unknown kernel workspace model')
    removals=[r for r in records if r['label']=='after-remove-kernel']
    if len(removals)!=4:raise ValueError('Missing post-removal snapshots')
    rows=[]
    for number,phase in enumerate(phases):
        probe=phase['result']
        writes=[r for r in records if r['label']==f'phase{number}-write']
        if len(writes)!=1 or json.loads(raw(writes[0]))!=probe:raise ValueError('Probe result disagrees with journaled output')
        if probe.get('readback_verified') is not True or probe.get('bytes')!=4194304:
            raise ValueError('Unverified corpus')
        before=snapshot(f'phase{number}-before-kernel')
        initialized=snapshot(f'phase{number}-initialized',True)
        filled=snapshot(f'phase{number}-stats',True)
        removed=kernel_snapshot(raw(removals[number]))
        if initialized['zram']['logical_bytes']!=0 or filled['zram']['logical_bytes']!=4194304:
            raise ValueError('Unexpected logical corpus size')
        stable=all(s['online_cpus']==before['online_cpus'] for s in (initialized,filled,removed))
        count=len(before['online_cpus'])
        # Exact retained kernel's page-rounded requests; conditional on one stream per online CPU.
        per_stream=workspace_evidence['results'][phase['algorithm']+'_init']['page_rounded_workspace_bytes']
        workspace=count*per_stream if stable else None
        rows.append(dict(phase=number,algorithm=phase['algorithm'],probe=probe,
                         before=before,initialized=initialized,filled=filled,removed=removed,
                         cpus_stable=stable,conditional_workspace_request_bytes=workspace,
                         init_zstd_reported_backing_delta_bytes=initialized['zstd_init_reported_backing_bytes']-before['zstd_init_reported_backing_bytes'],
                         removal_zstd_reported_backing_residual_bytes=removed['zstd_init_reported_backing_bytes']-before['zstd_init_reported_backing_bytes'],
                         conditional_zsmalloc_plus_workspace_bytes=(filled['zram']['zsmalloc_physical_bytes']+workspace) if workspace is not None else None,
                         init_vmalloc_virtual_delta_bytes=initialized['vmalloc_virtual_allocated_bytes']-before['vmalloc_virtual_allocated_bytes'],
                         removal_vmalloc_virtual_residual_bytes=removed['vmalloc_virtual_allocated_bytes']-before['vmalloc_virtual_allocated_bytes']))
    medians={}
    for algorithm in ('lzo','zstd'):
        arm=[row for row in rows if row['algorithm']==algorithm]
        medians[algorithm]={key:statistics.median(row['filled']['zram'][key] for row in arm)
                           for key in ('compressed_payload_bytes','zsmalloc_physical_bytes')}
        medians[algorithm].update({key:statistics.median(row['probe'][key] for row in arm)
                                  for key in ('write_ns','write_cpu_ns','read_ns','read_cpu_ns','write_page_p50_ns','write_page_p95_ns')})
        costs=[row['conditional_zsmalloc_plus_workspace_bytes'] for row in arm]
        medians[algorithm]['conditional_zsmalloc_plus_workspace_bytes']=statistics.median(costs) if None not in costs else None
    return dict(image=state['image'],boot=state['boot'],probe_sha256=state['probe_sha256'],
                phases=rows,medians=medians,raw_snapshot_sha256=hashes,
                result_sha256=hashlib.sha256((directory/'result.json').read_bytes()).hexdigest(),
                journal_sha256=hashlib.sha256((directory/'journal.jsonl').read_bytes()).hexdigest(),
                workspace_evidence='docs/evidence/memory-zstd-kernel-workspace01.json',
                workspace_evidence_sha256=hashlib.sha256(workspace_data).hexdigest(),
                workspace_kernel_sha256=workspace_evidence['kernel_sha256'],
                scope='Synthetic 4MiB corpus only, two samples per algorithm. No Android working-set or interaction-latency conclusion. Vmalloc totals are virtual allocation extents; separately reported pages= counts track zstd_init backing pages with 4KiB pages on this target. Conditional workspace requests exclude allocator/crypto/zcomp metadata and page tables; do not add them again to occupied visible RAM. Background Android activity remains a confound.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report=summarize(args.directory)
    with args.output.open('x') as output:output.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report['medians']))
