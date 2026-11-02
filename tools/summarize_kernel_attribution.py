"""Rank captured kernel-related costs without treating nominal slab geometry as RAM."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from summarize_memory_audit import summarize


def slabs(text):
    if '\nSLAB\n' not in text or not text.rstrip().endswith('END'):
        raise ValueError('Require complete allocator capture')
    section = text.split('\nSLAB\n', 1)[1]
    if not section.startswith('slabinfo - version: 2.1\n'):
        raise ValueError('Unsupported slabinfo format')
    rows = []
    for line in section.splitlines()[2:]:
        if line == 'END':
            break
        parts = line.split()
        if len(parts) != 16 or parts[6:8] != [':', 'tunables'] or parts[11:13] != [':', 'slabdata']:
            raise ValueError('Malformed slab row')
        active, count, size, per_slab, pages = map(int, parts[1:6])
        active_slabs, total_slabs, shared = map(int, parts[13:16])
        if active > count or not size or not per_slab or not pages:
            raise ValueError('Invalid slab counts')
        rows.append(dict(name=parts[0], active_objects_reported=active,
            total_objects=count, object_size_bytes=size,
            object_capacity_bytes=count*size,
            inactive_object_capacity_bytes=(count-active)*size,
            nominal_objects_per_slab=per_slab, nominal_pages_per_slab=pages,
            total_slabs=total_slabs,
            nominal_geometry_matches=(count == per_slab*total_slabs)))
    if not rows:
        raise ValueError('Empty slab capture')
    return sorted(rows, key=lambda r:r['object_capacity_bytes'], reverse=True)


def analyze(root):
    census = summarize(root)
    raw = (root/'allocators.txt').read_bytes()
    rows = slabs(raw.decode())
    processes = [{k:p[k] for k in ('pid','command','VmPTE','Threads')} for p in census['processes']]
    return dict(source_directory=str(root), allocator_sha256=hashlib.sha256(raw).hexdigest(),
        snapshots=[{k:s['meminfo'][k] for k in ('Slab','SReclaimable','SUnreclaim','KernelStack','PageTables')} for s in census['snapshots']],
        observed_processes=len(processes), omitted=census['omitted'],
        sum_process_VmPTE_KiB=sum(p['VmPTE'] or 0 for p in processes),
        sum_userspace_threads=sum(p['Threads'] for p in processes),
        processes_by_VmPTE=sorted(processes,key=lambda p:p['VmPTE'] or 0,reverse=True),
        slab_caches=rows,
        limits=['Historical sequential capture, not a frozen baseline.',
            'VmPTE and global PageTables can use different accounting; no residual is labeled a leak.',
            'Object capacity excludes packing/metadata; inactive objects are not necessarily reclaimable pages.',
            'SLUB nominal order can differ from actual slab order; do not multiply slab count by nominal pages to claim physical usage.',
            'Userspace thread count excludes kernel threads; no stack byte estimate is assigned.',
            'All these kernel costs already lie inside occupied visible RAM.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    with args.output.open('x') as output:
        output.write(json.dumps(analyze(args.capture),indent=2)+'\n')
