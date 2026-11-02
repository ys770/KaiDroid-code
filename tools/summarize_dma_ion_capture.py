"""Reconcile reported ION/DMA-BUF views; exported capacity is not physical RAM."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re


def union_size(ranges):
    end=-1;total=0
    for lo,hi in sorted(ranges):
        total+=max(0,hi-max(lo,end));end=max(end,hi)
    return total


def dma_buffers(text):
    lines=text.splitlines();rows=[];current=None;devices=[];footer=None
    for line in lines:
        match=re.fullmatch(r'(\d+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)',line)
        if match:
            if current is not None:raise ValueError('DMA row missing attachment footer')
            size,flags,mode,refs,name=match.groups()
            current=dict(size_bytes=int(size,10),flags=int(flags,16),mode=int(mode,16),reported_file_refs=int(refs,10),exporter=name);devices=[]
            if current['size_bytes']<=0:raise ValueError('Nonpositive buffer')
        elif re.fullmatch(r'Total \d+ devices attached',line):
            if current is None:raise ValueError('Unexpected attachment footer')
            count=int(line.split()[1])
            if count!=len(devices):raise ValueError('Attachment count mismatch')
            current.update(attached_devices=devices,reported_attachment_count=count);rows.append(current);current=None
        elif line.startswith('Total ') and ' objects, ' in line:
            m=re.fullmatch(r'Total (\d+) objects, (\d+) bytes',line)
            if not m or footer is not None:raise ValueError('Malformed/repeated DMA footer')
            footer=tuple(map(int,m.groups()))
        elif current is not None and line.strip() and line.strip()!='Attached Devices:':devices.append(line.strip())
    if current is not None or footer is None or footer!=(len(rows),sum(row['size_bytes'] for row in rows)):
        raise ValueError('Incomplete/mismatched DMA inventory')
    return rows


def ion_heaps(text):
    heaps=[];heap=None;client_table=False;memory_map=False
    for line in text.splitlines():
        if re.fullmatch(r'\s*client\s+pid\s+size\s*',line):
            heap=dict(index=len(heaps),clients=[],physical_range_rows=[],reported_heap_total_bytes=None,reported_orphan_bytes=None)
            heaps.append(heap);client_table=True;memory_map=False
        elif heap is None:continue
        elif line.strip().startswith('orphaned allocations'):
            client_table=False
        elif line.strip()=='Memory Map':memory_map=True;client_table=False
        elif re.fullmatch(r'\s*total orphaned\s+\d+\s*',line):heap['reported_orphan_bytes']=int(line.split()[-1])
        elif re.fullmatch(r'\s*total\s+\d+\s*',line):
            if heap['reported_heap_total_bytes'] is not None:raise ValueError('Repeated heap total')
            heap['reported_heap_total_bytes']=int(line.split()[-1])
        elif client_table:
            row=re.fullmatch(r'\s*(\S+)\s+(\d+)\s+(\d+)\s*',line)
            if row:heap['clients'].append(dict(client=row[1],pid=int(row[2]),reported_handle_bytes=int(row[3])))
        elif memory_map:
            row=re.fullmatch(r'\s*(\S+)\s+(0x(?:0x)?[0-9a-fA-F]+)\s+(0x(?:0x)?[0-9a-fA-F]+)\s+(\d+)\s+\(0x[0-9a-fA-F]+\)',line)
            if row:
                lo=int(row[2].replace('0x0x','0x'),16);hi=int(row[3].replace('0x0x','0x'),16)+1;size=int(row[4])
                if hi<=lo or hi-lo!=size:raise ValueError('Physical range length mismatch')
                heap['physical_range_rows'].append(dict(owner=row[1],start=lo,end_exclusive=hi,size_bytes=size))
    if not heaps or any(h['reported_heap_total_bytes'] is None or h['reported_orphan_bytes'] is None for h in heaps):
        raise ValueError('Incomplete ION heap summaries')
    for heap in heaps:
        heap['sum_client_handle_bytes_not_unique']=sum(c['reported_handle_bytes'] for c in heap['clients'])
        heap['printed_physical_range_union_bytes']=union_size([(r['start'],r['end_exclusive']) for r in heap['physical_range_rows']])
        # Addresses stay in ignored original captures; sanitized report retains coverage totals.
        heap['printed_physical_range_rows']=len(heap.pop('physical_range_rows'))
    return heaps


def summarize(capture):
    manifest=json.loads((capture/'manifest.json').read_text());raw=(capture/'allocators.txt').read_bytes()
    expected=[r for r in manifest['captures'] if r['name']=='allocators']
    digest=hashlib.sha256(raw).hexdigest()
    if len(expected)!=1 or expected[0].get('returncode')!=0 or expected[0]['sha256']!=digest:
        raise ValueError('Allocator capture hash/exit mismatch')
    text=raw.decode().replace('\r\n','\n')
    if not text.startswith('ION\n') or '\nDMA\n' not in text or '\nSLAB\n' not in text or not text.rstrip().endswith('END'):
        raise ValueError('Incomplete allocator boundaries')
    ion=text.split('\nDMA\n')[0];dma=text.split('\nDMA\n',1)[1].split('\nSLAB\n',1)[0]
    rows=dma_buffers(dma);heaps=ion_heaps(ion)
    groups=Counter((r['size_bytes'],r['exporter'],tuple(sorted(r['attached_devices']))) for r in rows)
    grouped=[dict(size_bytes=size,exporter=exporter,attached_device_rows=list(devices),reported_objects=count,
                  exported_capacity_bytes=size*count) for (size,exporter,devices),count in groups.items()]
    grouped.sort(key=lambda r:r['exported_capacity_bytes'],reverse=True)
    dma_total=sum(r['size_bytes'] for r in rows);ion_total=sum(h['reported_heap_total_bytes'] for h in heaps)
    return dict(image=manifest['image'],boot=manifest['boot'],capture=str(capture),allocator_sha256=digest,
        dma_reported_objects=len(rows),dma_exported_capacity_bytes=dma_total,ion_reported_heap_total_bytes=ion_total,
        arithmetic_dma_minus_ion_total_bytes=dma_total-ion_total,ion_heaps=heaps,dma_groups=grouped,
        total_attachment_rows_not_unique_buffers=sum(r['reported_attachment_count'] for r in rows),
        limits=['Heap names are absent because the historical collector concatenated heap files without filename labels.',
                'ION client handle sums overlap across processes/imports; they are not unique bytes.',
                'DMA size rows are reported exported capacity, not proof of distinct nonoverlapping physical pages or resident PSS.',
                'Repeated attachment device names are attachment rows, not extra allocations.',
                'ION/DMA collection is sequential. Their arithmetic difference has no assigned owner/cause.',
                'Printed physical-range unions only cover the heaps that printed ranges; no scatter-gather/whole-driver coverage claim.',
                'No reliable cross-view object ID is printed. Size equality alone does not establish buffer identity.',
                'Do not add these capacities to PSS/occupied RAM/CMA or claim reclaimable savings.'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('capture',type=Path);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();report=summarize(a.capture)
    with a.output.open('x') as out:out.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('dma_reported_objects','dma_exported_capacity_bytes','ion_reported_heap_total_bytes','arithmetic_dma_minus_ion_total_bytes')},indent=2))
