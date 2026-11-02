"""Attribute smaps to exclusive backing categories; labels are not savings estimates."""
import argparse
import hashlib
import json
import re
from pathlib import Path

METRICS=('Rss','Pss','Private_Clean','Private_Dirty','Shared_Clean','Shared_Dirty','Swap','SwapPss')
HEADER=re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([-rwxps]+)\s+[0-9a-f]+\s+[0-9a-f:]+\s+\d+(?:\s+(.*))?$')


def category(name):
    lower=name.lower()
    backing=re.sub(r' \(deleted\)$','',lower)
    # File identity precedes words in a path (NetworkStack.apk/libunwindstack.so).
    if backing.endswith(('.apk','.jar')): return 'apk_jar'
    if backing.endswith('.so'): return 'native_library'
    if backing.endswith(('.oat','.odex','.vdex','.dex')): return 'art_code_dex'
    if any(token in lower for token in ('jit-code-cache','jit-data-cache','jit-zygote-cache','jit-cache')):
        return 'art_jit'
    if re.search(r'\.art(?: \(deleted\))?\]?$', lower):
        return 'art_image'
    if any(token in lower for token in ('dalvik-main space','dalvik-zygote space','dalvik-alloc space','dalvik-large object','dalvik-non moving','dalvik-rosalloc')):
        return 'managed_heap'
    if 'dalvik-' in lower: return 'art_metadata_other'
    if any(token in lower for token in ('libc_malloc','jemalloc','scudo:')) or name=='[heap]':
        return 'native_heap'
    if (name.startswith('[anon:') and 'stack' in lower) or re.fullmatch(r'\[stack(?::\d+)?\]',lower):
        return 'stack_labelled'
    if any(token in lower for token in ('/dev/kgsl','/dev/ion','dmabuf','gralloc')):
        return 'graphics_dma_labelled'
    if '/dev/ashmem' in lower or 'memfd:' in lower: return 'other_shared_buffer'
    if not name or name.startswith('[anon:') or name.startswith('['): return 'other_anonymous'
    return 'other_file'


def summarize(text):
    mappings=[]
    for line in text.splitlines():
        header=HEADER.fullmatch(line)
        if header:
            name=header[4] or ''
            mappings.append(dict(name=name,category=category(name),permissions=header[3],metrics={}))
        elif mappings:
            metric=re.fullmatch(r'(\w+):\s+(\d+) kB',line)
            if metric and metric[1] in METRICS: mappings[-1]['metrics'][metric[1]]=int(metric[2])
    if not mappings or any('Pss' not in item['metrics'] or 'Rss' not in item['metrics'] for item in mappings):
        raise ValueError('Require complete smaps metrics for every mapping')
    groups={}
    backings={}
    for item in mappings:
        for table,key in ((groups,item['category']),(backings,item['name'] or '(unnamed)')):
            row=table.setdefault(key,dict(mappings=0,**{m:0 for m in METRICS}))
            row['mappings']+=1
            for m,v in item['metrics'].items(): row[m]+=v
    return dict(groups_KiB=groups,
                largest_backings_KiB=sorted([dict(name=k,**v) for k,v in backings.items()],key=lambda x:x['Pss']+x['SwapPss'],reverse=True)[:30],
                total_KiB={m:sum(item['metrics'].get(m,0) for item in mappings) for m in METRICS},
                scope='One sequential process smaps capture. Categories are exclusive labels, not live allocation reachability, allocator waste or possible savings. PSS and SwapPss remain separate physical/logical quantities. Graphics allocations can be missing from smaps.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('smaps',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    raw=a.smaps.read_bytes()
    result=summarize(raw.decode())
    result['source_sha256']=hashlib.sha256(raw).hexdigest()
    with a.output.open('x') as f: f.write(json.dumps(result,indent=2)+'\n')
