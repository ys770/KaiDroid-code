"""Inventory captured DT reserved-memory without calling reusable pools unavailable."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path


def cells(data, count):
    if count not in (1, 2) or len(data) != count*4:
        raise ValueError('Unexpected cell count/width')
    return int.from_bytes(data,'big')


def summarize(capture):
    archive=capture/'device-tree.tar'
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    manifest=json.loads((capture/'manifest.json').read_text())
    entry=next(e for e in manifest['reads'] if e['file']=='device-tree.tar')
    if not manifest.get('same_identity_and_boot') or entry['returncode'] or entry['stderr_bytes'] or entry['sha256']!=digest:
        raise ValueError('Unverified DT capture')
    with tarfile.open(archive) as tar:
        props={m.name:tar.extractfile(m).read() for m in tar if m.isfile()}
    parent='./reserved-memory'
    ac=cells(props.get(parent+'/#address-cells',props['./#address-cells']),1)
    sc=cells(props.get(parent+'/#size-cells',props['./#size-cells']),1)
    nodes=[]
    names=sorted({k.rsplit('/',1)[0] for k in props if k.startswith(parent+'/') and k.count('/')==3})
    for node in names:
        values={k.rsplit('/',1)[1]:v for k,v in props.items() if k.rsplit('/',1)[0]==node}
        result=dict(node=node,status=values.get('status',b'okay').rstrip(b'\0').decode(),
                    reusable='reusable' in values,no_map='no-map' in values,
                    compatible=values.get('compatible',b'').rstrip(b'\0').decode().split('\0'))
        if 'reg' in values:
            data=values['reg']; stride=(ac+sc)*4
            if len(data)%stride: raise ValueError('Bad reg '+node)
            result['regions']=[dict(address=cells(data[i:i+ac*4],ac),
                                    bytes=cells(data[i+ac*4:i+stride],sc))
                               for i in range(0,len(data),stride)]
        if 'size' in values: result['dynamic_size_bytes']=cells(values['size'],sc)
        if 'alignment' in values: result['alignment_bytes']=cells(values['alignment'],sc)
        nodes.append(result)
    intervals=sorted((r['address'],r['address']+r['bytes']) for n in nodes
                     if n['status'] in ('okay','ok') and n['no_map'] and not n['reusable']
                     for r in n.get('regions',[]))
    merged=[]
    for start,end in intervals:
        if merged and start<=merged[-1][1]: merged[-1][1]=max(end,merged[-1][1])
        else: merged.append([start,end])
    return dict(source_sha256=digest,source_image=manifest.get('image'),source_boot=manifest.get('boot'),nodes=nodes,
                enabled_static_no_map_union_bytes=sum(end-start for start,end in merged),
                enabled_reusable_dynamic_bytes=sum(n.get('dynamic_size_bytes',0) for n in nodes
                                                  if n['status'] in ('okay','ok') and n['reusable']),
                scope='Identity-verified captured DT configuration, not a measurement of allocated buffer bytes. Reusable pools can remain in MemTotal. Dynamic allocations, mem= limits and runtime reservations require boot-log/iomem reconciliation; do not sum all nodes as excluded RAM.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture',type=Path)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    result=summarize(a.capture)
    with a.output.open('x') as f: f.write(json.dumps(result,indent=2)+'\n')
