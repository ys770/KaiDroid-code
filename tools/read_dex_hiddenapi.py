"""Read encoded boot DEX hidden-API flags without modifying an archive.

Format: https://source.android.com/docs/core/runtime/dex-format#hiddenapi_class_data_item
Reports complete encoded words, not just the low restriction bits.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

from audit_tcl_target_api import parse


def encoded_flags(data):
    classes,methods,fields,stale=parse(data)
    def u32(pos):
        if pos<0 or pos+4>len(data):raise ValueError('DEX uint outside file')
        return struct.unpack_from('<I',data,pos)[0]
    def uleb(pos,end):
        value=0;start=pos
        for shift in range(0,35,7):
            if pos>=end:raise ValueError('Truncated hidden API/member ULEB')
            byte=data[pos];pos+=1;value|=(byte&127)<<shift
            if not byte&128:
                if value>0xffffffff:raise ValueError('Hidden API/member ULEB overflow')
                return value,pos,start
        raise ValueError('Invalid hidden API/member ULEB')
    map_offset=u32(52);count=u32(map_offset)
    if map_offset+4+12*count>len(data):raise ValueError('Truncated DEX map')
    sections=[]
    for i in range(count):
        kind,unused,items,offset=struct.unpack_from('<HHII',data,map_offset+4+12*i)
        if kind==0xf000:
            if unused or items!=1:raise ValueError('Invalid hidden API map entry')
            sections.append(offset)
    if len(sections)>1:raise ValueError('Duplicate hidden API map sections')
    section=sections[0] if sections else None
    minimum=4+4*len(classes)
    if section is not None:
        size=u32(section)
        if size<minimum or section+size>len(data):raise ValueError('Hidden API section size outside file/class table')
    else:size=0
    result={};ranges=[]
    for number,owner in enumerate(classes):
        cursor=u32(u32(100)+32*number+24)
        members=[]
        if cursor:
            counts=[]
            for _ in range(4):n,cursor,_=uleb(cursor,len(data));counts.append(n)
            for kind,n in enumerate(counts):
                index=0
                for _ in range(n):
                    delta,cursor,_=uleb(cursor,len(data));index+=delta
                    _,cursor,_=uleb(cursor,len(data))
                    if kind>=2:_,cursor,_=uleb(cursor,len(data))
                    table=fields if kind<2 else methods
                    if index>=len(table):raise ValueError('Member index outside DEX table')
                    declared,name,descriptor=table[index]
                    if declared!=owner:raise ValueError('Hidden API member owner mismatch')
                    signature=owner+'->'+name+(':'+descriptor if kind<2 else descriptor)
                    members.append((signature,kind))
        offset=u32(section+4+number*4) if section is not None else None
        if offset and not minimum<=offset<size:raise ValueError('Hidden API class offset outside flag data')
        position=section+offset if offset else None
        start=position
        for signature,kind in members:
            if signature in result:raise ValueError('Duplicate declared hidden API signature')
            if position is not None:
                value,position,flag_at=uleb(position,section+size)
            else:value,flag_at=(0,None) if section is not None else (None,None)
            result[signature]=dict(flag=value,flag_offset=flag_at,member_kind=kind,class_def_index=number)
        if start is not None and position>start:ranges.append((start,position))
    ranges.sort()
    if any(a[1]>b[0] for a,b in zip(ranges,ranges[1:])):raise ValueError('Overlapping hidden API class flag arrays')
    return result,dict(section_offset=section,section_size=size,declared_members=len(result),stale_dex_sha1=stale)


def inventory(path):
    result={};dexes={}
    with zipfile.ZipFile(path) as archive:
        names=[n for n in archive.namelist() if n.startswith('classes') and n.endswith('.dex')]
        if not names or any('/' in n for n in names):raise ValueError('Missing/unreviewed DEX archive shape')
        for name in names:
            data=archive.read(name);rows,summary=encoded_flags(data)
            if result.keys()&rows.keys():raise ValueError('Duplicate declaration across DEX files')
            for row in rows.values():row['dex']=name
            result.update(rows);dexes[name]=dict(summary,sha256=hashlib.sha256(data).hexdigest())
    return result,dexes


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--jar',type=Path,required=True);p.add_argument('--signature',action='append',required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    rows,dexes=inventory(a.jar)
    report=dict(archive_sha256=hashlib.sha256(a.jar.read_bytes()).hexdigest(),dexes=dexes,
        selected={name:rows.get(name) for name in a.signature},complete_declared_members=len(rows),
        no_archive_modification=True,restriction_values=dict(whitelist=0,greylist=1,blacklist=2),
        format_source='https://source.android.com/docs/core/runtime/dex-format#hiddenapi_class_data_item')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x',encoding='utf-8') as f:f.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
