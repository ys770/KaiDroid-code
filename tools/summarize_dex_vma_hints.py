"""Summarize recorded mapping advice flags; virtual coverage is not RAM savings."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HEADER = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+\S+\s+\d+(?:\s+(.*?))?\s*$')
TARGETS = ('/system/framework/framework.jar','/system/framework/services.jar',
    '/apex/com.android.art/javalib/core-oj.jar',
    '/system/system_ext/priv-app/SystemUI/SystemUI.apk',
    '/system/framework/boot-framework.vdex','/system/framework/oat/arm/services.vdex',
    '/system/framework/arm/boot-framework.oat','/system/framework/oat/arm/services.odex',
    '/apex/com.android.art/lib/libart.so',
    '/data/dalvik-cache/arm/system@system_ext@priv-app@SystemUI@SystemUI.apk@classes.')


def parse(text):
    mappings=[]
    for line in text.splitlines():
        header=HEADER.fullmatch(line)
        if header:
            lo,hi=int(header[1],16),int(header[2],16)
            if hi <= lo:raise ValueError('Invalid VMA range')
            mappings.append(dict(start=hex(lo),end=hex(hi),permissions=header[3],
                file_offset=int(header[4],16),path=header[5] or '',virtual_bytes=hi-lo))
        elif mappings:
            if line.startswith('VmFlags:'):mappings[-1]['vm_flags']=line.split()[1:]
            metric=re.fullmatch(r'(Rss|Pss):\s+(\d+) kB\s*',line)
            if metric:mappings[-1][metric[1]+'_KiB']=int(metric[2])
    if not mappings or any(not {'vm_flags','Rss_KiB','Pss_KiB'} <= m.keys() for m in mappings):
        raise ValueError('Incomplete smaps capture')
    return [m for m in mappings if m['path'].startswith(TARGETS)]


def summarize(root):
    manifest=json.loads((root/'manifest.json').read_text())
    if not manifest['complete']:raise ValueError('Incomplete guarded capture')
    processes=[]
    for process in manifest['processes']:
        name=str(process['pid'])+'-smaps'
        raw=(root/(name+'.txt')).read_bytes()
        digest=hashlib.sha256(raw).hexdigest()
        matches=[r for r in manifest['reads'] if r['name']==name]
        if len(matches)!=1 or matches[0]['returncode'] or matches[0]['sha256']!=digest:
            raise ValueError('Raw capture hash/exit mismatch')
        rows=parse(raw.decode())
        groups={}
        for row in rows:
            group=groups.setdefault(row['path'],dict(mappings=0,virtual_bytes=0,rr_virtual_bytes=0,Rss_KiB=0,Pss_KiB=0))
            group['mappings']+=1
            for key in ('virtual_bytes','Rss_KiB','Pss_KiB'):group[key]+=row[key]
            if 'rr' in row['vm_flags']:group['rr_virtual_bytes']+=row['virtual_bytes']
        processes.append(dict(**process,raw_smaps_sha256=digest,backings=groups,mappings=rows))
    return dict(image=manifest['image'],boot=manifest['boot'],raw_directory=str(root),
        capture_manifest_sha256=hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),
        processes=processes,
        limits=['Post-census sequential mapping capture; not the timed memory sample.',
                'rr records the kernel random-access advice flag; it does not prove fewer reads or better latency.',
                'Virtual advice coverage is not resident memory or eliminated allocation.',
                'Targets include DEX containers and native/OAT controls; no claim that entire containers are eligible DEX ranges.',
                'Stored ZIP DEX, resources, metadata and partial edge pages can share a container. Compare exact offsets/flags.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=summarize(args.capture)
    with args.output.open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps([dict(command=p['command'],backings=p['backings']) for p in result['processes']],indent=2))
