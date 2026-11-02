"""Compare code, registers and catches in retained dexdumps; exclude debug metadata.

Pool comments and file offsets are discarded. Branches use instruction ordinals;
switch and array payloads are decoded fully from DEX, not truncated dump previews.
Input dumps must have been produced by the same dexdump binary.
"""
import argparse
import gzip
import hashlib
import json
import re
import struct
from pathlib import Path
from copy import deepcopy


def fold_service_loader_names(before,after):
    """Match R8 service-loader helpers by complete body, then rename their callers.

    This permits only a bijection among existing helpers of this exact synthetic
    class. Unknown bodies, helper additions/removals or ambiguity are rejected.
    """
    owner='L$$ServiceLoaderMethods;'
    old={k:v for k,v in before.items() if k[0]==owner}
    new={k:v for k,v in after.items() if k[0]==owner}
    if old.keys()!=new.keys():
        raise ValueError('Service-loader helper set changed')
    mapping={}
    for key,body in new.items():
        matches=[k for k,v in old.items() if v==body]
        if len(matches)!=1 or matches[0] in mapping.values():
            raise ValueError('Service-loader bodies are not a unique bijection')
        mapping[key]=matches[0]
    renamed={}
    for key,body in after.items():
        row=deepcopy(body)
        for i,instruction in enumerate(row['instructions']):
            if not isinstance(instruction,str) or not instruction.startswith('invoke-'):
                continue
            for new_key,old_key in mapping.items():
                old_target=owner+'.'+new_key[1]+':'+new_key[2]
                if instruction.endswith(', '+old_target):
                    row['instructions'][i]=instruction[:-len(old_target)]+owner+'.'+old_key[1]+':'+old_key[2]
                    break
        renamed[mapping.get(key,key)]=row
    return renamed,[dict(candidate=k,baseline=v) for k,v in sorted(mapping.items()) if k!=v]


def normalize(method, data):
    raw=method['instructions']
    instructions=[r for r in raw if not r['spacer']]
    positions={r['offset']:i for i,r in enumerate(instructions)}
    positions[method['units']]=len(instructions)
    for i,r in enumerate(raw):
        if r['spacer']:
            positions[r['offset']]=next((positions[x['offset']] for x in raw[i+1:]
                                        if not x['spacer']),len(instructions))
    def target(offset):
        if offset not in positions:
            raise ValueError('Branch/catch target is not an instruction boundary')
        return '@'+str(positions[offset])
    switches={}
    for r in instructions:
        match=re.fullmatch(r'(packed-switch|sparse-switch) v\d+, ([0-9a-f]+)',r['text'])
        if match:
            payload=int(match[2],16)
            if payload in switches:
                raise ValueError('Shared switch payload requires separate interpretation')
            switches[payload]=r['offset']
    result=[]
    for r in instructions:
        text=r['text']
        payload=re.fullmatch(r'(packed-switch-data|sparse-switch-data|array-data) \((\d+) units\)',text)
        if payload:
            start=r['file_offset'];ident,size=struct.unpack_from('<HH',data,start)
            if ident==0x100 and payload[1]=='packed-switch-data':
                first=struct.unpack_from('<i',data,start+4)[0]
                values=struct.unpack_from('<'+'i'*size,data,start+8)
                text=['packed-switch-data',first,[target(switches[r['offset']]+v) for v in values]]
            elif ident==0x200 and payload[1]=='sparse-switch-data':
                keys=struct.unpack_from('<'+'i'*size,data,start+4)
                values=struct.unpack_from('<'+'i'*size,data,start+4+size*4)
                text=['sparse-switch-data',keys,[target(switches[r['offset']]+v) for v in values]]
            elif ident==0x300 and payload[1]=='array-data':
                count=struct.unpack_from('<I',data,start+4)[0]
                text=['array-data',size,count,data[start+8:start+8+size*count].hex()]
            else:
                raise ValueError('Unexpected payload identifier')
        elif re.match(r'^(if-\S+|goto(?:/\d+)?|packed-switch|sparse-switch|fill-array-data) ',text):
            match=re.search(r'([0-9a-f]+)$',text)
            if not match:
                raise ValueError('Unrecognized branch syntax')
            text=text[:match.start()]+target(int(match[1],16))
        elif text.startswith('const-string/jumbo '):
            text=text.replace('const-string/jumbo ','const-string ',1)
        result.append(text)
    catches=[re.sub(r'0x([0-9a-f]+)',lambda m:target(int(m[1],16)),line)
             for line in method['catches']]
    return dict(frame=method['frame'],access=method['access'],instructions=result,catches=catches)


def methods(dump, dex):
    data=dex.read_bytes();owner=None;current=None;result={};catching=False
    def finish():
        if current and current.get('code') and current.get('type','').startswith('('):
            key=(owner,current['name'],current['type'])
            if key in result:
                raise ValueError('Duplicate method')
            result[key]=normalize(current,data)
    # Latin1 preserves every output byte, including raw MUTF8 string literals.
    with gzip.open(dump,'rt',encoding='latin1',newline='') as stream:
        for line in stream:
            line=line.rstrip('\r\n')
            if line.startswith('Class #'):
                finish();current=None;owner=None;continue
            match=re.search(r"Class descriptor\s+: '([^']+)'",line)
            if match:
                owner=match[1];continue
            if re.match(r'^    #\d+\s+: \(in ',line):
                finish();current=dict(instructions=[],frame={},catches=[]);catching=False;continue
            if current is None:
                continue
            match=re.match(r"\s+(name|type)\s+: '(.*)'$",line)
            if match:
                current[match[1]]=match[2];continue
            match=re.match(r'\s+access\s+: (0x[0-9a-f]+)',line)
            if match:
                current['access']=match[1];continue
            if re.match(r'\s+code\s+-$',line):
                current['code']=True;continue
            match=re.match(r'\s+(registers|ins|outs|insns size)\s+: (\d+)',line)
            if match:
                if match[1]=='insns size':current['units']=int(match[2])
                else:current['frame'][match[1]]=int(match[2])
                continue
            match=re.match(r'^([0-9a-f]+):.*\|([0-9a-f]+): (.*)$',line)
            if match:
                text=match[3].rsplit(' // ',1)[0]
                current['instructions'].append(dict(file_offset=int(match[1],16),
                    offset=int(match[2],16),text=text,spacer='// spacer' in match[3]))
                continue
            if re.match(r'\s+catches\s+:',line):
                catching=True;current['catches'].append(line.strip());continue
            if re.match(r'\s+(positions|locals)\s*:',line):
                catching=False
            if catching and line.strip():current['catches'].append(line.strip())
    finish()
    return result


def compare(before_dump,before_dex,after_dump,after_dex):
    before=methods(before_dump,before_dex);after=methods(after_dump,after_dex)
    changed=[]
    for key in sorted(before.keys()&after.keys()):
        if before[key]!=after[key]:
            changed.append(dict(method=key,before=before[key],after=after[key]))
    folded,mapping=fold_service_loader_names(before,after)
    folded_changes=[key for key in sorted(before.keys()&folded.keys()) if before[key]!=folded[key]]
    return dict(before_methods=len(before),after_methods=len(after),
        unchanged_existing_methods=len(before.keys()&after.keys())-len(changed),
        added_methods=sorted(after.keys()-before.keys()),removed_methods=sorted(before.keys()-after.keys()),
        changed_existing_methods=changed,
        exact_service_loader_body_bijection=mapping,
        changed_existing_methods_after_helper_renaming=folded_changes,
        inputs={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in
                (before_dump,before_dex,after_dump,after_dex)},
        scope='Normalized decoded code/frame/catch comparison; excludes debug positions/locals, annotations, fields and class metadata. Does not prove runtime behavior.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('before-dump','before-dex','after-dump','after-dex','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();result=compare(a.before_dump,a.before_dex,a.after_dump,a.after_dex)
    with a.output.open('x') as output:output.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:len(v) if isinstance(v,list) else v for k,v in result.items()
                      if k not in ('inputs','scope')}))
