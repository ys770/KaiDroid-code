"""Rewrite reviewed Clock identity strings and Java hash dispatch in smali, offline."""
import argparse
import json
import re
from pathlib import Path


def java_hash(value):
    h=0
    data=value.encode('utf-16-be')
    for i in range(0,len(data),2): h=(31*h+int.from_bytes(data[i:i+2],'big'))&0xffffffff
    return h if h<0x80000000 else h-0x100000000


def rewrite_method(method, mapping):
    active={a:b for a,b in mapping.items() if '"'+a+'"' in method}
    hashes={}
    if 'Ljava/lang/String;->hashCode()I' in method:
        for old,new in active.items():
            h=java_hash(old)
            if h in hashes: raise ValueError('Review hash collision explicitly')
            hashes[h]=java_hash(new)
    changed_hashes=[]
    def number(value):
        n=int(value,0)
        return n if n<0x80000000 else n-0x100000000
    def mapped(value):
        n=number(value)
        if n not in hashes:return value
        changed_hashes.append([n,hashes[n]])
        return hex(hashes[n])
    def table(match):
        entries=[]
        for line in match[1].splitlines():
            if not line.strip():continue
            m=re.fullmatch(r'\s*(-?0x[0-9a-f]+) -> (:\w+)\s*',line)
            if not m:raise ValueError('Unsupported sparse switch row: '+line)
            key=mapped(m[1]);entries.append((number(key),key,m[2]))
        if len({e[0] for e in entries})!=len(entries):raise ValueError('New switch hash collision')
        return '.sparse-switch\n'+''.join('        '+k+' -> '+label+'\n' for _,k,label in sorted(entries))+'    .end sparse-switch'
    method=re.sub(r'\.sparse-switch\n(.*?)\s*\.end sparse-switch',table,method,flags=re.S)
    def constant(match):
        value=mapped(match[3])
        if value==match[3]:return match[0]
        return match[1]+'const '+match[2]+', '+value
    method=re.sub(r'(?m)^(\s*)const(?:/16)? (\w+), (-?0x[0-9a-f]+)$',constant,method)
    # Literal strings only: class descriptors and typed const-class references stay intact.
    for old,new in active.items():method=method.replace('"'+old+'"','"'+new+'"')
    return method,changed_hashes


def rewrite(source,mapping):
    hashes=[]
    def method(m):
        s,h=rewrite_method(m[0],mapping);hashes.extend(h);return s
    out=re.sub(r'(?ms)^\.method .*?^\.end method',method,source)
    lines=[]
    for line in out.splitlines(keepends=True):
        if line.startswith('.field '):
            for old,new in mapping.items():line=line.replace('"'+old+'"','"'+new+'"')
        lines.append(line)
    return ''.join(lines),hashes


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','plan','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();plan=json.loads(a.plan.read_text());mapping={s:s.replace(plan['old_identity'],plan['proposed_identity']) for s in plan['strings']}
    if a.output.exists():raise FileExistsError(a.output)
    results={};payload={}
    for path in a.source.rglob('*.smali'):
        original=path.read_text(encoding='utf-8');changed,hashes=rewrite(original,mapping)
        payload[path.relative_to(a.source)]=changed
        if changed!=original:results[path.relative_to(a.source).as_posix()]=dict(hash_updates=hashes)
    a.output.mkdir(parents=True)
    for path,s in payload.items():
        dest=a.output/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(s,encoding='utf-8',newline='\n')
    (a.output/'identity-rewrite.json').write_text(json.dumps(dict(changed=results,apk_built=False,installed=False),indent=2)+'\n')
    print(json.dumps(dict(files_changed=len(results),hash_updates=sum(len(v['hash_updates']) for v in results.values()),apk_built=False)))


if __name__=='__main__':main()
