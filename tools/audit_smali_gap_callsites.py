"""Locate direct invokes/callers for static app API gaps; no runtime claims."""
import argparse
import hashlib
import json
from pathlib import Path
import re


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(1024*1024),b''):h.update(data)
    return h.hexdigest()


def audit(root, gaps):
    sites=[];incoming={};inputs={};count=0
    for path in sorted(root.glob('smali*/**/*.smali')):
        text=path.read_text(encoding='utf-8')
        declarations=[line for line in text.splitlines() if line.startswith('.class ')]
        if len(declarations)!=1:raise ValueError('Missing/duplicate class declaration: '+str(path))
        owner=declarations[0].split('#',1)[0].split()[-1]
        if not owner.startswith('L') or not owner.endswith(';'):raise ValueError('Bad owner')
        digest=sha(path);inputs[path.relative_to(root).as_posix()]=digest
        for section in text.split('.method ')[1:]:
            if section.count('.end method')!=1:raise ValueError('Malformed method')
            body=section.split('.end method')[0];lines=body.splitlines()
            key=owner+'->'+lines[0].split()[-1];count+=1
            for i,line in enumerate(lines):
                if not line.lstrip().startswith('invoke-') or '}, ' not in line:continue
                ref=line.split('}, ',1)[1].strip()
                incoming.setdefault(ref,set()).add(key)
                if ref not in gaps:continue
                sites.append(dict(reference=ref,method=key,file=path.relative_to(root).as_posix(),
                    source_sha256=digest,near_call='\n'.join(lines[max(0,i-8):i+3]),
                    catch_types_in_method=re.findall(r'^\s*\.catch (\S+)',body,re.M),
                    catchall_in_method='.catchall' in body,method_lines=len(lines)))
    if not inputs:raise ValueError('No smali inputs')
    for site in sites:site['direct_callers']=sorted(incoming.get(site['method'],[]))
    canonical=json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()
    return dict(scope='Direct invoke sites and direct callers in the supplied decode only. Not reflection/JNI/runtime reachability. Catch lists cover whole methods, not necessarily each invoke.',
                decoded_source_inventory_sha256=hashlib.sha256(canonical).hexdigest(),
                decoded_classes=len(inputs),decoded_methods=count,sites=sites,
                gap_references_without_invoke_sites=sorted(gaps-{s['reference'] for s in sites}))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('smali','readiness','apk','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--app',required=True)
    a=p.parse_args()
    report=json.loads(a.readiness.read_text(encoding='utf-8'))
    matches=[r for r in report['apps'] if r['name']==a.app]
    if len(matches)!=1:raise ValueError('Expected exactly one app')
    app=matches[0]
    if sha(a.apk)!=app['apk_sha256']:raise ValueError('Original APK hash mismatch')
    gaps={g['owner']+'->'+g['name']+g['descriptor'] for g in app['boot_owner_gaps'] if g['kind']=='methods'}
    result=audit(a.smali,gaps)
    result.update(app=a.app,original_apk_sha256=sha(a.apk),readiness_sha256=sha(a.readiness),
                  decode_provenance='Caller must decode the pinned original APK into a fresh directory; this tool does not attest an arbitrary existing decode.')
    with a.output.open('x',encoding='utf-8') as out:out.write(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(app=a.app,sites=len(result['sites']),missing_invoke_sites=len(result['gap_references_without_invoke_sites']),classes=result['decoded_classes'])))


if __name__=='__main__':main()
