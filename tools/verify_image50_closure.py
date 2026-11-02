"""Verify full immutable49-to-PiP50 raw content/mode/UID/GID/link/xattr closure."""
import argparse
import json
from pathlib import Path
from stage_pip_image50 import RAW,OLD,NEW,APK,PARTITION,sha,validate_manifest

def compare_raw(before,after,oldprops,newprops,oldattrs,newattrs):
    if before.keys()!=after.keys():raise ValueError('Raw path set changed')
    changed={n for n in before if before[n]!=after[n]}
    if changed!={'/system/'+APK,'/system/build.prop'}:raise ValueError('Wrong raw changed set')
    for n in changed:
        if {k:v for k,v in before[n].items() if k!='sha256'}!={k:v for k,v in after[n].items() if k!='sha256'}:raise ValueError('Inode mode/UID/GID/kind changed')
    if before['/system/'+APK]['sha256']!=OLD or after['/system/'+APK]['sha256']!=NEW:raise ValueError('Wrong APK')
    if oldprops.splitlines().count(b'ro.kaidroid.image=49')!=1 or newprops!=oldprops.replace(b'ro.kaidroid.image=49',b'ro.kaidroid.image=50'):raise ValueError('Unexpected build.prop difference')
    if oldattrs!=newattrs or oldattrs.keys()!=before.keys():raise ValueError('Xattrs or coverage changed')
    return changed

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['baseline','candidate','manifest','output']:p.add_argument('--'+n,type=Path,required=True)
    for n in ['candidate-sha256','manifest-sha256']:p.add_argument('--'+n,required=True)
    a=p.parse_args()
    if sha(a.manifest)!=a.manifest_sha256:raise ValueError('Unreviewed manifest')
    m=json.loads(a.manifest.read_text());validate_manifest(m)
    for f,h in [(a.baseline,RAW),(a.candidate,a.candidate_sha256)]:
        if f.stat().st_size!=PARTITION or sha(f)!=h:raise ValueError('Raw hash/size mismatch')
    from verify_image43_closure import inventory
    from verify_image40_xattrs import inventory as attrs
    before,bp=inventory(a.baseline);after,ap=inventory(a.candidate);bx,_=attrs(a.baseline);ax,counts=attrs(a.candidate)
    changed=compare_raw(before,after,bp,ap,bx,ax)
    for n,h in {**m['protected49_sha256'],**m['framework49_export'],**m['art_apex'],**m['preserved_alarm_files']}.items():
        if before['/system/'+n].get('sha256')!=h or after['/system/'+n].get('sha256')!=h:raise ValueError('Protected49 content differs: '+n)
    r=dict(baseline_sha256=RAW,candidate_sha256=a.candidate_sha256,manifest_sha256=a.manifest_sha256,entries=len(before),changed=sorted(changed),all_content_modes_uid_gid_links_xattrs_preserved_except_two_payloads=True,xattrs_verified=sum(counts.values()),framework49_ART24_provider_tones8_preserved=True,installed=False,limits=['Timestamps/inode allocation excluded; AVB separately verified by packager.','Raw closure does not prove boot, runtime behavior or memory savings.'])
    with a.output.open('x') as f:f.write(json.dumps(r,indent=2)+'\n')
    print(json.dumps(r))
