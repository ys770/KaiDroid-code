"""Compare all46/47 content, inode mode/UID/GID, symlinks and xattrs; never flash."""
import argparse
import hashlib
import json
from pathlib import Path

from verify_image43_closure import inventory
from verify_image40_xattrs import inventory as xattrs

BASE='17fbb4ca99df1a1207ea006126ac92617ab8661d86e5a632fe48ee2138290b02'
OLD='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
NEW='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
APK='/system/system_ext/priv-app/SystemUI/SystemUI.apk'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['baseline','candidate','output']:p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--candidate-sha256',required=True)
    a=p.parse_args()
    for path,pin in [(a.baseline,BASE),(a.candidate,a.candidate_sha256)]:
        assert path.stat().st_size==834666496,'Partition size mismatch'
        with path.open('rb') as file:assert hashlib.file_digest(file,'sha256').hexdigest()==pin,'Raw image identity mismatch'
    before,oldprops=inventory(a.baseline);after,newprops=inventory(a.candidate)
    assert before.keys()==after.keys(),'Entry set changed (including46 alarm paths)'
    changed={path for path in before if before[path]!=after[path]}
    assert changed=={APK,'/system/build.prop'},changed
    for path in changed:
        assert {k:v for k,v in before[path].items() if k!='sha256'}=={k:v for k,v in after[path].items() if k!='sha256'},'Changed inode metadata'
    assert before[APK]['sha256']==OLD and after[APK]['sha256']==NEW
    assert before['/system/framework/framework.jar']['sha256']=='11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1'
    assert before['/system/framework/framework-res.apk']['sha256']=='42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72'
    assert before['/system/priv-app/TelephonyProvider/TelephonyProvider.apk']['sha256']=='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'
    assert oldprops.splitlines().count(b'ro.kaidroid.image=46')==1
    assert newprops==oldprops.replace(b'ro.kaidroid.image=46',b'ro.kaidroid.image=47')
    oldattrs,_=xattrs(a.baseline);newattrs,counts=xattrs(a.candidate)
    assert oldattrs==newattrs,'SELinux/capability/all extended attributes differ'
    report=dict(baseline_sha256=BASE,candidate_sha256=a.candidate_sha256,filesystem_entries=len(before),
        changed=sorted(changed),all_extended_attributes_identical=True,compared_xattrs=sum(counts.values()),
        content_modes_uid_gid_symlinks_verified=True,framework_provider_alarms_preserved=True,installed=False,
        exclusions=['timestamps','inode allocation'],avb_verification='Separate build verification artifact required')
    with a.output.open('x') as file:file.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
