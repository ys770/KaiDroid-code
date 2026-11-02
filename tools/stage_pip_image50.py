"""Stage audited PiP SystemUI+revision50 over immutable49; never build or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE='engineering-tcl-dialog-stage-49'
STAGE='engineering-pip-stage-50'
RAW='5b3a37a96408fe15d1b9bc256c279091f0ead792c31e8ef9b14728662c5a9842'
BASE_MANIFEST='25e89b8977c1b463670262abfa6ec4ed1405c42190bdddf30ced3031e793d5f5'
OLD='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
NEW='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
GATE='51b4c7b793471efd331cd5f8a4b43ba24596cb621d9436659b68efe1860d1426'
FRAMEWORK='2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'
APK='system_ext/priv-app/SystemUI/SystemUI.apk'
PARTITION=834666496

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()

def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def inventory(root):
    rows={}
    for folder,dirs,files in os.walk(root,followlinks=False):
        for n in dirs+files:
            p=Path(folder)/n
            rows[p.relative_to(root).as_posix()]=['link',os.readlink(p)] if p.is_symlink() else ['dir',p.stat().st_mode&4095] if p.is_dir() else ['file',p.stat().st_mode&4095,sha(p)]
    return rows

def compare_staged(before,after):
    if before.keys()!=after.keys():raise ValueError('Entry set changed')
    changed={n for n in before if before[n]!=after[n]}
    if changed!={APK,'build.prop'}:raise ValueError('Not exactly SystemUI+revision')
    for n in changed:
        if before[n][:2]!=after[n][:2]:raise ValueError('Type/mode changed')
    if before[APK][2]!=OLD or after[APK][2]!=NEW:raise ValueError('Wrong APK content')
    return changed

def validate_manifest(m):
    if m['image']!=50 or m['baseline_image']!=49 or m['base_raw_sha256']!=RAW or m['base_manifest_sha256']!=BASE_MANIFEST or m['apk_gate_canonical_sha256']!=GATE:
        raise ValueError('Unreviewed stage')
    if set(m['changed'])!={APK,'build.prop'} or len(m['preserved_alarm_files'])!=8 or len(m['art_apex'])!=24 or len(m['framework49_export'])!=30:
        raise ValueError('Protected closure differs')
    if m['protected49_sha256']['framework/framework.jar']!=FRAMEWORK:raise ValueError('Framework49 pin differs')

def check_stage(s):
    m=json.loads((s/'staging.json').read_text());validate_manifest(m)
    if (s/'staging.complete').read_text().strip()!=sha(s/'staging.json'):raise ValueError('Incomplete stage')
    for n,h in m['metadata_files_sha256'].items():
        if sha(s/n)!=h:raise ValueError('Control changed: '+n)
    for n,tree in [('system-inventory.json','compact-system'),('root-inventory.json','compact-root')]:
        if inventory(s/tree)!=json.loads((s/n).read_text()):raise ValueError('Staged payload drift')
    base=s.parent/BASE
    if sha(base/'compact-image/system.raw.img')!=RAW or sha(base/'staging.json')!=BASE_MANIFEST:raise ValueError('Immutable49 identity drift')
    if inventory(base/'compact-system')!=json.loads((s/'baseline-system-inventory.json').read_text()) or inventory(base/'compact-root')!=inventory(s/'compact-root'):
        raise ValueError('Immutable49 trees drifted')
    for n,h in {**m['protected49_sha256'],**m['framework49_export'],**m['art_apex'],**m['preserved_alarm_files']}.items():
        if sha(s/'compact-system'/n)!=h:raise ValueError('Protected content changed: '+n)
    if shutil.disk_usage(s).free<2*PARTITION+2*1024**3:raise ValueError('Insufficient pack margin')
    return m

def launcher():
    return '''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-pip-stage-50"
test -f "$stage/staging.complete"
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
for name in ninja soong_build e2fsdroid; do
 if pgrep -x "$name" >/dev/null; then echo 'Build active; never restart.' >&2; exit 1; fi
done
test -z "$(sudo docker ps -q)"
python3 "$stage/stage-check.py" --check-stage "$stage"
sudo docker image inspect kaidroid-build:20261023 --format '{{.Id}}' > "$stage/container-image-id"
test "$(cat "$stage/container-image-id")" = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
sudo docker run -d --network none --name kaidroid-pip-image50 \\
 -v "$root:/build:ro" \\
 -v "$stage:/build/engineering-pip-stage-50:rw" \\
 kaidroid-build:20261023 bash /build/engineering-pip-stage-50/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''

def stage(root,builder,gate):
    if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:raise ValueError('Require Linux builder1000:1000')
    root=root.resolve(strict=True)
    if str(root)!=ROOT:raise ValueError('Unexpected root')
    base=root/BASE;out=root/STAGE;apk=root/'memory-lazy-pip-build01/output/SystemUI.apk'
    if out.exists():raise FileExistsError(out)
    for n in ['ninja','soong_build','e2fsdroid']:
        if subprocess.run(['pgrep','-x',n],capture_output=True).returncode!=1:raise ValueError('Build active/ambiguous')
    if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container active')
    if sha(base/'staging.json')!=BASE_MANIFEST or (base/'staging.complete').read_text().strip()!=BASE_MANIFEST or (base/'build.exit').read_text().strip()!='0' or sha(base/'compact-image/system.raw.img')!=RAW:raise ValueError('Wrong immutable49')
    g=json.loads(gate.read_text())
    if canonical(g)!=GATE or g['baseline_sha256']!=OLD or g['candidate_sha256']!=NEW or sha(apk)!=NEW:raise ValueError('Wrong audited PiP APK')
    m49=json.loads((base/'staging.json').read_text());before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
    if before!=json.loads((base/'system-inventory.json').read_text()) or roots!=json.loads((base/'root-inventory.json').read_text()):raise ValueError('Baseline tree drift')
    protected={n:h for n,h in m49['protected48_sha256'].items() if n!=APK};protected['framework/framework.jar']=FRAMEWORK
    keep={**protected,**m49['exported_files'],**m49['art_apex'],**m49['preserved_alarm_files']}
    if len(m49['exported_files'])!=30 or len(m49['art_apex'])!=24 or len(m49['preserved_alarm_files'])!=8:raise ValueError('Wrong protected closure')
    for n,h in keep.items():
        if before[n][0]!='file' or before[n][2]!=h:raise ValueError('Wrong protected49 content: '+n)
    if before[APK][2]!=OLD:raise ValueError('Wrong baseline SystemUI')
    props=(base/'compact-system/build.prop').read_bytes();config=(base/'system_image_info.compact.txt').read_text()
    if props.splitlines().count(b'ro.kaidroid.image=49')!=1 or config.count('/build/'+BASE+'/')!=2:raise ValueError('Wrong baseline revision/config')
    copies=sum((Path(f)/n).stat().st_size for t in ['compact-system','compact-root'] for f,_,files in os.walk(base/t) for n in files if not (Path(f)/n).is_symlink());free=shutil.disk_usage(root).free
    if free<copies+2*PARTITION+2*1024**3:raise ValueError('Insufficient independent copy/image margin')
    out.mkdir()
    for tree in ['compact-system','compact-root']:shutil.copytree(base/tree,out/tree,symlinks=True)
    (out/'compact-image').mkdir();shutil.copyfile(apk,out/'compact-system'/APK)
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=49',b'ro.kaidroid.image=50'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt');(out/'system_image_info.compact.txt').write_text(config.replace('/build/'+BASE+'/', '/build/'+STAGE+'/'))
    after=inventory(out/'compact-system');changed=compare_staged(before,after)
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:raise ValueError('Baseline/root changed')
    (out/'build.sh').write_bytes(builder.read_bytes().replace(b'\r\n',b'\n'));shutil.copyfile(Path(__file__),out/'stage-check.py');shutil.copyfile(gate,out/'apk-scope.json');(out/'launch.sh').write_text(launcher())
    for n,v in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]: (out/n).write_text(json.dumps(v,indent=2)+'\n')
    controls=['build.sh','stage-check.py','launch.sh','apk-scope.json','file_contexts.txt','system_image_info.compact.txt','system-inventory.json','root-inventory.json','baseline-system-inventory.json']
    m=dict(image=50,baseline_image=49,base_raw_sha256=RAW,base_manifest_sha256=BASE_MANIFEST,apk_gate_canonical_sha256=GATE,protected49_sha256=protected,framework49_export=m49['exported_files'],art_apex=m49['art_apex'],preserved_alarm_files=m49['preserved_alarm_files'],changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},metadata_files_sha256={n:sha(out/n) for n in controls},copy_bytes=copies,free_bytes_before=free,system_partition_bytes=PARTITION,built=False,installed=False)
    (out/'staging.json').write_text(json.dumps(m,indent=2)+'\n');(out/'staging.complete').write_text(sha(out/'staging.json')+'\n');print(json.dumps(m))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check-stage',type=Path)
    for n in ['root','build-script','apk-gate']:p.add_argument('--'+n,type=Path)
    a=p.parse_args()
    if a.check_stage:check_stage(a.check_stage)
    elif all([a.root,a.build_script,a.apk_gate]):stage(a.root,a.build_script,a.apk_gate)
    else:p.error('Require check-stage or root/build-script/apk-gate')
