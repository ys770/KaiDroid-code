"""Prepare only reviewed SystemUI+revision47 over immutable46; never launch/flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_RAW='17fbb4ca99df1a1207ea006126ac92617ab8661d86e5a632fe48ee2138290b02'
OLD='5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'
NEW='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
GATE='60e50bc4681a96464db5df362599b6cb724a133ec241c6aae38aad7a77f76b11'
APK='system_ext/priv-app/SystemUI/SystemUI.apk'
PROTECTED={'framework/framework.jar':'11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1',
 'framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
 'framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d',
 'priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'}


def sha(path):
    result=hashlib.sha256()
    with path.open('rb') as file:
        for chunk in iter(lambda:file.read(1024*1024),b''):result.update(chunk)
    return result.hexdigest()


def inventory(root):
    rows={}
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            p=Path(folder)/name
            rows[p.relative_to(root).as_posix()]=(['link',os.readlink(p)] if p.is_symlink() else
                ['dir',p.stat().st_mode&0o7777] if p.is_dir() else ['file',p.stat().st_mode&0o7777,sha(p)])
    return rows


def stage(root,build_script,apk_gate):
    if os.name!='posix':raise ValueError('Image staging is Linux only')
    root=root.resolve(strict=True)
    if str(root)!=ROOT:raise ValueError('Unexpected build root')
    base=root/'engineering-tcl-resolver-stage-46';out=root/'engineering-wallpaper-stage-47'
    candidate=root/'memory-wallpaper-build01/output/SystemUI.apk'
    if out.exists():raise FileExistsError(out)
    if (base/'build.exit').read_text().strip()!='0' or sha(base/'compact-image/system.raw.img')!=BASE_RAW:
        raise ValueError('Immutable46 build/raw mismatch')
    checked=json.loads(apk_gate.read_text())
    canonical=hashlib.sha256(json.dumps(checked,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if canonical!=GATE or checked['baseline_sha256']!=OLD or checked['candidate_sha256']!=NEW:
        raise ValueError('Unreviewed full APK scope gate')
    if sha(candidate)!=NEW or sha(base/'compact-system'/APK)!=OLD:raise ValueError('SystemUI identity mismatch')
    before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
    if before!=json.loads((base/'system-inventory.json').read_text()) or roots!=json.loads((base/'root-inventory.json').read_text()):
        raise ValueError('Image46 staged tree drifted from its packed inventory')
    base_report=json.loads((base/'staging.json').read_text());alarms=base_report['added_alarm_files']
    if base_report['image']!=46 or len(alarms)!=8:raise ValueError('Image46 alarm closure differs')
    for path,pin in {**PROTECTED,**alarms}.items():
        if before[path][0]!='file' or before[path][2]!=pin:raise ValueError('Protected46 content changed: '+path)
    props=(base/'compact-system/build.prop').read_bytes()
    if props.splitlines().count(b'ro.kaidroid.image=46')!=1:raise ValueError('Wrong baseline revision')
    config=(base/'system_image_info.compact.txt').read_text()
    if config.count('/build/'+base.name+'/')!=2:raise ValueError('Unexpected pack config paths')
    copies=sum((Path(folder)/name).stat().st_size for tree in ['compact-system','compact-root']
        for folder,_,files in os.walk(base/tree,followlinks=False) for name in files if not (Path(folder)/name).is_symlink())
    free=shutil.disk_usage(root).free
    if free<copies+2*834666496+2*1024**3:raise ValueError('Insufficient copy/image/margin space')
    out.mkdir()
    for name in ['compact-system','compact-root']:shutil.copytree(base/name,out/name,symlinks=True)
    (out/'compact-image').mkdir()
    shutil.copyfile(candidate,out/'compact-system'/APK)
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=46',b'ro.kaidroid.image=47'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+base.name+'/', '/build/'+out.name+'/'))
    after=inventory(out/'compact-system')
    changed={n for n in before.keys()|after.keys() if before.get(n)!=after.get(n)}
    if changed!={APK,'build.prop'}:raise ValueError('Unexpected image47 staged changes')
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:
        raise ValueError('Original stage or root closure changed')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    for name,data in [('system-inventory.json',after),('root-inventory.json',roots)]:
        (out/name).write_text(json.dumps(data,indent=2)+'\n')
    report=dict(image=47,baseline_image=46,base_raw_sha256=BASE_RAW,candidate_apk_sha256=NEW,
        apk_gate_canonical_sha256=GATE,baseline_entries=len(before),baseline_stage_unchanged=True,root_unchanged=True,
        changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},
        protected46_sha256=PROTECTED,preserved_alarm_files=alarms,
        apk_size_delta_bytes=candidate.stat().st_size-(base/'compact-system'/APK).stat().st_size,
        metadata_files_sha256={name:sha(out/name) for name in ['file_contexts.txt','system_image_info.compact.txt','build.sh','system-inventory.json','root-inventory.json']},
        copy_bytes=copies,free_bytes_before=free,system_partition_bytes=834666496,built=False,installed=False,
        raw_uid_gid_xattr_verification_required=True)
    (out/'staging.json').write_text(json.dumps(report,indent=2)+'\n')
    launch=(base/'launch.sh').read_text()
    if launch.count('kaidroid-tcl-resolver-image46')!=1:raise ValueError('Unexpected baseline Docker container name')
    launch=launch.replace(base.name,out.name).replace('kaidroid-tcl-resolver-image46','kaidroid-wallpaper-image47')
    marker='test ! -e "$stage/container-id"'
    if launch.count(marker)!=1:raise ValueError('Unexpected reviewed launcher shape')
    launch=launch.replace(marker,'test -f "$stage/staging.complete"\n'+marker,1)
    (out/'launch.sh').write_text(launch)
    (out/'staging.complete').write_text(sha(out/'staging.json')+'\n')
    print(json.dumps(report))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['root','build-script','apk-gate']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();stage(a.root,a.build_script,a.apk_gate)
