"""Stage reviewed dialog framework03 over immutable image47; never launch or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_NAME='engineering-wallpaper-stage-47'
STAGE_NAME='engineering-tcl-dialog-stage-48'
COMPILED='tcl-dialog-build03'
BASE_RAW='54d43eb8a7ebb408adf840d9d2611b0455e05d9ce5fde413d8b9a1abae9c37c4'
FRAMEWORK='897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
OLD_FRAMEWORK='11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1'
COMPILE_STAGE='ad24e63af1f067888c05dfafec77b35e297adb0a752128a1ee93632711d1645b'
EXPORT='9e3db7012c3e993852007563ede7922136b017701515266b0d2318ef359d5930'
AUDIT='a1a6380cb8f8965fbad3c250af99898abc599404316360bcc9f65a4a54c984f9'
FILES='286011610a13a9d35e919efe0271075af66866c2d116383169e64b9bcf5b8543'
PARTITION=834666496
PINS={'system_ext/priv-app/SystemUI/SystemUI.apk':'2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87',
      'priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c',
      'framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72',
      'framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d'}


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def inventory(root):
    rows={}
    for folder,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            p=Path(folder)/name
            rows[p.relative_to(root).as_posix()]=(['link',os.readlink(p)] if p.is_symlink() else
                ['dir',p.stat().st_mode&0o7777] if p.is_dir() else ['file',p.stat().st_mode&0o7777,sha(p)])
    return rows


def validate_audit(value):
    if canonical(value)!=AUDIT or value.get('baseline_sha256')!=OLD_FRAMEWORK or value.get('candidate_sha256')!=FRAMEWORK or \
            value.get('overlay_version')!=3 or value.get('expected_dialog_delta_only') is not True or \
            value.get('accepted_chooser_heading_menu_methods_unchanged') is not True:
        raise ValueError('Not the exact reviewed compiled method audit')


def validate_export(metadata,export):
    files=export['files'];before=metadata['before_closure']
    if canonical(files)!=FILES:raise ValueError('Not the exact reviewed30-file export')
    if metadata['dialog_overlay_version']!=3 or metadata['baseline_image']!=46 or \
            export['dialog_overlay_version']!=3 or export.get('art_apex_unchanged') is not True or \
            export.get('baseline_preserved') is not True or export.get('new_class_in_dex') is not True or \
            len(files)!=30 or set(files)!=set(metadata['closure']) or set(files)!=set(before) or \
            files.get('framework/framework.jar')!=FRAMEWORK or before.get('framework/framework.jar')!=OLD_FRAMEWORK:
        raise ValueError('Unexpected framework export closure')
    for name,digest in files.items():
        if not re.fullmatch(r'framework/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',name) or '..' in Path(name).parts or \
                not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('Unsafe export path/hash')
    for name,pin in PINS.items():
        if name in files and files[name]!=pin:raise ValueError('Protected resource/service export changed')
    if len(metadata['art_apex'])!=24:raise ValueError('Unexpected ART closure')
    return files


def compare_staged(before,after,export):
    if before.keys()!=after.keys():raise ValueError('Staged path set changed')
    expected={n for n,d in export.items() if before[n][2]!=d}|{'build.prop'}
    changed={n for n in before if before[n]!=after[n]}
    if changed!=expected:raise ValueError('Unexpected staged content delta')
    for name in changed:
        if before[name][:2]!=after[name][:2]:raise ValueError('Staged type/mode changed: '+name)
    for name,digest in export.items():
        if after[name][0]!='file' or after[name][2]!=digest:raise ValueError('Missing exported payload: '+name)
    return changed


def check_stage(stage):
    m=json.loads((stage/'staging.json').read_text(encoding='utf-8'))
    if (stage/'staging.complete').read_text().strip()!=sha(stage/'staging.json') or \
            m['image']!=48 or m['baseline_image']!=47 or m['base_raw_sha256']!=BASE_RAW:
        raise ValueError('Incomplete/unreviewed image48 stage')
    for name,digest in m['metadata_files_sha256'].items():
        if sha(stage/name)!=digest:raise ValueError('Stage control changed: '+name)
    for name,tree in [('system-inventory.json','compact-system'),('root-inventory.json','compact-root')]:
        if inventory(stage/tree)!=json.loads((stage/name).read_text()):raise ValueError('Staged payload drift: '+tree)
    base=stage.parent/BASE_NAME
    if sha(base/'compact-image/system.raw.img')!=BASE_RAW or \
            inventory(base/'compact-system')!=json.loads((stage/'baseline-system-inventory.json').read_text()) or \
            inventory(base/'compact-root')!=json.loads((stage/'root-inventory.json').read_text()):
        raise ValueError('Immutable47 baseline drifted')
    for name,digest in {**PINS,**m['preserved_alarm_files']}.items():
        if sha(stage/'compact-system'/name)!=digest:raise ValueError('Protected content changed: '+name)
    if shutil.disk_usage(stage).free < 2*PARTITION+2*1024**3:raise ValueError('Insufficient pack headroom')
    return m


def launcher():
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-tcl-dialog-stage-48"
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
sudo docker run -d --network none --name kaidroid-tcl-dialog-image48 \
 -v "$root:/build:ro" \
 -v "$stage:/build/engineering-tcl-dialog-stage-48:rw" \
 kaidroid-build:20261023 bash /build/engineering-tcl-dialog-stage-48/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def stage(root,build_script,audit):
    if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:
        raise ValueError('Run Linux staging as the attested image builder UID/GID1000')
    root=root.resolve(strict=True)
    if str(root)!=ROOT:raise ValueError('Unexpected build root')
    base=root/BASE_NAME;compiled=root/COMPILED;out=root/STAGE_NAME
    if out.exists():raise FileExistsError(out)
    for name in ('ninja','soong_build','e2fsdroid'):
        if subprocess.run(['pgrep','-x',name],capture_output=True).returncode!=1:raise ValueError('Build active or observation failed')
    if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container active; coordinate first')
    if (base/'build.exit').read_text().strip()!='0' or sha(base/'compact-image/system.raw.img')!=BASE_RAW or \
            (compiled/'build.exit').read_text().strip()!='0':raise ValueError('Baseline/build not confirmed exact success')
    if sha(compiled/'staging.json')!=COMPILE_STAGE or sha(compiled/'outputs.json')!=EXPORT:
        raise ValueError('Compiled manifests changed')
    validate_audit(json.loads(audit.read_text(encoding='utf-8')))
    metadata=json.loads((compiled/'staging.json').read_text());export=json.loads((compiled/'outputs.json').read_text())
    files=validate_export(metadata,export)
    before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
    if before!=json.loads((base/'system-inventory.json').read_text()) or roots!=json.loads((base/'root-inventory.json').read_text()):
        raise ValueError('Image47 tree differs from its packed inventory')
    alarms=json.loads((base/'staging.json').read_text())['preserved_alarm_files']
    if len(alarms)!=8:raise ValueError('Alarm closure changed')
    for name,pin in {**PINS,**alarms,**metadata['before_closure'],**metadata['art_apex']}.items():
        if before[name][0]!='file' or before[name][2]!=pin:raise ValueError('Immutable47 protected content drift: '+name)
    for name,digest in files.items():
        p=compiled/'output'/name
        if p.is_symlink() or sha(p)!=digest:raise ValueError('Export payload changed: '+name)
    props=(base/'compact-system/build.prop').read_bytes()
    if props.splitlines().count(b'ro.kaidroid.image=47')!=1:raise ValueError('Unexpected image revision')
    config=(base/'system_image_info.compact.txt').read_text()
    if config.count('/build/'+BASE_NAME+'/')!=2:raise ValueError('Unreviewed pack config paths')
    copies=sum((Path(folder)/name).stat().st_size for tree in ('compact-system','compact-root')
        for folder,_,names in os.walk(base/tree,followlinks=False) for name in names if not (Path(folder)/name).is_symlink())
    free=shutil.disk_usage(root).free
    if free<copies+2*PARTITION+2*1024**3:raise ValueError('Insufficient copy/image/margin space')
    out.mkdir()
    for tree in ('compact-system','compact-root'):shutil.copytree(base/tree,out/tree,symlinks=True)
    (out/'compact-image').mkdir()
    for name in files:shutil.copyfile(compiled/'output'/name,out/'compact-system'/name)
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=47',b'ro.kaidroid.image=48'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/'),encoding='utf-8')
    after=inventory(out/'compact-system');changed=compare_staged(before,after,files)
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:
        raise ValueError('Immutable baseline or root closure changed')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    shutil.copyfile(Path(__file__),out/'stage-check.py')
    shutil.copyfile(audit,out/'compiled-method-audit.json')
    (out/'launch.sh').write_text(launcher(),encoding='utf-8')
    for name,value in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    controls=['build.sh','stage-check.py','launch.sh','compiled-method-audit.json','system-inventory.json',
              'root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt']
    report=dict(image=48,baseline_image=47,base_raw_sha256=BASE_RAW,framework_sha256=FRAMEWORK,
        build_manifest_sha256=COMPILE_STAGE,outputs_sha256=EXPORT,compiled_audit_canonical_sha256=AUDIT,
        exported_files=files,art_apex=metadata['art_apex'],preserved_alarm_files=alarms,protected47_sha256=PINS,
        changed={n:dict(before=before[n],after=after[n]) for n in sorted(changed)},
        metadata_files_sha256={n:sha(out/n) for n in controls},copy_bytes=copies,free_bytes_before=free,
        system_partition_bytes=PARTITION,baseline_stage_unchanged=True,root_unchanged=True,
        built=False,installed=False,raw_uid_gid_xattr_verification_required=True)
    (out/'staging.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (out/'staging.complete').write_text(sha(out/'staging.json')+'\n')  # Last mutation: no partial stage may launch.
    print(json.dumps(report))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check-stage',type=Path)
    for name in ('root','build-script','audit'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    if a.check_stage:check_stage(a.check_stage)
    elif all((a.root,a.build_script,a.audit)):stage(a.root,a.build_script,a.audit)
    else:p.error('Require --check-stage or --root/--build-script/--audit')
