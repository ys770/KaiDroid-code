"""Stage reviewed dialog owner policy over immutable image48; never launch or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_NAME='engineering-tcl-dialog-stage-48'
STAGE_NAME='engineering-tcl-dialog-stage-49'
COMPILED='tcl-dialog-build05'
BASE_RAW='fc7f4cb0419aa445675c1516d560bb43945f620c9b269fa4a7942df874ce2e42'
FRAMEWORK='2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'
OLD_FRAMEWORK='897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
COMPILE_STAGE='3d6e7be2a841ce3b7415755de095752f86450a07a979dacb86d4aa8f289c84fa'
EXPORT='62898fb1e958dc2eea5d1451bfe069b504262d737da556fc61ed3a0993f73c5a'
AUDIT='c676c7505556bd55c5b800b6726d7c7077d208e57bbb2eba6423aef87629f9a5'
FILES='8e242977f632a366db428716e07be314049be8c3bf04330d744f17e1d00ea451'
CACHE_PROOF='45624c80b1526e94de82ba43d417ded6b7a5e3dde928f9b41793b78ea64665cd'
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
            value.get('overlay_version')!=4 or value.get('expected_dialog_delta_only') is not True or \
            value.get('accepted_chooser_heading_menu_methods_unchanged') is not True:
        raise ValueError('Not the exact reviewed compiled method audit')


def validate_export(metadata,export):
    files=export['files'];before=metadata['before_closure']
    if canonical(files)!=FILES:raise ValueError('Not the exact reviewed30-file export')
    if metadata['dialog_overlay_version']!=4 or metadata['baseline_image']!=48 or \
            export['dialog_overlay_version']!=4 or export.get('art_apex_unchanged') is not True or \
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
    if (stage/'staging.complete').read_text(encoding='utf-8').strip()!=sha(stage/'staging.json') or \
            m['image']!=49 or m['baseline_image']!=48 or m['base_raw_sha256']!=BASE_RAW:
        raise ValueError('Incomplete/unreviewed image49 stage')
    if m.get('cache_preservation_verified') is not True or m.get('cache_preservation_sha256')!=CACHE_PROOF:
        raise ValueError('Stage lost exact cache preservation gate')
    for name,digest in m['metadata_files_sha256'].items():
        if sha(stage/name)!=digest:raise ValueError('Stage control changed: '+name)
    for name,tree in [('system-inventory.json','compact-system'),('root-inventory.json','compact-root')]:
        if inventory(stage/tree)!=json.loads((stage/name).read_text(encoding='utf-8')):raise ValueError('Staged payload drift: '+tree)
    base=stage.parent/BASE_NAME
    if sha(base/'compact-image/system.raw.img')!=BASE_RAW or \
            inventory(base/'compact-system')!=json.loads((stage/'baseline-system-inventory.json').read_text(encoding='utf-8')) or \
            inventory(base/'compact-root')!=json.loads((stage/'root-inventory.json').read_text(encoding='utf-8')):
        raise ValueError('Immutable48 baseline drifted')
    for name,digest in {**PINS,**m['preserved_alarm_files']}.items():
        if sha(stage/'compact-system'/name)!=digest:raise ValueError('Protected content changed: '+name)
    if shutil.disk_usage(stage).free < 2*PARTITION+2*1024**3:raise ValueError('Insufficient pack headroom')
    return m


def launcher():
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-tcl-dialog-stage-49"
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
sudo docker run -d --network none --name kaidroid-tcl-dialog-image49 \
 -v "$root:/build:ro" \
 -v "$stage:/build/engineering-tcl-dialog-stage-49:rw" \
 kaidroid-build:20261023 bash /build/engineering-tcl-dialog-stage-49/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def validate_cache_proof(proof,metadata):
    state=proof.get('terminal_state',{})
    if proof.get('container_id')!='5b80a7b8d4003b91bc0c7bfb008dbd5ef377e1944a721dced914bb2e7bb330c6' or \
            proof.get('original_lower_all_files_content_metadata_unchanged') is not True or proof.get('lower_entries')!=565530 or \
            proof.get('before_inventory_sha256')!=metadata['layered_output']['before_inventory_sha256'] or \
            state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or \
            state.get('Pid')!=0 or state.get('ExitCode')!=0:
        raise ValueError('Exact terminal05 cache preservation proof missing/failed')


def stage(root,build_script,audit):
    cache_proof_sha256=CACHE_PROOF
    if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:
        raise ValueError('Run Linux staging as the attested image builder UID/GID1000')
    root=root.resolve(strict=True)
    if str(root)!=ROOT:raise ValueError('Unexpected build root')
    base=root/BASE_NAME;compiled=root/COMPILED;out=root/STAGE_NAME
    if out.exists():raise FileExistsError(out)
    for name in ('ninja','soong_build','e2fsdroid'):
        if subprocess.run(['pgrep','-x',name],capture_output=True).returncode!=1:raise ValueError('Build active or observation failed')
    if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container active; coordinate first')
    if (base/'build.exit').read_text(encoding='utf-8').strip()!='0' or sha(base/'compact-image/system.raw.img')!=BASE_RAW or \
            (compiled/'build.exit').read_text(encoding='utf-8').strip()!='0':raise ValueError('Baseline/build not confirmed exact success')
    if sha(compiled/'staging.json')!=COMPILE_STAGE or sha(compiled/'outputs.json')!=EXPORT:
        raise ValueError('Compiled manifests changed')
    validate_audit(json.loads(audit.read_text(encoding='utf-8')))
    metadata=json.loads((compiled/'staging.json').read_text(encoding='utf-8'));export=json.loads((compiled/'outputs.json').read_text(encoding='utf-8'))
    files=validate_export(metadata,export)
    if not re.fullmatch('[0-9a-f]{64}',cache_proof_sha256) or sha(compiled/'cache-preservation.json')!=cache_proof_sha256:
        raise ValueError('Unreviewed cache preservation proof bytes')
    proof=json.loads((compiled/'cache-preservation.json').read_text(encoding='utf-8'))
    validate_cache_proof(proof,metadata)
    for name,key in [('cache-lower-before.json','before_inventory_sha256'),('cache-upper-after.json','upper_inventory_sha256'),('cache-view-delta.json','view_delta_sha256')]:
        if sha(compiled/name)!=proof[key]:raise ValueError('Cache preservation journal changed: '+name)
    before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
    if before!=json.loads((base/'system-inventory.json').read_text(encoding='utf-8')) or roots!=json.loads((base/'root-inventory.json').read_text(encoding='utf-8')):
        raise ValueError('Image48 tree differs from its packed inventory')
    alarms=json.loads((base/'staging.json').read_text(encoding='utf-8'))['preserved_alarm_files']
    if len(alarms)!=8:raise ValueError('Alarm closure changed')
    for name,pin in {**PINS,**alarms,**metadata['before_closure'],**metadata['art_apex']}.items():
        if before[name][0]!='file' or before[name][2]!=pin:raise ValueError('Immutable48 protected content drift: '+name)
    for name,digest in files.items():
        p=compiled/'output'/name
        if p.is_symlink() or sha(p)!=digest:raise ValueError('Export payload changed: '+name)
    props=(base/'compact-system/build.prop').read_bytes()
    if props.splitlines().count(b'ro.kaidroid.image=48')!=1:raise ValueError('Unexpected image revision')
    config=(base/'system_image_info.compact.txt').read_text(encoding='utf-8')
    if config.count('/build/'+BASE_NAME+'/')!=2:raise ValueError('Unreviewed pack config paths')
    copies=sum((Path(folder)/name).stat().st_size for tree in ('compact-system','compact-root')
        for folder,_,names in os.walk(base/tree,followlinks=False) for name in names if not (Path(folder)/name).is_symlink())
    free=shutil.disk_usage(root).free
    if free<copies+2*PARTITION+2*1024**3:raise ValueError('Insufficient copy/image/margin space')
    out.mkdir()
    for tree in ('compact-system','compact-root'):shutil.copytree(base/tree,out/tree,symlinks=True)
    (out/'compact-image').mkdir()
    for name in files:shutil.copyfile(compiled/'output'/name,out/'compact-system'/name)
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=48',b'ro.kaidroid.image=49'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/'),encoding='utf-8')
    after=inventory(out/'compact-system');changed=compare_staged(before,after,files)
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:
        raise ValueError('Immutable baseline or root closure changed')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    shutil.copyfile(Path(__file__),out/'stage-check.py')
    shutil.copyfile(audit,out/'compiled-method-audit.json')
    shutil.copyfile(compiled/'cache-preservation.json',out/'cache-preservation.json')
    (out/'launch.sh').write_text(launcher(),encoding='utf-8')
    for name,value in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    controls=['cache-preservation.json','build.sh','stage-check.py','launch.sh','compiled-method-audit.json','system-inventory.json',
              'root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt']
    report=dict(image=49,baseline_image=48,base_raw_sha256=BASE_RAW,framework_sha256=FRAMEWORK,
        build_manifest_sha256=COMPILE_STAGE,outputs_sha256=EXPORT,compiled_audit_canonical_sha256=AUDIT,cache_preservation_sha256=cache_proof_sha256,cache_preservation_verified=True,
        exported_files=files,art_apex=metadata['art_apex'],preserved_alarm_files=alarms,protected48_sha256=PINS,
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
