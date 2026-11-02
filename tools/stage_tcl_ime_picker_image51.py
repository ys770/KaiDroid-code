"""Stage reviewed titleless picker over immutable image50; never launch or flash."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT='/opt/kaidroid/kaidroid-build-20261023'
BASE_NAME='engineering-pip-stage-50'
STAGE_NAME='engineering-tcl-ime-picker-stage-51'
COMPILED='tcl-dialog-build06'
BASE_RAW='4b876a7a4d1800fda46b43f96808125431ec72e2b6a2380e6ff209a42c30a1b9'
FRAMEWORK='efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb'
OLD_FRAMEWORK='2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'
CACHE_FRAMEWORK='897e1b2fb943a258f95dcd331b9c98204727337b78f1a8daafc15c44852357cb'
BASE_MANIFEST='0700a50e0ab495aca081b36021e4aa14a52a0f0e4836c8ea712a6770bdaab6b4'
BASE_OUTPUTS='f65b34f3a88c03cc52b37389781cdc163f1a3ad2e854b1bf349bde063baccf25'
METADATA_AUDIT='ebf9c8e7849484f55d07528b8b123a1993b789f36e5cc98083244760b0b70a4a'
COMPILE_STAGE='268ffec83ebe8f90e63ff306cad9908e0efd9b45684168e33ece9a7e37f981bf'
EXPORT='fe6fbaa02a2b68d9c9ea9697d688268f996d0c1a519d06171f718b8fec813985'
AUDIT='98d7a5584371f16f1d8c4882ce771afe7a7a3a3a1943a0ee28f2dbd03066743b'
FILES='0fe4caff3739624b2fff6ab8c8686506a4ed128ad99b6ff7069252e56f1ab693'
CACHE_PROOF='ff6af5e4b1b43eaddcefbb8203015316e07e8c3f2aaba305778ada5365aa9033'
PARTITION=834666496
PINS={'system_ext/priv-app/SystemUI/SystemUI.apk':'aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46',
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
            value.get('expected_picker_delta_only') is not True or \
            value.get('lifecycle_code_unchanged_except_dialog_reference_types') is not True:
        raise ValueError('Not the exact reviewed compiled method audit')


def validate_metadata(value):
    if canonical(value)!=METADATA_AUDIT or value.get('expected_metadata_delta_only') is not True or value.get('candidate_sha256')!=FRAMEWORK or value.get('source_sha256')!='027507c72249681c2eabd5b4fb47a65e613dfb62a81a9c3ecf84e91d1998077b':
        raise ValueError('Not the exact reviewed compiled field/class audit')


def validate_export(metadata,export):
    files=export['files'];before=metadata['before_closure']
    if canonical(files)!=FILES:raise ValueError('Not the exact reviewed30-file export')
    if metadata['dialog_overlay_version']!=5 or metadata['baseline_image']!=48 or \
            export['dialog_overlay_version']!=5 or export.get('art_apex_unchanged') is not True or \
            export.get('baseline_preserved') is not True or export.get('new_class_in_dex') is not True or \
            len(files)!=30 or set(files)!=set(metadata['closure']) or set(files)!=set(before) or \
            files.get('framework/framework.jar')!=FRAMEWORK or before.get('framework/framework.jar')!=CACHE_FRAMEWORK:
        raise ValueError('Unexpected framework export closure')
    for name,digest in files.items():
        if not re.fullmatch(r'framework/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',name) or '..' in Path(name).parts or \
                not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('Unsafe export path/hash')
    for name,pin in PINS.items():
        if name in files and files[name]!=pin:raise ValueError('Protected resource/service export changed')
    if metadata.get('accepted_framework_baseline')!=OLD_FRAMEWORK or export.get('accepted_framework_baseline')!=OLD_FRAMEWORK:raise ValueError('Lost accepted49 policy baseline')
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
            m['image']!=51 or m['baseline_image']!=50 or m['base_raw_sha256']!=BASE_RAW or m.get('base_manifest_sha256')!=BASE_MANIFEST:
        raise ValueError('Incomplete/unreviewed image51 stage')
    if m.get('cache_preservation_verified') is not True or m.get('cache_preservation_sha256')!=CACHE_PROOF:
        raise ValueError('Stage lost exact cache preservation gate')
    for name,digest in m['metadata_files_sha256'].items():
        if sha(stage/name)!=digest:raise ValueError('Stage control changed: '+name)
    for name,tree in [('system-inventory.json','compact-system'),('root-inventory.json','compact-root')]:
        if inventory(stage/tree)!=json.loads((stage/name).read_text(encoding='utf-8')):raise ValueError('Staged payload drift: '+tree)
    validate_audit(json.loads((stage/'compiled-method-audit.json').read_text(encoding='utf-8')))
    validate_metadata(json.loads((stage/'compiled-metadata-audit.json').read_text(encoding='utf-8')))
    base=stage.parent/BASE_NAME
    if sha(base/'staging.json')!=BASE_MANIFEST or sha(base/'outputs.json')!=BASE_OUTPUTS or sha(base/'compact-image/system.raw.img')!=BASE_RAW or \
            inventory(base/'compact-system')!=json.loads((stage/'baseline-system-inventory.json').read_text(encoding='utf-8')) or \
            inventory(base/'compact-root')!=json.loads((stage/'root-inventory.json').read_text(encoding='utf-8')):
        raise ValueError('Immutable50 baseline drifted')
    for name,digest in {**PINS,**m['preserved_alarm_files']}.items():
        if sha(stage/'compact-system'/name)!=digest:raise ValueError('Protected content changed: '+name)
    if shutil.disk_usage(stage).free < 2*PARTITION+2*1024**3:raise ValueError('Insufficient pack headroom')
    return m


def launcher():
    return r'''#!/usr/bin/env bash
set -euo pipefail
root=/opt/kaidroid/kaidroid-build-20261023
stage="$root/engineering-tcl-ime-picker-stage-51"
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
sudo docker run -d --network none --name kaidroid-tcl-ime-picker-image51 \
 -v "$root:/build:ro" \
 -v "$stage:/build/engineering-tcl-ime-picker-stage-51:rw" \
 kaidroid-build:20261023 bash /build/engineering-tcl-ime-picker-stage-51/build.sh > "$stage/container-id"
cat "$stage/container-id"
'''


def validate_cache_proof(proof,metadata):
    state=proof.get('terminal_state',{})
    if proof.get('container_id')!='dbf2432c3114a467ecb9dcf02520a6636cea09a707e2cf8aacf6a01d92b09d69' or \
            proof.get('original_lower_all_files_content_metadata_unchanged') is not True or proof.get('lower_entries')!=565530 or proof.get('projected_changed_entries')!=130 or proof.get('projected_removed_entries')!=[] or \
            proof.get('before_inventory_sha256')!=metadata['layered_output']['before_inventory_sha256'] or \
            state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or \
            state.get('Pid')!=0 or state.get('ExitCode')!=0:
        raise ValueError('Exact terminal06 cache preservation proof missing/failed')


def stage(root,build_script,audit,metadata_audit):
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
    validate_metadata(json.loads(metadata_audit.read_text(encoding='utf-8')))
    if sha(base/'staging.json')!=BASE_MANIFEST or sha(base/'outputs.json')!=BASE_OUTPUTS:raise ValueError('Immutable50 manifests changed')
    fifty=json.loads((base/'staging.json').read_text(encoding='utf-8'))
    metadata=json.loads((compiled/'staging.json').read_text(encoding='utf-8'));export=json.loads((compiled/'outputs.json').read_text(encoding='utf-8'))
    files=validate_export(metadata,export)
    if not re.fullmatch('[0-9a-f]{64}',cache_proof_sha256) or sha(compiled/'cache-preservation.json')!=cache_proof_sha256:
        raise ValueError('Unreviewed cache preservation proof bytes')
    proof=json.loads((compiled/'cache-preservation.json').read_text(encoding='utf-8'))
    validate_cache_proof(proof,metadata)
    for name,key in [('cache-lower-before.json','before_inventory_sha256'),('cache-upper-after.json','upper_inventory_sha256'),('cache-view-delta.json','view_delta_sha256')]:
        if sha(compiled/name)!=proof[key]:raise ValueError('Cache preservation journal changed: '+name)
    if fifty.get('image')!=50 or fifty.get('framework49_export',{}).get('framework/framework.jar')!=OLD_FRAMEWORK or fifty['art_apex']!=metadata['art_apex']:raise ValueError('Unexpected immutable50 framework/ART baseline')
    before=inventory(base/'compact-system');roots=inventory(base/'compact-root')
    if before!=json.loads((base/'system-inventory.json').read_text(encoding='utf-8')) or roots!=json.loads((base/'root-inventory.json').read_text(encoding='utf-8')):
        raise ValueError('Image50 tree differs from its packed inventory')
    alarms=json.loads((base/'staging.json').read_text(encoding='utf-8'))['preserved_alarm_files']
    if len(alarms)!=8:raise ValueError('Alarm closure changed')
    for name,pin in {**PINS,**alarms,**fifty['framework49_export'],**metadata['art_apex']}.items():
        if before[name][0]!='file' or before[name][2]!=pin:raise ValueError('Immutable50 protected content drift: '+name)
    for name,digest in files.items():
        p=compiled/'output'/name
        if p.is_symlink() or sha(p)!=digest:raise ValueError('Export payload changed: '+name)
    props=(base/'compact-system/build.prop').read_bytes()
    if props.splitlines().count(b'ro.kaidroid.image=50')!=1:raise ValueError('Unexpected image revision')
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
    (out/'compact-system/build.prop').write_bytes(props.replace(b'ro.kaidroid.image=50',b'ro.kaidroid.image=51'))
    shutil.copyfile(base/'file_contexts.txt',out/'file_contexts.txt')
    (out/'system_image_info.compact.txt').write_text(config.replace('/build/'+BASE_NAME+'/', '/build/'+STAGE_NAME+'/'),encoding='utf-8')
    after=inventory(out/'compact-system');changed=compare_staged(before,after,files)
    if inventory(base/'compact-system')!=before or inventory(base/'compact-root')!=roots or inventory(out/'compact-root')!=roots:
        raise ValueError('Immutable baseline or root closure changed')
    (out/'build.sh').write_bytes(build_script.read_bytes().replace(b'\r\n',b'\n'))
    shutil.copyfile(Path(__file__),out/'stage-check.py')
    shutil.copyfile(audit,out/'compiled-method-audit.json')
    shutil.copyfile(metadata_audit,out/'compiled-metadata-audit.json')
    shutil.copyfile(compiled/'cache-preservation.json',out/'cache-preservation.json')
    (out/'launch.sh').write_text(launcher(),encoding='utf-8')
    for name,value in [('system-inventory.json',after),('root-inventory.json',roots),('baseline-system-inventory.json',before)]:
        (out/name).write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
    controls=['cache-preservation.json','build.sh','stage-check.py','launch.sh','compiled-method-audit.json','system-inventory.json',
              'compiled-metadata-audit.json','root-inventory.json','baseline-system-inventory.json','file_contexts.txt','system_image_info.compact.txt']
    report=dict(image=51,baseline_image=50,base_raw_sha256=BASE_RAW,base_manifest_sha256=BASE_MANIFEST,framework_sha256=FRAMEWORK,
        build_manifest_sha256=COMPILE_STAGE,outputs_sha256=EXPORT,compiled_audit_canonical_sha256=AUDIT,compiled_metadata_audit_canonical_sha256=METADATA_AUDIT,cache_preservation_sha256=cache_proof_sha256,cache_preservation_verified=True,
        exported_files=files,art_apex=metadata['art_apex'],preserved_alarm_files=alarms,protected50_sha256=PINS,
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
    for name in ('root','build-script','audit','metadata-audit'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    if a.check_stage:check_stage(a.check_stage)
    elif all((a.root,a.build_script,a.audit,a.metadata_audit)):stage(a.root,a.build_script,a.audit,a.metadata_audit)
    else:p.error('Require --check-stage or --root/--build-script/--audit/--metadata-audit')
