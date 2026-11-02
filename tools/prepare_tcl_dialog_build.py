"""Prepare an isolated dialog framework build only after hardware assigns a slot; never launch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
from datetime import datetime

from prepare_option_menu42_build import idle, sha
from prepare_tcl_dialog_overlay import canonical, SOURCE_PINS

BASE = 'engineering-tcl-resolver-stage-46'
CACHE = 'tcl-resolver-build02/out'
APP = 'core/java/com/android/internal/app'
MENU = 'core/java/android/widget/MenuBar.java'
CANONICAL = '29c4da54a2028e369261d89114c8c4352cd2f45cd0a3b4491a98b260877aa8d3'
RAW = '17fbb4ca99df1a1207ea006126ac92617ab8661d86e5a632fe48ee2138290b02'
GIB = 1024**3
IMAGE_ID='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
BUILDER_UID=BUILDER_GID=1000  # Direct image identity probe; Dockerfile uses the same numeric IDs.


def capacity_requirement(allocated, reviewed, reusing=False):
    if reusing:
        if not reviewed:raise ValueError('Output reuse requires the explicitly reviewed budget')
        return 40*GIB
    return allocated+40*GIB if reviewed else allocated*2+20*GIB


def verify_builder_image():
    rows=json.loads(subprocess.check_output(['sudo','docker','image','inspect','kaidroid-build:20261023'],text=True))
    if len(rows)!=1 or rows[0]['Id']!=IMAGE_ID or rows[0]['Config'].get('User')!='builder':
        raise ValueError('Unreviewed image or builder identity')
    return dict(image_id=IMAGE_ID,image_user='builder',uid=BUILDER_UID,gid=BUILDER_GID)


def assign_new_stage_owner(stage):
    stage.chmod(0o755)
    current=stage.stat()
    if (current.st_uid,current.st_gid)!=(BUILDER_UID,BUILDER_GID):
        os.chown(stage,BUILDER_UID,BUILDER_GID)  # This newly created top directory only.
    current=stage.stat()
    if (current.st_uid,current.st_gid)!=(BUILDER_UID,BUILDER_GID) or \
            current.st_mode & (stat.S_IWUSR|stat.S_IXUSR)!=(stat.S_IWUSR|stat.S_IXUSR):
        raise ValueError('New stage is not writable by the attested builder')


def verify_output_owner(output):
    owner=output.stat()
    if (owner.st_uid,owner.st_gid)!=(BUILDER_UID,BUILDER_GID) or owner.st_mode & 0o700 != 0o700:
        raise ValueError('Existing output is not writable by the attested builder; do not chown it')


def verify_stage02_journal_failure(root,previous,old,cid,elapsed,text):
    if previous.name!='tcl-dialog-build02' or cid!='dcfc21340cb904af87629bbe89cbb0b4fe7d2358891417903ac3062e50b8f487' or \
            not 0<=elapsed<=1 or text.strip() or (previous/'build.exit').read_text().strip()!='1' or \
            sha(previous/'build.log')!='8669175f2f72e5313bbbdf4cc5590d43452b31fd9d5474366b9267cf9a14c53e':
        raise ValueError('Not the exact reviewed stage02 pre-frontend journal failure')
    phasefile=previous/'disk-phases.jsonl'
    rows=[json.loads(line) for line in phasefile.read_text().splitlines()]
    mode=phasefile.stat()
    if not rows or any(row.get('phase')!='pre-start' or row.get('breach') is not None for row in rows) or \
            mode.st_uid!=0 or stat.S_IMODE(mode.st_mode)!=0o644:
        raise ValueError('Stage02 host journal failure evidence changed')
    retained=old.get('reused_terminal_attempt',{})
    if retained.get('previous_stage')!=str(root/'tcl-dialog-build01') or \
            old.get('output_source')!=str(root/'tcl-dialog-build01/out'):
        raise ValueError('Stage02 did not retain the reviewed independent stage01 output')


def verify_terminal_reuse(root,previous,spec,product,inspect=None,logs=None,failure_kind="initial-log-permission"):
    from monitor_tcl_dialog_disk import load_stage,validate_container,verify_inputs
    previous=previous.resolve(strict=True)
    if previous.parent!=root or not re.fullmatch(r'tcl-dialog-build[0-9]+',previous.name):
        raise ValueError('Reuse requires a named direct-child dialog stage')
    old=load_stage(root,previous)
    verify_inputs(previous,old)
    if old['overlay']!=spec['files'] or old['before_closure']!=spec['before_closure'] or \
            old['art_apex']!=spec['art_apex'] or json.loads((previous/'clone-state.json').read_text())['state']!='complete':
        raise ValueError('Prior source/clone/closure identity changed')
    if failure_kind not in ('initial-log-permission','stage02-journal-permission'):
        raise ValueError('Unreviewed reuse failure kind')
    forbidden=('frontend.log','source-graph.json','dependency-plan.log','plan-ready.json','plan-review.json','outputs.json','output')
    if failure_kind=='initial-log-permission':forbidden+=('build.log','build.exit')
    for name in forbidden:
        if (previous/name).exists():raise ValueError('Prior job may have progressed; no automatic output reuse: '+name)
    cid=(previous/'container-id').read_text().strip()
    if not re.fullmatch('[0-9a-f]{64}',cid):raise ValueError('Missing exact prior container ID')
    if inspect is None:
        def inspect(value):return json.loads(subprocess.check_output(['sudo','docker','inspect',value],text=True))[0]
    if logs is None:
        def logs(value):
            result=subprocess.run(['sudo','docker','logs',value],capture_output=True,text=True,check=True)
            return result.stdout+result.stderr
    info=inspect(cid);validate_container(info,root,previous,cid)
    state=info['State']
    if info.get('Image')!=IMAGE_ID or info['Config'].get('User')!='builder' or \
            info['Config'].get('Cmd')!=['bash','/build/'+previous.name+'/build.sh'] or \
            state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or \
            state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=1:
        raise ValueError('Prior container is not the confirmed terminal pre-build failure')
    elapsed=(datetime.fromisoformat(state['FinishedAt'].replace('Z','+00:00'))-
             datetime.fromisoformat(state['StartedAt'].replace('Z','+00:00'))).total_seconds()
    text=logs(cid)
    if failure_kind=='initial-log-permission':
        if not 0<=elapsed<=1 or 'build.log: Permission denied' not in text or 'line 7:' not in text:
            raise ValueError('Prior failure did not occur at the initial log redirection')
    else:
        verify_stage02_journal_failure(root,previous,old,cid,elapsed,text)
    output=Path(old.get('output_source',str(previous/'out')))
    if output.resolve(strict=True)!=output or output.name!='out' or output.parent.parent!=root or \
            not re.fullmatch(r'tcl-dialog-build[0-9]+',output.parent.name):
        raise ValueError('Unsafe reused output path')
    verify_output_owner(output)
    prepared=output/'target/product/n139dl/system'
    closure=dict(spec['before_closure']);closure.update(spec['art_apex'])
    for name,digest in closure.items():
        if sha(prepared/name)!=digest or sha(product/name)!=digest or \
                (prepared/name).stat().st_ino==(product/name).stat().st_ino:
            raise ValueError('Previously independent output no longer matches baseline: '+name)
    proof=dict(previous_stage=str(previous),container_id=cid,terminal_state=state,failure_kind=failure_kind,
        old_staging_sha256=sha(previous/'staging.json'),old_controls_sha256=sha(previous/'control-inputs.json'),
        docker_log_sha256=hashlib.sha256(text.encode()).hexdigest(),
        inputs_canonical_sha256=canonical(old.get('inputs',{})),
        closure_files=len(spec['before_closure']),art_files=len(spec['art_apex']),no_new_clone=True)
    if failure_kind=='stage02-journal-permission':
        proof['build_log_sha256']=sha(previous/'build.log')
        proof['phase_journal_sha256']=sha(previous/'disk-phases.jsonl')
        proof['build_exit_sha256']=sha(previous/'build.exit')
    return output,proof


def launcher_source(root,stage,bind,reviewed,staging_sha,output_source=None):
    before = 'python3 "$stage/disk-monitor.py" check --root "$root" --stage "$stage" --phase pre-start\n' if reviewed else ''
    after = '''sudo python3 "$stage/disk-monitor.py" monitor --root "$root" --stage "$stage" --container-id-file "$stage/container-id" --daemonize
sudo python3 "$stage/disk-monitor.py" ready --root "$root" --stage "$stage" --container-id-file "$stage/container-id"
sudo docker start "$(cat "$stage/container-id")" > "$stage/start.log" 2>&1
''' if reviewed else ''
    return '''#!/usr/bin/env bash
set -euo pipefail
root=ROOT_PATH
stage="$root/STAGE_NAME"
output_source=OUTPUT_SOURCE
test ! -e "$stage/container-id"
test ! -e "$stage/build.log"
test ! -e "$stage/build.exit"
for name in ninja soong_build e2fsdroid; do
 if pgrep -x "$name" >/dev/null; then echo 'Build active; do not restart.' >&2; exit 1; fi
done
test -z "$(sudo docker ps -q)"
BEFORE_CREATEsudo docker DOCKER_COMMAND --name kaidroid-STAGE_NAME --network none \\
 --label kaidroid.dialog.stage=STAGE_NAME --label kaidroid.dialog.staging=STAGING_SHA \\
 -v "$root:/build:ro" -v "$root:/baseline:ro" \\
 -v "$stage:/build/STAGE_NAME:rw" -v "$output_source:/build/out-eng-02:rw" \\
BIND_INPUTS kaidroid-build:20261023 bash /build/STAGE_NAME/build.sh > "$stage/container-id"
AFTER_CREATEcat "$stage/container-id"
'''.replace('ROOT_PATH',shlex.quote(str(root))).replace('STAGE_NAME',stage.name).replace('STAGING_SHA',staging_sha) \
        .replace('OUTPUT_SOURCE',shlex.quote(str(output_source or stage/'out'))) \
        .replace('BEFORE_CREATE',before).replace('DOCKER_COMMAND','create' if reviewed else 'run -d') \
        .replace('BIND_INPUTS',bind).replace('AFTER_CREATE',after)


def prepare(root, overlay, contract, script, stage, overlay_version=1, reviewed_disk_budget=False,reuse_terminal_stage=None,reuse_failure="initial-log-permission"):
    root=root.resolve(strict=True);stage=stage.absolute()
    if stage.parent != root or stage.exists() or not re.fullmatch(r'tcl-dialog-build[0-9]+',stage.name):
        raise ValueError('Require fresh direct-child tcl-dialog-buildNN stage')
    if reviewed_disk_budget and overlay_version!=3:
        raise ValueError('Reviewed budget is scoped to overlay03')
    if reuse_terminal_stage is not None and not reviewed_disk_budget:
        raise ValueError('Explicit reviewed budget required for terminal output reuse')
    monitor=Path(__file__).with_name('monitor_tcl_dialog_disk.py').resolve(strict=True)
    idle()
    if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():
        raise ValueError('Container active; coordinate first')
    builder=verify_builder_image()
    versions = {
        1: (CANONICAL,'4a4169743fe7444c64d81a8291c9a122909cd8087ffe9437e2a3efc473260fde'),
        2: ('98ef6b7db01b419773c50f4ebe771913e71385e2606fd8dd26f5b22e9dc3e9d5',
            '91a37c6138815cd63f3cc178cd7ca48d38b718676cee5a0c1d13eb9c68fd580d'),
        3: ('8d31c694b24423758bd36ac07d0c3486a53731adc811e454552ec04f71f38c3b',
            'fdd76a30954341aa44b99ecebbf82b64a5d92ce952e96785c74adcd850df3028')}
    if overlay_version not in versions:
        raise ValueError('Unreviewed overlay version')
    expected_canonical, contract_sha = versions[overlay_version]
    if sha(contract)!=contract_sha:
        raise ValueError('Frozen contract bytes changed')
    spec=json.loads(contract.read_text())
    if canonical(spec['files']) != expected_canonical or spec['canonical_sha256'] != expected_canonical:
        raise ValueError('Unreviewed six-file source closure')
    expected=set(SOURCE_PINS)|{MENU,APP+'/ChooserActivity.java',APP+'/TclResolverPresentation.java'}
    if set(spec['files']) != expected or set(spec['source_baseline']) != {'aosp/frameworks/base/'+n for n in SOURCE_PINS}:
        raise ValueError('Unexpected overlay/source scope')
    for n,d in spec['files'].items():
        if (overlay/n).is_symlink() or sha(overlay/n)!=d:
            raise ValueError('Source mismatch: '+n)
    pins=dict(spec['source_baseline'])
    pins.update({BASE+'/compact-image/system.raw.img':RAW,
        'aosp/frameworks/base/'+MENU:'73f871ffa9bda03951050d91cab118f6a8f6e663e1090fc68ce8767a1389cc26',
        'aosp/frameworks/base/'+APP+'/ChooserActivity.java':'8ce601b48e97871d2d68326bebce1c44673ed27a3512adad756e6c162daecc10',
        'tcl-resolver-build02/staging.json':spec['cache_staging_sha256'],
        'tcl-resolver-build02/outputs-retry02.json':spec['cache_export_sha256'],
        BASE+'/compact-system/system_ext/priv-app/SystemUI/SystemUI.apk':'5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708',
        BASE+'/compact-system/priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'})
    for n,d in pins.items():
        if sha(root/n)!=d: raise ValueError('Baseline mismatch: '+n)
    if (root/BASE/'build.exit').read_text().strip()!='0' or \
            (root/'tcl-resolver-build02/build-retry02.exit').read_text().strip()!='0':
        raise ValueError('Baseline/cache not terminal success; never restart')
    exports=json.loads((root/'tcl-resolver-build02/outputs-retry02.json').read_text())['files']
    if exports!=spec['before_closure'] or len(exports)!=30:
        raise ValueError('Accepted export closure changed')
    product=root/CACHE/'target/product/n139dl/system'
    base=root/BASE/'compact-system'
    for n,d in exports.items():
        if not n.startswith('framework/') or '..' in Path(n).parts or \
                sha(base/n)!=d or sha(product/n)!=d:
            raise ValueError('Image/cache closure mismatch: '+n)
    if not spec['art_apex']:
        raise ValueError('Missing ART APEX inventory')
    for n,d in spec['art_apex'].items():
        if sha(base/n)!=d or sha(product/n)!=d:raise ValueError('ART APEX changed: '+n)
    app=root/'aosp/frameworks/base'/APP
    if any(p.is_symlink() for p in app.rglob('*')) or (app/'TclResolverPresentation.java').exists():
        raise ValueError('Review unexpected shared app source/symlinks')
    allocated=int(subprocess.check_output(['du','-sk',str(root/CACHE)]).split()[0])*1024
    output_source=stage/'out';reuse_proof=None
    if reuse_terminal_stage is not None:
        output_source,reuse_proof=verify_terminal_reuse(root,reuse_terminal_stage,spec,product,failure_kind=reuse_failure)
    free_before=shutil.disk_usage(root).free
    if free_before < capacity_requirement(allocated,reviewed_disk_budget,reuse_proof is not None):
        raise ValueError('Insufficient independent clone/build headroom; do not delete files')
    stage.mkdir();assign_new_stage_owner(stage);inputs=stage/'inputs';inputs.mkdir()
    if reviewed_disk_budget:
        (stage/'disk-preparation.jsonl').write_text(json.dumps(dict(phase='pre-reuse' if reuse_proof else 'pre-clone',
            cache_allocated_bytes=allocated,free_bytes=free_before,
            required_bytes=capacity_requirement(allocated,True,reuse_proof is not None)))+'\n')
    shutil.copytree(app,inputs/'app')
    for n in expected:
        target=inputs/'app'/Path(n).name if n.startswith(APP+'/') else inputs/Path(n).name
        shutil.copy2(overlay/n,target);os.utime(target,None)
    inventory={p.relative_to(inputs).as_posix():sha(p) for p in inputs.rglob('*') if p.is_file()}
    if reuse_proof and canonical(inventory)!=reuse_proof['inputs_canonical_sha256']:
        raise ValueError('Retry inputs differ from the retained first attempt')
    if reuse_proof is None:
        (stage/'clone-state.json').write_text('{"state":"copying"}\n')
        with (stage/'clone.log').open('wb') as log:
            proc=subprocess.Popen(['cp','--reflink=auto','-a',str(root/CACHE),str(output_source)],stdout=log,stderr=subprocess.STDOUT)
            (stage/'clone.pid').write_text(str(proc.pid)+'\n')
            if proc.wait():raise ValueError('Clone failed; retain and inspect same stage')
    idle()
    free_after=shutil.disk_usage(root).free
    if reviewed_disk_budget:
        with (stage/'disk-preparation.jsonl').open('a') as disk_log:
            disk_log.write(json.dumps(dict(phase='post-reuse' if reuse_proof else 'post-clone',free_bytes=free_after,
                required_bytes=40*GIB))+'\n')
    if reviewed_disk_budget and free_after < 40*GIB:
        raise ValueError('Post-clone budget+floor no longer fit; retain stage, never delete/restart')
    verify_output_owner(output_source)
    for n,d in exports.items():
        copied=output_source/'target/product/n139dl/system'/n
        if sha(copied)!=d or copied.stat().st_ino==(product/n).stat().st_ino:
            raise ValueError('Clone is not independent/exact: '+n)
    manifest=dict(baseline_image=46,baseline_pins=pins,before_closure=exports,
        art_apex=spec['art_apex'],inputs=inventory,overlay=spec['files'],closure=sorted(exports),
        shared_root_read_only=True,launched=False,installed=False,
        image_packaging='Future hardware packager must use current accepted image47-or-later baseline; export framework closure only')
    manifest['dialog_overlay_version'] = overlay_version
    manifest['builder_identity']=builder
    manifest['output_source']=str(output_source)
    if reuse_proof is not None:manifest['reused_terminal_attempt']=reuse_proof
    if reviewed_disk_budget:
        manifest['disk_plan']=dict(cache_allocated_bytes=allocated,free_before_clone_bytes=free_before,
            free_after_clone_bytes=free_after,incremental_budget_bytes=20*GIB,emergency_floor_bytes=20*GIB,
            forecast_not_measured_peak=True,explicit_reviewed_option=True)
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (stage/'targets.txt').write_text(''.join('/build/out-eng-02/target/product/n139dl/system/'+n+'\n' for n in sorted(exports)))
    (stage/'build.sh').write_text(script.read_text().replace('STAGE_NAME',stage.name),newline='\n')
    shutil.copyfile(monitor,stage/'disk-monitor.py')
    mounts=[('app','core/java/com/android/internal/app')]+[(Path(n).name,n) for n in expected if not n.startswith(APP+'/')]
    bind=''.join(' -v "$stage/inputs/'+src+':/build/aosp/frameworks/base/'+dst+':ro" \\\n' for src,dst in sorted(mounts))
    launcher=launcher_source(root,stage,bind,reviewed_disk_budget,sha(stage/'staging.json'),output_source)
    (stage/'launch.sh').write_text(launcher,newline='\n')
    (stage/'control-inputs.json').write_text(json.dumps({n:sha(stage/n) for n in ('build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py')},indent=2)+'\n')
    (stage/'clone-state.json').write_text('{"state":"complete"}\n')
    for name in ('staging.json','targets.txt','build.sh','disk-monitor.py','launch.sh','control-inputs.json'):
        (stage/name).chmod(0o644)
    print(json.dumps(dict(stage=str(stage),launched=False,closure_files=len(exports))))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('root','overlay','contract','script','stage'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--overlay-version',type=int,choices=(1,2,3),default=1)
    p.add_argument('--reviewed-disk-budget',action='store_true',help='Explicit hardware-reviewed one-clone+20GiB growth+20GiB floor option')
    p.add_argument('--reuse-terminal-stage',type=Path,help='Reuse only verified unchanged output of an explicitly reviewed terminal failure')
    p.add_argument('--reuse-failure',choices=('initial-log-permission','stage02-journal-permission'),default='initial-log-permission')
    a=p.parse_args();prepare(a.root,a.overlay,a.contract,a.script,a.stage,a.overlay_version,a.reviewed_disk_budget,a.reuse_terminal_stage,a.reuse_failure)
