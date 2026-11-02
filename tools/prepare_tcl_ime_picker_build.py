"""Prepare isolated accepted49 picker over preserved48 compile cache. Never launch or pack."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from layered_dialog_output import sha,semantic,inventory,verify_mounts
from prepare_tcl_dialog_build import launcher_source

ROOT=Path('/opt/kaidroid/kaidroid-build-20261023')
IMAGE='sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
BASE='engineering-tcl-dialog-stage-48'
RAW='fc7f4cb0419aa445675c1516d560bb43945f620c9b269fa4a7942df874ce2e42'
STAGING48='dc35b147d0d3f205b3b39afff844b494e9a22d8fee5388dfd2df2c6caee1c811'
OUTPUT48='2a059ae7864b6568807e56640a1c4f2c1d7cfabf3feb1bef562a4f6e243c60f1'
OLD_STAGE='ad24e63af1f067888c05dfafec77b35e297adb0a752128a1ee93632711d1645b'
OLD_EXPORT='9e3db7012c3e993852007563ede7922136b017701515266b0d2318ef359d5930'
OLD_CID='e91e694bd5d851ccd27b35f1ff5e6a9a7c8a91df1e1dedd3d1fb3b31a4e38c16'
POLICY={'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
        'core/java/android/app/TctDialog.java':'e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6',
        'core/java/android/widget/KeypadImeController.java':'027507c72249681c2eabd5b4fb47a65e613dfb62a81a9c3ecf84e91d1998077b'}
GIB=1024**3


def canonical(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def idle():
    for record in ROOT.glob('tcl-dialog-build*/prepare.pid'):
        pid=int(record.read_text(encoding='utf-8').strip())
        if pid==os.getpid():continue
        cmd=Path('/proc')/str(pid)/'cmdline'
        try:active=cmd.read_bytes()
        except FileNotFoundError:continue
        if b'prepare_tcl_' in active:raise ValueError('Existing preparation PID is live; observe it')
    for name in ('ninja','soong_build','e2fsdroid'):
        if subprocess.run(['pgrep','-x',name],capture_output=True).returncode!=1:raise ValueError('Live build or failed process observation')
    if subprocess.check_output(['sudo','docker','ps','-q'],text=True).strip():raise ValueError('Container live; do not duplicate')


def make_launcher(root,stage,overlay_files,staging_sha):
    app='core/java/com/android/internal/app'
    mounts=[('app',app)]+[(Path(n).name,n) for n in overlay_files if not n.startswith(app+'/')]
    bind=''.join(' -v "$stage/inputs/'+src+':/build/aosp/frameworks/base/'+dest+':ro" \\\n' for src,dest in sorted(mounts))
    bind+=' -v \"$stage/lower-ro:/build/'+stage.name+'/lower-ro:ro\" \\\n'
    bind+=' -v \"$stage/out:/build/'+stage.name+'/out:rw\" \\\n'
    launch=launcher_source(root,stage,bind,True,staging_sha,stage/'out')
    launch=launch.replace('test ! -e "$stage/container-id"','test -f "$stage/preparation.complete"\ntest ! -e "$stage/container-id"',1)
    return launch


ACCEPTED49='2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'
ACCEPTED_CID='5b80a7b8d4003b91bc0c7bfb008dbd5ef377e1944a721dced914bb2e7bb330c6'


def accepted49(root):
    prior=root/'tcl-dialog-build05'
    pins={'staging.json':'3d6e7be2a841ce3b7415755de095752f86450a07a979dacb86d4aa8f289c84fa',
          'outputs.json':'62898fb1e958dc2eea5d1451bfe069b504262d737da556fc61ed3a0993f73c5a',
          'cache-preservation.json':'45624c80b1526e94de82ba43d417ded6b7a5e3dde928f9b41793b78ea64665cd'}
    if prior.resolve(strict=True)!=prior:raise ValueError('Symlinked accepted49 stage')
    for name,digest in pins.items():
        if sha(prior/name)!=digest:raise ValueError('Accepted49 proof changed: '+name)
    if (prior/'build.exit').read_text(encoding='utf-8').strip()!='0' or (prior/'container-id').read_text(encoding='utf-8').strip()!=ACCEPTED_CID:
        raise ValueError('Accepted49 build not exact terminal success')
    info=json.loads(subprocess.check_output(['sudo','docker','inspect',ACCEPTED_CID],text=True))[0];state=info['State']
    if info['Id']!=ACCEPTED_CID or info.get('Name')!='/kaidroid-tcl-dialog-build05' or info.get('Image')!=IMAGE or info['Config'].get('User')!='builder' or info['Config'].get('Cmd')!=['bash','/build/tcl-dialog-build05/build.sh'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=0:
        raise ValueError('Accepted49 container identity/state changed')
    spec=json.loads((prior/'staging.json').read_text(encoding='utf-8'))
    exports=json.loads((prior/'outputs.json').read_text(encoding='utf-8'))['files']
    if len(exports)!=30 or exports.get('framework/framework.jar')!=ACCEPTED49:raise ValueError('Wrong accepted49 export closure')
    for name,digest in spec['inputs'].items():
        if (prior/'inputs'/name).is_symlink() or sha(prior/'inputs'/name)!=digest:raise ValueError('Accepted49 source input changed: '+name)
    for name,digest in exports.items():
        if (prior/'output'/name).is_symlink() or sha(prior/'output'/name)!=digest:raise ValueError('Accepted49 retained export changed: '+name)
    retained={(prior/name).relative_to(root).as_posix():digest for name,digest in pins.items()}
    retained.update({(prior/'inputs'/name).relative_to(root).as_posix():digest for name,digest in spec['inputs'].items()})
    retained.update({(prior/'output'/name).relative_to(root).as_posix():digest for name,digest in exports.items()})
    return retained


def prepare(root,overlay,stage):
    if os.name!='posix' or os.geteuid()!=1000 or os.getegid()!=1000:raise ValueError('Prepare as attested builder1000:1000')
    root=root.resolve(strict=True);stage=stage.absolute()
    if root!=ROOT or stage.parent!=root or stage.exists() or not re.fullmatch('tcl-dialog-build[0-9]+',stage.name):
        raise ValueError('Require fresh named direct-child dialog stage')
    idle()
    accepted_pins=accepted49(root)
    image=json.loads(subprocess.check_output(['sudo','docker','image','inspect','kaidroid-build:20261023'],text=True))[0]
    if image['Id']!=IMAGE or image['Config'].get('User')!='builder':raise ValueError('Image/builder changed')
    prior=root/'tcl-dialog-build03';base=root/BASE;lower=root/'tcl-dialog-build01/out'
    if lower.resolve(strict=True)!=lower or prior.resolve(strict=True)!=prior or base.resolve(strict=True)!=base:
        raise ValueError('Unreviewed symlinked baseline/cache')
    pins={BASE+'/compact-image/system.raw.img':RAW,BASE+'/staging.json':STAGING48,BASE+'/outputs.json':OUTPUT48,
          'tcl-dialog-build03/staging.json':OLD_STAGE,'tcl-dialog-build03/outputs.json':OLD_EXPORT}
    for name,digest in pins.items():
        if sha(root/name)!=digest:raise ValueError('Reviewed baseline manifest/raw changed: '+name)
    if (base/'build.exit').read_text(encoding='utf-8').strip()!='0' or (prior/'build.exit').read_text(encoding='utf-8').strip()!='0':
        raise ValueError('Prior stage not terminal success')
    if (prior/'container-id').read_text(encoding='utf-8').strip()!=OLD_CID:raise ValueError('Wrong prior container')
    oldinfo=json.loads(subprocess.check_output(['sudo','docker','inspect',OLD_CID],text=True))[0];state=oldinfo['State']
    if oldinfo['Id']!=OLD_CID or oldinfo.get('Name')!='/kaidroid-tcl-dialog-build03' or oldinfo.get('Image')!=IMAGE or oldinfo['Config'].get('User')!='builder' or oldinfo['Config'].get('Cmd')!=['bash','/build/tcl-dialog-build03/build.sh'] or \
            state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=0:
        raise ValueError('Prior exact container not terminal success')
    old=json.loads((prior/'staging.json').read_text(encoding='utf-8'));export=json.loads((prior/'outputs.json').read_text(encoding='utf-8'))['files']
    if old.get('output_source')!=str(lower) or len(export)!=30 or set(export)!=set(old['closure']) or len(old['art_apex'])!=24:
        raise ValueError('Unexpected dedicated lower/export closure')
    controls=json.loads((prior/'control-inputs.json').read_text(encoding='utf-8'))
    if set(controls)!={'build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py'}:raise ValueError('Old controls changed')
    for name,digest in controls.items():
        if sha(prior/name)!=digest:raise ValueError('Frozen03 control changed')
    for name,digest in old['inputs'].items():
        if sha(prior/'inputs'/name)!=digest:raise ValueError('Frozen03 source input changed')
    for name,digest in {**export,**old['art_apex']}.items():
        if sha(lower/'target/product/n139dl/system'/name)!=digest or sha(base/'compact-system'/name)!=digest or \
                (name in export and sha(prior/'output'/name)!=digest):raise ValueError('Accepted48 cache/export/raw-stage differs: '+name)
    pins.update(accepted_pins)
    pins.update({name:d for name,d in old['baseline_pins'].items() if name.startswith('aosp/')})
    for name,digest in pins.items():
        if sha(root/name)!=digest:raise ValueError('Original shared source changed: '+name)
    for name,digest in POLICY.items():
        if (overlay/name).is_symlink() or sha(overlay/name)!=digest:raise ValueError('Policy source changed: '+name)
    if shutil.disk_usage(root).free<40*GIB:raise ValueError('Require20GiB growth+20GiB floor; no clone/delete')
    stage.mkdir();stage.chmod(0o755);(stage/'prepare.pid').write_text(str(os.getpid())+'\n')
    shutil.copytree(prior/'inputs',stage/'inputs')
    for name in POLICY:shutil.copyfile(overlay/name,stage/'inputs'/Path(name).name)
    inputs={p.relative_to(stage/'inputs').as_posix():sha(p) for p in (stage/'inputs').rglob('*') if p.is_file()}
    changed={n for n in old['inputs'].keys()|inputs.keys() if old['inputs'].get(n)!=inputs.get(n)}
    if changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java'}:raise ValueError('Unexpected source input delta')
    for name in ('lower-ro','cache-upper','cache-work','out'):(stage/name).mkdir(mode=0o755)
    for name in ('cache-upper','cache-work'):
        s=(stage/name).stat()
        if (s.st_uid,s.st_gid)!=(1000,1000):raise ValueError('New upper/work must belong to builder; never chown old lower')
    tools=Path(__file__).parent
    shutil.copyfile(tools/'layered_dialog_output.py',stage/'layered_dialog_output.py')
    subprocess.run(['sudo','python3',str(stage/'layered_dialog_output.py'),'snapshot','--stage',str(stage)],check=True)
    subprocess.run(['sudo','mount','--bind',str(lower),str(stage/'lower-ro')],check=True)
    subprocess.run(['sudo','mount','-o','remount,bind,ro',str(stage/'lower-ro')],check=True)
    options='lowerdir='+str(stage/'lower-ro')+',upperdir='+str(stage/'cache-upper')+',workdir='+str(stage/'cache-work')+',index=off,redirect_dir=off,metacopy=off'
    subprocess.run(['sudo','mount','-t','overlay','overlay','-o',options,str(stage/'out')],check=True)
    layer=dict(lower=str(lower),lower_ro=str(stage/'lower-ro'),upper=str(stage/'cache-upper'),work=str(stage/'cache-work'),
               merged=str(stage/'out'),before_inventory_sha256=sha(stage/'cache-lower-before.json'),original_lower_read_only=True)
    verify_mounts(stage,dict(layered_output=layer))
    before=json.loads((stage/'cache-lower-before.json').read_text(encoding='utf-8'))
    if semantic(before)!=inventory(stage/'out',identity=False):raise ValueError('Initial layered projection differs from accepted cache')
    idle();free=shutil.disk_usage(root).free
    if free<40*GIB:raise ValueError('Layer preparation consumed required headroom')
    overlay_files=dict(old['overlay']);overlay_files.update(POLICY)
    manifest=dict(baseline_image=48,baseline_pins=pins,before_closure=export,art_apex=old['art_apex'],closure=sorted(export),
        inputs=inputs,overlay=overlay_files,dialog_overlay_version=5,accepted_framework_baseline=ACCEPTED49,output_source=str(stage/'out'),layered_output=layer,
        builder_identity=dict(image_id=IMAGE,image_user='builder',uid=1000,gid=1000),
        disk_plan=dict(cache_allocated_bytes=int(subprocess.check_output(['du','-sk',str(lower)]).split()[0])*1024,
            free_after_clone_bytes=free,incremental_budget_bytes=20*GIB,emergency_floor_bytes=20*GIB,
            forecast_not_measured_peak=True,explicit_reviewed_option=True),
        prior_exact_container_id=OLD_CID,prior_controls_sha256=sha(prior/'control-inputs.json'),
        old_source_inputs_unchanged=True,full_output_clone=False,launched=False,installed=False)
    (stage/'staging.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (stage/'targets.txt').write_text(''.join('/build/out-eng-02/target/product/n139dl/system/'+n+'\n' for n in sorted(export)))
    (stage/'build.sh').write_text((tools/'build_tcl_ime_picker.sh').read_text(encoding='utf-8').replace('STAGE_NAME',stage.name),newline='\n')
    shutil.copyfile(tools/'monitor_tcl_dialog_ime_disk.py',stage/'disk-monitor.py')
    launch=make_launcher(root,stage,overlay_files,sha(stage/'staging.json'))
    (stage/'launch.sh').write_text(launch,newline='\n')
    names=('build.sh','launch.sh','targets.txt','staging.json','disk-monitor.py','layered_dialog_output.py')
    (stage/'control-inputs.json').write_text(json.dumps({n:sha(stage/n) for n in names},indent=2)+'\n')
    for name in names: (stage/name).chmod(0o644)
    (stage/'preparation.complete').write_text(sha(stage/'staging.json')+'\n')
    print(json.dumps(dict(stage=str(stage),launched=False,lower_preserved=True,private_upper=True,free_bytes=free)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('root','overlay','stage'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();prepare(a.root,a.overlay,a.stage)
