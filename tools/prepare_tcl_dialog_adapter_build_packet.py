"""Generate native09 Calendar adapter packet offline; no host/device operations."""
import argparse
import ast
import gzip
import io
import json
from pathlib import Path
import tarfile

import prepare_tcl_ime_correction_build_packet as frozen
from prepare_tcl_dialog_adapter import patch

FRAMEWORK08='78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2'
INPUTS={
    'core/java/android/app/TctDialog.java':'c28919ef89c53efed268df916caefd9144bda7395db00f0d1dc7a86c7d084cc7',
    'core/java/android/widget/MenuBar.java':'5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
    'core/java/android/widget/KeypadImeController.java':'d6d86478c77936a0687bca48d8b01c86b5cc99fb9c00d3bb87ab7a6955849cbd',
    'core/java/android/widget/KeypadImeModeState.java':'cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806',
}

RETAINED08=frozen.RETAINED07_CHECK
for old,new in {
    'retained07':'retained08','Retained07':'Retained08','tcl-dialog-build07':'tcl-dialog-build08',
    '6488021baa4bcac7de551f68dd451e21053519ca015e0a933bb693d18dc569d5':'e19fbd2355e262bac4706ea5c4d663c442c6e45f0e88cb4bec3d73804427a889',
    '771595acdf235b0341f08a8ad67d1cefe8955bb578e64cc23d2660af8c3fa02f':'daac9ca0d3b950604041ba7a352fe026c6bddd48d409771f0fd1639c77b7f067',
    'd3617e32e67a68727864d00e348103373088c2bd1af6a4ad6226110ccbe82eb1':'6be37ca14c1af60ba023344fe2cbe2a79d9f31a077d01c18c689b947cf97e62b',
    '0648dd7fe56e049e5895d07261f2330b618ca200d60c8787e1100d1591cbc9fe':'259ae484f1b5097a63720e1b400d38b41fca39cfd9f0fd6a5ff35b06c92dcafd',
    frozen.FRAMEWORK07:FRAMEWORK08,
}.items():
    RETAINED08=RETAINED08.replace(old,new)

RETAINED53='''
def retained53(root):
    prior=root/'engineering-tcl-ime-guard-stage-53'
    cid='80b7d658f07773e709f567e2279fd9ab521a92331425f7e955a174412f566ffe'
    pins={
        'staging.json':'4ed37c11ee869bc85c2d8a993126311326438778625feb85e8a75a601d7b8dea',
        'compact-image/system.raw.img':'f587f445ce66e397718110762c7e952fcb19c03feef4b1ae35c7638209c51f56',
        'avb-info.txt':'ae336c7500bb892b219f1bbbea2e12ccb5fa50121ae4a7d03607dd2ea158fe2f',
        'avb-verification.txt':'7eb4ac9515976d201e7dc0a217494d225189616805f5beca9a3eb9466dcb7d7b',
        'compact-system/framework/framework.jar':'78328f3ad42ee0c0086cc6fd7e1ed29d46d3fbee7442ca471ec3c9f641cf17f2',
    }
    if prior.resolve(strict=True)!=prior:raise ValueError('Symlinked retained53')
    for name,digest in pins.items():
        target=prior/name
        if target.resolve(strict=True)!=target or sha(target)!=digest:
            raise ValueError('Retained53 proof changed: '+name)
    if (prior/'build.exit').read_text().strip()!='0' or (prior/'container-id').read_text().strip()!=cid:
        raise ValueError('Retained53 not exact terminal success')
    info=json.loads(subprocess.check_output(['sudo','docker','inspect',cid],text=True))[0];state=info['State']
    if info['Id']!=cid or info.get('Name')!='/kaidroid-tcl-ime-guard-image53' or info.get('Image')!=IMAGE or info['Config'].get('User')!='builder' or info['Config'].get('Cmd')!=['bash','/build/engineering-tcl-ime-guard-stage-53/build.sh'] or state.get('Status')!='exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid')!=0 or state.get('ExitCode')!=0:
        raise ValueError('Retained53 container identity/state changed')
    return {(prior/name).relative_to(root).as_posix():digest for name,digest in pins.items()}

'''


def packet_files(root):
    previous=frozen.packet_files(root,3)
    sources={n[len('overlay/'):]:b for n,b in previous.items() if n.startswith('overlay/')}
    sources['core/java/android/app/TctDialog.java']=patch(sources['core/java/android/app/TctDialog.java'],2)
    if {n:frozen.sha(b) for n,b in sources.items()}!=INPUTS:
        raise ValueError('Adapter2/retained08 source bundle changed')
    tools=frozen.transformed_tools(root,sources,3)
    replace=frozen.replace_once
    prep=tools['prepare_tcl_ime_picker_build.py'].decode()
    prep=replace(prep,'def prepare(root,overlay,stage):',RETAINED08+RETAINED53+'\ndef prepare(root,overlay,stage):')
    prep=replace(prep,'    accepted_pins.update(retained07(root))',
                 '    accepted_pins.update(retained07(root))\n    accepted_pins.update(retained08(root))\n    accepted_pins.update(retained53(root))')
    prep=replace(prep,"accepted_framework_baseline='"+frozen.FRAMEWORK07+"'","accepted_framework_baseline='"+FRAMEWORK08+"'")
    prep=replace(prep,'    if root!=ROOT or stage.parent!=root or stage.exists() or not re.fullmatch(\'tcl-dialog-build[0-9]+\',stage.name):',
                 "    if root!=ROOT or stage!=root/'tcl-dialog-build09':")
    prep=replace(prep,'    idle()\n    accepted_pins=',
                 '    from layered_dialog_output import verify_external_storage, external_sample\n    verify_external_storage(stage,fresh=True)\n    idle()\n    accepted_pins=')
    prep=replace(prep,"    if shutil.disk_usage(root).free<34*GIB:raise ValueError('Require reviewed14GiB growth+unchanged20GiB floor; no clone/delete')",
                 "    initial_plan=dict(free_after_clone_bytes=shutil.disk_usage(stage).free,incremental_budget_bytes=14*GIB,emergency_floor_bytes=20*GIB)\n    if external_sample(root,stage,initial_plan,initial=True)['breach']:raise ValueError('Require external34GiB and root20GiB headroom')\n    verify_external_storage(stage,fresh=True)")
    prep=replace(prep,"    stage.mkdir();stage.chmod(0o755);(stage/'prepare.pid').write_text(str(os.getpid())+'\\n')",
                 "    (stage/'prepare.pid').write_text(str(os.getpid())+'\\n')")
    prep=replace(prep,'    idle();free=shutil.disk_usage(root).free',
                 '    idle();verify_external_storage(stage);free=shutil.disk_usage(stage).free')
    prep=replace(prep,"    if free<34*GIB:raise ValueError('Layer preparation consumed required headroom')",
                 "    if external_sample(root,stage,initial_plan,initial=True)['breach']:raise ValueError('Layer preparation consumed external/root headroom')")
    prep=replace(prep,'        disk_plan=dict(cache_allocated_bytes=',
                 "        external_storage=dict(volume='/mnt/ext1',backing='/mnt/ext1/kaidroid-tcl-dialog-build09',device='8:0',root_floor_bytes=20*GIB,root_initial_free_bytes=shutil.disk_usage(root).free),\n        disk_plan=dict(cache_allocated_bytes=")
    tools['prepare_tcl_ime_picker_build.py']=prep.encode()

    # Embed the policy into an already-hashed stage control, preserving all12
    # Docker mounts and the exact six-file control set.
    helper=(root/'tools/tcl_dialog_external_storage.py').read_text(encoding='utf-8')
    layer=tools['layered_dialog_output.py'].decode()
    layer=replace(layer,"if __name__=='__main__':main()",helper+"\n\nif __name__=='__main__':main()")
    layer=replace(layer,"    layer=spec['layered_output'];rows=mounts(",
                  "    verify_external_storage(stage)\n    layer=spec['layered_output'];rows=mounts(")
    layer=replace(layer,'    stage=path.resolve(strict=True)',
                  '    stage=path.resolve(strict=True)\n    verify_external_storage(stage)')
    tools['layered_dialog_output.py']=layer.encode()

    monitor=tools['monitor_tcl_dialog_ime_disk.py'].decode()
    monitor=replace(monitor,'GIB = 1024**3','from layered_dialog_output import external_sample\n\nGIB = 1024**3')
    monitor=replace(monitor,"    row = dict(assess(spec['disk_plan'],shutil.disk_usage(root).free if free is None else free),phase=phase)",
                    "    if free is not None:raise ValueError('Single-volume override forbidden for dual-volume guard')\n    row = dict(external_sample(root,stage,spec['disk_plan'],initial=phase in ('pre-start','pre-frontend')),phase=phase)")
    monitor=replace(monitor,"    check_phase(root,stage,'pre-start',free(root))","    check_phase(root,stage,'pre-start')")
    monitor=replace(monitor,'    minimum = free(root)','    minimum = free(stage)\n    root_minimum = free(root)')
    monitor=replace(monitor,"        row = assess(spec['disk_plan'],free(root));minimum=min(minimum,row['free_bytes'])",
                    "        row = external_sample(root,stage,spec['disk_plan'],free=free);minimum=min(minimum,row['free_bytes'])\n        root_minimum=min(root_minimum,row['root_free_bytes'])")
    # Keep terminal/readiness, exact container stop-once, heartbeat and actual
    # plan/source hash review semantics unchanged.
    monitor=monitor.replace('minimum_free_bytes=minimum','minimum_free_bytes=minimum,minimum_root_free_bytes=root_minimum')
    tools['monitor_tcl_dialog_ime_disk.py']=monitor.encode()
    build=tools['build_tcl_ime_picker.sh'].decode()
    marker=" assert any(b'pickerModes' in b and b'selectionActions' in b for b in dex),'New policy API missing'"
    build=replace(build,marker,marker+"\n assert any(b'setListAdapter' in b and b'getListSelectedPoistion' in b for b in dex),'Calendar adapter API missing'")
    tools['build_tcl_ime_picker.sh']=build.encode()
    for name,data in tools.items():
        if name.endswith('.py'):ast.parse(data,filename=name,feature_version=(3,10))
    files={'overlay/'+n:b for n,b in sources.items()}
    files.update({'tools/'+n:b for n,b in tools.items()})
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();root=Path(__file__).resolve().parents[1]
    files=packet_files(root)
    manifest=dict(scope='Offline native09 only; hardware creates/verifies mounts and reviews actual plan before launch.',
        native_audit_baseline=FRAMEWORK08,source_inputs=INPUTS,
        compile_cache_image=48,stage='tcl-dialog-build09',backing='/mnt/ext1/kaidroid-tcl-dialog-build09',
        external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,
        external_floor_bytes=20*1024**3,root_floor_bytes=20*1024**3,
        retained_builds=[6,7,8],retained_image=53,total_container_bind_count=12,
        original_lower_readonly=True,actual_plan_review_required=True,
        files={n:frozen.sha(b) for n,b in sorted(files.items())},launched=False,installed=False)
    files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    args.output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        target=args.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    archive=Path(str(args.output)+'.tar.gz')
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as tar:
                for name,data in sorted(files.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644;tar.addfile(info,io.BytesIO(data))
    print(json.dumps(dict(packet=str(args.output),archive=str(archive),sha256=frozen.sha(archive.read_bytes()),launched=False)))


if __name__=='__main__':main()
