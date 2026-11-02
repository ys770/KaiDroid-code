"""Prepare fresh native11 footer packet offline; never touch host, build, pack or phone."""
import argparse
import ast
import gzip
import io
import json
from pathlib import Path
import tarfile
import prepare_tcl_dialog_hiddenapi_build_packet as prior
from prepare_tcl_ime_footer_candidate import BASE, single_unit
from prepare_tcl_ime_footer_flags import BASE as FLAGS_BASE, predict, sha

IMS = "core/java/android/inputmethodservice/InputMethodService.java"
IMS_SHA = "5966fa968a05ee01c8b5b4fec5f38f018d69619f79524828dd02606be14568c4"
FRAMEWORK = "429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53"
FLAGS = "bb6da7de3b49099e28eb3aa102bd5e0d06cf02ab4316a49adc677e9491a3a979"
RECOVERY = "e84160080d752a8060fc930219dd050adc77fcd48f70fa7961d263d64c614dee"
OUTPUTS = "6cb452828ce2db9b1bddaa6c7a31d325582eab0ca8fc8cac2ed2f880e06e1b63"
RECOVERY_TOOL = "16e5682ad0c088ccc4195814e5cb28db5bea9aa4a4965d677936b1974db09614"

RETAINED10 = r'''
def retained10(root):
    import recover_tcl_dialog_native10_export as original
    prior=root/'tcl-dialog-build10'; recovery=prior/'export-recovery01'
    if prior.resolve(strict=True)!=prior or recovery.resolve(strict=True)!=recovery:
        raise ValueError('Symlinked retained10')
    info=json.loads(subprocess.check_output(['sudo','docker','inspect',original.CID],text=True))[0]
    original.validate_terminal(info);spec=original.validate_stage(prior)
    pins={'export-recovery01/recovery.json':RECOVERY_PIN,'export-recovery01/outputs.json':OUTPUTS_PIN}
    for name,pin in pins.items():
        path=prior/name
        if path.resolve(strict=True)!=path or sha(path)!=pin:raise ValueError('Retained10 recovery receipt changed')
    result=json.loads((recovery/'recovery.json').read_text())
    if result.get('passed') is not True or result.get('terminal') is not True or result.get('compiler_restarted') is not False or result.get('original_failed_status_preserved') is not True:
        raise ValueError('Retained10 recovery is not original audited export-only success')
    exports=json.loads((recovery/'outputs.json').read_text())['files']
    if len(exports)!=30 or exports.get('framework/framework.jar')!=FRAMEWORK_PIN:
        raise ValueError('Retained10 recovered closure changed')
    pins.update({'export-recovery01/output/'+n:d for n,d in exports.items()})
    pins.update({'inputs/'+n:d for n,d in spec['inputs'].items()})
    pins.update(json.loads((prior/'control-inputs.json').read_text()))
    pins.update({'control-inputs.json':original.CONTROLS,'build.log':original.LOG,
                 'cache-preservation.json':original.CACHE_PROOF})
    for name,pin in pins.items():
        path=prior/name
        if path.resolve(strict=True)!=path or sha(path)!=pin:raise ValueError('Retained10 payload changed: '+name)
    return {(prior/n).relative_to(root).as_posix():d for n,d in pins.items()}

'''.replace('RECOVERY_PIN',repr(RECOVERY)).replace('OUTPUTS_PIN',repr(OUTPUTS)).replace('FRAMEWORK_PIN',repr(FRAMEWORK))


def packet_files(root, ims_source, flags):
    candidate=single_unit(ims_source)
    if sha(candidate)!=IMS_SHA:raise ValueError('Single-unit IMS candidate changed')
    expected=predict(flags)
    if sha(expected)!=FLAGS:raise ValueError('Full Linux flags prediction changed')
    files=prior.packet_files(root);replace=prior.prior.frozen.replace_once
    # Stage identifiers only: retained predecessor functions keep their original IDs.
    for name,data in list(files.items()):
        if name.startswith('tools/'):
            files[name]=data.replace(b'tcl-dialog-build10',b'tcl-dialog-build11')
    files['overlay/'+IMS]=candidate
    recovery_tool=(root/'tools/recover_tcl_dialog_native10_export.py').read_bytes()
    if sha(recovery_tool)!=RECOVERY_TOOL:raise ValueError('Retained10 verifier changed')
    files['tools/recover_tcl_dialog_native10_export.py']=recovery_tool
    key='tools/prepare_tcl_ime_picker_build.py';prep=files[key].decode()
    prep=replace(prep,'GIB=1024**3', 'POLICY.update('+repr({IMS:IMS_SHA})+')\nGIB=1024**3')
    prep=replace(prep,'def prepare(root,overlay,stage):',RETAINED10+'def prepare(root,overlay,stage):')
    prep=replace(prep,'    accepted_pins.update(retained54(root))',
      '    accepted_pins.update(retained54(root))\n    accepted_pins.update(retained10(root))\n'+
      '    ims_original=root/'+repr('aosp/frameworks/base/'+IMS)+'\n'+
      '    if ims_original.resolve(strict=True)!=ims_original or sha(ims_original)!='+repr(BASE)+":raise ValueError('Shared original IMS changed')\n"+
      '    accepted_pins['+repr('aosp/frameworks/base/'+IMS)+']='+repr(BASE))
    prep=replace(prep,"if changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java','KeypadImeModeState.java'}:",
      "if changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java','KeypadImeModeState.java','InputMethodService.java'}:")
    prep=replace(prep,"accepted_framework_baseline='"+prior.FRAMEWORK09+"'", "accepted_framework_baseline='"+FRAMEWORK+"'")
    prep=replace(prep,"    inputs['generate_hiddenapi_lists.py'] = sha(stage/'inputs'/'generate_hiddenapi_lists.py')",
      "    inputs['generate_hiddenapi_lists.py'] = sha(stage/'inputs'/'generate_hiddenapi_lists.py')\n    if len(inputs)!=97:raise ValueError('Expected exact97 source inputs')")
    files[key]=prep.encode()
    key='tools/monitor_tcl_dialog_ime_disk.py';monitor=files[key].decode()
    monitor=replace(monitor,"('KeypadImeModeState.java','widget')]:", "('KeypadImeModeState.java','widget'),('InputMethodService.java','inputmethodservice')]:")
    files[key]=monitor.encode()
    key='tools/build_tcl_ime_picker.sh';build=files[key].decode()
    build=replace(build,repr(prior.GENERATED_FLAGS),repr(FLAGS))
    build=build.replace('Full generated flags differ from exact two-row prediction','Full generated flags differ from exact retained-plus-seven-private-API prediction')
    build=replace(build," 'frameworks/base/core/java/android/widget/KeypadImeController.java'", " 'frameworks/base/core/java/android/inputmethodservice/InputMethodService.java',\n 'frameworks/base/core/java/android/widget/KeypadImeController.java'")
    build=replace(build," assert any(b'Landroid/widget/KeypadImePicker;' in b for b in dex),'New picker helper missing'",
      " assert any(b'Landroid/widget/KeypadImePicker;' in b for b in dex),'New picker helper missing'\n assert any(b'Landroid/inputmethodservice/TclImeFooterLayout;' in b for b in dex),'Footer helper missing'")
    build=build.replace('Native10 exact adapter whitelist/test-api flags only; Java frozen09, compile cache48; future image baseline separately reviewed',
      'Native11 Kika footer geometry; four native10 Java inputs and generator retained; compile cache48; future pack separate')
    files[key]=build.encode()
    for name,data in files.items():
        if name.endswith('.py'):ast.parse(data,filename=name,feature_version=(3,10))
    overlays={n[8:]:sha(b) for n,b in files.items() if n.startswith('overlay/')}
    if overlays!={**prior.prior.INPUTS,IMS:IMS_SHA}:raise ValueError('Unexpected Java source delta')
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('aosp-source','flags','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    files=packet_files(root,a.aosp_source.read_bytes(),a.flags.read_bytes())
    manifest=dict(scope='Offline native11 packet; parent owns actual process/space/mount/plan review and launch',
      stage='tcl-dialog-build11',backing='/mnt/ext1/kaidroid-tcl-dialog-build11',native_audit_baseline=FRAMEWORK,
      unchanged_java_inputs=prior.prior.INPUTS,added_ims_source={IMS:IMS_SHA},
      hiddenapi_generator=prior.auxiliary_info(),baseline_csv_sha256=FLAGS_BASE,generated_csv_sha256=FLAGS,
      csv_delta='Exactly seven new private blacklist rows;429755 retained rows unchanged',
      predicted_method_delta='Only IMS.initViews,onComputeInsets,lambda$new$0; four added helper methods',
      predicted_metadata_delta='One private IMSboolean field; one package-private final helper class,2staticfinal fields,4methods',
      total_container_binds=14,source_inputs=97,control_files=6,
      retained_native10_original_terminal1=True,retained_native10_export_only_recovery=True,
      external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,external_floor_bytes=20*1024**3,root_floor_bytes=20*1024**3,
      modes={n:(0o755 if n=='hiddenapi-generator/'+prior.AUX else 0o644) for n in files},
      files={n:sha(b) for n,b in sorted(files.items())},source_generator_regeneration_required=True,
      binary_patch_allowed=False,global_runtime_policy_changed=False,stubs_changed=False,launched=False,installed=False,full_parity=False)
    files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    a.output.mkdir(parents=True,exist_ok=False)
    for name,data in files.items():
        path=a.output/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    archive=Path(str(a.output)+'.tar.gz')
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as tar:
                for name,data in sorted(files.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=manifest['modes'].get(name,0o644)
                    tar.addfile(info,io.BytesIO(data))
    print(json.dumps(dict(archive=str(archive),sha256=sha(archive.read_bytes()),launched=False)))


if __name__=='__main__':main()
