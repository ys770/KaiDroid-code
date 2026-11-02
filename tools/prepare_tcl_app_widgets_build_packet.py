"""Freeze native12 app-selector/title-padding inputs offline; hardware owns execution."""
import argparse
import ast
import gzip
import io
import json
from pathlib import Path
import tarfile
import prepare_tcl_ime_footer_build_packet as prior
from prepare_tcl_ime_app_style import sources as style_sources
from prepare_tcl_title_editor_padding import patch as title_patch,BASE as TITLE_BASE
from prepare_tcl_app_widgets_flags import predict,sha

FRAMEWORK='a5f20e01980dbc5a7ea71f883b24d7f77d2781b2407fda9aa0e298f7c4490330'
FLAGS='6a9d085640be47d5d8a3409e102e422d2dde0cfa964409362a6881ee2ce61d8e'
REVIEW='a1f11d3a76a91c0b1044641687958316488a7266b7323aee6645f082bac88bbe'
CID='027e91ff2bb67e0cb502c2e15d8eb1d7448f24604cd30ac8a8c624be6876e9b7'
TITLE='core/java/android/widget/TitleEditText.java'

RETAINED11='''
def retained11(root,overlay):
    import importlib.util
    import sys
    previous=root/'tcl-dialog-build11'
    if previous.resolve(strict=True)!=previous:raise ValueError('Symlinked retained11')
    pins={'staging.json':'8f8b6428da6def83e5fb81a55bb778afb051ebea85ddb7b5eb90e0268e5a34e3',
          'outputs.json':'36bf97169e0d71886bb27aa5ad15134d7854edc78e139bbd25a195bc59b45077',
          'cache-preservation.json':'d507c02a90d46cafdec799a32f3eb71859d539b614b0f99a810467cd11eae7ae',
          'control-inputs.json':'0e4efd7950e314b65b47c37fa7f99ce1772ca3e3148ba303ce84142601548783',
          'build.exit':'9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa'}
    for name,pin in pins.items():
        if (previous/name).resolve(strict=True)!=previous/name or sha(previous/name)!=pin:
            raise ValueError('Retained11 proof changed: '+name)
    proof=overlay.parent/'proofs/native11-parent-review.json'
    if proof.resolve(strict=True)!=proof or sha(proof)!=REVIEW_PIN:raise ValueError('Native11 independent review changed')
    reviewed=json.loads(proof.read_text())
    if reviewed.get('combined_source_binary_review_passed') is not True or reviewed.get('structural_audit',{}).get('candidate_sha256')!=FRAMEWORK_PIN or reviewed.get('independent_body_review',{}).get('passed') is not True:
        raise ValueError('Native11 baseline lacks exact independent body review')
    controls=json.loads((previous/'control-inputs.json').read_text())
    for name,pin in controls.items():
        if (previous/name).is_symlink() or sha(previous/name)!=pin:raise ValueError('Retained11 control changed')
    # The retained verifier must use its own exact11 storage contract, not12's.
    layer_spec=importlib.util.spec_from_file_location('retained11_layer',previous/'layered_dialog_output.py')
    old_layer=importlib.util.module_from_spec(layer_spec);layer_spec.loader.exec_module(old_layer)
    active_layer=sys.modules.get('layered_dialog_output')
    try:
        sys.modules['layered_dialog_output']=old_layer
        spec=importlib.util.spec_from_file_location('retained11_monitor',previous/'disk-monitor.py')
        monitor=importlib.util.module_from_spec(spec);spec.loader.exec_module(monitor)
        staged=monitor.load_stage(root,previous);monitor.verify_inputs(previous,staged)
    finally:
        if active_layer is None:sys.modules.pop('layered_dialog_output',None)
        else:sys.modules['layered_dialog_output']=active_layer
    cid=CID_PIN
    info=json.loads(subprocess.check_output(['sudo','docker','inspect',cid],text=True))[0]
    monitor.validate_container(info,root,previous,cid)
    state=info.get('State',{})
    if state.get('Running') is not False or state.get('Status')!='exited' or state.get('ExitCode')!=0 or state.get('OOMKilled') is not False:
        raise ValueError('Retained11 is not definitive non-OOM terminal0')
    if (previous/'container-id').read_text().strip()!=cid:raise ValueError('Retained11 CID receipt differs')
    cache=json.loads((previous/'cache-preservation.json').read_text())
    if cache.get('container_id')!=cid or cache.get('lower_entries')!=565530 or cache.get('original_lower_all_files_content_metadata_unchanged') is not True or cache.get('projected_removed_entries')!=[]:
        raise ValueError('Retained11 cache preservation differs')
    exports=json.loads((previous/'outputs.json').read_text())['files']
    if len(exports)!=30 or exports.get('framework/framework.jar')!=FRAMEWORK_PIN:raise ValueError('Wrong native11 export closure')
    pins.update(controls);pins.update({'inputs/'+n:d for n,d in staged['inputs'].items()})
    pins.update({'output/'+n:d for n,d in exports.items()})
    for name,pin in pins.items():
        if (previous/name).resolve(strict=True)!=previous/name or sha(previous/name)!=pin:
            raise ValueError('Retained11 bytes changed: '+name)
    return {(previous/n).relative_to(root).as_posix():d for n,d in pins.items()}

'''.replace('REVIEW_PIN',repr(REVIEW)).replace('FRAMEWORK_PIN',repr(FRAMEWORK)).replace('CID_PIN',repr(CID))


def packet_files(root,aosp_source,flags10,flags11,native11_sources):
    expected=predict(flags11)
    if sha(expected)!=FLAGS:raise ValueError('Full native12 flags prediction changed')
    files=prior.packet_files(root,aosp_source,flags10)
    replace=prior.prior.prior.frozen.replace_once
    for name,data in list(files.items()):
        if name.startswith('tools/'):files[name]=data.replace(b'tcl-dialog-build11',b'tcl-dialog-build12')
    new=style_sources(native11_sources)
    new[TITLE]=title_patch((root/'framework/core/java/android/widget/TitleEditText.java').read_bytes())
    for name,data in new.items():files['overlay/'+name]=data
    proof=(root/'docs/evidence/tcl-ime-footer-native11-parent-review01.json').read_bytes()
    if sha(proof)!=REVIEW:raise ValueError('Exact raw independent native11 review changed')
    files['proofs/native11-parent-review.json']=proof
    key='tools/prepare_tcl_ime_picker_build.py';prep=files[key].decode()
    prep=replace(prep,'GIB=1024**3','POLICY.update('+repr({n:sha(b) for n,b in new.items()})+')\nGIB=1024**3')
    prep=replace(prep,'def prepare(root,overlay,stage):',RETAINED11+'def prepare(root,overlay,stage):')
    prep=replace(prep,'    accepted_pins.update(retained10(root))',
        '    accepted_pins.update(retained10(root))\n    accepted_pins.update(retained11(root,overlay))\n'+
        '    title_original=root/'+repr('aosp/frameworks/base/'+TITLE)+'\n'+
        '    if title_original.resolve(strict=True)!=title_original or sha(title_original)!='+repr(TITLE_BASE)+":raise ValueError('Shared original title widget changed')\n"+
        '    accepted_pins['+repr('aosp/frameworks/base/'+TITLE)+']='+repr(TITLE_BASE))
    old="if changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java','KeypadImeModeState.java','InputMethodService.java'}:"
    prep=replace(prep,old,old.replace("'InputMethodService.java'","'InputMethodService.java','TitleEditText.java'"))
    prep=replace(prep,'if len(inputs)!=97:', 'if len(inputs)!=98:').replace('Expected exact97 source inputs','Expected exact98 source inputs')
    prep=replace(prep,"accepted_framework_baseline='"+prior.FRAMEWORK+"'","accepted_framework_baseline='"+FRAMEWORK+"'")
    files[key]=prep.encode()
    key='tools/monitor_tcl_dialog_ime_disk.py';monitor=files[key].decode()
    monitor=replace(monitor,"('InputMethodService.java','inputmethodservice')]:", "('InputMethodService.java','inputmethodservice'),('TitleEditText.java','widget')]:")
    files[key]=monitor.encode()
    key='tools/build_tcl_ime_picker.sh';build=files[key].decode()
    build=replace(build,repr(prior.FLAGS),repr(FLAGS)).replace('retained-plus-seven-private-API','retained-plus-eight-private-API')
    build=replace(build," 'frameworks/base/core/java/android/inputmethodservice/InputMethodService.java',", " 'frameworks/base/core/java/android/widget/TitleEditText.java',\n 'frameworks/base/core/java/android/inputmethodservice/InputMethodService.java',")
    marker=" assert any(b'Landroid/inputmethodservice/TclImeFooterLayout;' in b for b in dex),'Footer helper missing'"
    build=replace(build,marker,marker+"\n assert any(b'Landroid/widget/KeypadImePicker$StyledImeRow;' in b for b in dex),'App-selector row helper missing'")
    files[key]=build.encode()
    for name,data in files.items():
        if name.startswith('tools/') and name.endswith(('.py','.sh')) and b'\r' in data:raise ValueError('Noncanonical executable text: '+name)
        if name.endswith('.py'):ast.parse(data,filename=name,feature_version=(3,10))
    expected_sources={**prior.prior.prior.INPUTS,prior.IMS:prior.IMS_SHA,**{n:sha(d) for n,d in new.items()}}
    if {n[8:]:sha(d) for n,d in files.items() if n.startswith('overlay/')}!=expected_sources:raise ValueError('Unexpected source set')
    return files


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('aosp-source','flags10','flags11','native11-sources','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    files=packet_files(root,a.aosp_source.read_bytes(),a.flags10.read_bytes(),a.flags11.read_bytes(),a.native11_sources)
    manifest=dict(scope='Frozen native12 app-selector/title-padding packet; no execution',stage='tcl-dialog-build12',
        backing='/mnt/ext1/kaidroid-tcl-dialog-build12',native_audit_baseline=FRAMEWORK,native11_review_sha256=REVIEW,
        generated_csv_sha256=FLAGS,retained_csv_rows=429762,added_private_rows=8,total_csv_rows=429770,
        total_container_binds=15,source_inputs=98,compile_cache=48,full30_exports_required=True,
        predicted_existing_changed_methods=5,predicted_added_methods=6,predicted_removed_methods=0,
        native11_ims_footer_retained=True,unresolved_clock_scroll_gap_included=False,
        external_initial_bytes=34*1024**3,external_growth_bytes=14*1024**3,external_floor_bytes=20*1024**3,root_floor_bytes=20*1024**3,
        modes={n:(0o755 if n.startswith('hiddenapi-generator/') else 0o644) for n in files},
        files={n:sha(d) for n,d in sorted(files.items())},launched=False,installed=False,full_parity=False)
    files['packet.json']=(json.dumps(manifest,indent=2)+'\n').encode()
    a.output.mkdir(exist_ok=False,parents=True)
    for name,data in files.items():
        target=a.output/name;target.parent.mkdir(exist_ok=True,parents=True);target.write_bytes(data)
    archive=Path(str(a.output)+'.tar.gz')
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream,mode='wb',filename='',mtime=0) as zipped:
            with tarfile.open(fileobj=zipped,mode='w') as tar:
                for name,data in sorted(files.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=manifest['modes'].get(name,0o644);tar.addfile(info,io.BytesIO(data))
    print(json.dumps(dict(archive=str(archive),archive_sha256=sha(archive.read_bytes()),manifest_sha256=sha(files['packet.json']),launched=False)))


if __name__=='__main__':main()
