"""Build a permission-free original-dialog reference/candidate diagnostic; never install."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile
from prepare_tcl_checkbox_binding import bind
from prepare_tcl_dialog_ime_policy import patch as ime_policy_patch
from prepare_tcl_ime_picker import sources as picker_sources
from prepare_tcl_ime_picker_correction import sources as picker_correction_sources
from prepare_tcl_dialog_adapter import patch as adapter_patch


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('sdk', 'jdk', 'output'):
        p.add_argument('--'+n, type=Path, required=True)
    p.add_argument('--candidate', action='store_true')
    p.add_argument('--adapter-candidate', action='store_true', help='Isolated supplied-adapter APIs; requires candidate')
    p.add_argument('--adapter-version',type=int,choices=(1,2),default=1)
    p.add_argument('--ime-picker-candidate', action='store_true', help='Isolated original titleless keyboard menu; requires candidate')
    p.add_argument('--ime-picker-correction', action='store_true', help='Isolated native51 Symbols/touch-mode correction; requires candidate')
    p.add_argument('--ime-picker-correction-version',type=int,choices=(4,5),default=4)
    p.add_argument('--ime-app-style-inputs',type=Path,help='Exact native11 inputs for isolated application-selector candidate')
    p.add_argument('--ime-app-style-baseline',action='store_true',help='SDK negative control: retain exact native11 sources')
    p.add_argument('--title-editor-padding',action='store_true',help='Isolated constructor padding correction with app-style SDK fixture')
    p.add_argument('--ime-picker-edge-spy',action='store_true',help='SDK-only counted services for deterministic same-editor availability test')
    p.add_argument('--ime-handover-inputs',type=Path,help='Isolated native12 handover sources with SDK-only service/focus doubles')
    p.add_argument('--ime-handover-baseline',action='store_true',help='Negative SDK control: original callback plus diagnostic-only fields')
    p.add_argument('--checkbox-overlay',type=Path,help='Fixture-only original artwork control; never part of the active03 build')
    p.add_argument('--checkbox-binding',action='store_true',help='Isolated future source binding, requires candidate and original checkbox resources')
    p.add_argument('--dialog-ime-policy',action='store_true',help='Isolated accepted48 dialog owner correction; no production source edit')
    a = p.parse_args()
    if a.ime_handover_baseline and not a.ime_handover_inputs:p.error('Handover baseline requires handover fixture')
    if a.ime_handover_inputs and (not a.ime_app_style_inputs or a.ime_app_style_baseline or a.ime_picker_edge_spy):
        p.error('Handover fixture requires app-style inputs and excludes baseline/old edge spy')
    if a.ime_app_style_baseline and not a.ime_app_style_inputs:p.error('App-style baseline requires exact inputs')
    if a.ime_app_style_inputs and not a.candidate:p.error('App-style fixture requires candidate relocation')
    if a.title_editor_padding and not a.ime_app_style_inputs:p.error('Title padding fixture requires exact app-style inputs')
    if a.adapter_version!=1 and not a.adapter_candidate:p.error('--adapter-version requires --adapter-candidate')
    if (a.ime_picker_edge_spy or a.ime_picker_correction_version!=4) and not a.ime_picker_correction:
        p.error('Correction version/service spy requires --ime-picker-correction')
    if a.adapter_candidate and (not a.candidate or a.ime_picker_candidate or a.ime_picker_correction or a.dialog_ime_policy or a.checkbox_binding or a.checkbox_overlay):
        p.error('--adapter-candidate requires candidate and excludes other isolated changes')
    if a.ime_picker_correction and (not a.candidate or a.ime_picker_candidate or a.dialog_ime_policy or a.checkbox_binding or a.checkbox_overlay):
        p.error('--ime-picker-correction requires candidate and excludes other isolated changes')
    if a.ime_picker_candidate and (not a.candidate or a.dialog_ime_policy or a.checkbox_binding or a.checkbox_overlay):
        p.error('--ime-picker-candidate requires candidate and excludes separate changes')
    if a.dialog_ime_policy and (not a.candidate or a.checkbox_binding or a.checkbox_overlay):
        p.error('--dialog-ime-policy requires candidate and excludes separate checkbox resources/binding')
    if a.checkbox_binding and not (a.candidate and a.checkbox_overlay):
        p.error('--checkbox-binding requires --candidate and --checkbox-overlay')
    root = Path(__file__).resolve().parents[1]
    out = a.output.resolve()
    if out.exists():
        raise FileExistsError(out)
    out.mkdir(parents=True)
    bt = a.sdk/'build-tools/35.0.0'
    android = a.sdk/'platforms/android-30/android.jar'
    exe = '.exe' if os.name == 'nt' else ''
    env = dict(os.environ, JAVA_HOME=str(a.jdk))
    env['PATH'] = str(a.jdk/'bin')+os.pathsep+env.get('PATH','')
    def run(argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, text=True, env=env, timeout=120)
        with (out/'build.log').open('a', encoding='utf-8') as f:
            f.write(result.stdout+result.stderr)
        result.check_returncode()
    source = root/'tests/dialogprobe'
    inputs = [source/'AndroidManifest.xml', *sorted(source.glob('src/**/*.java'))]
    sources = inputs[1:]
    classes, dex, generated = (out/n for n in ('classes','dex','generated'))
    for d in (classes,dex,generated):
        d.mkdir()
    resource_args = []
    if a.candidate:
        resources = root/'framework/core/res/res'
        resource_args = ['-S',resources]
        inputs += sorted(f for f in resources.rglob('*') if f.is_file())
        originals = sorted((root/'framework/core/java/android').rglob('*.java'))
        picker = picker_correction_sources(root,a.ime_picker_correction_version) if a.ime_picker_correction else (picker_sources(root) if a.ime_picker_candidate else {})
        if a.ime_app_style_inputs:
            if any((a.ime_picker_correction,a.ime_picker_candidate,a.adapter_candidate,a.dialog_ime_policy,a.checkbox_binding,a.checkbox_overlay)):
                raise ValueError('Application-selector candidate excludes other isolated changes')
            from prepare_tcl_ime_app_style import sources as app_style_sources, PINS as app_style_pins
            picker=app_style_sources(a.ime_app_style_inputs)
            if a.ime_app_style_baseline:
                picker={'core/java/android/widget/'+n:(a.ime_app_style_inputs/n).read_bytes() for n in app_style_pins}
            state=(a.ime_app_style_inputs/'KeypadImeModeState.java').read_bytes()
            if hashlib.sha256(state).hexdigest()!='cb4c9b934b811d594c4270a51eac0b2fdd268e7ffa5b7651f4ec8d278f3f4806':
                raise ValueError('Wrong retained native11 mode policy')
            picker['core/java/android/widget/KeypadImeModeState.java']=state
            if a.title_editor_padding:
                from prepare_tcl_title_editor_padding import patch as title_padding_patch
                picker['core/java/android/widget/TitleEditText.java']=title_padding_patch((root/'framework/core/java/android/widget/TitleEditText.java').read_bytes())
        if 'core/java/android/widget/KeypadImePicker.java' in picker:
            originals.append(root/'experiments/ui/KeypadImePicker.java')
        if a.ime_handover_inputs:
            from prepare_tcl_ime_handover import sources as handover_sources
            expected=handover_sources(root/'work/tcl-app-widgets-build-packet12-03/overlay/core/java/android/widget')
            for name,data in expected.items():
                if (a.ime_handover_inputs/name).read_bytes()!=data:raise ValueError('Handover candidate source differs')
                picker['core/java/android/widget/'+name]=data
            if a.ime_handover_baseline:
                original=(root/'work/tcl-app-widgets-build-packet12-03/overlay/core/java/android/widget/KeypadImeController.java').read_text()
                anchor='    private long pickerFocusDeadline;'
                if original.count(anchor)!=1:raise ValueError('Wrong original callback negative control')
                picker['core/java/android/widget/KeypadImeController.java']=original.replace(anchor,anchor+'\n    private Runnable pendingSelection; // SDK diagnostic field only; no behavior change.').encode()
        for original in originals:
            if original.name == 'MarqueeTextView.java':
                continue  # Requires the patched boot TextView, not used by TctDialog.
            relative = (Path('android/widget/KeypadImePicker.java') if original.name == 'KeypadImePicker.java'
                        else original.relative_to(root/'framework/core/java'))
            text = original.read_text(encoding='utf-8')
            key = 'core/java/'+relative.as_posix()
            if key in picker:
                text = picker[key].decode('utf-8')
            if a.adapter_candidate and original.name == 'TctDialog.java':
                text = adapter_patch(original.read_bytes(),a.adapter_version).decode('utf-8')
            if (a.ime_picker_edge_spy or a.ime_handover_inputs) and original.name == 'KeypadImeController.java':
                old='import android.view.inputmethod.InputMethodManager;'
                if text.count(old)!=1:raise ValueError('Unexpected IME service import for fixture spy')
                text=text.replace(old,'import org.kaidroid.dialogprobe.spy.InputMethodManager;')
            if a.dialog_ime_policy and original.name in ('TctDialog.java','MenuBar.java'):
                text=ime_policy_patch(original.name,original.read_bytes()).decode('utf-8').replace('\r\n','\n')
            if a.checkbox_binding and original.name=='TctDialog.java':
                text=bind(original.read_bytes()).decode('utf-8').replace('\r\n','\n')
                lookup='"zz_kaidroid_tcl_dialog_checkbox", "drawable", "android"'
                if text.count(lookup)!=1:raise ValueError('Unexpected source binding lookup')
                text=text.replace(lookup,'"zz_kaidroid_tcl_dialog_checkbox", "drawable", getContext().getPackageName()')
            package = 'android.'+relative.parts[1]
            text = text.replace('package '+package+';',
                'package org.kaidroid.dialogprobe.compat.'+relative.parts[1]+';\nimport '+package+'.*;',1)
            for name in ('MenuBar','TctDialogMessage'):
                text = text.replace('import android.widget.'+name+';',
                    'import org.kaidroid.dialogprobe.compat.widget.'+name+';')
            text = text.replace('com.android.internal.R.style.TctDialogStyle',
                                'org.kaidroid.dialogprobe.R.style.TctDialogStyle')
            text = text.replace('import com.android.internal.R;', 'import org.kaidroid.dialogprobe.R;')
            target = out/'relocated'/relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text,encoding='utf-8',newline='\n')
            sources.append(target)
            inputs.append(original)
        if a.ime_picker_edge_spy:
            extra=sorted((root/'tests/imeedge/src').rglob('*.java'))
            if len(extra)!=2:raise ValueError('Expected two isolated SDK service-spy fixture sources')
            inputs+=extra;sources+=extra
        if a.ime_handover_inputs:
            extra=sorted((root/'tests/imehandover/src').rglob('*.java'))
            if len(extra)!=2:raise ValueError('Expected isolated handover instrumentation and service spy')
            inputs+=extra;sources+=extra
    if a.ime_app_style_inputs:
        if not a.candidate:raise ValueError('Application-selector fixture requires candidate')
        extra=root/'tests/imeappstyle'
        sources+=sorted((extra/'src').rglob('*.java'))
        inputs+=sorted(f for f in extra.rglob('*') if f.is_file())
        resource_args+=['-S',extra/'res']
        manifest=out/'app-style'/'AndroidManifest.xml'
        manifest.parent.mkdir()
        xml=inputs[0].read_text(encoding='utf-8')
        xml=xml.replace('</application>','<activity android:name=".AppStyleActivity" android:exported="false" /></application>')
        xml=xml.replace('</manifest>','<instrumentation android:name=".AppStyleInstrumentation" android:targetPackage="org.kaidroid.dialogprobe" /></manifest>')
        xml=xml.replace('</manifest>','<instrumentation android:name=".TitleLayoutInstrumentation" android:targetPackage="org.kaidroid.dialogprobe" /></manifest>')
        if a.ime_handover_inputs:
            xml=xml.replace('</manifest>','<instrumentation android:name=".compat.widget.HandoverInstrumentation" android:targetPackage="org.kaidroid.dialogprobe" /></manifest>')
        manifest.write_text(xml,encoding='utf-8');inputs[0]=manifest
    unsigned = out/'unsigned.apk'
    if a.checkbox_overlay:
        if not a.candidate:raise ValueError('Original boot reference must retain native artwork')
        spec=json.loads((root/'docs/contracts/tcl-checkbox-overlay01.json').read_text(encoding='utf-8'))
        canonical=hashlib.sha256(json.dumps(spec['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if canonical!='c93c73003e307752cdf461f6424ed8ad18c274c7583506b208b888571f07bea3':
            raise ValueError('Unreviewed checkbox artwork control')
        extra=out/'checkbox-res'
        for name,digest in spec['files'].items():
            path=Path(name);source=(a.checkbox_overlay/path).resolve(strict=True)
            if path.is_absolute() or '..' in path.parts or hashlib.sha256(source.read_bytes()).hexdigest()!=digest:
                raise ValueError('Wrong checkbox resource: '+name)
            target=extra/path;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
            inputs.append(source)
        resource_args+=['-S',extra]
    run([bt/('aapt'+exe),'package','-f','-m','--auto-add-overlay','-M',inputs[0],
         *resource_args,'-I',android,'-J',generated,'-F',unsigned])
    run([a.jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,
         *sources,*generated.rglob('*.java')])
    run([a.jdk/'bin'/('java'+exe),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8',
         '--lib',android,'--output',dex,*classes.rglob('*.class')])
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(dex/'classes.dex','classes.dex')
    aligned = out/'aligned.apk'
    run([bt/('zipalign'+exe),'-f','4',unsigned,aligned])
    key = out/'diagnostic-only.p12'
    run([a.jdk/'bin'/('keytool'+exe),'-genkeypair','-keystore',key,'-storepass','android',
         '-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Dialog Diagnostic',
         '-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
    apk = out/'dialog-probe.apk'
    signer = [a.jdk/'bin'/('java'+exe),'-jar',bt/'lib/apksigner.jar']
    run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([*signer,'verify','--verbose','--print-certs',apk])
    report = dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),candidate=a.candidate,
                  isolated_ime_app_style=bool(a.ime_app_style_inputs),
                  ime_app_style_negative_baseline=a.ime_app_style_baseline,
                  isolated_title_editor_padding=a.title_editor_padding,
                  original_checkbox_artwork_fixture=bool(a.checkbox_overlay),
                  original_checkbox_source_binding=bool(a.checkbox_binding),
                  isolated_ime_picker_candidate=bool(a.ime_picker_candidate),
                  isolated_ime_picker_correction=bool(a.ime_picker_correction),
                  ime_picker_correction_version=a.ime_picker_correction_version if a.ime_picker_correction else None,
                  sdk_only_ime_service_spy=bool(a.ime_picker_edge_spy),
                  isolated_adapter_candidate=bool(a.adapter_candidate),
                  adapter_version=a.adapter_version if a.adapter_candidate else None,
                  dialog_ime_policy_control=bool(a.dialog_ime_policy),
                  inputs={str(n.relative_to(root)):hashlib.sha256(n.read_bytes()).hexdigest() for n in inputs},
                  scope='Built only; original boot mode contains no relocated framework classes; candidate mode uses source copies')
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(apk=str(apk),sha256=report['apk_sha256'],candidate=a.candidate)))


if __name__ == '__main__':
    main()
