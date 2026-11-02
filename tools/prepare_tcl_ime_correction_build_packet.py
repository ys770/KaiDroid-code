"""Generate a fresh private picker-correction build packet locally; never launch."""
import argparse
import ast
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

from prepare_tcl_ime_picker_correction import sources

PINS = {
    'prepare_tcl_ime_picker_build.py': '540e6dbfc88f311276df187551c2d00fc16dedb8103e94b002b513b1532361d9',
    'build_tcl_ime_picker.sh': '558bc2a1f7b992adbc670ac9c36f0fda73607e10d6bff3e8e895fbd91cb1572d',
    'layered_dialog_output.py': '162707151a6c151fba8a3a2649ff49228817b09cdd5dab6975ffdf8db9dc995b',
    'monitor_tcl_dialog_ime_disk.py': 'c5d487ee621a17928593dece5925278967bdaa9a9f804472f544c8e36e9b8b76',
    'prepare_tcl_dialog_build.py': '3e2fb62056bcdaf13ca66a001e991206471c007a8293e9304c16d20cc41a045f',
    'prepare_option_menu42_build.py': 'da945f5c9b3bcb04acd0ca29a44e49ae5ff9e64ab79d7a594fdb2d3be6150d95',
    'prepare_tcl_dialog_overlay.py': 'f9200c44e88ae3155d6b7c02486ae4f2333f102cff8b7af5e3e8984e3213328f',
}
RETAINED = {
    'core/java/android/widget/MenuBar.java': '5802dde1d4f3a90f3cd3515422ca89649fc0d5edf27b9d1d3e3b3df291b2865d',
    'core/java/android/app/TctDialog.java': 'e21a894eb1a5e55bbd3c42503ecbf60b4e31f86915ec55d7f6511f781af093b6',
}
FRAMEWORK51 = 'efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb'
FRAMEWORK07 = 'fc87c5f661224cedbe5d4960b8c00b8d41025ce8b9852af657b5899df90a9d08'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Frozen template shape changed: ' + old)
    return text.replace(old, new)


# This verifies build06 as the audit baseline, not as an accepted complete UI.
RETAINED51_CHECK = '''
def retained51(root):
    prior = root/'tcl-dialog-build06'
    cid = 'dbf2432c3114a467ecb9dcf02520a6636cea09a707e2cf8aacf6a01d92b09d69'
    pins = {'staging.json':'268ffec83ebe8f90e63ff306cad9908e0efd9b45684168e33ece9a7e37f981bf',
            'outputs.json':'fe6fbaa02a2b68d9c9ea9697d688268f996d0c1a519d06171f718b8fec813985',
            'cache-preservation.json':'ff6af5e4b1b43eaddcefbb8203015316e07e8c3f2aaba305778ada5365aa9033'}
    if prior.resolve(strict=True) != prior:
        raise ValueError('Symlinked retained51 stage')
    for name, digest in pins.items():
        if (prior/name).is_symlink() or sha(prior/name) != digest:
            raise ValueError('Retained51 proof changed: ' + name)
    if (prior/'build.exit').read_text().strip() != '0' or (prior/'container-id').read_text().strip() != cid:
        raise ValueError('Retained51 terminal identity changed')
    info = json.loads(subprocess.check_output(['sudo','docker','inspect',cid],text=True))[0]
    state = info['State']
    if info['Id'] != cid or info.get('Name') != '/kaidroid-tcl-dialog-build06' or info.get('Image') != IMAGE or info['Config'].get('User') != 'builder' or info['Config'].get('Cmd') != ['bash','/build/tcl-dialog-build06/build.sh'] or state.get('Status') != 'exited' or state.get('Running') or state.get('Restarting') or state.get('OOMKilled') or state.get('Pid') != 0 or state.get('ExitCode') != 0:
        raise ValueError('Retained51 container identity/state changed')
    spec = json.loads((prior/'staging.json').read_text())
    exports = json.loads((prior/'outputs.json').read_text())['files']
    if len(exports) != 30 or exports.get('framework/framework.jar') != 'efd9dce85da9c10a81184755bcd3f1b902367b3808d5b96c84054cdaab37e0cb':
        raise ValueError('Wrong retained51 export closure')
    retained = {(prior/name).relative_to(root).as_posix(): digest for name,digest in pins.items()}
    for folder, entries in [('inputs',spec['inputs']),('output',exports)]:
        for name,digest in entries.items():
            target = prior/folder/name
            if target.is_symlink() or sha(target) != digest:
                raise ValueError('Retained51 source/export changed: ' + name)
            retained[target.relative_to(root).as_posix()] = digest
    return retained

'''

RETAINED07_CHECK = RETAINED51_CHECK.replace('retained51','retained07').replace('Retained51','Retained07')
for old,new in {
    'tcl-dialog-build06':'tcl-dialog-build07',
    'dbf2432c3114a467ecb9dcf02520a6636cea09a707e2cf8aacf6a01d92b09d69':'6488021baa4bcac7de551f68dd451e21053519ca015e0a933bb693d18dc569d5',
    '268ffec83ebe8f90e63ff306cad9908e0efd9b45684168e33ece9a7e37f981bf':'771595acdf235b0341f08a8ad67d1cefe8955bb578e64cc23d2660af8c3fa02f',
    'fe6fbaa02a2b68d9c9ea9697d688268f996d0c1a519d06171f718b8fec813985':'d3617e32e67a68727864d00e348103373088c2bd1af6a4ad6226110ccbe82eb1',
    'ff6af5e4b1b43eaddcefbb8203015316e07e8c3f2aaba305778ada5365aa9033':'0648dd7fe56e049e5895d07261f2330b618ca200d60c8787e1100d1591cbc9fe',
    FRAMEWORK51:FRAMEWORK07,
}.items():
    RETAINED07_CHECK=RETAINED07_CHECK.replace(old,new)


def reviewed_budget02(prep, monitor):
    prep=replace_once(prep,"if shutil.disk_usage(root).free<40*GIB:raise ValueError('Require20GiB growth+20GiB floor; no clone/delete')",
                      "if shutil.disk_usage(root).free<35*GIB:raise ValueError('Require reviewed15GiB growth+unchanged20GiB floor; no clone/delete')")
    prep=replace_once(prep,"if free<40*GIB:raise ValueError('Layer preparation consumed required headroom')",
                      "if free<35*GIB:raise ValueError('Layer preparation consumed required headroom')")
    prep=replace_once(prep,'incremental_budget_bytes=20*GIB,emergency_floor_bytes=20*GIB',
                      'incremental_budget_bytes=15*GIB,emergency_floor_bytes=20*GIB')
    monitor=replace_once(monitor,"if plan and (plan.get('incremental_budget_bytes') != 20*GIB or",
                         "if not isinstance(plan,dict) or (type(plan.get('incremental_budget_bytes')) is not int or\n                 type(plan.get('emergency_floor_bytes')) is not int or\n                 plan.get('incremental_budget_bytes') != 15*GIB or")
    monitor=replace_once(monitor,"plan['free_after_clone_bytes'] < 40*GIB):",
                         "plan['free_after_clone_bytes'] < 35*GIB):")
    monitor=replace_once(monitor,"if phase in ('pre-start','pre-frontend') and row['free_bytes'] < 40*GIB:",
                         "if phase in ('pre-start','pre-frontend') and row['free_bytes'] < 35*GIB:")
    return prep,monitor


def reviewed_budget03(prep,monitor):
    prep=replace_once(prep,"if shutil.disk_usage(root).free<35*GIB:raise ValueError('Require reviewed15GiB growth+unchanged20GiB floor; no clone/delete')",
                      "if shutil.disk_usage(root).free<34*GIB:raise ValueError('Require reviewed14GiB growth+unchanged20GiB floor; no clone/delete')")
    prep=replace_once(prep,"if free<35*GIB:raise ValueError('Layer preparation consumed required headroom')",
                      "if free<34*GIB:raise ValueError('Layer preparation consumed required headroom')")
    prep=replace_once(prep,'incremental_budget_bytes=15*GIB,emergency_floor_bytes=20*GIB',
                      'incremental_budget_bytes=14*GIB,emergency_floor_bytes=20*GIB')
    monitor=replace_once(monitor,"plan.get('incremental_budget_bytes') != 15*GIB or",
                         "plan.get('incremental_budget_bytes') != 14*GIB or")
    monitor=replace_once(monitor,"plan['free_after_clone_bytes'] < 35*GIB):",
                         "plan['free_after_clone_bytes'] < 34*GIB):")
    monitor=replace_once(monitor,"if phase in ('pre-start','pre-frontend') and row['free_bytes'] < 35*GIB:",
                         "if phase in ('pre-start','pre-frontend') and row['free_bytes'] < 34*GIB:")
    return prep,monitor


def transformed_tools(root, source_files, version=1):
    if version not in (1,2,3):raise ValueError('Unreviewed packet version')
    tools = {}
    for name, digest in PINS.items():
        data = (root/'tools'/name).read_bytes()
        if sha(data) != digest:
            raise ValueError('Frozen build tool changed: ' + name)
        tools[name] = data
    prep = tools['prepare_tcl_ime_picker_build.py'].decode('utf-8')
    a = prep.index('POLICY=')
    b = prep.index('\nGIB=', a)
    prep = prep[:a]+'POLICY='+repr({name: sha(data) for name,data in source_files.items()})+prep[b:]
    checks=RETAINED51_CHECK+(RETAINED07_CHECK if version==3 else '')
    prep = replace_once(prep, 'def prepare(root,overlay,stage):', checks+'\ndef prepare(root,overlay,stage):')
    accepted='    accepted_pins=accepted49(root)\n    accepted_pins.update(retained51(root))'
    if version==3:accepted+='\n    accepted_pins.update(retained07(root))'
    prep = replace_once(prep, '    accepted_pins=accepted49(root)', accepted)
    prep = replace_once(prep, '    pins.update(accepted_pins)', '''    pins.update(accepted_pins)
    pins['aosp/frameworks/base/core/java/android/widget/KeypadImeModeState.java'] = '00cf41fe1e0d8452d7d829db2bd1cee5ba40938830e36f8f5fd394109335d5a1' ''')
    prep = replace_once(prep, "changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java'}", "changed!={'TctDialog.java','MenuBar.java','KeypadImeController.java','KeypadImeModeState.java'}")
    baseline=FRAMEWORK07 if version==3 else FRAMEWORK51
    prep = replace_once(prep, 'dialog_overlay_version=5,accepted_framework_baseline=ACCEPTED49',
                        "dialog_overlay_version=6,accepted_framework_baseline='"+baseline+"',native_audit_baseline_ui_accepted=False")
    prep = replace_once(prep, 'Prepare isolated accepted49 picker over preserved48 compile cache.',
                        'Prepare isolated51 picker correction over preserved48 compile cache.')
    monitor = tools['monitor_tcl_dialog_ime_disk.py'].decode('utf-8')
    monitor = replace_once(monitor, "('TctDialogMessage.java','widget'),('KeypadImeController.java','widget')]:",
                           "('TctDialogMessage.java','widget'),('KeypadImeController.java','widget'),('KeypadImeModeState.java','widget')]:")
    if version>=2:prep,monitor=reviewed_budget02(prep,monitor)
    if version==3:prep,monitor=reviewed_budget03(prep,monitor)
    tools['prepare_tcl_ime_picker_build.py'] = prep.encode('utf-8')
    tools['monitor_tcl_dialog_ime_disk.py'] = monitor.encode('utf-8')
    build = tools['build_tcl_ime_picker.sh'].decode('utf-8')
    build = replace_once(build, " 'frameworks/base/core/java/android/widget/KeypadImeController.java']",
                         " 'frameworks/base/core/java/android/widget/KeypadImeController.java',\n 'frameworks/base/core/java/android/widget/KeypadImeModeState.java']")
    marker = " assert any(b'Landroid/widget/KeypadImePicker;' in b for b in dex),'New picker helper missing'"
    build = replace_once(build, marker, marker+"\n assert any(b'pickerModes' in b and b'selectionActions' in b for b in dex),'New policy API missing'")
    build = replace_once(build, 'Accepted49 original keyboard picker only; compile cache48, future image baseline separately reviewed',
                         'Native51 picker correction only; compile cache48, future image baseline separately reviewed')
    tools['build_tcl_ime_picker.sh'] = build.encode('utf-8')
    for name,data in tools.items():
        if name.endswith('.py'):
            ast.parse(data, filename=name, feature_version=(3,10))
    return tools


def packet_files(root, version=1):
    source_files = sources(root,5 if version==3 else 4)
    for name,digest in RETAINED.items():
        data = (root/'framework'/name).read_bytes()
        if sha(data) != digest:
            raise ValueError('Retained49 policy source changed: ' + name)
        source_files[name] = data
    tools = transformed_tools(root, source_files, version)
    files = {'overlay/'+name: data for name,data in source_files.items()}
    files.update({'tools/'+name: data for name,data in tools.items()})
    return files


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version',type=int,choices=(1,2,3),default=1,
                   help='Version3 uses guard05/14+20GiB; version2 keeps04/15+20GiB; version1 keeps04/40GiB threshold')
    a = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = packet_files(root,a.version)
    a.output.mkdir(parents=True, exist_ok=False)
    manifest = dict(scope='Offline packet only. Hardware reservation and actual plan review required; no image baseline selected.',
                    native_audit_baseline=FRAMEWORK07 if a.version==3 else FRAMEWORK51, native_audit_baseline_ui_accepted=False,
                    compile_cache_image=48, readonly_source_bind_count=5, total_container_bind_count=12,
                    files={name:sha(data) for name,data in sorted(files.items())},
                    frozen_tool_templates=PINS, launched=False, installed=False)
    if a.version==2:
        manifest.update(packet_version=2,reviewed_disk_budget=dict(incremental_budget_bytes=15*1024**3,
            emergency_floor_bytes=20*1024**3,initial_threshold_bytes=35*1024**3,
            prior_same_833_command_build_observed_decline_bytes=2068504576,
            observation_is_not_a_guarantee=True,hardware_review_before_host_preparation_required=True))
    if a.version==3:
        manifest.update(packet_version=3,correction_version=5,reviewed_disk_budget=dict(
            incremental_budget_bytes=14*1024**3,emergency_floor_bytes=20*1024**3,
            initial_threshold_bytes=34*1024**3,
            justification='Parent reviewed fresh37,797,113,856B free and prior227,966,976B preparation cost; comparable07 compiler decline about2.06GB plus exports.14GiB is over6times observation, not a guarantee.',
            observation_is_not_a_guarantee=True,hardware_review_before_host_preparation_required=True))
    files['packet.json'] = (json.dumps(manifest,indent=2)+'\n').encode('utf-8')
    for name,data in files.items():
        target=a.output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    archive = Path(str(a.output)+'.tar.gz')
    with archive.open('xb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', filename='', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for name,data in sorted(files.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o644
                    tar.addfile(info,io.BytesIO(data))
    print(json.dumps(dict(packet=str(a.output),archive=str(archive),sha256=sha(archive.read_bytes()),bytes=archive.stat().st_size,launched=False)))


if __name__ == '__main__':
    main()
