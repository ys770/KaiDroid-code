"""Run an unchanged donor dialog fixture on the exact image54 framework.

Requires an explicit current boot ID. No reboot, settings changes or flashing.
On an ambiguous instrumentation timeout, retain the fixture for investigation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PKG = 'org.kaidroid.dialogprobe'
FRAMEWORK = 'a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
SYSTEMUI = 'aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
FIXTURES = {
    'adapter': ('work/tcl-dialog-adapter-original02/dialog-probe.apk',
                '03d0979ba1eb9b7c851e7cd31ed4a90c3dbeac213141e9358b49167dcda2cde8', 8),
    'adapter-composite': ('work/tcl-dialog-composite-original01/dialog-probe.apk',
                '901f6750711cc141856d85b96a20f59bc698a95a79e21b713c918610d71b8711', 4),
    'static': ('work/tcl-dialog-original-probe01/dialog-probe.apk',
               '9323849b37301e3651f5a86ef7151f6f4eafb51df0d6c501ab138ded9b474145', 3),
    'dynamic': ('work/tcl-dialog-dynamic-original02/dialog-probe.apk',
                '543d74c09383de2009bcb5bb4a2ca3abb8ef6c46fc3c4baf5c178449a36bdcfd', 4),
    'variants': ('work/tcl-dialog-variants-original01/dialog-probe.apk',
                 'bc94fd3c9e3adf196cd9cb5df57669353c2191d9f108b5ba56dbe4ebdeba439f', 9),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def nodes(tree):
    yield tree
    for child in tree.get('children', []):
        yield from nodes(child)


def require_launcher(window):
    focus = [line for line in window.splitlines() if 'mCurrentFocus=' in line]
    require(len(focus) == 1 and 'com.android.launcher3/' in focus[0], 'Launcher is not focused')


def require_terminal_success(output):
    failures = [line.partition('failure=')[2] for line in output.splitlines()
                if line.startswith('INSTRUMENTATION_RESULT: failure=')]
    require(not failures, 'Fixture reported failure: ' + '; '.join(failures))
    require('INSTRUMENTATION_RESULT: result=PASS' in output, 'Fixture did not report PASS')
    require('INSTRUMENTATION_CODE: -1' in output, 'Missing successful terminal code')


def validate_result(output, report, suite):
    require('INSTRUMENTATION_RESULT: result=PASS' in output, 'Fixture did not report PASS')
    require('INSTRUMENTATION_CODE: -1' in output, 'Missing successful terminal code')
    require('INSTRUMENTATION_RESULT: failure=' not in output, 'Fixture reported failure')
    require(report.get('mode') == 'boot' and report.get('suite', 'static') == suite
            and report.get('class') == 'android.app.TctDialog', 'Wrong tested class/suite')
    require(not report.get('failure'), 'Report contains failure')
    require(len(report['cases']) == FIXTURES[suite][2], 'Incomplete case set')
    if suite == 'adapter':
        names = ['adapter-initial', 'adapter-up', 'adapter-down', 'adapter-center',
                 'adapter-center-button', 'adapter-empty', 'adapter-populated',
                 'adapter-replaced-after-show']
        require([c.get('case') for c in report['cases']] == names, 'Wrong adapter case order')
        require(report.get('observations') == [dict(adapter_list_callbacks=[0]),
            dict(adapter_center_selected_positions=[2]),
            dict(adapter_notify_applied=True, late_adapter_setter_rebinds=False)],
            'Adapter callbacks/notify/late setter differ from original TCL')
        for case, selected in zip(report['cases'], [0, 2, 0, 0, 2, -1, 0, 0]):
            values = [n['selected_position'] for n in nodes(case['tree']) if 'selected_position' in n]
            require(values == [selected], 'Adapter selection differs: ' + case['case'])
    elif suite == 'adapter-composite':
        names = ['adapter-dual-retain', 'adapter-dual-dismiss', 'array-dual-retain', 'array-dual-dismiss']
        require([c.get('case') for c in report['cases']] == names, 'Wrong composite case order')
        expected = [dict(case=name, events=['button:1', 'row:1'] if retained else ['button:1'],
                         center_callback_count=1, row_callback_count=1 if retained else 0,
                         showing_after_center=retained)
                    for name, retained in zip(names, [True, False, True, False])]
        require(report.get('observations') == expected, 'Composite callback order/count/dismissal differs')
    elif suite == 'variants':
        # This original APK asserts each cancellation internally, then writes
        # PASS/report only after editor Cancel. It has no per-case callback field.
        require([case.get('case') for case in report['cases']] == [
            'checkbox-initial', 'checkbox-focused', 'checkbox-center', 'checkbox-left',
            'list-initial', 'list-up', 'list-down', 'list-center', 'editor'], 'Wrong variants')
        require(report.get('observations') == [dict(checkbox_changes=[False]),
                dict(list_callbacks=[0]), dict(editor_content='123')], 'Variant callbacks/content differ')
        for case, checked in zip(report['cases'][:4], [True, True, True, False]):
            values = [node['checked'] for node in nodes(case['tree']) if 'checked' in node]
            require(values == [checked], 'Checkbox behavior differs: ' + case['case'])
        for case, selected in zip(report['cases'][4:8], [0, 2, 0, 0]):
            values = [node['selected_position'] for node in nodes(case['tree']) if 'selected_position' in node]
            require(values == [selected], 'List behavior differs: ' + case['case'])
        editors = [node for node in nodes(report['cases'][8]['tree']) if 'input_type' in node]
        require(len(editors) == 1 and editors[0].get('input_type') == 524289
                and editors[0].get('text') == '123', 'Editor type/text differs')
    else:
        callbacks = [case['cancel_callback_slot'] for case in report['cases']
                     if 'cancel_callback_slot' in case]
        require(len(callbacks) == (3 if suite == 'static' else 2)
                and all(value == 0 for value in callbacks), 'Cancel callback failed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=FIXTURES, required=True)
    parser.add_argument('--boot-id', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--adb', default='/opt/kaidroid/source/Documents/platform-tools/adb.exe')
    args = parser.parse_args()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', args.boot_id), 'Invalid boot ID')
    apk_name, pin, _ = FIXTURES[args.suite]
    apk = Path(apk_name)
    require(hashlib.sha256(apk.read_bytes()).hexdigest() == pin, 'Original APK hash mismatch')
    args.out.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, '-s', 'DEVICE_SERIAL_REQUIRED']

    def run(name, command, timeout=30):
        try:
            result = subprocess.run(adb + command, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (args.out / (name + '.stdout')).write_bytes(exc.stdout or b'')
            (args.out / (name + '.stderr')).write_bytes(exc.stderr or b'')
            raise
        (args.out / (name + '.stdout')).write_bytes(result.stdout)
        (args.out / (name + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    def shell(name, command):
        return run(name, ['shell', command]).decode().replace('\r\n', '\n').strip()

    def guard(label):
        identity = shell(label, 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id')
        require(identity == 'DEVICE_SERIAL_REQUIRED\n54\n' + args.boot_id, 'Handset/image/boot changed')

    def fixture_hash(label):
        path = shell(label + '-path', 'pm path ' + PKG).removeprefix('package:')
        require(re.fullmatch(r'/data/app/[A-Za-z0-9_./=+~-]+/base.apk', path), 'Unexpected fixture path')
        require(shell(label + '-hash', 'sha256sum ' + path).split()[0] == pin, 'Installed fixture changed')

    guard('identity-before')
    hashes = shell('framework-before', 'sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
    require([line.split()[0] for line in hashes.splitlines()] == [FRAMEWORK, SYSTEMUI], 'Framework/SystemUI mismatch')
    require(not shell('package-before', 'pm list packages ' + PKG), 'Fixture already installed')
    require(PKG not in shell('process-before', 'ps -A'), 'Fixture process already running')
    require_launcher(shell('window-before', 'dumpsys window'))
    ime = shell('ime-before', 'settings get secure default_input_method')
    bluetooth = shell('bluetooth-before', 'settings get global bluetooth_on')
    state = dict(image=54, suite=args.suite, apk_sha256=pin, framework_sha256=FRAMEWORK,
                 boot_id=args.boot_id, passed=False, fixture_removed=False, physical_keys_tested=False)
    installed = False
    ambiguous = False
    try:
        installed = True  # An interrupted install may still have installed the owned APK.
        ambiguous = True
        install = run('install', ['install', '--no-incremental', str(apk)], 60)
        require('Success' in install.decode().splitlines(), 'No definitive install success')
        fixture_hash('installed')
        ambiguous = False
        ambiguous = True
        output = run('instrument', ['shell', 'am', 'instrument', '-w', '-r', '-e', 'mode', 'boot',
                                   '-e', 'suite', args.suite, PKG + '/.DialogInstrumentation'], 150).decode()
        ambiguous = 'INSTRUMENTATION_CODE:' not in output
        require(not ambiguous, 'No terminal instrumentation status; retain fixture for inspection')
        # Recover available screenshots even when the old fixture exits before saving report.json.
        names = shell('fixture-files', 'run-as ' + PKG + ' ls files')
        for name in names.splitlines():
            if re.fullmatch(r'[A-Za-z0-9_-]+\.png', name) or name == 'report.json':
                data = run('capture-' + name, ['exec-out', 'run-as', PKG, 'cat', 'files/' + name])
                (args.out / name).write_bytes(data)
        require_terminal_success(output)
        report = json.loads((args.out / 'report.json').read_text())
        validate_result(output, report, args.suite)
        state['cases'] = len(report['cases'])
        state['passed'] = True
    except Exception as exc:
        state['failure'] = str(exc)
        raise
    finally:
        try:
            if installed and not ambiguous:
                guard('identity-cleanup')
                if shell('package-cleanup', 'pm list packages ' + PKG):
                    fixture_hash('cleanup')
                    run('uninstall', ['uninstall', PKG], 60)
                require(not shell('package-after', 'pm list packages ' + PKG), 'Fixture remains installed')
                require(PKG not in shell('process-after', 'ps -A'), 'Fixture process remains')
                state['fixture_removed'] = True
                shell('home', 'input keyevent 3')
                require(shell('ime-after', 'settings get secure default_input_method') == ime, 'IME changed')
                require(shell('bluetooth-after', 'settings get global bluetooth_on') == bluetooth, 'Bluetooth changed')
                guard('identity-after')
                state['same_boot_ime_bluetooth'] = True
        except Exception as exc:
            state['cleanup_failure'] = str(exc)
            state['passed'] = False
            raise
        finally:
            state['instrumentation_state_ambiguous'] = ambiguous
            (args.out / 'result.json').write_text(json.dumps(state, indent=2) + '\n')
    print(json.dumps(state), flush=True)


if __name__ == '__main__':
    main()
