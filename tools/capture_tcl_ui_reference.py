"""Capture one identity-bound TCL reference state and an optional navigation key.

Screenshots/XML may contain private data. Keep output under ignored artifacts.
No calls, texts, settings writes, installation, or root mutations are performed.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import time
from pathlib import Path

SERIAL = 'DEVICE_SERIAL_REQUIRED'
FINGERPRINT = 'TCL/4058L1/Gflip6_USCC:11/RP1A.200720.011/PJEP:user/release-keys'
NAV_KEYS = {1, 2, 3, 4, 19, 20, 21, 22, 23, 82, 223, 224}
CALCULATOR_KEYS = set(range(7, 19)) | {67}


def capture(adb, output, key=None, component=None, calculator_key=None):
    if calculator_key is not None:
        if key is not None or component is not None or calculator_key not in CALCULATOR_KEYS:
            raise ValueError('Conflicting or unreviewed Calculator input')
        key = calculator_key
    if component and (key is not None or not re.fullmatch(r"[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+", component)):
        raise ValueError("Invalid component or conflicting navigation action")
    output.mkdir(parents=True, exist_ok=False)
    report = dict(serial=SERIAL, fingerprint=FINGERPRINT, key=key,
                  complete=False, physical_input=False, actions=[], component=component)
    def run(label, *args):
        try:
            result = subprocess.run([str(adb), '-s', SERIAL, *args], capture_output=True, timeout=40)
        except subprocess.TimeoutExpired as error:
            (output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (output / (label + '.stderr')).write_bytes(error.stderr or b'')
            raise
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; do not retry without process inspection')
        return result.stdout
    def shell(label, command):
        return run(label, 'shell', command).decode('utf-8').strip()
    try:
        if shell('identity', 'getprop ro.build.fingerprint') != FINGERPRINT:
            raise ValueError('Wrong donor')
        boot = shell('boot-before', 'cat /proc/sys/kernel/random/boot_id')
        report['boot_id'] = boot
        report['selected_ime_before'] = shell('ime-before', 'settings get secure default_input_method')
        shell('activity-before', 'dumpsys activity activities')
        if calculator_key is not None:
            focus = shell('calculator-focus-before', 'dumpsys input')
            if not re.search(r"FocusedWindows:\s*\n\s*displayId=0, name='Window\{[^\n]* com\.android\.calculator2/(?:\.Calculator|com\.android\.calculator2\.Calculator)\}'", focus):
                raise ValueError('Calculator must own focused window before numeric input')
            report['input_scope'] = 'Calculator-only digit/star/pound/delete; focus verified'
        if key is not None:
            if key not in NAV_KEYS and calculator_key is None:
                raise ValueError('Not a reviewed navigation key')
            report['actions'].append(dict(command='input keyevent ' + str(key), attempted=True))
            shell('key', 'input keyevent ' + str(key))
            time.sleep(1)
        if component:
            report['actions'].append(dict(command='am start -W -n ' + component, attempted=True))
            shell('launch', 'am start -W -n ' + component)
            time.sleep(2)
        png = run('screen', 'exec-out', 'screencap', '-p')
        if png[:8] != b'\x89PNG\r\n\x1a\n' or len(png) < 24:
            raise ValueError('Invalid screenshot transport')
        report['dimensions'] = list(struct.unpack('>II', png[16:24]))
        (output / 'screen.png').write_bytes(png)
        report['screenshot_sha256'] = hashlib.sha256(png).hexdigest()
        # Unique file avoids overwriting another capture's hierarchy.
        remote = '/data/local/tmp/tcl-reference-' + output.name + '.xml'
        shell('hierarchy-dump', 'uiautomator dump ' + remote)
        (output / 'hierarchy.xml').write_text(shell('hierarchy', 'cat ' + remote), encoding='utf-8')
        shell('activity-after', 'dumpsys activity activities')
        shell('window', 'dumpsys window')
        shell('power', 'dumpsys power')
        report['selected_ime_after'] = shell('ime-after', 'settings get secure default_input_method')
        report['ime_changed_during_capture'] = report['selected_ime_before'] != report['selected_ime_after']
        if shell('boot-after', 'cat /proc/sys/kernel/random/boot_id') != boot:
            raise ValueError('Donor rebooted during capture')
        report['complete'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (output / 'capture.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--key', type=int, choices=sorted(NAV_KEYS))
    p.add_argument('--calculator-key', type=int, choices=sorted(CALCULATOR_KEYS),
                   help='Numeric Calculator input, rejected unless Calculator owns the focused window')
    p.add_argument('--component', help='Exact resolved launcher component; mutually exclusive with key')
    a = p.parse_args()
    if not a.output.name.replace('-', '').replace('_', '').isalnum():
        raise ValueError('Output name must be a safe capture label')
    print(json.dumps(capture(a.adb, a.output, a.key, a.component, a.calculator_key)))
