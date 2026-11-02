"""Hardware-only trial on installed Contacts/controller candidates; no APK install.

One exact call-log Allow choice, then grant/flag/mode restoration. The enclosing
hardware procedure must not roll back APKs until restoration_verified is true.
"""
import argparse
import hashlib
import json
import shlex
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from compare_runtime_permissions import snapshot, compare
from smoke_contacts_permission_state import smoke, HELPER_SHA

CONTROLLER_SHA = '3da34d2d40ba964502ad680d8e63d2e51f3f90f670692a5cbf32992a8e8b2655'
PREFIX = 'com.android.permissioncontroller:id/'


def check_prompt(xml, focused):
    nodes = list(ET.fromstring(xml).iter('node'))
    def unique(resource):
        matches = [n for n in nodes if n.get('resource-id') == PREFIX + resource]
        if len(matches) != 1:
            raise ValueError('Missing/ambiguous prompt element: ' + resource)
        return matches[0]
    message = unique('permission_message')
    if message.get('text') != 'Allow Contacts to access your phone call logs?':
        raise ValueError('Unexpected permission question')
    for name, text in [('allow', 'ALLOW'), ('deny', 'DENY')]:
        button = unique('permission_' + name + '_button')
        if (button.get('package') != 'com.android.permissioncontroller'
                or button.get('text') != text or button.get('enabled') != 'true'
                or button.get('clickable') != 'true'
                or button.get('focused') != str(name == focused).lower()):
            raise ValueError('Unexpected native button state: ' + name)
    focus_nodes = [n for n in nodes if n.get('focused') == 'true']
    if len(focus_nodes) != 1:
        raise ValueError('Ambiguous focus')
    if not any(n.get('text') == focused.title() and n.get('bounds') == '[80,280][159,320]'
               and n.get('package') == 'com.android.permissioncontroller' for n in nodes):
        raise ValueError('Center soft-key label mismatch')


def trial(shell, screen, remote, boot_id, report, settle=time.sleep):
    report.update(choice_attempted=False, call_log_grant_observed=False,
                  restoration_verified=False, physical_parity_verified=False)
    smoke_result = smoke(shell, remote, boot_id)
    baseline = remote + '/baseline.json'
    command = 'CLASSPATH=' + shlex.quote(remote + '/helper.jar') + ' app_process /system/bin ContactsPermissionState '
    path = shell('controller-path', 'pm path com.android.permissioncontroller')
    if not path.startswith('package:/data/app/') or '\n' in path:
        raise ValueError('Expected single compact controller update')
    if shell('controller-hash', 'sha256sum ' + shlex.quote(path[8:])).split()[0] != CONTROLLER_SHA:
        raise ValueError('Wrong controller candidate')
    before = snapshot(shell('full-package-before', 'dumpsys package com.android.contacts'), 'com.android.contacts', 0)
    for scope, target in [('package', 'com.android.contacts'), ('uid', '10073')]:
        shell('appops-' + scope + '-before', 'cmd appops get ' + target)
    baseline_state = json.loads(shell('read-baseline', 'cat ' + shlex.quote(baseline)))
    if baseline_state['permissions']['READ_CALL_LOG']['granted'] or baseline_state['permissions']['READ_SMS']['granted']:
        raise ValueError('Expected both trial permissions initially denied')
    timed_out = False
    try:
        shell('wake', 'input keyevent 224')
        shell('unlock', 'wm dismiss-keyguard')
        shell('launch', 'am start -W -n com.android.contacts/com.android.contacts.activities.PeopleActivity')
        settle(5)
        def prompt(stage, focus):
            shell(stage + '-dump', 'uiautomator dump ' + remote + '/window.xml')
            xml = shell(stage + '-xml', 'cat ' + remote + '/window.xml')
            screen(stage)
            check_prompt(xml, focus)
        prompt('deny', 'deny')
        shell('focus-allow', 'input keyevent 19')
        prompt('allow', 'allow')
        # This is the only activation in the entire trial, never retried.
        report['choice_attempted'] = True
        shell('activate-allow-once', 'input keyevent 23')
        settle(1)
        shell('stop-after-choice', 'am force-stop com.android.contacts')
        shell('capture-after-choice', command + 'capture ' + shlex.quote(remote + '/after-choice.json'))
        changed = json.loads(shell('read-after-choice', 'cat ' + shlex.quote(remote + '/after-choice.json')))
        shell('full-package-after-choice', 'dumpsys package com.android.contacts')
        for scope, target in [('package', 'com.android.contacts'), ('uid', '10073')]:
            shell('appops-' + scope + '-after-choice', 'cmd appops get ' + target)
        report['call_log_grant_observed'] = changed['permissions']['READ_CALL_LOG']['granted']
        if not report['call_log_grant_observed']:
            raise ValueError('Labelled call-log choice did not grant READ_CALL_LOG')
        for name, state in baseline_state['permissions'].items():
            if name != 'READ_CALL_LOG' and changed['permissions'][name] != state:
                raise ValueError('Unexpected other permission change: ' + name)
    except (TimeoutError, subprocess.TimeoutExpired):
        timed_out = True
        raise
    finally:
        if not timed_out:
            shell('stop-before-restore', 'am force-stop com.android.contacts')
            if shell('baseline-hash-before-restore', 'sha256sum ' + shlex.quote(baseline)).split()[0] != smoke_result['baseline_sha256']:
                raise ValueError('Saved baseline changed; no restoration attempted')
            shell('restore-state', command + 'restore ' + shlex.quote(baseline))
            shell('verify-restored', command + 'verify ' + shlex.quote(baseline))
            settle(2)
            shell('verify-restored-settled', command + 'verify ' + shlex.quote(baseline))
            after = snapshot(shell('full-package-after', 'dumpsys package com.android.contacts'), 'com.android.contacts', 0)
            for scope, target in [('package', 'com.android.contacts'), ('uid', '10073')]:
                shell('appops-' + scope + '-after', 'cmd appops get ' + target)
            if not compare(before, after)['runtime_permissions_equal']:
                raise ValueError('Full runtime permissions differ outside helper scope')
            report['restoration_verified'] = True
        else:
            report['observation_timeout_requires_process_review'] = True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    p.add_argument('--helper', type=Path, required=True)
    p.add_argument('--boot-id', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if str(uuid.UUID(a.boot_id)) != a.boot_id or hashlib.sha256(a.helper.read_bytes()).hexdigest() != HELPER_SHA:
        raise ValueError('Invalid boot/helper')
    a.output.mkdir(parents=True, exist_ok=False)
    remote = '/data/local/tmp/contacts-one-choice-' + uuid.uuid4().hex
    base = [str(a.adb), '-s', 'DEVICE_SERIAL_REQUIRED']
    def run(label, args):
        try:
            r = subprocess.run(base + args, capture_output=True, timeout=45)
        except subprocess.TimeoutExpired as error:
            (a.output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (a.output / (label + '.stderr')).write_bytes(error.stderr or b'')
            raise
        (a.output / (label + '.stdout')).write_bytes(r.stdout)
        (a.output / (label + '.stderr')).write_bytes(r.stderr)
        if r.returncode:
            raise RuntimeError(label + ' failed')
        return r.stdout
    def shell(label, command):
        return run(label, ['shell', command]).decode('utf-8').strip()
    report = dict(remote=remote, restoration_verified=False)
    try:
        for label, command, expected in [('image', 'getprop ro.kaidroid.image', '31'),
                                        ('boot', 'cat /proc/sys/kernel/random/boot_id', a.boot_id),
                                        ('root', 'id -u', '0')]:
            if shell('preflight-' + label, command) != expected:
                raise ValueError('Preflight identity mismatch')
        shell('mkdir', 'mkdir -m 700 ' + remote)
        run('push', ['push', str(a.helper), remote + '/helper.jar'])
        trial(shell, lambda stage: run(stage + '-screen', ['exec-out', 'screencap -p']), remote, a.boot_id, report)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
