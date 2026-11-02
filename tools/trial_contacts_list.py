"""Hardware-only trial on installed Contacts/controller candidates; no APK install.

Two exact call-log/SMS Allow choices, then PeopleActivity observation and restoration. The enclosing
hardware procedure must not roll back APKs until restoration_verified is true.
"""
import argparse
import hashlib
import json
import re
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


def check_prompt(xml, focused, question="Allow Contacts to access your phone call logs?"):
    nodes = list(ET.fromstring(xml).iter('node'))
    def unique(resource):
        matches = [n for n in nodes if n.get('resource-id') == PREFIX + resource]
        if len(matches) != 1:
            raise ValueError('Missing/ambiguous prompt element: ' + resource)
        return matches[0]
    message = unique('permission_message')
    if message.get('text') != question:
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
    if not any(n.get('text') == focused.title() and n.get('bounds') == '[80,290][159,320]'
               and n.get('package') == 'com.android.permissioncontroller' for n in nodes):
        raise ValueError('Center soft-key label mismatch')


def quiesce_permission_ui(shell, settle):
    """Stop both writers before restoration; never retry a failed cleanup."""
    shell('stop-before-restore', 'am force-stop --user 0 com.android.contacts')
    path = shell('cleanup-controller-path', 'pm path com.android.permissioncontroller')
    if not path.startswith('package:/data/app/') or '\n' in path:
        raise ValueError('Controller identity changed before cleanup')
    if shell('cleanup-controller-hash', 'sha256sum ' + shlex.quote(path[8:])).split()[0] != CONTROLLER_SHA:
        raise ValueError('Controller hash changed before cleanup')
    shell('stop-controller-before-restore', 'am force-stop --user 0 com.android.permissioncontroller')
    settle(2)
    activity = shell('cleanup-activities', 'dumpsys activity activities')
    if 'ACTIVITY MANAGER ACTIVITIES' not in activity:
        raise ValueError('Missing activity inventory; no restoration attempted')
    if 'GrantPermissionsActivity' in activity:
        raise ValueError('Permission dialog remains; no restoration attempted')


def trial(shell, screen, remote, boot_id, report, settle=time.sleep, settings_navigation=False, sort_cancel=False):
    report.update(choices_attempted=0, granted_permissions=[], people_activity_observed=False,
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
        def prompt(stage, focus, question):
            shell(stage + '-dump', 'uiautomator dump ' + remote + '/window.xml')
            xml = shell(stage + '-xml', 'cat ' + remote + '/window.xml')
            screen(stage)
            check_prompt(xml, focus, question)
        intended = set()
        for permission, question in [
                ('READ_CALL_LOG', 'Allow Contacts to access your phone call logs?'),
                ('READ_SMS', 'Allow Contacts to send and view SMS messages?')]:
            stage = permission.lower()
            prompt(stage + '-deny', 'deny', question)
            shell(stage + '-focus-allow', 'input keyevent 19')
            prompt(stage + '-allow', 'allow', question)
            report['choices_attempted'] += 1
            shell(stage + '-activate-once', 'input keyevent 23')
            settle(3)
            state_path = remote + '/' + stage + '.json'
            shell(stage + '-capture', command + 'capture ' + shlex.quote(state_path))
            changed = json.loads(shell(stage + '-state', 'cat ' + shlex.quote(state_path)))
            intended.add(permission)
            for name, state in baseline_state['permissions'].items():
                if name in intended:
                    if not changed['permissions'][name]['granted']:
                        raise ValueError('Expected normal UI grant missing: ' + name)
                elif changed['permissions'][name] != state:
                    raise ValueError('Unexpected other permission change: ' + name)
            report['granted_permissions'].append(permission)
            shell(stage + '-package', 'dumpsys package com.android.contacts')
            for scope, target in [('package', 'com.android.contacts'), ('uid', '10073')]:
                shell(stage + '-appops-' + scope, 'cmd appops get ' + target)
        settle(3)
        activity = shell('people-activity', 'dumpsys activity activities')
        if not re.search(r'mResumedActivity:.*com\.android\.contacts/(?:com\.android\.contacts)?\.activities\.PeopleActivity(?:\s|})', activity):
            raise ValueError('PeopleActivity is not resumed after both choices')
        shell('people-dump', 'uiautomator dump ' + remote + '/people.xml')
        hierarchy = shell('people-xml', 'cat ' + remote + '/people.xml')
        screen('people')
        nodes = list(ET.fromstring(hierarchy).iter('node'))
        if not any(n.get('package') == 'com.android.contacts' for n in nodes):
            raise ValueError('Contacts UI not present')
        if any(n.get('resource-id') == PREFIX + 'permission_message' for n in nodes):
            raise ValueError('Unexpected additional permission prompt')
        report['people_activity_observed'] = True
        report['list_layout_requires_saved_screenshot_review'] = True
        if settings_navigation:
            from contacts_settings_navigation import navigate
            navigate(shell, screen, remote, report, settle, sort_cancel=sort_cancel)
        shell('people-logs', 'logcat -d -b all -v threadtime -t 1500')
    except (TimeoutError, subprocess.TimeoutExpired):
        timed_out = True
        raise
    finally:
        if not timed_out:
            quiesce_permission_ui(shell, settle)
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
    p.add_argument('--settings-navigation', action='store_true')
    p.add_argument('--sort-dialog-cancel', action='store_true')
    a = p.parse_args()
    if str(uuid.UUID(a.boot_id)) != a.boot_id or hashlib.sha256(a.helper.read_bytes()).hexdigest() != HELPER_SHA:
        raise ValueError('Invalid boot/helper')
    a.output.mkdir(parents=True, exist_ok=False)
    remote = '/data/local/tmp/contacts-list-' + uuid.uuid4().hex
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
        for label, command, expected in [('image', 'getprop ro.kaidroid.image', '36'),
                                        ('boot', 'cat /proc/sys/kernel/random/boot_id', a.boot_id),
                                        ('root', 'id -u', '0')]:
            if shell('preflight-' + label, command) != expected:
                raise ValueError('Preflight identity mismatch')
        shell('mkdir', 'mkdir -m 700 ' + remote)
        run('push', ['push', str(a.helper), remote + '/helper.jar'])
        trial(shell, lambda stage: run(stage + '-screen', ['exec-out', 'screencap -p']), remote, a.boot_id, report,
              settings_navigation=a.settings_navigation or a.sort_dialog_cancel,
              sort_cancel=a.sort_dialog_cancel)
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
