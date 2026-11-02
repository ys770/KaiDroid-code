"""Bounded PeopleActivity launch with same-handset APK rollback; no contact actions."""
import argparse
import hashlib
import json
import re
import subprocess
import struct
import sys
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', choices=('29', '31'), default='29')
p.add_argument('--permission-state-helper', type=Path, help='No-launch/no-grant smoke only')
p.add_argument('--permission-navigation', action='store_true',
               help='Check Up/Down permission focus without activating any choice')
for key in ('adb', 'boot_id', 'candidate_sha256'):
    p.add_argument('--' + key.replace('_', '-'), required=True)
for key in ('candidate', 'original', 'output'):
    p.add_argument('--' + key, required=True, type=Path)
a = p.parse_args()
if a.permission_state_helper:
    assert a.image == '31' and not a.permission_navigation
    from smoke_contacts_permission_state import HELPER_SHA
    assert hashlib.sha256(a.permission_state_helper.read_bytes()).hexdigest() == HELPER_SHA
assert hashlib.sha256(a.candidate.read_bytes()).hexdigest() == a.candidate_sha256
assert hashlib.sha256(a.original.read_bytes()).hexdigest() == '7cc2c14fe371adf7c98900ffda85fbfc274b8cb8da7e33fc4d0bf79d8a746e0d'
with zipfile.ZipFile(a.candidate) as archive, a.candidate.open('rb') as stream:
    resource = archive.getinfo('resources.arsc')
    stream.seek(resource.header_offset)
    header = stream.read(30)
    name_size, extra_size = struct.unpack_from('<HH', header, 26)
    assert resource.compress_type == zipfile.ZIP_STORED
    assert (resource.header_offset + 30 + name_size + extra_size) % 4 == 0
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED']


def run(name, args, timeout=30):
    r = subprocess.run(base + args, capture_output=True, timeout=timeout)
    (a.output / (name + '.stdout')).write_bytes(r.stdout)
    (a.output / (name + '.stderr')).write_bytes(r.stderr)
    if r.returncode:
        raise RuntimeError(name + ' failed; inspect saved output')
    return r.stdout


def shell(name, command):
    # shell protocol propagates the remote exit status; exec-out on this
    # transport does not. Keep exec-out only for binary screencap output.
    return run(name, ['shell', command]).decode(errors='replace').strip()


def guard(label):
    assert shell(label + '-boot', 'cat /proc/sys/kernel/random/boot_id') == a.boot_id
    assert shell(label + '-image', 'getprop ro.kaidroid.image') == a.image
    assert shell(label + '-debug', 'getprop ro.debuggable') == '1'
    assert shell(label + '-root', 'id -u') == '0'


guard('before')
before = shell('package-before', 'dumpsys package com.android.contacts')
assert re.search(r'userId=10073\b', before)
assert re.search(r'versionCode=10731\b', before)
result = dict(installed=False, rollback_verified=False, physical_parity_verified=False)
try:
    installed = run('install', ['install', '-r', str(a.candidate)], timeout=120)
    assert b'Success' in installed
    result['installed'] = True
    after = shell('package-candidate', 'dumpsys package com.android.contacts')
    assert re.search(r'userId=10073\b', after)
    assert re.search(r'versionCode=122209261\b', after)
    path = shell('candidate-path', 'pm path com.android.contacts')
    assert path.count('package:') == 1
    remote = path.removeprefix('package:')
    assert remote.startswith('/data/app/') and remote.endswith('.apk')
    assert shell('candidate-hash', 'sha256sum ' + remote).split()[0] == a.candidate_sha256
    if a.permission_state_helper:
        q = subprocess.run([sys.executable, str(Path(__file__).with_name('smoke_contacts_permission_state.py')),
            '--adb', a.adb, '--helper', str(a.permission_state_helper), '--boot-id', a.boot_id,
            '--output', str(a.output/'permission-smoke')], capture_output=True)
        (a.output/'permission-smoke.stdout').write_bytes(q.stdout)
        (a.output/'permission-smoke.stderr').write_bytes(q.stderr)
        q.check_returncode()
        result['permission_state_no_grant_smoke'] = True
    else:
        shell('wake', 'input keyevent 224; wm dismiss-keyguard')
        shell('launch', 'am start -W -n com.android.contacts/com.android.contacts.activities.PeopleActivity')
        time.sleep(8)
        shell('activity', 'dumpsys activity activities')
        shell('process', 'pidof com.android.contacts || true')
        shell('logs', 'logcat -d -b all -v threadtime -t 1500')
        run('screenshot', ['exec-out', 'screencap -p'])
        shell('ui-dump', 'uiautomator dump /data/local/tmp/kaidroid-contacts-window.xml')
        shell('ui-xml', 'cat /data/local/tmp/kaidroid-contacts-window.xml')
        if a.permission_navigation:
            for label, key, expected in [('initial', None, 'DENY'), ('up', 19, 'ALLOW'), ('down', 20, 'DENY')]:
                if key is not None:
                    shell('key-' + label, 'input keyevent ' + str(key))
                shell('dump-' + label, 'uiautomator dump /data/local/tmp/kaidroid-contacts-window.xml')
                xml = shell('xml-' + label, 'cat /data/local/tmp/kaidroid-contacts-window.xml')
                nodes = list(ET.fromstring(xml).iter('node'))
                assert any(n.get('text') == expected and n.get('focused') == 'true' for n in nodes), label
                assert any(n.get('text') == expected.title() for n in nodes), label
                run('screen-' + label, ['exec-out', 'screencap -p'])
            result['permission_navigation_verified'] = True
finally:
    if result['installed']:
        guard('rollback')
        shell('stop', 'am force-stop com.android.contacts')
        restored = run('restore', ['install', '-r', '-d', str(a.original)], timeout=120)
        assert b'Success' in restored
        state = shell('package-restored', 'dumpsys package com.android.contacts')
        assert re.search(r'userId=10073\b', state)
        assert re.search(r'versionCode=10731\b', state)
        restored_path = shell('restored-path', 'pm path com.android.contacts')
        assert restored_path.count('package:') == 1
        restored_path = restored_path.removeprefix('package:')
        assert restored_path.startswith(('/data/app/', '/system/')) and restored_path.endswith('.apk')
        assert shell('restored-hash', 'sha256sum ' + restored_path).split()[0] == hashlib.sha256(a.original.read_bytes()).hexdigest()
        result['rollback_verified'] = True
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
