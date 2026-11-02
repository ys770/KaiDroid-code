"""Retained-data update/rollback of the reviewed Messaging boot adapter on image43.

No reboot, manual boot broadcast, message send, role mutation or data clearing.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

BASE = 'bd7d17b7ce6536a9eb0eb041c5cdaa0fa29011cc28f8539e048267e4a0284dea'
NEW = 'd6bbbdcd1097c96316a04f4b681256c7e340188979a4e0b3279facbb0e2bf699'
CERT = 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('install', 'rollback'), required=True)
    p.add_argument('--boot-id', type=uuid.UUID, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--apply', action='store_true')
    a = p.parse_args()
    source, target = (BASE, NEW) if a.mode == 'install' else (NEW, BASE)
    apk = Path('work/messaging-boot-recovery-signed02/signed.apk' if a.mode == 'install'
               else 'work/messaging-key-counter-signed01/signed.apk')
    assert hashlib.sha256(apk.read_bytes()).hexdigest() == target
    a.output.mkdir(parents=True, exist_ok=False)
    adb = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(mode=a.mode, boot_id=str(a.boot_id), applied=False, data_cleared=False)
    def run(name, command):
        (a.output / (name + '.started.json')).write_text(json.dumps(command))
        r = subprocess.run(command, capture_output=True, timeout=120)
        (a.output / (name + '.stdout')).write_bytes(r.stdout)
        (a.output / (name + '.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout.decode().replace('\r', '').strip()
    def sh(name, command):
        return run(name, adb + ['shell', command])
    def guard(name):
        assert sh(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce').splitlines() == ['43', str(a.boot_id), '0', 'Enforcing']
    def inspect(name, expected):
        pkg = sh(name + '-package', 'dumpsys package com.android.mms')
        assert 'userId=10100' in pkg and 'versionCode=2403041' in pkg
        assert 'stopped=false' in pkg
        path = sh(name + '-path', 'pm path com.android.mms')
        assert path.startswith('package:/data/app/') and '\n' not in path
        assert sh(name + '-hash', 'sha256sum ' + path[8:]).split()[0] == expected
        roles = sh(name + '-roles', 'dumpsys role')
        assert re.search(r'name=android.app.role.SMS\s+holders=com.android.mms\s', roles)
        return sorted(re.findall(r'android.permission.[A-Z_]+: granted=(?:true|false)', pkg))
    try:
        guard('identity')
        permissions = inspect('before', source)
        signer = ['java', '-jar',
                  '/opt/android-sdk/build-tools/35.0.0/lib/apksigner.jar']
        cert = run('certificate', signer + ['verify', '--print-certs', str(apk)])
        assert re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', cert) == [CERT]
        report['preflight_passed'] = True
        if a.apply:
            guard('install-guard')
            assert 'Success' in run('install', adb + ['install', '--no-incremental', '-r', str(apk)])
            assert inspect('after', target) == permissions
            report.update(applied=True, target_sha256=target, uid_role_permissions_preserved=True)
    except Exception as error:
        report['error'] = repr(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
