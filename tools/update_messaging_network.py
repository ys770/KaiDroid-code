"""Guarded retained-data Messaging update after independent audit; no launch/reboot/send."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

BASE = '6486b20af5b777500590981f3aa32914ed72a91e97e41f8994a2ef857f68ba2e'
CERT = 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_artifacts(apk, audit, audit_pin, receipt):
    if sha(audit) != audit_pin:
        raise ValueError('Parent audit receipt changed')
    review = json.loads(audit.read_text())
    signed = json.loads(receipt.read_text())
    required = ('passed', 'secondary_dex_exact_reference_compile',
                'manifest_resources_other_archive_bytes_identical')
    if not all(review.get(key) is True for key in required) or review.get('baseline_sha256') != BASE:
        raise ValueError('Independent audit did not pass for installed baseline')
    if signed.get('source_sha256') != review.get('candidate_sha256'):
        raise ValueError('Signing receipt refers to another candidate')
    if (signed.get('package'), signed.get('version'), signed.get('certificate')) != ('com.android.mms', '2403041', CERT):
        raise ValueError('Wrong package/version/certificate receipt')
    if not signed.get('payload_preserved') or not signed.get('aligned') or sha(apk) != signed.get('sha256'):
        raise ValueError('Signed APK identity or payload receipt differs')
    return signed['sha256']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'audit', 'signing-report', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--audit-sha256', required=True)
    p.add_argument('--boot', type=uuid.UUID, required=True)
    p.add_argument('--image', choices=('55', '56'), required=True)
    p.add_argument('--apply', action='store_true')
    a = p.parse_args()
    target = validate_artifacts(a.apk, a.audit, a.audit_sha256, a.signing_report)
    a.output.mkdir(parents=True, exist_ok=False)
    adb = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(image=a.image, boot=str(a.boot), applied=False, target_sha256=target,
                  data_cleared=False, messages_requested=False, reboot_requested=False)

    def run(label, command, timeout=40):
        result = subprocess.run(command, capture_output=True, timeout=timeout)
        (a.output / (label + '.stdout')).write_bytes(result.stdout)
        (a.output / (label + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    def read(label, command):
        return run(label, adb + ['shell', command]).decode().replace('\r', '').strip()

    def guard(label):
        text = read(label, 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce')
        if text.splitlines() != ['DEVICE_SERIAL_REQUIRED', a.image, str(a.boot), '0', 'Enforcing']:
            raise ValueError('Wrong handset/image/boot/security state')

    def state(label, expected):
        package = read(label + '-package', 'dumpsys package com.android.mms')
        if 'userId=10100' not in package or 'versionCode=2403041' not in package:
            raise ValueError('Wrong Messaging UID/version')
        roles = read(label + '-roles', 'dumpsys role')
        if not re.search(r'name=android.app.role.SMS\s+holders=com.android.mms\s', roles):
            raise ValueError('Messaging SMS role changed')
        path = read(label + '-path', 'pm path com.android.mms')
        if not re.fullmatch(r'package:/data/app/[A-Za-z0-9_./=+~-]+/base.apk', path):
            raise ValueError('Unexpected APK path')
        if read(label + '-hash', 'sha256sum ' + path[8:]).split()[0] != expected:
            raise ValueError('Installed APK changed')
        files = read(label + '-data', 'for d in /data/user/0/com.android.mms /data/user_de/0/com.android.mms; do if test -d "$d"; then find "$d" -type f -exec sha256sum {} \\; ; fi; done')
        return path[8:], dict(uid=10100, sms_role='com.android.mms',
            grants=sorted(re.findall(r'(android\.permission\.[A-Z_]+): granted=(true|false), flags=([^\n]+)', package)),
            data_hashes=sorted(files.splitlines()))

    try:
        guard('before-identity')
        if read('process-before', 'pidof com.android.mms; true'):
            raise ValueError('Messaging running; coordinate idle update instead of force-stopping')
        path, before = state('before', BASE)
        java = 'java'
        signer = '/opt/android-sdk/build-tools/35.0.0/lib/apksigner.jar'
        cert = run('certificate', [java, '-jar', signer, 'verify', '--print-certs', str(a.apk)]).decode()
        if re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', cert) != [CERT]:
            raise ValueError('Actual signature differs')
        report['preflight_passed'] = True
        if a.apply:
            # Package replacement can awaken components too; require empty
            # outgoing queues before installation, not only before later tests.
            run('queue-gate', [sys.executable, str(Path(__file__).with_name('check_messaging_queues.py')),
                '--image', a.image, '--boot', str(a.boot), '--apk-sha256', BASE,
                '--output', str(a.output / 'queues-before')])
            run('backup-apk', adb + ['pull', path, str(a.output / 'original.apk')])
            if sha(a.output / 'original.apk') != BASE:
                raise ValueError('Rollback APK hash differs')
            for label, directory in [('ce', '/data/user/0'), ('de', '/data/user_de/0')]:
                run('backup-' + label, adb + ['exec-out', 'tar -C ' + directory + ' -cf - com.android.mms'])
            guard('install-identity')
            if state('preinstall', BASE)[1] != before or read('process-preinstall', 'pidof com.android.mms; true'):
                raise ValueError('App state changed before install')
            result = run('install', adb + ['install', '--no-incremental', '-r', str(a.apk)], 120).decode()
            if 'Success' not in result.splitlines():
                raise ValueError('Install success not established; inspect before retry')
            report['applied'] = True
            guard('after-identity')
            _, after = state('after', target)
            report['state_preserved'] = after == before
            if after != before:
                raise ValueError('App state changed; inspect before launching')
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
