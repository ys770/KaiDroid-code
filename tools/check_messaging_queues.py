"""Read-only, serial-bound outgoing queue gate; never transmits or clears messages."""
import argparse
import hashlib
import json
import re
import subprocess
import uuid
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', choices=('55', '56'), required=True)
    parser.add_argument('--boot', type=uuid.UUID, required=True)
    parser.add_argument('--apk-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.apk_sha256):
        parser.error('Exact reviewed installed APK hash required')
    args.output.mkdir(parents=True, exist_ok=False)
    adb = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(image=args.image, boot=str(args.boot), passed=False, read_only=True,
                  queues_empty=False, data_cleared=False, messages_requested=False)

    def read(label, command):
        result = subprocess.run(adb + ['shell', command], capture_output=True, timeout=30)
        (args.output / (label + '.stdout')).write_bytes(result.stdout)
        (args.output / (label + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        if result.stderr.strip():
            raise ValueError('Query stderr: ' + label)
        return result.stdout.decode().replace('\r', '').strip()

    identity = ('getprop ro.serialno; getprop ro.kaidroid.image; '
                'cat /proc/sys/kernel/random/boot_id; id -u; getenforce; '
                'getprop sys.boot_completed; pidof system_server; pidof com.android.systemui')
    try:
        before = read('identity-before', identity).splitlines()
        if len(before) != 8 or before[:6] != ['DEVICE_SERIAL_REQUIRED', args.image, str(args.boot), '0', 'Enforcing', '1']:
            raise ValueError('Wrong handset/build/boot/security state')
        if not all(re.fullmatch('[1-9][0-9]*', value) for value in before[6:]):
            raise ValueError('Missing system processes')
        path = read('apk-path', 'pm path com.android.mms')
        if not re.fullmatch(r'package:/data/app/[A-Za-z0-9_./=+~-]+/base.apk', path):
            raise ValueError('Unexpected package path')
        if read('apk-hash', 'sha256sum ' + path[8:]).split()[0] != args.apk_sha256:
            raise ValueError('Installed APK differs')
        package = read('package', 'dumpsys package com.android.mms')
        if 'userId=10100' not in package or 'versionCode=2403041' not in package:
            raise ValueError('Messaging UID/version differs')
        roles = read('roles', 'dumpsys role')
        if not re.search(r'name=android.app.role.SMS\s+holders=com.android.mms\s', roles):
            raise ValueError('SMS role differs')
        # Only IDs are requested, never addresses, text or attachments. Include
        # failed/queued SMS conservatively because recovery may retry them.
        queries = {
            'sms-outgoing': "content query --uri content://sms --projection _id --where 'type IN (4,5,6)'",
            'mms-outgoing': "content query --uri content://mms --projection _id --where 'msg_box=4'",
            'pending': 'content query --uri content://mms-sms/pending --projection _id',
        }
        outcomes = {label: read(label, command) for label, command in queries.items()}
        if any(value != 'No result found.' for value in outcomes.values()):
            raise ValueError('Outgoing queue not proven empty; inspect private captures, never clear it')
        if read('identity-after', identity).splitlines() != before:
            raise ValueError('Boot/process identity changed')
        report.update(passed=True, queues_empty=True, apk_sha256=args.apk_sha256,
                      queue_counts={label: 0 for label in queries},
                      limits=['Point-in-time provider observation; recheck immediately before a connectivity trigger.'])
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        report['capture_hashes'] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                                   for f in args.output.iterdir() if f.is_file()}
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
