"""Hardware-owned image36 no-grant helper smoke test, after candidate install.

Does not install/launch apps, grant permissions, send keys, or restore APKs.
The hardware owner installs and restores Contacts in its enclosing procedure.
"""
import argparse
import hashlib
import json
import re
import shlex
import subprocess
import uuid
from pathlib import Path

HELPER_SHA = 'd530faeb678a60191320fcf468e8f8a4f5c14a2d194c0938ecfecb26a730fd52'
CANDIDATE_SHA = '20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248'


def smoke(shell, remote, boot_id):
    def guard(label):
        expected = [('image', 'getprop ro.kaidroid.image', '36'),
                    ('boot', 'cat /proc/sys/kernel/random/boot_id', boot_id),
                    ('root', 'id -u', '0'), ('debug', 'getprop ro.debuggable', '1'),
                    ('selinux', 'getenforce', 'Enforcing')]
        for key, command, value in expected:
            if shell(label + '-' + key, command).strip() != value:
                raise ValueError('Identity mismatch: ' + key)
        density = shell(label + '-density', 'wm density')
        values = re.findall(r'(?:Physical|Override) density: (\d+)', density)
        if not values or values[-1] != '160':
            raise ValueError('Expected effective density160')


    guard('before')
    jar = remote + '/helper.jar'
    baseline = remote + '/baseline.json'
    if shell('helper-hash', 'sha256sum ' + shlex.quote(jar)).split()[0] != HELPER_SHA:
        raise ValueError('Helper hash mismatch')
    path = shell('candidate-path', 'pm path com.android.contacts').strip()
    if not re.fullmatch(r'package:/data/app/[^\r\n]+\.apk', path):
        raise ValueError('Expected one candidate update APK')
    if shell('candidate-hash', 'sha256sum ' + shlex.quote(path[8:])).split()[0] != CANDIDATE_SHA:
        raise ValueError('Candidate hash mismatch')
    command = 'CLASSPATH=' + shlex.quote(jar) + ' app_process /system/bin ContactsPermissionState '
    shell('capture', command + 'capture ' + shlex.quote(baseline))
    saved = shell('baseline', 'cat ' + shlex.quote(baseline))
    state = json.loads(saved)
    if state['boot'] != boot_id or state['image'] != '36' or state['uid'] != 10073:
        raise ValueError('Captured identity mismatch')
    baseline_hash = shell('baseline-hash', 'sha256sum ' + shlex.quote(baseline)).split()[0]
    if not re.fullmatch('[0-9a-f]{64}', baseline_hash):
        raise ValueError('Malformed baseline hash')
    # Read-only verification must pass before the restore entrypoint is tested.
    # Any changed grant/flag/mode means this is no longer a no-op smoke test.
    shell('verify-before', command + 'verify ' + shlex.quote(baseline))
    guard('before-noop')
    if shell('baseline-hash-again', 'sha256sum ' + shlex.quote(baseline)).split()[0] != baseline_hash:
        raise ValueError('Baseline changed')
    shell('restore-noop', command + 'restore-noop ' + shlex.quote(baseline))
    shell('verify-after', command + 'verify ' + shlex.quote(baseline))
    guard('after')
    return dict(no_grant_smoke_passed=True, baseline_sha256=baseline_hash,
                actual_grant_restoration_verified=False, apk_rollback_verified=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    p.add_argument('--helper', type=Path, required=True)
    p.add_argument('--boot-id', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if str(uuid.UUID(a.boot_id)) != a.boot_id:
        raise ValueError('Invalid boot ID')
    if hashlib.sha256(a.helper.read_bytes()).hexdigest() != HELPER_SHA:
        raise ValueError('Wrong local helper')
    a.output.mkdir(parents=True, exist_ok=False)
    remote = '/data/local/tmp/contacts-permission-smoke-' + uuid.uuid4().hex
    base = [str(a.adb), '-s', 'DEVICE_SERIAL_REQUIRED']

    def run(label, args):
        try:
            result = subprocess.run(base + args, capture_output=True, timeout=45)
        except subprocess.TimeoutExpired as error:
            (a.output / (label + '.stdout')).write_bytes(error.stdout or b'')
            (a.output / (label + '.stderr')).write_bytes(error.stderr or b'')
            raise RuntimeError('Observation timeout: do not rerun; inspect active device process') from error
        (a.output / (label + '.stdout')).write_bytes(result.stdout)
        (a.output / (label + '.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError(label + ' failed; retain evidence for hardware review')
        return result.stdout.decode('utf-8').strip()

    def shell(label, command):
        return run(label, ['shell', command])

    report = dict(no_grant_smoke_passed=False, remote=remote)
    try:
        # Check binding before even creating the isolated helper directory.
        if shell('preflight-image', 'getprop ro.kaidroid.image') != '36' or shell(
                'preflight-boot', 'cat /proc/sys/kernel/random/boot_id') != a.boot_id:
            raise ValueError('Wrong image/boot')
        if shell('preflight-root', 'id -u') != '0':
            raise ValueError('Root required')
        shell('mkdir', 'mkdir -m 700 ' + remote)
        run('push', ['push', str(a.helper), remote + '/helper.jar'])
        report.update(smoke(shell, remote, a.boot_id))
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
