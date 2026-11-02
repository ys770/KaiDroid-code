"""Hardware-owned Messaging38 trial. Default read-only; never sends or accepts roles."""
import argparse
import json
import re
import subprocess
import uuid
from pathlib import Path
from deliver_stock_apps36 import digest, installed_paths, metadata
from trial_clock_parallel38 import packages, uid, FRAMEWORK_SHA
from verify_tcl_app_build import PLATFORM_CERT

PACKAGE = 'com.android.mms'
ORIGINAL = 'com.android.messaging'
TELEPHONY = 'com.android.providers.telephony'
CANDIDATE_SHA = '210871a165dd08acafa3db9228ae840976e4e7496bb7997b49f1588e0ad241b9'
ORIGINAL_SHA = '6b7c873195b602d3f8394119926d393ea3df3a93a0e8fc2368e42e2f80394940'
ORIGINAL_PATH = '/system/product/app/messaging/messaging.apk'
AUTHORITIES = {'com.android.mms.MessageTemplateProvider', 'com.android.mms.SuggestionsProvider',
               'com.android.mms.provider', 'com.kaidroid.messages.datamodel.MediaScratchFileProvider', 'mms_temp_file'}


def sms_holder(text):
    if re.findall(r'^\s*user_id=(\d+)\s*$', text, re.M) != ['0']:
        raise ValueError('Expected exactly user0 role state')
    blocks = re.findall(r'\{([^{}]*)\}', text, re.S)
    sms = [b for b in blocks if re.search(r'^\s*name=android\.app\.role\.SMS\s*$', b, re.M)]
    if len(sms) != 1:
        raise ValueError('Missing or ambiguous SMS role')
    holders = re.findall(r'^\s*holders=([^\r\n]+)', sms[0], re.M)
    if holders != [ORIGINAL]:
        raise ValueError('SMS role does not belong exclusively to original app')
    return holders[0]


def provider_owners(text):
    rows = re.findall(r'^\s*\[([^\]\r\n]+)\]:\s*\r?\n\s*Provider\{[^\s}]+ ([^/\s}]+)/[^}]+\}', text, re.M)
    if not rows or len({key for key, _ in rows}) != len(rows):
        raise ValueError('Missing or duplicate registered provider map')
    return dict(rows)


def fresh(inventory, providers):
    if not {ORIGINAL, TELEPHONY} <= inventory or PACKAGE in inventory:
        raise ValueError('Expected existing SMS apps and absent candidate')
    if AUTHORITIES & provider_owners(providers).keys():
        raise ValueError('Candidate provider authority collision')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for n in ('adb', 'java', 'build-tools', 'output'):
        p.add_argument('--'+n, type=Path, required=True)
    p.add_argument('--boot', required=True)
    p.add_argument('--install', action='store_true')
    p.add_argument('--launch', action='store_true', help='Launch once after successful new install; never interacts with prompts')
    a = p.parse_args()
    if str(uuid.UUID(a.boot)) != a.boot or (a.launch and not a.install):
        raise ValueError('Canonical boot UUID required; launch requires install')
    a.output.mkdir(parents=True, exist_ok=False)
    candidate = Path(__file__).resolve().parents[1]/'work/messaging-authority-candidate01/KaiDroidTclMessaging.apk'
    base = [str(a.adb), '-s', 'DEVICE_SERIAL_REQUIRED']
    report = dict(image=38, boot=a.boot, installed=False, launched=False, runtime_verified=False,
                  sends_invoked=False, role_changes_invoked=False, prompts_accepted=False)

    def run(label, command, timeout=120):
        try:
            r = subprocess.run([str(x) for x in command], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            (a.output/(label+'.stdout')).write_bytes(e.stdout or b'')
            (a.output/(label+'.stderr')).write_bytes(e.stderr or b'')
            report['timed_out_command'] = label
            raise
        (a.output/(label+'.stdout')).write_bytes(r.stdout)
        (a.output/(label+'.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout

    def shell(label, command):
        return run(label, base+['shell', command]).decode('utf-8').strip()

    def guard(label):
        for key, command, expected in [('image', 'getprop ro.kaidroid.image', '38'),
            ('boot', 'cat /proc/sys/kernel/random/boot_id', a.boot), ('root', 'id -u', '0'),
            ('selinux', 'getenforce', 'Enforcing'), ('user', 'am get-current-user', '0')]:
            if shell(label+'-'+key, command) != expected:
                raise ValueError('Guard failed: '+key)
        if shell(label+'-framework', 'sha256sum /system/framework/framework.jar').split()[0] != FRAMEWORK_SHA:
            raise ValueError('Wrong framework')

    def inspect(label, apk, package):
        metadata(run(label+'-badging', [a.build_tools/'aapt.exe', 'dump', 'badging', apk]).decode('utf-8'), package)
        sig = run(label+'-signer', [a.java, '-jar', a.build_tools/'lib/apksigner.jar', 'verify', '--print-certs', apk]).decode('utf-8')
        if re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', sig) != [PLATFORM_CERT]:
            raise ValueError('Wrong signer: '+label)

    def snapshot(label):
        if installed_paths(shell(label+'-path', 'pm path '+ORIGINAL)) != [ORIGINAL_PATH]:
            raise ValueError('Original APK path changed')
        if shell(label+'-hash', 'sha256sum '+ORIGINAL_PATH).split()[0] != ORIGINAL_SHA:
            raise ValueError('Original APK changed')
        if uid(shell(label+'-package', 'dumpsys package '+ORIGINAL)) != 10082:
            raise ValueError('Original UID changed')
        result = dict(sms_holder=sms_holder(shell(label+'-roles', 'dumpsys role')),
                      sms_setting=shell(label+'-sms-setting', 'settings get secure sms_default_application'), data={})
        for package in (ORIGINAL, TELEPHONY):
            for kind, parent in [('ce', '/data/user/0/'), ('de', '/data/user_de/0/')]:
                path = parent+package
                tag = package+'-'+kind
                state = shell(label+'-'+tag+'-exists', 'if test -d '+path+'; then echo present; else echo absent; fi')
                if state not in ('present', 'absent'):
                    raise ValueError('Unrecognized data state')
                row = dict(state=state, path=path, parent=parent, package=package)
                if state == 'present':
                    row['files'] = sorted(shell(label+'-'+tag+'-hashes', 'find '+path+' -type f -exec sha256sum {} +').splitlines())
                    row['directory'] = shell(label+'-'+tag+'-directory', 'ls -ldZ '+path)
                result['data'][tag] = row
        return result

    try:
        if digest(candidate) != CANDIDATE_SHA:
            raise ValueError('Candidate changed')
        inspect('candidate', candidate, PACKAGE)
        manifest = run('candidate-manifest', [a.build_tools/'aapt.exe', 'dump', 'xmltree', candidate, 'AndroidManifest.xml']).decode('utf-8')
        if set(re.findall(r'android:authorities[^\n]*="([^"]+)"', manifest)) != AUTHORITIES or 'android:sharedUserId' in manifest:
            raise ValueError('Unexpected manifest authorities/shared UID')
        guard('preflight')
        inventory = packages(shell('packages-before', 'pm list packages -u --user 0'))
        fresh(inventory, shell('providers-before', 'dumpsys package providers'))
        before = snapshot('before'); report['before'] = before
        run('original-apk-backup', base+['pull', ORIGINAL_PATH, a.output/'original.apk'])
        if digest(a.output/'original.apk') != ORIGINAL_SHA:
            raise ValueError('Original APK backup mismatch')
        inspect('original', a.output/'original.apk', ORIGINAL)
        report['preflight_passed'] = True
        if not a.install:
            return
        for tag, row in before['data'].items():
            if row['state'] == 'present':
                data = run(tag+'-backup', base+['exec-out', 'tar', '-C', row['parent'], '-cf', '-', row['package']])
                (a.output/(tag+'.tar')).write_bytes(data)
        guard('preinstall')
        if snapshot('preinstall') != before:
            raise ValueError('Original data/role changed during backup; no install')
        fresh(packages(shell('packages-preinstall', 'pm list packages -u --user 0')), shell('providers-preinstall', 'dumpsys package providers'))
        result = run('install', base+['install', '--user', '0', candidate]).decode('utf-8').strip()
        if result != 'Success' and not result.endswith('\nSuccess'):
            raise ValueError('Install did not report success')
        report['installed'] = True
        guard('postinstall')
        after_packages = packages(shell('packages-after', 'pm list packages -u --user 0'))
        if after_packages-inventory != {PACKAGE} or inventory-after_packages:
            raise ValueError('Unexpected package delta')
        paths = installed_paths(shell('installed-path', 'pm path '+PACKAGE))
        if len(paths) != 1:
            raise ValueError('Expected one candidate APK')
        run('installed-pull', base+['pull', paths[0], a.output/'installed.apk'])
        if digest(a.output/'installed.apk') != CANDIDATE_SHA:
            raise ValueError('Installed APK hash mismatch')
        inspect('installed', a.output/'installed.apk', PACKAGE)
        if uid(shell('installed-package', 'dumpsys package '+PACKAGE)) < 10000:
            raise ValueError('Unexpected candidate system/shared UID')
        owners = provider_owners(shell('providers-after', 'dumpsys package providers'))
        if any(owners.get(authority) != PACKAGE for authority in AUTHORITIES):
            raise ValueError('Provider owner mismatch')
        if snapshot('postinstall') != before:
            raise ValueError('Original data/role changed; inspect, never auto-rollback')
        report['installed_identity_verified'] = True
        if a.launch:
            result = shell('launch', 'am start -W -n com.android.mms/com.android.mms.ui.ConversationList')
            report['launched'] = True
            shell('window-after-launch', 'dumpsys window')
            run('screen-after-launch', base+['exec-out', 'screencap', '-p'])
            shell('activity-after-launch', 'dumpsys activity activities')
            shell('crash-after-launch', 'logcat -b crash -d -t 100')
            if not re.search(r'^Status: ok\s*$', result, re.M):
                raise ValueError('Launch status not ok')
            guard('postlaunch')
            if snapshot('postlaunch') != before:
                raise ValueError('Original data/role changed after launch; inspect evidence')
            report['launch_status_ok'] = True
            report['screen_requires_review'] = True
    except Exception as e:
        report['error'] = str(e)
        raise
    finally:
        (a.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
