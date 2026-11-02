"""Image33 candidate installation around the Settings open/back trial.

Retain candidates if grant restoration cannot be proven; never conceal a failed
permission rollback with an APK downgrade.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--sort-dialog-cancel', action='store_true')
p.set_defaults(trial='settings-navigation')
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
adb = '/opt/kaidroid/source/Documents/platform-tools/adb.exe'
boot = '00000000-0000-0000-0000-000000000004'
base = [adb, '-s', 'DEVICE_SERIAL_REQUIRED']
specs = [
    ('controller', 'com.android.permissioncontroller',
     'work/permission-controller-build02/PermissionController.apk',
     '3da34d2d40ba964502ad680d8e63d2e51f3f90f670692a5cbf32992a8e8b2655',
     'artifacts/runtime/permission-controller-preflight01/PermissionController.original.apk',
     'b94c069e92ff1ccfdf80c15f25b4155d8647d520f8a47834f71dedff2bfdfb30'),
    ('contacts', 'com.android.contacts', 'work/contacts-dialog-width01/signed/FPContacts.apk',
     '20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248',
     'artifacts/runtime/tcl-contacts-preflight01/Contacts.original.apk',
     '7cc2c14fe371adf7c98900ffda85fbfc274b8cb8da7e33fc4d0bf79d8a746e0d'),
]
helper = root/'work/contacts-permission-state33-width02/contacts-permission-state.jar'
assert hashlib.sha256(helper.read_bytes()).hexdigest() == 'b4d81bb68cdd1ec286b6f32ac1398b719aba5fa358b8c0849ce402032d4d4ed0'
for _, _, candidate, candidate_sha, original, original_sha in specs:
    assert hashlib.sha256((root/candidate).read_bytes()).hexdigest() == candidate_sha
    assert hashlib.sha256((root/original).read_bytes()).hexdigest() == original_sha
a.output.mkdir(parents=True, exist_ok=False)

def run(label, args):
    r = subprocess.run(base+args, capture_output=True, timeout=120)
    (a.output/(label+'.stdout')).write_bytes(r.stdout)
    (a.output/(label+'.stderr')).write_bytes(r.stderr)
    r.check_returncode()
    return r.stdout.decode().strip()

def sh(label, command):
    return run(label, ['shell', command])

def guard(label):
    assert sh(label, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce').splitlines() == ['33', boot, '0', 'Enforcing']

def verify(label, package, digest):
    path = sh(label+'-path', 'pm path '+package)
    assert path.startswith('package:/') and '\n' not in path
    assert sh(label+'-hash', 'sha256sum '+path[8:]).split()[0] == digest
    sh(label+'-package', 'dumpsys package '+package)

guard('before')
for name, package, _, _, _, digest in specs:
    verify(name+'-original', package, digest)
report = dict(installed=[], originals_restored=[], permission_restoration_verified=False, trial=a.trial)
report['sort_cancel_requested'] = a.sort_dialog_cancel
report['sort_preference_verified'] = not a.sort_dialog_cancel
trial_started = False
try:
    for name, package, candidate, digest, _, _ in specs:
        assert 'Success' in run(name+'-install', ['install', '-r', str(root/candidate)])
        report['installed'].append(name)
        verify(name+'-candidate', package, digest)
    trial_started = True
    trial_file = 'trial_contacts_list.py'
    q = subprocess.run([sys.executable, str(root/'tools'/trial_file),
        '--adb', adb, '--helper', str(helper), '--boot-id', boot,
        '--output', str(a.output/'trial'), '--settings-navigation']
        + (['--sort-dialog-cancel'] if a.sort_dialog_cancel else []), capture_output=True)
    (a.output/'trial.stdout').write_bytes(q.stdout)
    (a.output/'trial.stderr').write_bytes(q.stderr)
    report['trial_exit'] = q.returncode
    state = json.loads((a.output/'trial/result.json').read_text())
    report['permission_restoration_verified'] = state.get('restoration_verified') is True
    if a.sort_dialog_cancel:
        report['sort_preference_verified'] = state.get('sort_cancel_preserved_preference') is True
    q.check_returncode()
finally:
    try:
        if not trial_started or (report['permission_restoration_verified'] and report['sort_preference_verified']):
            guard('rollback-identity')
            for name, package, _, _, original, digest in reversed(specs):
                if name not in report['installed']:
                    continue
                sh(name+'-stop', 'am force-stop '+package)
                args = ['install', '-r'] + (['-d'] if name == 'contacts' else [])
                assert 'Success' in run(name+'-restore', args+[str(root/original)])
                verify(name+'-restored', package, digest)
                report['originals_restored'].append(name)
        else:
            report['action'] = 'Retain candidates and inspect saved process/permission state; no blind APK rollback.'
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
