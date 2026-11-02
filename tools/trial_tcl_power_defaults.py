"""Bounded image33 donor-default trial; restores settings, never changes credentials."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot-id', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(exist_ok=False, parents=True)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell']


def run(label, cmd):
    r = subprocess.run(base + [cmd], capture_output=True, timeout=30)
    (a.output / (label + '.txt')).write_bytes(r.stdout + r.stderr)
    r.check_returncode()
    return r.stdout.decode(errors='replace')


def guard(label):
    values = run(label, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').split()
    assert values == ['33', a.boot_id, '0']


guard('identity-before')
locks = run('lock-settings-before', 'dumpsys lock_settings')
assert re.search(r'CredentialType:\s+None', locks) and not re.search(r'CredentialType:\s+(?!None\b)\S+', locks)
calls = re.findall(r'mCallState=(\d+)', run('calls-before', 'dumpsys telephony.registry'))
assert calls and all(value == '0' for value in calls)
specs = [('secure', 'lockscreen.disabled', '1'), ('system', 'end_button_behavior', '1'),
         ('system', 'screen_off_timeout', '30000')]
original = {}
original_lock_disabled = run('lock-disabled-before', 'locksettings get-disabled').strip()
assert original_lock_disabled in ('true', 'false')
for namespace, key, _ in specs:
    value = run(key + '-before', 'settings get ' + namespace + ' ' + key).strip()
    assert re.fullmatch(r'null|\d+', value)
    original[key] = value
report = dict(image=33, boot_id=a.boot_id, original_settings=original,
              original_lock_disabled=original_lock_disabled,
              settings_restored=False, physical_keys_tested=False,
              scope='Injected End key on an idle-call engineering handset. USB stay-awake remains a lab setting; timeout/sleep/physical wake and full donor parity not proven.')
try:
    run('lock-disabled-set', 'locksettings set-disabled true')
    assert run('lock-disabled-configured', 'locksettings get-disabled').strip() == 'true'
    for namespace, key, value in specs:
        run(key + '-set', 'settings put ' + namespace + ' ' + key + ' ' + value)
    run('wake', 'input keyevent 224; wm dismiss-keyguard')
    run('settings-launch', 'am start -W -a android.settings.SETTINGS')
    time.sleep(1)
    before = run('activity-before-end', 'dumpsys activity activities')
    assert 'com.android.settings' in before
    policy = run('policy-configured', 'dumpsys window policy')
    assert 'mEndcallBehavior=home' in policy
    calls = re.findall(r'mCallState=(\d+)', run('calls-before-end', 'dumpsys telephony.registry'))
    assert calls and all(value == '0' for value in calls)
    run('end', 'input keyevent 6')
    time.sleep(1)
    after = run('activity-after-end', 'dumpsys activity activities')
    power = run('power-after-end', 'dumpsys power')
    report['resumed_after_end'] = [line.strip() for line in after.splitlines()
                                   if 'mResumedActivity' in line or 'topResumedActivity' in line]
    report['awake_after_end'] = 'mWakefulness=Awake' in power
    report['policy_end_home'] = True
    run('sleep', 'input keyevent 223')
    time.sleep(1)
    run('wake-again', 'input keyevent 224')
    time.sleep(1)
    keyguard = run('policy-after-wake', 'dumpsys window policy')
    report['keyguard_not_showing_after_wake'] = 'mIsShowing=false' in keyguard
finally:
    guard('identity-before-restore')
    run('lock-disabled-restore', 'locksettings set-disabled ' + original_lock_disabled)
    assert run('lock-disabled-restored', 'locksettings get-disabled').strip() == original_lock_disabled
    for namespace, key, _ in specs:
        old = original[key]
        cmd = 'settings delete ' + namespace + ' ' + key if old == 'null' else 'settings put ' + namespace + ' ' + key + ' ' + old
        run(key + '-restore', cmd)
        assert run(key + '-restored', 'settings get ' + namespace + ' ' + key).strip() == old
    report['settings_restored'] = True
    (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
