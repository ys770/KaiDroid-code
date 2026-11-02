"""Bounded image30/31 init-domain test. Always stop the disabled service."""
import argparse
import json
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot-id', required=True)
p.add_argument('--image', choices=('30', '31'), default='30')
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell']

def shell(name, command):
    r = subprocess.run(base + [command], capture_output=True, timeout=20)
    (a.output / (name + '.txt')).write_bytes(r.stdout + r.stderr)
    r.check_returncode()
    return r.stdout.decode(errors='replace').strip()

def guard(name):
    values = shell(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; '
                   'id -u; getenforce; getprop sys.boot_completed').splitlines()
    assert [v.strip() for v in values if v.strip()] == [a.image, a.boot_id, '0', 'Enforcing', '1'], values

guard('identity-before')
assert shell('initial-service', 'getprop init.svc.kaidroid-hall') in ('', 'stopped')
assert shell('initial-pid', 'pidof kaidroid-hall || true') == ''
assert shell('rc-hash', 'sha256sum /system/etc/init/kaidroid-hall.rc').split()[0] == '4edca485144a9e48e1a173f561adf6cd01de1d5b757ab46e46d4ccddf6c29ad2'
assert 'KaiDroid Nokia Lid' not in shell('input-before', 'cat /proc/bus/input/devices')
shell('labels', 'ls -lZ /system/bin/kaidroid-hall /dev/uinput /dev/input/event* '
      '/sys/devices/platform/soc/soc:hall_sensor/hall_status')
before_kernel = set(shell('dmesg-before', 'dmesg').splitlines())
result = {'image': int(a.image), 'boot_id': a.boot_id, 'physical_transitions_tested': False,
          'power_policy_changed': False, 'boot_enabled': False}
started = False
try:
    # Set before issuing start: even a transport error must attempt cleanup.
    started = True
    shell('start', 'start kaidroid-hall')
    time.sleep(3)
    assert shell('service-running', 'getprop init.svc.kaidroid-hall') == 'running'
    pid = shell('pid', 'pidof kaidroid-hall')
    assert pid.isdigit(), pid
    assert shell('domain', 'cat /proc/' + pid + '/attr/current').rstrip('\0') == 'u:r:kaidroid_hall:s0'
    assert 'KaiDroid Nokia Lid' in shell('input-running', 'cat /proc/bus/input/devices')
    shell('android-input', 'dumpsys input')
    time.sleep(5)
    assert shell('pid-stable', 'pidof kaidroid-hall') == pid
    result['dedicated_domain_running'] = True
    result['virtual_device_registered'] = True
    new_lines = set(shell('dmesg-running', 'dmesg').splitlines()) - before_kernel
    denials = sorted(line for line in new_lines if 'avc: denied' in line
                    and 'scontext=u:r:kaidroid_hall:s0' in line)
    result['new_hall_domain_denials'] = denials
    if a.image == '31':
        assert not denials, denials
except Exception as exc:
    result['error'] = repr(exc)
    raise
finally:
    try:
        if started:
            guard('identity-cleanup')
            shell('stop', 'stop kaidroid-hall')
            time.sleep(2)
            result['stopped'] = shell('service-stopped', 'getprop init.svc.kaidroid-hall') == 'stopped'
            result['virtual_device_removed'] = 'KaiDroid Nokia Lid' not in shell('input-after', 'cat /proc/bus/input/devices')
            shell('dmesg-after', 'dmesg')
            shell('logcat-after', 'logcat -b all -d -t 1500')
            guard('identity-after')
            assert result['stopped'] and result['virtual_device_removed']
    finally:
        (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
