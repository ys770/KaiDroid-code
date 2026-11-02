"""Bounded, serial/boot-bound compilation trial; no reboot or profile deletion."""
import argparse
import json
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot-id', required=True)
p.add_argument('--image', choices=['27', '29'], default='27',
               help='Expected installed image; retains the original image27 default')
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)

def shell(command, timeout=30):
    r = subprocess.run([a.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell', command],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(r.stderr + r.stdout)
    return r.stdout.strip()

def guard():
    assert shell('cat /proc/sys/kernel/random/boot_id') == a.boot_id
    assert shell('getprop ro.kaidroid.image') == a.image
    assert shell('getprop ro.product.device') == 'n139dl'
    assert shell('id -u') == '0'

guard()
for name, cmd in [('dexopt', 'dumpsys package dexopt'), ('space', 'df -k /data'),
                  ('memory', 'cat /proc/meminfo; cat /proc/swaps')]:
    (a.output / (name + '-before.txt')).write_text(shell(cmd), encoding='utf-8')
results = []
for package in ['com.android.systemui', 'com.android.bluetooth']:
    guard()
    start = time.monotonic()
    # Preserve profiles; package manager atomically manages derived artifacts.
    response = shell('cmd package compile -m speed ' + package, timeout=600)
    results.append(dict(package=package, response=response,
                        elapsed_seconds=time.monotonic() - start))
    (a.output / 'results.json').write_text(json.dumps(results, indent=2))
    print(package, response, flush=True)
    if response != 'Success':
        raise RuntimeError('Compilation did not report success; stop without retry')
guard()
(a.output / 'dexopt-after.txt').write_text(shell('dumpsys package dexopt'), encoding='utf-8')
(a.output / 'space-after.txt').write_text(shell('df -k /data'), encoding='utf-8')
