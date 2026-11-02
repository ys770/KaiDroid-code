"""Bounded image27 force-client trial; restore original all-zero SF debug state."""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot-id', required=True)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']

def run(name, command):
    r = subprocess.run(base + [command], capture_output=True, timeout=20)
    (a.output / (name + '.stdout')).write_bytes(r.stdout)
    (a.output / (name + '.stderr')).write_bytes(r.stderr)
    if r.returncode:
        raise RuntimeError(name + ' failed')
    return r.stdout.decode(errors='replace').strip()

def flags(text):
    words = []
    for line in text.splitlines():
        if re.match(r'\s*0x[0-9a-f]+:', line):
            words.extend(re.findall(r'\b[0-9a-f]{8}\b', line.split(':', 1)[1].split("'")[0]))
    return words

assert run('boot', 'cat /proc/sys/kernel/random/boot_id') == a.boot_id
assert run('image', 'getprop ro.kaidroid.image') == '27'
before = flags(run('flags-before', 'service call SurfaceFlinger 1010'))
assert before == ['00000000'] * 5, before
run('surface-before', 'dumpsys SurfaceFlinger')
changed = False
try:
    changed = True
    run('enable', 'service call SurfaceFlinger 1008 i32 1')
    assert flags(run('flags-active', 'service call SurfaceFlinger 1010')) == before[:4] + ['00000001']
    run('refresh', 'service call SurfaceFlinger 1006')
    time.sleep(3)
    run('surface-active', 'dumpsys SurfaceFlinger')
    run('screen-active', 'screencap -p')
finally:
    if changed:
        assert run('boot-restore', 'cat /proc/sys/kernel/random/boot_id') == a.boot_id
        run('restore', 'service call SurfaceFlinger 1008 i32 0')
        restored = flags(run('flags-restored', 'service call SurfaceFlinger 1010')) == before
        (a.output / 'result.json').write_text(json.dumps({'restored': restored,
            'boot_id': a.boot_id, 'physical_display_validated': False}, indent=2))
        assert restored
print('Trial complete; original compositor debug flags restored')
