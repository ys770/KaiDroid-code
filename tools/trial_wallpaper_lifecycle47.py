"""Three bounded injected wake/app transitions on the verified image47 boot."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path
from summarize_wallpaper_pair import surface_rows

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED']
result = dict(image=47, complete=False, cycles=[], physical_keys=False,
              deep_suspend=False, gl_context_recreation_proven=False)

def run(name, args):
    r = subprocess.run(base + args, capture_output=True, timeout=35)
    (a.output / (name + '.stdout')).write_bytes(r.stdout)
    (a.output / (name + '.stderr')).write_bytes(r.stderr)
    r.check_returncode()
    return r.stdout

def sh(name, command):
    return run(name, ['shell', command]).decode().replace('\r', '').strip()

def guard(name):
    lines = sh(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; '
               'id -u; getenforce; pidof system_server; pidof com.android.systemui').splitlines()
    if lines != ['47', a.boot, '0', 'Enforcing', '1169', '1360']:
        raise ValueError('Unexpected image, boot or process identity')

def launcher(name):
    window = sh(name + '-window', 'dumpsys window')
    if not any('mCurrentFocus=' in line and 'com.android.launcher3/com.android.launcher3.Launcher' in line
               for line in window.splitlines()):
        raise ValueError('Launcher not focused')
    power = sh(name + '-power', 'dumpsys power')
    if 'mWakefulness=Awake' not in power:
        raise ValueError('Display not awake')
    rows = surface_rows(sh(name + '-surfaceflinger', 'dumpsys SurfaceFlinger'))
    if any((r['width'], r['height'], r['format']) != (429, 353, 3) for r in rows):
        raise ValueError('Wallpaper buffer changed unexpectedly')
    screen = run(name + '-screen', ['exec-out', 'screencap', '-p'])
    (a.output / (name + '.png')).write_bytes(screen)
    return dict(buffers=rows, screenshot_sha256=hashlib.sha256(screen).hexdigest())

try:
    guard('before')
    pin = sh('systemui', 'sha256sum /system/system_ext/priv-app/SystemUI/SystemUI.apk').split()[0]
    if pin != '2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87':
        raise ValueError('Wrong SystemUI')
    result['initial'] = launcher('initial')
    if sh('power-policy', 'getprop ro.kaidroid.power_endcall') != 'true':
        raise ValueError('Wrong end-call policy')
    for i in range(1, 4):
        name = 'cycle' + str(i)
        guard(name + '-before')
        sh(name + '-settings', 'am start -W -a android.settings.SETTINGS')
        window = sh(name + '-settings-window', 'dumpsys window')
        if not any('mCurrentFocus=' in line and 'com.android.settings' in line for line in window.splitlines()):
            raise ValueError('Settings not focused')
        sh(name + '-endcall', 'input keyevent 26')
        time.sleep(2)
        home = launcher(name + '-home')
        sh(name + '-sleep', 'input keyevent 223')
        time.sleep(3)
        if 'mWakefulness=Asleep' not in sh(name + '-asleep', 'dumpsys power'):
            raise ValueError('Sleep not observed')
        sh(name + '-wake', 'input keyevent 224')
        time.sleep(3)
        awake = launcher(name + '-awake')
        guard(name + '-after')
        result['cycles'].append(dict(cycle=i, home=home, awake=awake))
    result['complete'] = True
finally:
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(dict(complete=result['complete'], cycles=len(result['cycles']))))
