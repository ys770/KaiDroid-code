"""Bounded read-only power telemetry; never writes charger or thermal controls."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--boot-id', required=True)
    p.add_argument('--image', required=True, type=int)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    serial = 'DEVICE_SERIAL_REQUIRED'

    def read(command):
        r = subprocess.run([a.adb, '-s', serial, 'shell', command],
                           capture_output=True, timeout=20)
        if r.returncode or r.stderr:
            raise RuntimeError('ADB read failed: ' + command)
        return r.stdout

    def guard():
        values = read('getprop ro.serialno; getprop ro.kaidroid.image; '
                      'cat /proc/sys/kernel/random/boot_id').decode().splitlines()
        if values != [serial, str(a.image), a.boot_id]:
            raise RuntimeError('Handset/image/boot identity changed')

    guard()
    a.output.mkdir(parents=True, exist_ok=False)
    command = ('cat /proc/uptime; dumpsys battery; '
               'cat /sys/class/power_supply/battery/uevent; '
               'cat /sys/class/power_supply/bms/uevent; '
               'getprop init.svc.thermal-engine; getprop persist.usb.chgdisabled')
    samples = []
    for i in range(3):
        guard()
        data = read(command)
        name = f'sample{i}.txt'
        (a.output / name).write_bytes(data)
        samples.append(dict(file=name, sha256=hashlib.sha256(data).hexdigest()))
        if i < 2:
            time.sleep(10)
    guard()
    result = dict(image=a.image, boot_id=a.boot_id, samples=samples,
                  same_identity_and_boot=True, controls_written=False,
                  scope='Three sequential USB-powered telemetry samples; no charge cycle, accuracy or physical thermal validation')
    (a.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
