"""Read-only, identity-bound physical-key capture; never injects keys or unlocks."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import re


def capture(args):
    adb = [str(args.adb), '-s', args.serial]

    def shell(command):
        p = subprocess.run(adb + ['shell', command], capture_output=True, timeout=20)
        p.check_returncode()
        return p.stdout

    def value(command):
        return shell(command).decode('utf-8', errors='replace').strip()

    # No output directory or long-lived reader before exact identity checks.
    if value('getprop ro.build.fingerprint') != args.fingerprint:
        raise ValueError('Unexpected fingerprint')
    if value('getprop ro.kaidroid.image') != args.revision:
        raise ValueError('Unexpected image revision')
    if value('id -u') != '0':
        raise ValueError('Root capture required')
    boot = value('cat /proc/sys/kernel/random/boot_id')
    if boot != args.boot_id:
        raise ValueError('Unexpected boot identity')
    hall_path = None
    if args.hall_state:
        devices = value('for d in /sys/class/input/event*; do '
                        '[ "$(cat "$d/device/name")" = hall_sensor ] && '
                        'readlink -f "$d/device/device"; done; true').splitlines()
        if len(devices) != 1 or not re.fullmatch(r'/sys/devices/[A-Za-z0-9_:/.-]+', devices[0]):
            raise ValueError('Expected one resolved hall sensor sysfs device')
        hall_path = devices[0]
        if value('cat ' + hall_path + '/hall_status') not in ('0', '1'):
            raise ValueError('Unexpected hall status encoding')
    args.output.mkdir(parents=True, exist_ok=False)
    commands = {'input': 'dumpsys input', 'policy': 'dumpsys window policy',
                'power': 'dumpsys power', 'devices': 'getevent -lp'}
    for name, command in commands.items():
        (args.output / (name + '-before.txt')).write_bytes(shell(command))
    sampler = None
    sampler_file = None
    if hall_path:
        # Both processes are phone-timeout bounded, even if USB disconnects.
        sampler_file = (args.output / 'hall-state.txt').open('xb')
        script = ('while true; do cut -d " " -f 1 /proc/uptime; '
                  'cat ' + hall_path + '/hall_status; sleep 0.2; done')
        sampler = subprocess.Popen(adb + ['shell', 'timeout ' + str(args.seconds)
            + " sh -c '" + script + "'"], stdout=sampler_file, stderr=subprocess.STDOUT)
    # Phone-side timeout bounds reader lifetime even if the host disconnects.
    with (args.output / 'events.txt').open('xb') as out, \
            (args.output / 'reader-stderr.txt').open('xb') as err:
        reader = subprocess.Popen(adb + ['shell', 'timeout', str(args.seconds),
                                        'getevent', '-lt'], stdout=out, stderr=err)
        try:
            code = reader.wait(timeout=args.seconds + 15)
        except subprocess.TimeoutExpired:
            reader.kill()
            reader.wait()
            raise RuntimeError('Host reader timeout; phone reader has its own deadline')
        finally:
            if sampler:
                try:
                    sampler_code = sampler.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    sampler.kill()
                    sampler.wait()
                    raise RuntimeError('Hall sampler host timeout')
                finally:
                    sampler_file.close()
    # Android timeout may return 124 or 143 on an otherwise successful interval.
    after_boot = value('cat /proc/sys/kernel/random/boot_id')
    for name, command in commands.items():
        (args.output / (name + '-after.txt')).write_bytes(shell(command))
    report = {'boot_before': boot, 'boot_after': after_boot,
              'same_boot': boot == after_boot, 'reader_exit': code,
              'duration_seconds': args.seconds, 'host_keys_injected': False,
              'hall_sysfs_path': hall_path,
              'hall_sampler_exit': sampler_code if sampler else None,
              'completed_at_unix': time.time(), 'sha256': {
                  p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in args.output.iterdir() if p.is_file()}}
    (args.output / 'capture.json').write_text(json.dumps(report, indent=2) + '\n')
    if (boot != after_boot or code not in (0, 124, 143)
            or (sampler and sampler_code not in (0, 124, 143))):
        raise RuntimeError('Capture interrupted; inspect evidence, do not infer dead keys')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    p.add_argument('--serial', required=True)
    p.add_argument('--fingerprint', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--boot-id', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--seconds', type=int, choices=range(15, 121), default=90)
    p.add_argument('--hall-state', action='store_true',
                   help='Also sample discovered hall_status at 5 Hz, read-only')
    capture(p.parse_args())
