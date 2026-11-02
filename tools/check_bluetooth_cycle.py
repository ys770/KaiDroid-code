"""Measure one identity-bound, disconnected Bluetooth OFF/ON cycle without tracing.

Raw output is private. This checks adapter lifecycle, not pairing or profiles.
An observation deadline never triggers an automatic second cycle.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('adb', 'serial', 'boot', 'image', 'output'):
        p.add_argument('--' + key, required=True)
    a = p.parse_args()
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=False)

    def shell(command):
        r = subprocess.run([a.adb, '-s', a.serial, 'shell', command],
                           capture_output=True, timeout=15, check=True)
        return r.stdout.decode(errors='replace').replace('\r\n', '\n')

    def identity():
        assert shell('cat /proc/sys/kernel/random/boot_id').strip() == a.boot
        assert shell('getprop ro.kaidroid.image').strip() == a.image
        assert shell('id -u').strip() == '0'

    def manager(name):
        s = shell('timeout 8 dumpsys bluetooth_manager')
        (out / (name + '.txt')).write_text(s, encoding='utf-8')
        return s

    identity()
    before = manager('before')
    assert re.search(r'^\s+state: ON$', before, re.M)
    assert 'ConnectionState: STATE_DISCONNECTED' in before
    assert 'Discovering: false' in before
    samples = []

    def observe(target, start):
        deadline = start + 45
        while time.monotonic() < deadline:
            s = manager(f'{target}-{len(samples):02d}')
            match = re.search(r'^\s+state: (\S+)$', s, re.M)
            samples.append(dict(target=target, seconds=time.monotonic() - start,
                                state=match.group(1) if match else 'UNKNOWN'))
            if match and match.group(1) == target:
                return True
            time.sleep(1)
        return False

    enable_requested = False
    report = dict(image=a.image, boot=a.boot, samples=samples,
                  scope='Single warm adapter cycle; not cold boot, pairing or profile validation')
    try:
        start = time.monotonic()
        shell('svc bluetooth disable')
        report['reached_off'] = observe('OFF', start)
        if not report['reached_off']:
            raise RuntimeError('OFF observation expired; no second cycle')
        start = time.monotonic()
        shell('svc bluetooth enable')
        enable_requested = True
        report['reached_on'] = observe('ON', start)
        identity()
        if not report['reached_on']:
            raise RuntimeError('ON observation expired; inspect ongoing state')
    finally:
        if not enable_requested:
            shell('svc bluetooth enable')
            report['restoration_requested'] = True
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
