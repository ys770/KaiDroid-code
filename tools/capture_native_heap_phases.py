"""Measure native allocator counters around two explicit GC-bearing meminfo dumps.

Requires a coordinated idle device window. Android11 ActivityThread.dumpMemInfo
reads native counters, then invokes GC. This is a controlled intervention, not a
read-only untouched-heap baseline. No policy, app, service or property changes.
"""
import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


def native_counters(text):
    rows = re.findall(r'^\s*Native Heap\s+([^\n]+)$', text, re.MULTILINE)
    if len(rows) != 1:
        raise ValueError('Expected exactly one Native Heap table row')
    values = rows[0].split()
    if len(values) < 7 or not all(v.isdigit() for v in values):
        raise ValueError('Incomplete or unexpected native heap table')
    size, allocated, free = map(int, values[-3:])
    return dict(size_KiB=size, allocated_KiB=allocated, free_KiB=free,
                timing='Counters read before this dump invokes managed GC; not physical footprint.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('adb', 'serial', 'image', 'boot'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--command', choices=('system_server', 'com.android.systemui'), required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.pid <= 1 or not a.image.isdigit() or not re.fullmatch(r'[a-f0-9-]{36}', a.boot):
        p.error('Invalid process or device identity')
    a.output.mkdir(parents=True, exist_ok=False)
    base = [a.adb, '-s', a.serial, 'exec-out']
    report = dict(image=a.image, boot=a.boot, pid=a.pid, command=a.command,
                  complete=False, intervention='Two meminfo calls; each invokes managed GC.',
                  captures=[], allocator_counters=[], device_policy_changed=False)

    def capture(name, command):
        started = time.monotonic()
        try:
            r = subprocess.run(base+[command], capture_output=True, timeout=20)
        except subprocess.TimeoutExpired as exc:
            (a.output/(name+'.partial')).write_bytes(exc.stdout or b'')
            report['captures'].append(dict(name=name, timed_out=True))
            raise RuntimeError('Capture timed out; inspect the existing device operation before retrying') from exc
        (a.output/(name+'.txt')).write_bytes(r.stdout)
        (a.output/(name+'.stderr')).write_bytes(r.stderr)
        report['captures'].append(dict(name=name, returncode=r.returncode,
            seconds=time.monotonic()-started, sha256=hashlib.sha256(r.stdout).hexdigest()))
        r.check_returncode()
        return r.stdout.decode()

    def guard(label, expected_start=None):
        identity = capture(label+'-identity',
            'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u')
        if identity.splitlines() != [a.image, a.boot, '0']:
            raise RuntimeError('Wrong image, boot or privilege')
        cmd = capture(label+'-command', f'cat /proc/{a.pid}/cmdline').split('\0')[0]
        stat = capture(label+'-stat', f'cat /proc/{a.pid}/stat')
        start = int(stat.rsplit(')', 1)[1].split()[19])
        if cmd != a.command or (expected_start is not None and start != expected_start):
            raise RuntimeError('Target process changed')
        return start

    def snapshot(label):
        capture(label+'-system', 'cat /proc/meminfo; cat /sys/block/zram0/mm_stat; cat /proc/uptime')
        capture(label+'-smaps', f'cat /proc/{a.pid}/smaps')

    try:
        start = guard('before')
        report['start_ticks'] = start
        snapshot('before')
        for index in range(2):
            guard(f'pre-dump{index}', start)
            text = capture(f'dump{index}', f'dumpsys -t 10 meminfo {a.pid}')
            if not re.search(r'\*\* MEMINFO in pid '+str(a.pid)+r' \[', text):
                raise RuntimeError('Dump did not identify the expected PID')
            if any(s in text.lower() for s in ('timed out', 'dump timeout', 'exception dumping')):
                raise RuntimeError('Incomplete meminfo dump')
            report['allocator_counters'].append(native_counters(text))
            guard(f'post-dump{index}', start)
            snapshot(f'after-dump{index}')
        report['complete'] = True
    finally:
        (a.output/'manifest.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
