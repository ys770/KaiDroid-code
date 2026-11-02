"""Bounded Settings launch comparison, with boot-bound restoration of read-ahead.

No cache dropping, package installs, permission changes, or boot modifications.
Warm-cache/order effects mean results cannot establish a startup ANR fix.
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED']
boot = '00000000-0000-0000-0000-000000000014'
node = '/sys/block/mmcblk0/queue/read_ahead_kb'
a.output.mkdir(parents=True, exist_ok=False)
report = dict(boot=boot, image=36, restored=False, samples=[],
              limitation='Repeated app launches; warm cache and order confounding. Not a boot ANR test.')

def shell(command, timeout=20):
    r = subprocess.run(base+['exec-out', command], capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace'))
    return r.stdout.decode().strip()

def guard():
    assert shell('getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').splitlines() == ['36', boot, '0']

def counters():
    vm = dict(line.split() for line in shell('cat /proc/vmstat').splitlines())
    disk = [line.split() for line in shell('cat /proc/diskstats').splitlines() if line.split()[2]=='mmcblk0']
    assert len(disk) == 1
    return dict(major_faults=int(vm['pgmajfault']), swapin=int(vm['pswpin']),
                sectors_read=int(disk[0][5]), read_ms=int(disk[0][6]))

guard()
original = shell('cat '+node)
assert original == '128', original
try:
    for label, value in [('baseline',128),('candidate',16),('restored',128)]:
        guard()
        shell('echo '+str(value)+' > '+node)
        assert shell('cat '+node)==str(value)
        for i in range(3):
            guard()
            shell('am force-stop --user 0 com.android.settings')
            time.sleep(2)
            before = counters()
            started = time.monotonic()
            output = shell('am start -W -a android.settings.SETTINGS', timeout=45)
            elapsed = time.monotonic()-started
            after = counters()
            assert 'Status: ok' in output and 'com.android.settings/' in output, output
            sample = dict(phase=label, readahead_kib=value, index=i, wall_seconds=elapsed,
                          activity_manager=output, delta={k:after[k]-before[k] for k in before})
            report['samples'].append(sample)
            (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps(sample),flush=True)
            time.sleep(3)
except Exception as error:
    report['error'] = repr(error)
    raise
finally:
    try:
        guard()
        shell('echo '+original+' > '+node)
        report['restored'] = shell('cat '+node)==original
        assert report['restored']
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
