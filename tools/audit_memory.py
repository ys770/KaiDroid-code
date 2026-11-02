"""Bounded read-only Android memory census; never changes device policy."""
import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('adb', 'serial', 'image', 'boot'):
        p.add_argument('--'+key, required=True)
    p.add_argument('--output', required=True, type=Path)
    p.add_argument('--topology', action='store_true', help='Also capture boot memory layout and properties')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    base = [a.adb, '-s', a.serial, 'exec-out']
    records = []

    def capture(name, command, timeout=30):
        started = time.monotonic()
        try:
            r = subprocess.run(base + [command], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (a.output / (name + '.partial.txt')).write_bytes(exc.stdout or b'')
            (a.output / (name + '.partial.stderr')).write_bytes(exc.stderr or b'')
            records.append(dict(name=name, seconds=time.monotonic()-started, timed_out=True))
            raise
        (a.output / (name + '.txt')).write_bytes(r.stdout)
        (a.output / (name + '.stderr')).write_bytes(r.stderr)
        records.append(dict(name=name, seconds=time.monotonic()-started,
                            returncode=r.returncode, sha256=hashlib.sha256(r.stdout).hexdigest()))
        if r.returncode:
            raise RuntimeError(f'{name} failed; preserved raw output')
        return r.stdout.decode(errors='replace')

    def guard(name):
        identity = capture(name, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u')
        if identity.splitlines() != [a.image, a.boot, '0']:
            raise RuntimeError('Identity mismatch; no further collection')

    system = '''echo MEMINFO; cat /proc/meminfo
echo VMSTAT; cat /proc/vmstat
echo ZRAM; cat /sys/block/zram0/mm_stat
echo SWAPS; cat /proc/swaps
echo UPTIME; cat /proc/uptime
echo CPU; cat /proc/stat
echo DISK; cat /proc/diskstats
echo PRESSURE; cat /proc/pressure/memory 2>/dev/null
echo POWER; cat /sys/class/power_supply/battery/uevent 2>/dev/null
echo END'''
    # One awk process avoids thousands of fork/exec page faults from per-PID cat.
    census = r'''awk 'BEGIN {
for (i=1;i<ARGC;i++) {
  path=ARGV[i]; sub(/\/stat$/, "", path)
  statfile=path "/stat"; if ((getline first < statfile)<=0) {close(statfile); continue}; close(statfile)
  statusfile=path "/status"; status=""; userspace=0
  while ((getline line < statusfile)>0) {status=status line "\n"; if (line ~ /^VmSize:/) userspace=1}; close(statusfile)
  if (!userspace) continue
  pid=path; sub(/.*\//,"",pid); print "PROCESS " pid; print first
  cmdfile=path "/cmdline"; cmd=""; getline cmd < cmdfile; close(cmdfile); gsub(/\000/," ",cmd); print cmd
  printf "%s",status; print "MAPTOTALS"
  roll=path "/smaps_rollup"; found=0
  while ((getline line < roll)>0) {print line; found=1}; close(roll)
  if (!found) {
    smaps=path "/smaps"; for (key in sums) delete sums[key]
    while ((getline line < smaps)>0) if (line ~ /^[A-Za-z_]+: *[0-9]+ kB$/) {split(line,fields); sums[fields[1]]+=fields[2]}
    close(smaps); for (key in sums) print key,sums[key],"kB"
  }
  print "STAT_AFTER"; if ((getline line < statfile)>0) print line; close(statfile); print "END_PROCESS"
}
print "END_CENSUS"
}' /proc/[0-9]*/stat'''
    try:
        guard('identity-before')
        capture('system-before', system)
        capture('processes', census, 60)
        guard('identity-middle')
        capture('services', 'service list; echo HIDL; lshal --neat 2>/dev/null; echo INIT; getprop | grep init.svc; echo END', 30)
        capture('allocators', 'echo ION; cat /sys/kernel/debug/ion/heaps/* 2>/dev/null; echo DMA; cat /sys/kernel/debug/dma_buf/bufinfo 2>/dev/null; echo SLAB; cat /proc/slabinfo; echo END', 30)
        if a.topology:
            capture('boot-memory', 'echo IOMEM; cat /proc/iomem; echo CMDLINE; cat /proc/cmdline; echo KERNEL; dmesg; echo END', 30)
            capture('properties', 'getprop', 20)
        capture('system-after', system)
        guard('identity-after')
    finally:
        (a.output / 'manifest.json').write_text(json.dumps(dict(image=a.image, boot=a.boot, captures=records), indent=2)+'\n')


if __name__ == '__main__':
    main()
