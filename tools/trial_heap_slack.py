"""Run a pre-staged isolated ART probe, only after hardware-lane handoff.

No property changes, framework restart, app installation, cache flush or service
controls. This still creates transient memory/CPU pressure and needs an idle lane.
"""
import argparse
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('adb','serial','image','boot'):
        p.add_argument('--'+key,required=True)
    p.add_argument('--jar',type=Path,required=True)
    p.add_argument('--remote',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not re.fullmatch(r'/data/local/tmp/[A-Za-z0-9_.-]+\.jar',a.remote):
        p.error('Use a simple already-staged /data/local/tmp/*.jar path')
    if not a.image.isdigit() or not re.fullmatch(r'[a-f0-9-]{36}',a.boot):
        p.error('Invalid image or boot')
    a.output.mkdir(parents=True,exist_ok=False)
    base=[a.adb,'-s',a.serial,'exec-out']
    report=dict(image=a.image,boot=a.boot,jar_sha256=hashlib.sha256(a.jar.read_bytes()).hexdigest(),
                device_policy_changed=False,samples=[],complete=False)
    def capture(name,command,timeout=20):
        try:
            r=subprocess.run(base+[command],capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            (a.output/(name+'.partial')).write_bytes(exc.stdout or b'')
            raise RuntimeError('Probe timeout; do not restart before inspecting live process') from exc
        (a.output/(name+'.txt')).write_bytes(r.stdout)
        (a.output/(name+'.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout.decode().strip()
    def guard(label):
        got=capture(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u')
        if got.splitlines()!=[a.image,a.boot,'0']:
            raise RuntimeError('Device identity changed')
    try:
        guard('identity-before')
        if capture('jar-hash','sha256sum '+a.remote).split()[0]!=report['jar_sha256']:
            raise RuntimeError('Pre-staged probe hash differs')
        report['clock_ticks_per_second']=int(capture('clock-ticks','getconf CLK_TCK'))
        report['properties']=capture('properties','getprop | grep dalvik.vm')
        report['low_ram_property']=capture('low-ram','getprop ro.config.low_ram')
        if report['low_ram_property']!='true':
            raise RuntimeError('Expected the measured low-RAM device configuration')
        report['explicit_low_memory_mode']=True
        # Explicit options passed directly to ART; AndroidRuntime is not invoked.
        common='dalvikvm -Xcheck:jni -XX:LowMemoryMode -Xms8m -Xmx256m -XX:HeapGrowthLimit=128m -XX:HeapTargetUtilization=0.75 -XX:ForegroundHeapGrowthMultiplier=2.0 '
        # Balanced ordering; A also repeats at the end to expose time/warm drift.
        for index,phase in enumerate(('baseline','candidate','candidate','baseline','baseline','candidate','baseline')):
            guard(f'identity-{index}')
            capture(f'system-{index}-before', 'cat /proc/meminfo; cat /proc/vmstat; cat /sys/block/zram0/mm_stat; cat /proc/uptime')
            values=('6m','8m') if phase=='baseline' else ('2m','4m')
            command=(common+f'-XX:HeapMinFree={values[0]} -XX:HeapMaxFree={values[1]} '
                     +f'-cp {a.remote} HeapSlackProbe {a.image} {a.boot}')
            started=time.monotonic()
            output=capture(f'probe-{index}-{phase}',command,60)
            capture(f'system-{index}-after', 'cat /proc/meminfo; cat /proc/vmstat; cat /sys/block/zram0/mm_stat; cat /proc/uptime')
            result=json.loads(output)
            if result['boot']!=a.boot or result['rounds']!=12:
                raise RuntimeError('Unexpected probe output')
            result.update(phase=phase,host_seconds=time.monotonic()-started,command=command)
            report['samples'].append(result)
            (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
        guard('identity-after')
        if capture('properties-after','getprop | grep dalvik.vm')!=report['properties']:
            raise RuntimeError('Concurrent property changes detected; reject comparison')
        if len({s['checksum'] for s in report['samples']})!=1:
            raise RuntimeError('Workload checksums differ')
        report['complete']=True
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
