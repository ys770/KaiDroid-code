"""Arm one no-GC census at a fixed boot age in an exclusively assigned phone window.

No retries, reboot, app navigation or policy changes. A missed deadline aborts.
Timing agreement alone does not establish a comparable workload or working set.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path


def start_ticks(stat,pid):
    if not stat.startswith(str(pid)+' ('):raise ValueError('Wrong stat PID')
    return int(stat.rsplit(')',1)[1].split()[19])


def require_identity(lines,image,boot,server,ui):
    if len(lines)!=9 or lines[:3]!=[image,boot,'0'] or lines[4:7]!=[str(server),str(ui),'1']:
        raise ValueError('Wrong image/boot/root/processes or boot incomplete')
    return float(lines[3].split()[0]),(start_ticks(lines[7],server),start_ticks(lines[8],ui))


def wait_seconds(target,observed_uptime,elapsed):
    delay=target-observed_uptime-elapsed
    if delay<0:raise ValueError('Target boot age already missed; no census launched')
    if delay>90:raise ValueError('Arm within90seconds of target in the assigned window')
    return delay


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','serial','image','boot'):p.add_argument('--'+name,required=True)
    p.add_argument('--system-server-pid',type=int,required=True)
    p.add_argument('--systemui-pid',type=int,required=True)
    p.add_argument('--target-uptime',type=float,required=True,help='Boot age for collector launch, seconds')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.serial!='DEVICE_SERIAL_REQUIRED' or not a.image.isdigit() or not re.fullmatch(r'[a-f0-9-]{36}',a.boot):
        p.error('Require exact engineering Nokia identity')
    if min(a.system_server_pid,a.systemui_pid)<=1 or a.system_server_pid==a.systemui_pid or not 180<=a.target_uptime<=1800:
        p.error('Invalid process or target boot age')
    a.output.mkdir(parents=True,exist_ok=False)
    collector=Path(__file__).with_name('audit_memory.py')
    report=dict(image=a.image,boot=a.boot,serial=a.serial,target_launch_uptime=a.target_uptime,
        collector_sha256=hashlib.sha256(collector.read_bytes()).hexdigest(),state='preflight',
        no_gc=True,device_policy_changed=False,baseline_frozen=False)
    base=[a.adb,'-s',a.serial,'exec-out']
    def save():
        (a.output/'timing.json').write_text(json.dumps(report,indent=2)+'\n')
    def guard(label):
        command=('getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; '
            'cat /proc/uptime; pidof system_server; pidof com.android.systemui; '
            f'getprop sys.boot_completed; cat /proc/{a.system_server_pid}/stat /proc/{a.systemui_pid}/stat')
        begin=time.monotonic()
        r=subprocess.run(base+[command],capture_output=True,timeout=20)
        end=time.monotonic()
        (a.output/(label+'.txt')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        uptime,starts=require_identity(r.stdout.decode().splitlines(),a.image,a.boot,a.system_server_pid,a.systemui_pid)
        return uptime,starts,end,end-begin
    try:
        uptime,starts,reference,roundtrip=guard('initial-guard')
        delay=wait_seconds(a.target_uptime,uptime,0)
        report.update(initial_uptime=uptime,initial_guard_roundtrip_seconds=roundtrip,
                      process_start_ticks=starts,state='armed',wait_seconds=delay)
        save();print(json.dumps({'state':'armed','wait_seconds':delay}),flush=True)
        deadline=reference+delay
        while time.monotonic()<deadline:
            time.sleep(max(0,min(1,deadline-time.monotonic())))
        # This fresh guard prevents an intervening reboot or PID reuse from
        # becoming a delayed measurement of another process lifetime.
        before,new_starts,_,_=guard('before-collector')
        if new_starts!=starts:raise ValueError('Process lifetime changed while armed')
        if abs(before-a.target_uptime)>2:raise ValueError('Timing tolerance missed; no census launched')
        report.update(state='collecting',guard_uptime_before_collector=before)
        save()
        command=[sys.executable,str(collector),'--adb',a.adb,'--serial',a.serial,
                 '--image',a.image,'--boot',a.boot,'--output',str(a.output/'census')]
        # Collector bounds its own ADB operations. Do not kill/restart it because
        # a caller's observation interval expires.
        with (a.output/'collector.stdout').open('xb') as out,(a.output/'collector.stderr').open('xb') as err:
            result=subprocess.run(command,stdout=out,stderr=err)
        report['collector_exit']=result.returncode
        result.check_returncode()
        after,new_starts,_,_=guard('after-collector')
        if new_starts!=starts:raise ValueError('Target process lifetime changed during census')
        if hashlib.sha256(collector.read_bytes()).hexdigest()!=report['collector_sha256']:
            raise ValueError('Collector source changed during operation')
        windows={}
        for phase in ('before','after'):
            text=(a.output/'census'/('system-'+phase+'.txt')).read_text()
            windows[phase]=float(text.split('UPTIME\n')[1].split()[0])
        report.update(state='complete',guard_uptime_after_collector=after,actual_snapshot_uptime=windows,
            scope='Timed sequential no-GC census. Foreground/radios/package/data/cache comparability and physical accounting require separate evidence.')
    except Exception as error:
        report.update(state='failed',error=repr(error));raise
    finally:save()


if __name__=='__main__':main()
