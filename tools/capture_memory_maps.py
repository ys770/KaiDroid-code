"""Read selected process smaps with image, boot, command and PID-lifetime guards."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('adb','serial','image','boot'):
        p.add_argument('--'+key,required=True)
    p.add_argument('--process',action='append',required=True,help='PID=exact_cmdline_name; at most four')
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--runtime-metadata',action='store_true',help='Record guarded uptime and Enforcing state around the capture')
    a=p.parse_args()
    if len(a.process)>4: p.error('At most four processes per bounded capture')
    targets=[]
    for entry in a.process:
        match=re.fullmatch(r'([1-9][0-9]*)=([A-Za-z0-9_./@:-]+)',entry)
        if not match: p.error('Invalid process specification')
        targets.append((int(match[1]),match[2]))
    a.output.mkdir(parents=True,exist_ok=False)
    base=[a.adb,'-s',a.serial,'exec-out']
    report=dict(image=a.image,boot=a.boot,complete=False,reads=[],processes=[])
    def capture(name,command):
        try:
            r=subprocess.run(base+[command],capture_output=True,timeout=20)
        except subprocess.TimeoutExpired as exc:
            (a.output/(name+'.partial')).write_bytes(exc.stdout or b'')
            raise
        (a.output/(name+'.txt')).write_bytes(r.stdout)
        (a.output/(name+'.stderr')).write_bytes(r.stderr)
        report['reads'].append(dict(name=name,returncode=r.returncode,sha256=hashlib.sha256(r.stdout).hexdigest()))
        r.check_returncode()
        return r.stdout
    def guard(name):
        actual=capture(name,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u')
        if actual.decode().splitlines()!=[a.image,a.boot,'0']: raise RuntimeError('Wrong image/boot/root')
    def start(stat):
        return int(stat.decode().rsplit(')',1)[1].split()[19])
    def metadata(label):
        from summarize_guarded_memory_maps import runtime_metadata
        raw=capture(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; cat /proc/uptime')
        return runtime_metadata(raw.decode(),a.image,a.boot)
    try:
        guard('identity-before')
        if a.runtime_metadata:
            report['runtime_metadata_version']=1
            report['uptime_before']=metadata('metadata-before')
        for pid,name in targets:
            prefix=str(pid)
            before=capture(prefix+'-stat-before',f'cat /proc/{pid}/stat')
            command=capture(prefix+'-cmdline',f'cat /proc/{pid}/cmdline').split(b'\0')[0].decode().strip()
            if command!=name: raise RuntimeError('PID belongs to another command')
            capture(prefix+'-smaps',f'cat /proc/{pid}/smaps')
            after=capture(prefix+'-stat-after',f'cat /proc/{pid}/stat')
            if start(before)!=start(after): raise RuntimeError('PID reused during capture')
            report['processes'].append(dict(pid=pid,command=name,start_ticks=start(before)))
        guard('identity-after')
        if a.runtime_metadata:
            report['uptime_after']=metadata('metadata-after')
            if report['uptime_after']<report['uptime_before']:raise RuntimeError('Uptime moved backwards')
        report['complete']=True
    finally:
        (a.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
