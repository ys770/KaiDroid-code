"""Read-only, boot-bound device-tree capture for reserved-memory accounting."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('adb','serial','image','boot'):
        p.add_argument('--'+key,required=True)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    base=[a.adb,'-s',a.serial,'exec-out']
    report=dict(image=a.image,boot=a.boot,same_identity_and_boot=False,reads=[])
    def run(name,command):
        r=subprocess.run(base+[command],capture_output=True,timeout=20)
        (a.output/name).write_bytes(r.stdout)
        (a.output/(name+'.stderr')).write_bytes(r.stderr)
        report['reads'].append(dict(file=name,returncode=r.returncode,
                                   stderr_bytes=len(r.stderr),sha256=hashlib.sha256(r.stdout).hexdigest()))
        r.check_returncode()
        return r.stdout
    def guard(name):
        got=run(name,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u')
        if got.decode().splitlines()!=[a.image,a.boot,'0']: raise RuntimeError('Wrong image/boot/root')
    try:
        guard('identity-before.txt')
        run('device-tree.tar','tar -cf - -C /proc/device-tree .')
        guard('identity-after.txt')
        report['same_identity_and_boot']=True
    finally:
        (a.output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':
    main()
