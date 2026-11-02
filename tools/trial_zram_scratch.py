"""Journaled fresh-zramN compression screen. Default is read-only preflight.

Use --apply only in an assigned exclusive hardware window after plan review.
Never resets/swaps/offlines zram0, enables swap, or writes a storage partition.
An uncertain timeout leaves the owned device recorded for inspection, not retried.
"""
import argparse
import hashlib
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

PROBE_SHA='bf5bf2720a0755607ebd92df1737484d132210d9949b9146fc576008117aa75a'


def process_identity(pid,stat):
    if stat.split(' ',1)[0]!=pid:raise ValueError('Process stat identity mismatch')
    return pid,stat.rsplit(')',1)[1].split()[19]


def device_ids(text):
    result=set()
    for line in text.splitlines():
        match=re.fullmatch(r'/sys/block/zram([0-9]+)',line)
        if not match:raise ValueError('Unexpected zram inventory output')
        result.add(int(match[1]))
    if 0 not in result:raise ValueError('Active zram0 missing')
    return result


def new_device(before,returned,after):
    if not re.fullmatch(r'[0-9]+',returned.strip()):raise ValueError('Uncertain allocation receipt')
    index=int(returned)
    if not 1<=index<=31 or index in before or after!=before|{index}:
        raise ValueError('New device identity/ownership ambiguous')
    return index


def swap_configuration(text):
    lines=text.splitlines()
    if not lines or lines[0].split()!=['Filename','Type','Size','Used','Priority']:
        raise ValueError('Missing swaps header')
    rows=[]
    for line in lines[1:]:
        fields=line.split()
        if len(fields)!=5:raise ValueError('Malformed swaps output')
        rows.append((fields[0],fields[1],int(fields[2]),int(fields[4])))
    return sorted(rows)  # Used bytes vary while Android continues running.


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','serial','image','boot'):p.add_argument('--'+name,required=True)
    p.add_argument('--probe',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    if a.serial!='DEVICE_SERIAL_REQUIRED' or not a.image.isdigit() or not re.fullmatch(r'[a-f0-9-]{36}',a.boot):
        p.error('Exact engineering Nokia image/boot required')
    if hashlib.sha256(a.probe.read_bytes()).hexdigest()!=PROBE_SHA:p.error('Unexpected probe binary')
    a.output.mkdir(parents=True,exist_ok=False)
    base=[a.adb,'-s',a.serial]
    remote='/data/local/tmp/kz'+uuid.uuid4().hex[:12]  # Linux comm limit is 15 bytes.
    report=dict(image=a.image,boot=a.boot,apply=a.apply,probe_sha256=PROBE_SHA,
        phases=[],complete=False,owned_device_pending=None,uncertain_operation=False,
        remote_probe=remote,active_swap_changed=False)
    sequence=0
    original_ids=None;zero=None;swaps=None;owned=None
    def save():
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(label,args,timeout=20,check=True):
        nonlocal sequence
        sequence+=1;name=f'{sequence:03d}-{label}'
        event=dict(label=label,argv=args,started_monotonic=time.monotonic(),
                   sequence=sequence,stdout_file=name+'.txt',stderr_file=name+'.stderr')
        with (a.output/'journal.jsonl').open('a') as f:
            f.write(json.dumps(dict(event,state='started'))+'\n');f.flush()
        try:r=subprocess.run(args,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (a.output/(name+'.partial')).write_bytes(error.stdout or b'')
            (a.output/(name+'.partial.stderr')).write_bytes(error.stderr or b'')
            report['uncertain_operation']=True;event['timeout']=True
            with (a.output/'journal.jsonl').open('a') as f:f.write(json.dumps(event)+'\n')
            save();raise RuntimeError('Timeout: inspect existing operation/device; do not retry') from error
        (a.output/(name+'.txt')).write_bytes(r.stdout);(a.output/(name+'.stderr')).write_bytes(r.stderr)
        event.update(returncode=r.returncode,sha256=hashlib.sha256(r.stdout).hexdigest(),
                     seconds=time.monotonic()-event['started_monotonic'])
        with (a.output/'journal.jsonl').open('a') as f:f.write(json.dumps(event)+'\n')
        if r.returncode and any(s in r.stderr.lower() for s in (b'device offline',b'error: closed',b'no devices')):
            report['uncertain_operation']=True;save()
        if check:r.check_returncode()
        # Windows adb shell-v2 returns CRLF; preserve raw bytes above, normalize parsing only.
        return r.stdout.decode().replace('\r\n','\n').strip(),r.returncode,r.stderr.decode(errors='replace').replace('\r\n','\n')
    # shell-v2 retains remote exit status/stderr; exec-out did neither on this device.
    def shell(label,command,**kwargs):return run(label,base+['shell','-T',command],**kwargs)[0]
    def guard(label,processes=True):
        lines=shell(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui; for p in $(pidof system_server) $(pidof com.android.systemui); do cat /proc/$p/stat; done').splitlines()
        if lines[:4]!=[a.image,a.boot,'0','Enforcing']:raise ValueError('Wrong device/access state')
        if not processes:return []
        if len(lines)!=8 or not all(re.fullmatch(r'[1-9][0-9]*',s) for s in lines[4:6]):
            raise ValueError('Missing/ambiguous system processes')
        identities=[process_identity(lines[i+4],lines[i+6]) for i in range(2)]
        if identities!=report.get('system_processes',identities):raise ValueError('System process lifetime changed')
        return identities
    def ids(label):return device_ids(shell(label,'ls -d /sys/block/zram[0-9]*'))
    def zero_state(label):
        lines=shell(label,'cat /sys/block/zram0/comp_algorithm; cat /sys/block/zram0/disksize').splitlines()
        if len(lines)!=2 or len(re.findall(r'\[[a-z0-9_-]+\]',lines[0]))!=1 or not lines[1].isdigit() or int(lines[1])<=0:
            raise ValueError('Malformed active zram0 state')
        return lines
    def available(label):
        text=shell(label,'cat /proc/meminfo')
        match=re.search(r'^MemAvailable:\s+(\d+) kB$',text,re.M)
        if not match or int(match[1])<65536:raise ValueError('Insufficient available memory for scratch test')
    def no_probe(label):
        text,code,_=run(label,base+['shell','-T','pidof '+Path(remote).name],check=False)
        if code not in (0,1) or text:raise ValueError('Probe process remains/unknown; stop before cleanup')
    def unused(index,identity,label):
        maj,min_=identity
        if shell(label+'-identity',f'cat /sys/block/zram{index}/dev')!=f'{maj}:{min_}':raise ValueError('Owned device changed')
        text=shell(label+'-mounts','cat /proc/self/mountinfo')
        if any(len(row.split())>2 and row.split()[2]==f'{maj}:{min_}' for row in text.splitlines()):
            raise ValueError('Owned device became mounted')
        text=shell(label+'-swaps','cat /proc/swaps')
        # Reject every changed swap path/configuration, including aliases of N.
        if swap_configuration(text)!=swaps:raise ValueError('Swap configuration changed')
    def cleanup():
        nonlocal owned
        if owned is None or report['uncertain_operation']:return
        index,identity=owned
        guard('cleanup-guard',processes=False);no_probe('cleanup-no-probe')
        unused(index,identity,'cleanup-unused')
        if zero_state('cleanup-zram0')!=zero:raise ValueError('Active zram0 configuration changed')
        report['removal_pending']=index;save()
        try:shell('remove-owned',f"printf '{index}\\n' > /sys/class/zram-control/hot_remove")
        except Exception:
            report['uncertain_operation']=True;save();raise
        if ids('after-remove')!=original_ids:raise ValueError('Device inventory not restored')
        owned=None;report['owned_device_pending']=None;report['removal_pending']=None;save()
        shell('after-remove-kernel','cat /proc/meminfo; cat /proc/vmallocinfo; cat /sys/devices/system/cpu/online')
    try:
        report['system_processes']=guard('initial-guard')
        original_ids=ids('initial-devices');zero=zero_state('initial-zram0')
        swaps=swap_configuration(shell('initial-swaps','cat /proc/swaps'))
        available('initial-memory');shell('initial-cpus','cat /sys/devices/system/cpu/online')
        shell('initial-mounts','cat /proc/self/mountinfo')
        report.update(initial_devices=sorted(original_ids),zram0_configuration=zero,swap_configuration=swaps)
        if a.apply:
            run('push-probe',base+['push',str(a.probe),remote],timeout=60)
            if shell('probe-hash','sha256sum '+remote).split()[0]!=PROBE_SHA:raise ValueError('Staged probe mismatch')
            shell('probe-mode','chmod 0700 '+remote)
            _,code,error=run('probe-index0-control',base+['shell','-T',remote+' 0 0 0 mixed --write'],check=False)
            if code!=1 or 'zram0/invalid index forbidden' not in error:raise ValueError('Runtime negative control failed')
            for phase,algorithm in enumerate(('lzo','zstd','zstd','lzo')):
                guard(f'phase{phase}-guard');available(f'phase{phase}-memory')
                if ids(f'phase{phase}-before')!=original_ids:raise ValueError('Concurrent zram allocation')
                shell(f'phase{phase}-before-kernel','cat /proc/meminfo; cat /proc/vmallocinfo; cat /sys/devices/system/cpu/online')
                report['allocation_pending']=dict(phase=phase,before=sorted(original_ids));save()
                returned=shell(f'phase{phase}-hot-add','cat /sys/class/zram-control/hot_add')
                report['allocation_pending']['receipt']=returned;save()
                index=new_device(original_ids,returned,ids(f'phase{phase}-after'))
                dev=shell(f'phase{phase}-identity',f'cat /sys/block/zram{index}/dev')
                if not re.fullmatch(r'[0-9]+:[0-9]+',dev):raise ValueError('Bad new device major/minor')
                identity=tuple(map(int,dev.split(':')));owned=(index,identity)
                report['owned_device_pending']=dict(index=index,major=identity[0],minor=identity[1]);save()
                report['allocation_pending']=None;save()
                unused(index,identity,f'phase{phase}-unused')
                if shell(f'phase{phase}-uninitialized',f'cat /sys/block/zram{index}/initstate')!='0':raise ValueError('New device already initialized')
                shell(f'phase{phase}-algorithm',f"printf '{algorithm}\\n' > /sys/block/zram{index}/comp_algorithm")
                shell(f'phase{phase}-size',f"printf '4194304\\n' > /sys/block/zram{index}/disksize")
                selected=shell(f'phase{phase}-selected',f'cat /sys/block/zram{index}/comp_algorithm')
                if f'[{algorithm}]' not in selected:raise ValueError('Compressor not selected')
                shell(f'phase{phase}-initialized',f'cat /sys/block/zram{index}/mm_stat; cat /proc/meminfo; cat /proc/vmallocinfo; cat /sys/devices/system/cpu/online')
                command=f'{remote} {index} {identity[0]} {identity[1]} mixed'
                pre=json.loads(shell(f'phase{phase}-preflight',command))
                if pre.get('wrote') is not False or pre.get('index')!=index or pre.get('bytes')!=4194304:raise ValueError('Probe preflight failed')
                guard(f'phase{phase}-write-guard')
                result=json.loads(shell(f'phase{phase}-write',command+' --write',timeout=60))
                if result.get('readback_verified') is not True or result.get('index')!=index or result.get('bytes')!=4194304:
                    raise ValueError('Probe result mismatch')
                shell(f'phase{phase}-stats',f'cat /sys/block/zram{index}/mm_stat; cat /proc/meminfo; cat /proc/vmallocinfo; cat /sys/devices/system/cpu/online')
                report['phases'].append(dict(phase=phase,algorithm=algorithm,result=result));save()
                cleanup()
            if len({p['result']['checksum'] for p in report['phases']})!=1:raise ValueError('Corpus differs between phases')
        guard('final-guard')
        if ids('final-devices')!=original_ids or zero_state('final-zram0')!=zero or swap_configuration(shell('final-swaps','cat /proc/swaps'))!=swaps:
            report['active_swap_changed']=True;raise ValueError('Device/swap configuration changed')
        report['complete']=True
    except Exception as error:
        report['error']=repr(error)
        if report.get('allocation_pending') or report.get('removal_pending'):
            report['uncertain_operation']=True
        try:cleanup()
        except Exception as cleanup_error:report['cleanup_error']=repr(cleanup_error)
        raise
    finally:save()
    print(json.dumps(report))


if __name__=='__main__':main()
