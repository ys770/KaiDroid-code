"""Synthetic lid policy test on the exact Nokia boot; always restore policy/service.

This verifies framework behavior, not a physical hinge movement.
"""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb',required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED']
report=dict(physical_test=False,restored=False)
def shell(label,cmd):
    r=subprocess.run(base+['shell',cmd],capture_output=True,check=True,timeout=20)
    (a.output/(label+'.txt')).write_bytes(r.stdout+r.stderr)
    return r.stdout.decode().replace('\r\n','\n').strip()
def guard(label):
    assert shell(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').splitlines()==['36','00000000-0000-0000-0000-000000000014','0']
def power(label,expected):
    for i in range(10):
        result=shell(label+str(i),'dumpsys power')
        if 'mWakefulness='+expected in result:return
        time.sleep(1)
    raise ValueError('Expected '+expected)
guard('identity')
assert shell('service-before','getprop init.svc.kaidroid-hall') in ('','stopped')
assert shell('hall-before','cat /sys/devices/platform/soc/soc:hall_sensor/hall_status')=='0'
original=shell('setting-before','settings get global lid_behavior')
assert original in ('null','0')
assert 'KaiDroid Nokia Lid' not in shell('inputs-before','cat /proc/bus/input/devices')
event=None
def emit(label,state):
    assert event and re.fullmatch('/dev/input/event[0-9]+',event)
    shell(label,'sendevent '+event+' 5 0 '+str(state)+' && sendevent '+event+' 0 0 0')
try:
    shell('start','start kaidroid-hall');time.sleep(2)
    assert shell('running','getprop init.svc.kaidroid-hall')=='running'
    blocks=shell('inputs-running','cat /proc/bus/input/devices').split('\n\n')
    matches=[b for b in blocks if 'Name="KaiDroid Nokia Lid"' in b]
    assert len(matches)==1
    handlers=[line for line in matches[0].splitlines() if line.startswith('H: Handlers=')]
    assert len(handlers)==1
    names=re.findall(r'\bevent[0-9]+\b',handlers[0]);assert len(names)==1
    event='/dev/input/'+names[0]
    shell('enable-policy','settings put global lid_behavior 1')
    time.sleep(1)
    assert 'getLidBehavior=LID_BEHAVIOR_SLEEP' in shell('policy','dumpsys window policy')
    emit('synthetic-close',1);power('closed-power','Asleep')
    report['synthetic_close_slept']=True
    emit('synthetic-open',0);power('opened-power','Awake')
    report['synthetic_open_woke']=True
except Exception as error:
    report['error']=repr(error)
    raise
finally:
    try:
        guard('cleanup-identity')
        if event:emit('cleanup-open',0)
        shell('restore-setting','settings delete global lid_behavior' if original=='null' else 'settings put global lid_behavior '+original)
        shell('stop','stop kaidroid-hall');time.sleep(2)
        report['restored']=shell('setting-after','settings get global lid_behavior')==original and shell('service-after','getprop init.svc.kaidroid-hall')=='stopped' and 'KaiDroid Nokia Lid' not in shell('inputs-after','cat /proc/bus/input/devices')
        assert report['restored']
    finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
