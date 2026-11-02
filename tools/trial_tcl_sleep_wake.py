"""Record donor Home/sleep/wake without dismissal, settings writes or credentials."""
import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from capture_tcl_ui_reference import capture, SERIAL, FINGERPRINT


def trial(adb, output):
    output.mkdir(parents=True, exist_ok=False)
    report=dict(physical_input=False, completed=False, dismissal_command_used=False)
    def shell(label, command):
        r=subprocess.run([str(adb),'-s',SERIAL,'shell',command],capture_output=True,timeout=40)
        (output/(label+'.stdout')).write_bytes(r.stdout)
        (output/(label+'.stderr')).write_bytes(r.stderr)
        if r.returncode:raise RuntimeError(label+' failed')
        return r.stdout.decode().strip()
    try:
        if shell('identity','getprop ro.build.fingerprint') != FINGERPRINT:raise ValueError('Wrong donor')
        boot=shell('boot','cat /proc/sys/kernel/random/boot_id')
        report['boot_id']=boot
        report['lockscreen_disabled']=shell('lock-disabled','su -c "locksettings get-disabled"')
        capture(adb,output/'before-home',3)
        shell('before-policy','dumpsys window policy')
        shell('sleep','input keyevent 223')
        time.sleep(2)
        sleeping=shell('sleep-power','dumpsys power')
        report['sleep_observed']=bool(re.search(r'mWakefulness=Asleep\b',sleeping))
        shell('sleep-policy','dumpsys window policy')
        shell('wake','input keyevent 224')
        time.sleep(3)
        capture(adb,output/'after-wake')
        policy=shell('after-policy','dumpsys window policy')
        if 'KeyguardServiceDelegate' not in policy:raise ValueError('Missing keyguard state section')
        section=policy.split('KeyguardServiceDelegate',1)[1]
        report['keyguard_showing']=bool(re.search(r'^\s+showing=true\s*$',section,re.M))
        report['keyguard_not_showing']=bool(re.search(r'^\s+showing=false\s*$',section,re.M))
        if shell('boot-after','cat /proc/sys/kernel/random/boot_id') != boot:raise ValueError('Boot changed')
        report['completed']=True
    except Exception as error:
        report['error']=str(error)
        raise
    finally:
        (output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    return report

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(trial(a.adb,a.output)))
