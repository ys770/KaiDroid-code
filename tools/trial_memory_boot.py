"""One authorized warm reboot, repeatable startup handling, and 300s no-GC census.

Default preflights only. --reboot requires an exclusive model-owner window.
No flash, package/policy changes, forced GC, or automatic reboot retries.
"""
import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path


def hashes(text):
    result={}
    for line in text.splitlines():
        digest,path=line.split(None,1)
        if not re.fullmatch('[0-9a-f]{64}',digest) or not path.startswith('/') or path in result:
            raise ValueError('Malformed APK hash list')
        result[path]=digest
    if len(result)!=6:raise ValueError('Require the six frozen APK paths')
    return result


def wait_button(xml):
    root=ET.fromstring(xml)
    nodes=[n for n in root.iter('node') if n.get('resource-id')=='android:id/aerr_wait']
    if not nodes:return None
    if len(nodes)!=1 or 'System UI' not in xml or nodes[0].get('enabled')!='true':
        raise ValueError('Unexpected/disabled ANR dialog; no input issued')
    match=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',nodes[0].get('bounds',''))
    if not match:raise ValueError('Invalid Wait button bounds')
    left,top,right,bottom=map(int,match.groups())
    if not 0<=left<right<=240 or not 0<=top<bottom<=320:raise ValueError('Wait button outside target display')
    return (left+right)//2,(top+bottom)//2


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','image','initial-boot'):p.add_argument('--'+name,required=True)
    p.add_argument('--apk-hashes',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--madvise-random',choices=('unset','false','true'),help='Also guard low_ram and effective VM property throughout the arm')
    p.add_argument('--reboot',action='store_true');a=p.parse_args()
    if a.image not in ('42','43','44') or not re.fullmatch(r'[a-f0-9-]{36}',a.initial_boot):p.error('Exact approved image/boot required')
    if a.image=='44' and a.madvise_random!='true':p.error('Image44 requires explicit true VM-property guard')
    if shutil.disk_usage(a.output.parent.resolve()).free<512*1024*1024:p.error('Reserve at least512MiB for evidence')
    expected=hashes(a.apk_hashes.read_text(encoding='utf-8-sig'));a.output.mkdir(parents=True,exist_ok=False)
    tools=Path(__file__).parent
    sources={name:hashlib.sha256((tools/name).read_bytes()).hexdigest() for name in
             ('trial_memory_boot.py','observe_startup_light.py','capture_timed_memory_audit.py','audit_memory.py')}
    report=dict(image=a.image,initial_boot=a.initial_boot,reboot_requested=a.reboot,source_sha256=sources,
                complete=False,no_gc=True,policy_changed=False,steps=[],observer_exit=None)
    report['expected_madvise_random']=a.madvise_random
    base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED'];observer=None;console=None;boot=a.initial_boot;sequence=0
    def save():(a.output/'protocol.json').write_text(json.dumps(report,indent=2)+'\n')
    def run(label,args,timeout=25,check=True):
        nonlocal sequence
        sequence+=1;name=f'{sequence:03d}-{label}';start=time.monotonic()
        result=subprocess.run(args,capture_output=True,timeout=timeout)
        (a.output/(name+'.stdout')).write_bytes(result.stdout);(a.output/(name+'.stderr')).write_bytes(result.stderr)
        report['steps'].append(dict(label=label,argv=args,returncode=result.returncode,seconds=time.monotonic()-start,
                                    stdout=name+'.stdout',stderr=name+'.stderr',sha256=hashlib.sha256(result.stdout).hexdigest()));save()
        if check:result.check_returncode()
        return result.stdout.decode().replace('\r\n','\n').strip(),result.returncode
    def shell(label,command,**kwargs):return run(label,base+['shell','-T',command],**kwargs)[0]
    def guard(label,allow_new=False):
        command='getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; cat /proc/uptime'
        if a.madvise_random is not None:
            command+='; getprop ro.config.low_ram; printf "VM_HINT="; getprop dalvik.vm.madvise-random'
        lines=shell(label,command).splitlines()
        if len(lines)!=(7 if a.madvise_random is not None else 5) or lines[0]!=a.image or lines[2:4]!=['0','Enforcing'] or (not allow_new and lines[1]!=boot):
            raise ValueError('Wrong image/boot/access state')
        if a.madvise_random is not None:
            expected_hint='' if a.madvise_random=='unset' else a.madvise_random
            if lines[5:]!=['true','VM_HINT='+expected_hint]:raise ValueError('Wrong low-RAM/VM-property state')
        return lines[1],float(lines[4].split()[0]),time.monotonic()
    config='; '.join('settings get '+kind+' '+key for kind,key in [('global','wifi_on'),('global','bluetooth_on'),('global','airplane_mode_on'),('global','stay_on_while_plugged_in'),('system','screen_off_timeout'),('system','screen_brightness'),('system','screen_brightness_mode'),('secure','default_input_method')])
    hash_command='sha256sum '+' '.join(shlex.quote(path) for path in expected)
    try:
        guard('initial-identity')
        if hashes(shell('initial-apks',hash_command))!=expected:raise ValueError('APK baseline differs')
        initial_config=shell('initial-configuration',config);report['initial_configuration']=initial_config;save()
        if not a.reboot:report['complete']=True;return
        run('one-reboot',base+['reboot'])
        for _ in range(20):
            _,code=run('disconnect',base+['get-state'],check=False)
            if code:break
            time.sleep(.5)
        else:raise ValueError('Disconnect not observed; do not repeat reboot')
        console=(a.output/'startup-console.txt').open('xb')
        observer=subprocess.Popen([sys.executable,str(tools/'observe_startup_light.py'),'--adb',a.adb,
            '--output',str(a.output/'startup'),'--seconds','180','--image',a.image,'--pressure','--process-io'],stdout=console,stderr=subprocess.STDOUT)
        report['observer_pid']=observer.pid;save()
        deadline=time.monotonic()+120
        while True:
            try:new_boot,uptime,reference=guard('new-boot',allow_new=True)
            except (ValueError,subprocess.CalledProcessError,subprocess.TimeoutExpired):
                if time.monotonic()>=deadline:raise
                time.sleep(2);continue
            if new_boot==a.initial_boot:raise ValueError('Old boot remained; never repeat reboot')
            boot=new_boot;report['boot']=boot;save();print(json.dumps(dict(state='boot_observed',boot=boot,uptime=uptime,observer_pid=observer.pid)),flush=True);break
        def age(target):
            until=reference+target-uptime
            while time.monotonic()<until:time.sleep(min(1,until-time.monotonic()))
            _,actual,_=guard('age'+str(target))
            report.setdefault('intervention_ages',{})[str(target)]=actual;save()
            if abs(actual-target)>2:raise ValueError('Intervention deadline missed')
        age(200)
        if observer.poll()!=0:raise ValueError('Startup observer not terminal0 at intervention')
        report['observer_exit']=0
        remote='/data/local/tmp/kv_memory_boot_'+a.image+'.xml'
        shell('ui-dump','uiautomator dump '+remote,timeout=25)
        xml=shell('ui-hierarchy','cat '+remote);button=wait_button(xml)
        report['anr_wait_button']=button;save()
        if button:shell('systemui-anr-wait',f'input tap {button[0]} {button[1]}')
        age(220);shell('wake','input keyevent 224')
        shell('launcher','am start -W -n com.android.launcher3/.Launcher')
        focus=shell('launcher-focus','dumpsys window')
        focus_lines=[line for line in focus.splitlines() if 'mCurrentFocus=' in line]
        if not focus_lines or 'com.android.launcher3/com.android.launcher3.Launcher' not in focus_lines[-1]:raise ValueError('Launcher not foreground')
        age(230);pids=shell('measurement-processes','pidof system_server; pidof com.android.systemui; getprop sys.boot_completed').splitlines()
        if len(pids)!=3 or pids[2]!='1' or not all(re.fullmatch('[1-9][0-9]*',pid) for pid in pids[:2]):raise ValueError('System processes/boot incomplete')
        report['measurement_pids']=pids[:2];save();print(json.dumps(dict(state='arming_300s_census',boot=boot,pids=pids[:2])),flush=True)
        command=[sys.executable,str(tools/'capture_timed_memory_audit.py'),'--adb',a.adb,'--serial','DEVICE_SERIAL_REQUIRED','--image',a.image,'--boot',boot,
            '--system-server-pid',pids[0],'--systemui-pid',pids[1],'--target-uptime','300','--output',str(a.output/'timed')]
        with (a.output/'timed.stdout').open('xb') as out,(a.output/'timed.stderr').open('xb') as error:
            child=subprocess.run(command,stdout=out,stderr=error)
        report['timed_exit']=child.returncode;save();child.check_returncode()
        guard('terminal-identity')
        if hashes(shell('terminal-apks',hash_command))!=expected or shell('terminal-configuration',config)!=initial_config:
            raise ValueError('APK/configuration changed during protocol')
        shell('terminal-window','dumpsys window windows');shell('terminal-power','dumpsys power')
        for name,digest in sources.items():
            if hashlib.sha256((tools/name).read_bytes()).hexdigest()!=digest:raise ValueError('Frozen tool source changed')
        report['complete']=True
    except BaseException as error:report['error']=repr(error);raise
    finally:
        if observer is not None:report['observer_exit']=observer.wait()
        if console is not None:console.close()
        save()
    print(json.dumps(dict(state='complete',image=a.image,boot=boot)),flush=True)


if __name__=='__main__':main()
