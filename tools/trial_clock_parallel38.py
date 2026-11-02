"""Hardware-owned Clock38 preflight/new-package install. Never launches or edits alarms."""
import argparse
import json
import re
import subprocess
import uuid
from pathlib import Path
from deliver_stock_apps36 import digest,installed_paths,metadata
from verify_tcl_app_build import PLATFORM_CERT

PACKAGE='com.kaidroid.tclclock'
ORIGINAL='com.android.deskclock'
CANDIDATE_SHA='b14ce4fecfd0bd8285ca455eb8ca679f98ffd334b481c4ca518e53f09842cd19'
FRAMEWORK_SHA='b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f'
ORIGINAL_SHA='2a4672496f6bfa006693d8ccc5ac7617cb4bc64ece82326bc4ec78bbb254d9ec'
ORIGINAL_PATH='/system/product/app/DeskClock/DeskClock.apk'


def packages(text):
    lines=text.splitlines()
    if not lines or any(not re.fullmatch(r'package:[A-Za-z0-9_.]+',s) for s in lines):raise ValueError('Invalid inventory')
    return {s[8:] for s in lines}


def uid(text):
    values=set(re.findall(r'^\s*userId=(\d+)\s*$',text,re.M))
    if len(values)!=1:raise ValueError('Ambiguous UID')
    return int(values.pop())


def require_fresh(inventory,providers):
    if ORIGINAL not in inventory or PACKAGE in inventory:raise ValueError('Expected original present and candidate absent')
    if PACKAGE in providers:raise ValueError('Candidate provider/identity already registered')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('adb','java','build-tools','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--boot',required=True)
    p.add_argument('--install',action='store_true')
    a=p.parse_args();boot=str(uuid.UUID(a.boot))
    if boot!=a.boot:raise ValueError('Canonical boot UUID required')
    a.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    candidate=root/'work/clock-parallel-candidate01/KaiDroidTclClockParallel.apk'
    base=[str(a.adb),'-s','DEVICE_SERIAL_REQUIRED']
    report=dict(image=38,boot=boot,install_requested=a.install,installed=False,launched=False,alarms_modified=False,runtime_verified=False)
    def run(label,cmd,timeout=120):
        try:r=subprocess.run(cmd,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as e:
            (a.output/(label+'.stdout')).write_bytes(e.stdout or b'');(a.output/(label+'.stderr')).write_bytes(e.stderr or b'');report['timed_out_command']=label;raise
        (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
        r.check_returncode();return r.stdout
    def shell(label,cmd):return run(label,base+['shell',cmd]).decode().strip()
    def guard(label):
        for key,cmd,value in [('image','getprop ro.kaidroid.image','38'),('boot','cat /proc/sys/kernel/random/boot_id',boot),('root','id -u','0'),('selinux','getenforce','Enforcing'),('user','am get-current-user','0')]:
            if shell(label+'-'+key,cmd)!=value:raise ValueError('Guard failed: '+key)
        if shell(label+'-framework','sha256sum /system/framework/framework.jar').split()[0]!=FRAMEWORK_SHA:raise ValueError('Wrong framework')
    def inspect(label,path,package):
        metadata(run(label+'-badging',[str(a.build_tools/'aapt.exe'),'dump','badging',str(path)]).decode(),package)
        sig=run(label+'-signature',[str(a.java),'-jar',str(a.build_tools/'lib/apksigner.jar'),'verify','--print-certs',str(path)]).decode()
        certs=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',sig)
        if len(certs)!=1:raise ValueError('Ambiguous signer')
        return certs[0]
    def original_snapshot(label):
        paths=installed_paths(shell(label+'-paths','pm path '+ORIGINAL))
        if paths!=[ORIGINAL_PATH]:raise ValueError('Original APK path changed')
        h=shell(label+'-apk-hash','sha256sum '+ORIGINAL_PATH).split()[0]
        if h!=ORIGINAL_SHA:raise ValueError('Original APK changed')
        details=shell(label+'-package','dumpsys package '+ORIGINAL)
        original_uid=uid(details)
        if original_uid<10000:raise ValueError('Unexpected original UID')
        data={}
        for kind,parent in [('ce','/data/user/0/'),('de','/data/user_de/0/')]:
            path=parent+ORIGINAL
            state=shell(label+'-'+kind+'-state','if test -d '+path+'; then echo present; else echo absent; fi')
            if state not in ('present','absent'):raise ValueError('Unknown data state')
            data[kind]=dict(state=state)
            if state=='present':
                data[kind]['files']=sorted(shell(label+'-'+kind+'-files','find '+path+' -type f -exec sha256sum {} +').splitlines())
                data[kind]['directory']=shell(label+'-'+kind+'-directory','ls -ldZ '+path)
        return dict(paths=paths,sha256=h,uid=original_uid,data=data)
    try:
        if digest(candidate)!=CANDIDATE_SHA:raise ValueError('Candidate changed')
        if inspect('candidate',candidate,PACKAGE)!=PLATFORM_CERT:raise ValueError('Candidate signer mismatch')
        manifest=run('candidate-manifest',[str(a.build_tools/'aapt.exe'),'dump','xmltree',str(candidate),'AndroidManifest.xml']).decode()
        if not re.search(r'android:sharedUserId[^\n]*="android.uid.system"',manifest):raise ValueError('Shared UID missing')
        if not re.search(r'android:authorities[^\n]*="'+re.escape(PACKAGE)+'"',manifest):raise ValueError('Provider identity mismatch')
        guard('preflight')
        inventory=packages(shell('packages-before','pm list packages -u --user 0'))
        providers=shell('providers-before','dumpsys package providers');require_fresh(inventory,providers)
        before=original_snapshot('original-before');report['original_before']=before
        run('original-backup',base+['pull',ORIGINAL_PATH,str(a.output/'original.apk')])
        if digest(a.output/'original.apk')!=ORIGINAL_SHA:raise ValueError('Original backup mismatch')
        if inspect('original',a.output/'original.apk',ORIGINAL)!='a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc':raise ValueError('Original signer mismatch')
        # Confirm shared UID platform signer from the exact framework-res package.
        run('platform-backup',base+['pull','/system/framework/framework-res.apk',str(a.output/'framework-res.apk')])
        if inspect('platform',a.output/'framework-res.apk','android')!=PLATFORM_CERT:raise ValueError('Platform signer mismatch')
        report['preflight_passed']=True
        if not a.install:return
        for kind,parent in [('ce','/data/user/0'),('de','/data/user_de/0')]:
            if before['data'][kind]['state']=='present':
                data=run(kind+'-backup',base+['exec-out','tar','-C',parent,'-cf','-',ORIGINAL])
                (a.output/(kind+'.tar')).write_bytes(data)
                report[kind+'_backup_sha256']=digest(a.output/(kind+'.tar'))
        guard('before-install')
        if original_snapshot('original-preinstall')!=before:raise ValueError('Original changed during backup; stop without install')
        require_fresh(packages(shell('packages-preinstall','pm list packages -u --user 0')),shell('providers-preinstall','dumpsys package providers'))
        result=run('install',base+['install','--user','0',str(candidate)]).decode().strip()
        if not (result=='Success' or result.endswith('\nSuccess')):raise ValueError('Install did not report success')
        report['installed']=True
        guard('after-install')
        after_packages=packages(shell('packages-after','pm list packages -u --user 0'))
        if after_packages-inventory!={PACKAGE} or inventory-after_packages:raise ValueError('Unexpected package alias/inventory change')
        paths=installed_paths(shell('candidate-paths','pm path '+PACKAGE))
        if len(paths)!=1:raise ValueError('Expected exactly one candidate APK')
        run('candidate-installed-pull',base+['pull',paths[0],str(a.output/'installed.apk')])
        if digest(a.output/'installed.apk')!=CANDIDATE_SHA:raise ValueError('Installed hash mismatch')
        inspect('installed',a.output/'installed.apk',PACKAGE)
        details=shell('candidate-package','dumpsys package '+PACKAGE)
        if uid(details)!=1000 or 'android.uid.system' not in details:raise ValueError('Installed shared UID mismatch')
        providers=shell('providers-after','dumpsys package providers')
        if PACKAGE+'/com.android.deskclock.provider.ClockProvider' not in providers:raise ValueError('Provider owner not confirmed')
        after=original_snapshot('original-after');report['original_after']=after
        if after!=before:raise ValueError('Original state changed; inspect retained evidence, no rollback')
        report['identity_verified']=True
        shell('focus-after','dumpsys window')
        run('screen-after',base+['exec-out','screencap','-p'])
    except Exception as e:report['error']=str(e);raise
    finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')


if __name__=='__main__':main()
