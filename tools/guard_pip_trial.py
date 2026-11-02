"""Read-only49/50 freeze guard; targeted PiP dump is allowed only AFTER a complete census."""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
from capture_timed_memory_audit import start_ticks

BASE_UI='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
NEW_UI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
FRAMEWORK='2edb5df3faad0cc29ec0740c7e89609ed31b4f2c0632004bde0831dfbabd2a68'

def pip_dump(text,image):
    if 'com.android.systemui.pip.PipUI' not in text or 'No services match' in text:raise ValueError('Targeted PipUI dump not established')
    count=len(re.findall(r'^\s*PipManager\s*$',text,re.M))
    if count!=(1 if image=='49' else 0):raise ValueError('Wrong baseline/candidate manager dump control')
    return count

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['adb','boot']:p.add_argument('--'+n,required=True)
    p.add_argument('--image',choices=['49','50'],required=True)
    for n in ['freeze','bundle','output']:p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--protocol',type=Path,help='Complete timed arm; required before targeted service diagnostic')
    a=p.parse_args()
    if not re.fullmatch('[a-f0-9-]{36}',a.boot):p.error('Exact boot UUID required')
    m=json.loads((a.freeze/'manifest.json').read_text());bundle=json.loads((a.bundle/'protocol.json').read_text())
    if m['image']!=49 or bundle['data_apk_count']!=19:raise ValueError('Wrong freeze/bundle')
    for n,h in m['files'].items():
        if hashlib.sha256((a.freeze/n).read_bytes()).hexdigest()!=h:raise ValueError('Freeze changed')
    for n,h in bundle['source05_sha256'].items():
        if hashlib.sha256((a.bundle/'tools'/n).read_bytes()).hexdigest()!=h:raise ValueError('Bundle changed')
    timing=None;arm=None
    if a.protocol:
        arm=json.loads((a.protocol/'protocol.json').read_text());timing=json.loads((a.protocol/'timed/timing.json').read_text())
        if not arm['complete'] or arm.get('error') or arm['timed_exit']!=0 or arm['observer_exit']!=0 or timing['state']!='complete' or arm['boot']!=a.boot or arm['image']!=a.image or arm['source_sha256']!=bundle['source05_sha256']:raise ValueError('Require exact successful05 arm before diagnostic')
    a.output.mkdir(parents=True,exist_ok=False);report=dict(image=a.image,boot=a.boot,complete=False,read_only=True,post_census=bool(a.protocol),files={},commands=[])
    def capture(n,command,expected=0):
        argv=[a.adb,'-s','DEVICE_SERIAL_REQUIRED','shell','-T',command];r=subprocess.run(argv,capture_output=True,timeout=30)
        (a.output/(n+'.txt')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr)
        report['files'][n+'.txt']=hashlib.sha256(r.stdout).hexdigest();report['commands'].append(dict(name=n,argv=argv,exit=r.returncode))
        if r.returncode!=expected or r.stderr:raise ValueError('Unexpected command exit/stderr: '+n)
        return r.stdout.decode().replace('\r','').strip()
    def identity(n):
        text=capture(n,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui; cat /proc/uptime; server=$(pidof system_server); ui=$(pidof com.android.systemui); cat /proc/$server/stat /proc/$ui/stat');r=text.splitlines()
        if len(r)!=9 or r[:4]!=[a.image,a.boot,'0','Enforcing'] or not all(x.isdecimal() for x in r[4:6]):raise ValueError('Identity differs')
        values=[int(x) for x in r[4:6]];starts=[start_ticks(r[i+7],values[i]) for i in range(2)];age=float(r[6].split()[0])
        if timing and (values!=list(map(int,arm['measurement_pids'])) or starts!=timing['process_start_ticks'] or age<timing['actual_snapshot_uptime']['after']):raise ValueError('Post-census process lifetime/order differs')
        return values,starts,age
    try:
        before=identity('before')
        config=capture('configuration','settings get system screen_off_timeout; settings get system screen_brightness; settings get system screen_brightness_mode; settings get system accelerometer_rotation; settings get system user_rotation; settings get global stay_on_while_plugged_in; settings get global low_power; settings get secure default_input_method; getprop ro.config.low_ram; getprop dalvik.vm.madvise-random; wm size; wm density')
        if config!=(a.freeze/'configuration.txt').read_text().replace('\r','').strip():raise ValueError('Configuration differs')
        paths={'/system/framework/framework.jar':FRAMEWORK,'/system/framework/framework-res.apk':'42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72','/system/framework/services.jar':'4de4b26bf3bd698b4a6033fa13992a333e6ec0a469ab76caadb7b15c356f103d','/system/priv-app/TelephonyProvider/TelephonyProvider.apk':'704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c','/system/system_ext/priv-app/SystemUI/SystemUI.apk':BASE_UI if a.image=='49' else NEW_UI,'/data/system/users/0/wallpaper_info.xml':'52c1295a96020f70fe68bbed8ef3f7884730a0c17845b1187179d1467040a2db'}
        actual={line.split(None,1)[1]:line.split()[0] for line in capture('assets','sha256sum '+' '.join(paths)).splitlines()}
        if actual!=paths:raise ValueError('Protected live inputs differ')
        if capture('feature','pm has-feature android.software.picture_in_picture',expected=1)!='false':raise ValueError('PiP feature is not false')
        if capture('wallpaper-paths','find /data/system/users/0 -maxdepth 1 -name "wallpaper*"')!='/data/system/users/0/wallpaper_info.xml' or capture('wallpaper-properties','getprop ro.config.wallpaper; getprop ro.config.lock_wallpaper'):raise ValueError('Wallpaper selection changed')
        cmd=[sys.executable,str(a.bundle/'tools/capture_data_apk_guard.py'),'--adb',a.adb,'--image',a.image,'--boot',a.boot,'--expected',str(a.bundle/'retained-data-apks.txt'),'--core-apk-hashes',str(a.bundle/('image'+a.image+'-core-apks.txt')),'--output',str(a.output/'data-apks')]
        result=subprocess.run(cmd,capture_output=True);(a.output/'data-guard.stdout').write_bytes(result.stdout);(a.output/'data-guard.stderr').write_bytes(result.stderr);result.check_returncode()
        data_result=json.loads((a.output/'data-apks/result.json').read_text())
        if result.stderr or data_result.get('complete') is not True or data_result.get('apk_count')!=19 or data_result.get('expected_match') is not True:raise ValueError('Full19 guard incomplete')
        if a.protocol:report['pip_manager_dump_count']=pip_dump(capture('pip-service','dumpsys activity service com.android.systemui/.SystemUIService com.android.systemui.pip.PipUI'),a.image)
        after=identity('after')
        if before[:2]!=after[:2] or after[2]<before[2]:raise ValueError('Process changed within guard')
        report.update(complete=True,guard_uptime=[before[2],after[2]],processes=before[0],start_ticks=before[1])
    finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__=='__main__':main()
