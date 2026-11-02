"""Owner-only bounded49/50 PiP-null lifecycle AFTER completed timed measurement.

Default is read-only preflight. --apply performs three Settings/Home/sleep/wake
cycles; no reboot, install, feature/settings mutation or memory-saving claim.
"""
import argparse,hashlib,json,subprocess,sys,time
from pathlib import Path
from capture_timed_memory_audit import start_ticks
from summarize_wallpaper_pair import surface_rows

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--adb',required=True)
    for n in ['protocol','freeze','bundle','output']:p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--apply',action='store_true');a=p.parse_args()
    arm=json.loads((a.protocol/'protocol.json').read_text());timing=json.loads((a.protocol/'timed/timing.json').read_text())
    if arm['image'] not in ['49','50'] or not arm['complete'] or arm.get('error') or arm['timed_exit']!=0 or arm['observer_exit']!=0 or timing['state']!='complete':raise ValueError('Require complete successful49/50 timed arm')
    image=arm['image'];boot=arm['boot'];pids=list(map(int,arm['measurement_pids']));a.output.mkdir(parents=True,exist_ok=False)
    report=dict(image=image,boot=boot,complete=False,apply=a.apply,after_timed_measurement=True,commands=[],screens=[],cleanup_complete=False)
    def run(n,args):
        cmd=[a.adb,'-s','DEVICE_SERIAL_REQUIRED',*args];r=subprocess.run(cmd,capture_output=True,timeout=30)
        (a.output/(n+'.stdout')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr)
        report['commands'].append(dict(name=n,argv=cmd,exit=r.returncode,sha256=hashlib.sha256(r.stdout).hexdigest()))
        if r.returncode or r.stderr:raise ValueError('Command failed: '+n)
        return r.stdout
    def sh(n,c):return run(n,['shell','-T',c]).decode().replace('\r','').strip()
    def identity(n):
        rows=sh(n,f'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui; cat /proc/uptime; cat /proc/{pids[0]}/stat /proc/{pids[1]}/stat').splitlines()
        if len(rows)!=9 or rows[:6]!=[image,boot,'0','Enforcing',*map(str,pids)] or [start_ticks(rows[7+i],pids[i]) for i in range(2)]!=timing['process_start_ticks'] or float(rows[6].split()[0])<timing['actual_snapshot_uptime']['after']:raise ValueError('Identity/lifetime/census ordering differs')
    def guard(n):
        cmd=[sys.executable,str(Path(__file__).with_name('guard_pip_trial.py')),'--adb',a.adb,'--image',image,'--boot',boot,'--freeze',str(a.freeze),'--bundle',str(a.bundle),'--protocol',str(a.protocol),'--output',str(a.output/n)]
        r=subprocess.run(cmd,capture_output=True);(a.output/(n+'.console')).write_bytes(r.stdout+r.stderr);r.check_returncode()
        if not json.loads((a.output/n/'result.json').read_text())['complete']:raise ValueError('PiP guard incomplete')
    def home(n):
        identity(n+'-identity');window=sh(n+'-window','dumpsys window')
        if not any('mCurrentFocus=' in line and 'com.android.launcher3/com.android.launcher3.Launcher' in line for line in window.splitlines()):raise ValueError('Launcher focus differs')
        power=sh(n+'-power','dumpsys power')
        if 'mWakefulness=Awake' not in power:raise ValueError('Display not awake')
        surface=surface_rows(sh(n+'-surfaceflinger','dumpsys SurfaceFlinger'))
        if any((r['width'],r['height'],r['format'])!=(429,353,3) for r in surface):raise ValueError('Wallpaper geometry differs')
        raw=run(n+'-screenshot',['exec-out','screencap','-p']);path=a.output/(n+'.png');path.write_bytes(raw);report['screens'].append(dict(path=path.name,sha256=hashlib.sha256(raw).hexdigest()))
    input_started=False
    report['source_sha256']={n:hashlib.sha256(Path(__file__).with_name(n).read_bytes()).hexdigest() for n in ('trial_pip_lifecycle.py','guard_pip_trial.py')}
    try:
        identity('initial');guard('before-guard');home('initial-home')
        if a.apply:
            for i in range(3):
                identity('cycle'+str(i)+'-before')
                input_started=True
                launched=sh('cycle'+str(i)+'-settings','am start -W -a android.settings.SETTINGS')
                if 'Status: ok' not in launched or 'Error:' in launched:raise ValueError('Settings launch failed')
                window=sh('cycle'+str(i)+'-settings-window','dumpsys window')
                if not any('mCurrentFocus=' in line and 'com.android.settings/' in line for line in window.splitlines()):raise ValueError('Settings focus differs')
                sh('cycle'+str(i)+'-home','am start -W -n com.android.launcher3/.Launcher');home('cycle'+str(i)+'-home')
                sh('cycle'+str(i)+'-sleep','input keyevent 223');time.sleep(3)
                sh('cycle'+str(i)+'-wake','input keyevent 224');time.sleep(3)
                sh('cycle'+str(i)+'-launcher','am start -W -n com.android.launcher3/.Launcher');home('cycle'+str(i)+'-wake')
            guard('after-guard')
        report['complete']=True
    except BaseException as error:
        report['error']=repr(error);raise
    finally:
        if a.apply and input_started:
            try:
                identity('cleanup-identity');sh('cleanup-wake','input keyevent 224');sh('cleanup-home','am start -W -n com.android.launcher3/.Launcher');home('cleanup-home');guard('cleanup-guard');report['cleanup_complete']=True
            except BaseException as error:report['cleanup_error']=repr(error);report['complete']=False
        else:report['cleanup_complete']=not input_started
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    if not report['complete'] or not report['cleanup_complete']:raise ValueError('Lifecycle incomplete; inspect existing operation, do not restart')
    print(json.dumps(report))

if __name__=='__main__':main()
