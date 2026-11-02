"""Observe a bounded physical hinge window; restore lid setting and stop adapter."""
import argparse,hashlib,json,subprocess,time,uuid
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb',required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED']
report=dict(image=47,physical_transition_observed=False,restored=False,samples=[])
def sh(name,command):
 r=subprocess.run(base+['shell',command],capture_output=True,timeout=20)
 (a.output/(name+'.stdout')).write_bytes(r.stdout)
 (a.output/(name+'.stderr')).write_bytes(r.stderr)
 r.check_returncode();return r.stdout.decode().replace('\r','').strip()
def guard(name):
 if sh(name,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui').splitlines()!=['47','00000000-0000-0000-0000-000000000010','0','Enforcing','1169','1360']:
  raise ValueError('Handset boot/process identity changed')
guard('before')
original=sh('setting-before','settings get global lid_behavior')
if original!='0' or sh('service-before','getprop init.svc.kaidroid-hall') not in ('','stopped'):
 raise ValueError('Unexpected policy/service prestate')
if sh('hall-before','cat /sys/devices/platform/soc/soc:hall_sensor/hall_status')!='0':
 raise ValueError('Start with hinge open')
if 'KaiDroid Nokia Lid' in sh('inputs-before','cat /proc/bus/input/devices'):
 raise ValueError('Virtual lid already exists')
lease='/data/local/tmp/kaidroid-hinge-watchdog-'+uuid.uuid4().hex
watchdog=Path(__file__).with_name('n139dl_hinge_watchdog.sh')
sh('watchdog-directory','mkdir '+lease)
push=subprocess.run(base+['push',str(watchdog),lease+'/watchdog.sh'],capture_output=True,timeout=25)
(a.output/'watchdog-push.stdout').write_bytes(push.stdout)
(a.output/'watchdog-push.stderr').write_bytes(push.stderr)
push.check_returncode()
if sh('watchdog-hash','sha256sum '+lease+'/watchdog.sh').split()[0]!=hashlib.sha256(watchdog.read_bytes()).hexdigest():
 raise ValueError('Watchdog transfer mismatch')
sh('watchdog-launch',f'nohup sh {lease}/watchdog.sh {lease} 00000000-0000-0000-0000-000000000010 210 >{lease}/log 2>&1 </dev/null &')
time.sleep(1)
if sh('watchdog-ready','cat '+lease+'/ready')!='armed':raise ValueError('Watchdog not ready; do not enable policy')
report['watchdog_lease']=lease
report['watchdog_seconds']=210
(a.output/'watchdog.json').write_text(json.dumps(dict(lease=lease,seconds=210,source_sha256=hashlib.sha256(watchdog.read_bytes()).hexdigest()),indent=2))
try:
 sh('start','start kaidroid-hall');time.sleep(2)
 if sh('service-started','getprop init.svc.kaidroid-hall')!='running':raise ValueError('Adapter not running')
 if 'KaiDroid Nokia Lid' not in sh('inputs-started','cat /proc/bus/input/devices'):raise ValueError('No virtual lid')
 sh('enable','settings put global lid_behavior 1')
 if 'getLidBehavior=LID_BEHAVIOR_SLEEP' not in sh('policy','dumpsys window policy'):raise ValueError('Policy not applied')
 print('READY: physical close/reopen window active for180seconds',flush=True)
 deadline=time.monotonic()+180
 while time.monotonic()<deadline:
  n=len(report['samples'])
  lines=sh('sample'+str(n),'cat /proc/uptime; cat /sys/devices/platform/soc/soc:hall_sensor/hall_status; dumpsys power | grep mWakefulness=; getprop init.svc.kaidroid-hall').splitlines()
  report['samples'].append(lines)
  (a.output/'samples.json').write_text(json.dumps(report['samples']))
  if any(len(x)>1 and x[1]=='1' for x in report['samples']) and lines[1]=='0':
   report['physical_transition_observed']=True
  time.sleep(1)
 guard('after')
except Exception as e:
 report['error']=repr(e);raise
finally:
 try:
  guard('cleanup-identity')
  sh('restore-setting','settings put global lid_behavior '+original)
  sh('stop','stop kaidroid-hall');time.sleep(2)
  report['restored']=sh('setting-after','settings get global lid_behavior')==original and sh('service-after','getprop init.svc.kaidroid-hall')=='stopped' and 'KaiDroid Nokia Lid' not in sh('inputs-after','cat /proc/bus/input/devices')
  if not report['restored']:raise ValueError('Cleanup not verified')
  sh('watchdog-cancel','touch '+lease+'/cancelled')
 finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='samples'}))
