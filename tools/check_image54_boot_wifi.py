"""Read-only image54 boot, framework, process and saved Wi-Fi checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

SERIAL='DEVICE_SERIAL_REQUIRED'
FRAMEWORK='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
SYSTEMUI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',default='/opt/kaidroid/source/Documents/platform-tools/adb.exe')
 p.add_argument('--boot',required=True,type=lambda s:str(uuid.UUID(s)))
 p.add_argument('--output',required=True,type=Path)
 a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 report={'image':54,'boot_id':a.boot,'passed':False,'configuration_changed':False}
 def read(label,command):
  r=subprocess.run([a.adb,'-s',SERIAL,'shell',command],capture_output=True,timeout=35)
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  r.check_returncode();return r.stdout.decode().replace('\r\n','\n').strip()
 command='getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; getprop sys.boot_completed; id -u; pidof system_server; pidof com.android.systemui'
 try:
  before=read('identity-before',command).splitlines()
  if len(before)!=7 or before[:5]!=[SERIAL,'54',a.boot,'1','0'] or not all(re.fullmatch('[1-9][0-9]*',pid) for pid in before[5:]):
   raise ValueError('Exact handset/image/boot/root or process identity not established')
  if read('selinux','getenforce')!='Enforcing':raise ValueError('SELinux changed')
  files='/system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk'
  if [r.split()[0] for r in read('framework','sha256sum '+files).splitlines()]!=[FRAMEWORK,SYSTEMUI]:
   raise ValueError('Framework/SystemUI identity differs')
  status=read('wifi','cmd wifi status')
  if 'Supplicant state: COMPLETED' not in status or '&VALIDATED' not in status:raise ValueError('Saved Wi-Fi not connected and validated')
  for label,target in [('ip','1.1.1.1'),('dns','example.com')]:
   reply=read(label,'ping -c 3 -W 3 '+target)
   if '3 packets transmitted, 3 received' not in reply:raise ValueError(label+' connectivity failed')
  # Full window dump: some Android builds return no focus for the windows subcommand.
  focus=[line for line in read('window','dumpsys window').splitlines() if 'mCurrentFocus=' in line]
  if len(focus)!=1 or 'com.android.launcher3/' not in focus[0]:raise ValueError('Launcher not currently focused')
  if read('identity-after',command).splitlines()!=before:raise ValueError('Boot/process identity changed')
  report.update(passed=True,framework_sha256=FRAMEWORK,systemui_sha256=SYSTEMUI,
   saved_network_connected=True,ip_packets=[3,3],dns_packets=[3,3],same_boot_and_processes=True,
   launcher_focused=True,selinux='Enforcing')
 except Exception as e:report['failure']=str(e)
 finally:
  report['captures']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in a.output.iterdir() if f.is_file()}
  (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(report))
 if not report['passed']:raise SystemExit('Read-only boot/Wi-Fi check incomplete; inspect captures')

if __name__=='__main__':main()
