"""Bounded normal RoleManager handoff to TCL SMS; no messages or global policy edits."""
import argparse,json,re,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--adb',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--boot',required=True);p.add_argument('--apply',action='store_true');a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
adb=[str(a.adb),'-s','DEVICE_SERIAL_REQUIRED'];report={'applied':False,'sent_messages':False,'idle_policy_changed':False,'boot':a.boot}
def shell(n,cmd,check=True):
 r=subprocess.run(adb+['shell',cmd],capture_output=True,timeout=30);(a.output/(n+'.stdout')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr)
 if check:r.check_returncode()
 return r.stdout.decode().replace('\r','').strip(),r.returncode
def holders(text):
 m=re.search(r'name=android\.app\.role\.SMS\s+holders=([^}]+)',text);assert m,'SMS role absent';return m.group(1).strip().split(',')
try:
 assert shell('boot','cat /proc/sys/kernel/random/boot_id')[0]==a.boot
 for name,cmd,want in [('image','getprop ro.kaidroid.image','39'),('root','id -u','0'),('completed','getprop sys.boot_completed','1')]:assert shell(name,cmd)[0]==want
 pkg=shell('target-before','dumpsys package com.android.mms')[0];assert 'userId=10100' in pkg and 'versionCode=2403041' in pkg
 flags=re.search(r'privateFlags=\[([^\]]+)\]',pkg);assert flags and 'PRIVILEGED' in flags.group(1)
 assert holders(shell('roles-before','dumpsys role')[0])==['com.android.messaging']
 shell('original-before','dumpsys package com.android.messaging')
 for label,pkg in [('original','com.android.messaging'),('target','com.android.mms')]:shell(label+'-appops-before','cmd appops get '+pkg,False)
 shell('idle-before','cmd deviceidle whitelist')
 report['preflight_passed']=True
 if a.apply:
  assert shell('boot-before-apply','cat /proc/sys/kernel/random/boot_id')[0]==a.boot
  text,code=shell('role-add','cmd role add-role-holder --user 0 android.app.role.SMS com.android.mms 0',False)
  report['command_exit']=code;report['command_output']=text
  # A 5-second controller callback timeout is not failure proof and never retried.
  for i in range(6):
   current=holders(shell('roles-after-'+str(i),'dumpsys role')[0]);report['observed_holders']=current
   if current==['com.android.mms']:break
   time.sleep(2)
  report['applied']=current==['com.android.mms']
  report['outcome']='holder observed' if report['applied'] else 'unresolved; inspect pending controller before any retry or rollback'
  for label,pkg in [('original','com.android.messaging'),('target','com.android.mms')]:
   shell(label+'-package-after','dumpsys package '+pkg);shell(label+'-appops-after','cmd appops get '+pkg,False)
  shell('idle-after','cmd deviceidle whitelist');assert shell('boot-after','cat /proc/sys/kernel/random/boot_id')[0]==a.boot
 report['rollback_command']='cmd role add-role-holder --user 0 android.app.role.SMS com.android.messaging 0'
except Exception as error:report['error']=repr(error);raise
finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
