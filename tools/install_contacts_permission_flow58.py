"""Install the reviewed image58 Contacts correction after a logical DB baseline.

No grants, app-data writes, provider changes or automatic downgrade. Preserve
failed evidence for explicit recovery using the retained original APK.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from compare_runtime_permissions import snapshot, compare

OLD='20358b8548494b4486d2020635197addc393f3a948675c2543932c939e320248'
NEW='9935b312c5ba698e51f8be91b37799837f5c1c3bd13abdb29812e2b49d5cc9d4'
BOOT='00000000-0000-0000-0000-000000000013'
FRAMEWORK='a0f05ced9933a272a3b7f46f99818325ead8ee706eaf9e8138e4ab20b0f94054'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('snapshot','analysis','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();root=Path(__file__).resolve().parents[1]
 candidate=root/'work/contacts-permission-flow-signed01/FPContacts.apk'
 original=root/'work/contacts-dialog-width01/signed/FPContacts.apk'
 sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
 assert sha(candidate)==NEW and sha(original)==OLD
 baseline=json.loads((a.snapshot/'snapshot.json').read_text())
 logical=json.loads(a.analysis.read_text())
 assert baseline['complete'] is True and logical['complete'] is True
 assert logical['snapshot_sha256']==sha(a.snapshot/'snapshot.json')
 assert baseline['boot']==BOOT and baseline['contacts_apk_sha256']==OLD
 assert logical['context']=={k:baseline[k] for k in ('serial','image','boot','framework_sha256','contacts_apk_sha256')}
 for name,row in baseline['files'].items():assert sha(a.snapshot/'files'/name)==row['sha256']
 a.output.mkdir(parents=True,exist_ok=False)
 adb=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED']
 def run(label,args):
  r=subprocess.run(adb+args,capture_output=True,timeout=90)
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  r.check_returncode();return r.stdout.decode().replace('\r','').strip()
 def sh(label,text):return run(label,['shell',text])
 def guard(label):
  assert sh(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui').splitlines()==['58',BOOT,'0','Enforcing','1164','1377']
  assert sh(label+'-framework','sha256sum /system/framework/framework.jar').split()[0]==FRAMEWORK
 def apk(label,pin):
  path=sh(label+'-path','pm path com.android.contacts')
  assert re.fullmatch(r'package:/data/app/[A-Za-z0-9_+=~./-]+\.apk',path)
  assert sh(label+'-hash','sha256sum '+path[8:]).split()[0]==pin
 report=dict(image=58,boot=BOOT,original_apk_sha256=OLD,candidate_apk_sha256=NEW,installed=False,permissions_unchanged=False,native_trial_passed=False)
 try:
  guard('before');apk('original',OLD)
  before=snapshot(sh('package-before','dumpsys package com.android.contacts'),'com.android.contacts',0)
  report['install_attempted']=True
  result=run('install',['install','-r',str(candidate)])
  assert result.splitlines()[-1]=='Success',result
  report['installed']=True;guard('after');apk('candidate',NEW)
  after=snapshot(sh('package-after','dumpsys package com.android.contacts'),'com.android.contacts',0)
  report['permission_comparison']=compare(before,after)
  assert report['permission_comparison']['runtime_permissions_equal']
  report['permissions_unchanged']=True
 except Exception as error:
  report['error']=repr(error);raise
 finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))

if __name__=='__main__':main()
