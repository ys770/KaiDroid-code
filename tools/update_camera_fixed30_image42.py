"""Retained-data fixed30 diagnostic camera candidate update or rollback on an explicitly selected image42/43/44 boot.

Default is preflight. Does not launch Camera, grant permissions or alter vendor.
"""
import argparse,hashlib,json,re,subprocess,uuid
from pathlib import Path
BASE='f8ea9baef449c8e658ac61e4af9b2167040045f339708275b1e34e4735af121e'
NEW='1ae46bf64f93903c4cefd54d0198e754b914c3d048468e22c1970cfbb96c1b94'
CERT='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'
PERMS=('CAMERA','RECORD_AUDIO','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--candidate',choices=('fixed30','startup-trace'),default='fixed30');p.add_argument('--mode',choices=('install','rollback'),required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--apply',action='store_true');p.add_argument('--boot-id',type=uuid.UUID,required=True);p.add_argument('--image',choices=('42','43','44'),default='42');a=p.parse_args()
 new, candidate_path = (NEW, 'work/camera-fixed30-signed01/signed.apk') if a.candidate=='fixed30' else ('8bfdf03bd0b9730ee5abec630a326f633c52184da4964c9c9713ce39201ec8dd', 'work/camera-startup-trace-signed01/signed.apk')
 apk=Path(candidate_path if a.mode=='install' else 'work/tcl-media-app-build01/KaiDroidTclTctCamera.apk')
 source,target=(BASE,new) if a.mode=='install' else (new,BASE)
 assert hashlib.sha256(apk.read_bytes()).hexdigest()==target
 a.output.mkdir(parents=True,exist_ok=False);adb=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED'];report={'image':a.image,'boot_id':str(a.boot_id),'mode':a.mode,'candidate':a.candidate,'applied':False,'data_cleared':False,'launched':False}
 def run(n,args):
  (a.output/(n+'.started.json')).write_text(json.dumps(args))
  r=subprocess.run(args,capture_output=True,timeout=120);(a.output/(n+'.stdout')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr);r.check_returncode();return r.stdout.decode().replace('\r','').strip()
 def sh(n,c):return run(n,adb+['shell',c])
 def guard(n):assert sh(n,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').splitlines()==[a.image,str(a.boot_id),'0']
 def package(n,expected):
  s=sh(n+'-package','dumpsys package com.tcl.camera');assert 'userId=10104' in s and 'versionCode=511004100' in s
  for perm in PERMS:assert re.search(r'android.permission.'+perm+r': granted=false',s),perm
  path=sh(n+'-path','pm path com.tcl.camera');assert path.startswith('package:/data/app/') and '\n' not in path
  assert sh(n+'-hash','sha256sum '+path[8:]).split()[0]==expected
 try:
  guard('identity');package('before',source)
  signer=['java','-jar','/opt/android-sdk/build-tools/35.0.0/lib/apksigner.jar']
  cert=run('signer',signer+['verify','--print-certs',str(apk)]);assert re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',cert)==[CERT]
  report['preflight_passed']=True;report['target_sha256']=target
  if a.apply:
   sh('stop','am force-stop com.tcl.camera');guard('install-guard')
   result=run('install',adb+['install','--no-incremental','-r',str(apk)]);assert 'Success' in result
   package('after',target);report['applied']=True
 except Exception as error:report['error']=repr(error);raise
 finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))
if __name__=='__main__':main()
