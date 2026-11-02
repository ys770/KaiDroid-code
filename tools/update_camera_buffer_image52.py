"""Retained-data camera candidate update or rollback on the explicit image52 boot.

Default is preflight. Does not launch Camera, grant permissions or alter vendor.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
BASE='f8ea9baef449c8e658ac61e4af9b2167040045f339708275b1e34e4735af121e'
NEW='cbc8276c752d46f157cdec987596c1a0c3e2c5e3f8f261f7811fd219e83c85e3'
CERT='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'
PERMS=('CAMERA','RECORD_AUDIO','READ_EXTERNAL_STORAGE','WRITE_EXTERNAL_STORAGE')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=('install','rollback'),required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--apply',action='store_true');p.add_argument('--boot',required=True);a=p.parse_args();assert re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',a.boot)
 apk=Path('work/camera-buffer-signed01/signed.apk' if a.mode=='install' else 'work/tcl-media-app-build01/KaiDroidTclTctCamera.apk')
 source,target=(BASE,NEW) if a.mode=='install' else (NEW,BASE)
 assert hashlib.sha256(apk.read_bytes()).hexdigest()==target
 a.output.mkdir(parents=True,exist_ok=False);adb=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED'];report={'image':52,'boot_id':a.boot,'mode':a.mode,'applied':False,'data_cleared':False,'launched':False}
 def run(n,args):
  (a.output/(n+'.started.json')).write_text(json.dumps(args))
  r=subprocess.run(args,capture_output=True,timeout=120);(a.output/(n+'.stdout')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr);r.check_returncode();return r.stdout.decode().replace('\r','').strip()
 def sh(n,c):return run(n,adb+['shell',c])
 def guard(n):assert sh(n,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').splitlines()==['52',a.boot,'0']
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
