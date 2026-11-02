"""Bounded original-TCL synthetic composite-dialog reference; needs hardware lease."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

SERIAL='DEVICE_SERIAL_REQUIRED'
FINGERPRINT='TCL/4058L1/Gflip6_USCC:11/RP1A.200720.011/PJEP:user/release-keys'
BOOT='00000000-0000-0000-0000-000000000003'
APK='901f6750711cc141856d85b96a20f59bc698a95a79e21b713c918610d71b8711'
PACKAGE='org.kaidroid.dialogprobe'
COMPONENT='com.android.calendar/com.android.calendar.AllInOneActivity'
IME='io.github.sspanak.tt9/.ime.TraditionalT9'
KEYS=['default_input_method','enabled_input_methods','selected_input_method_subtype','input_methods_subtype_history','show_ime_with_hard_keyboard']


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('adb','apk','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 if hashlib.sha256(a.apk.read_bytes()).hexdigest()!=APK:raise ValueError('Exact reviewed original fixture required')
 a.output.mkdir(parents=True,exist_ok=False)
 adb=[str(a.adb),'-s',SERIAL];installed=False;ambiguous=False
 report=dict(fixture_sha256=APK,suite='adapter-composite',terminal=False,
             calendar_provider_event_account_writes=False,ime_setting_writes=False,hardware_lease_required=True)
 def run(label,args,timeout=35):
  nonlocal ambiguous
  try:r=subprocess.run(adb+args,capture_output=True,timeout=timeout)
  except subprocess.TimeoutExpired as error:
   ambiguous=True;(a.output/(label+'.stdout')).write_bytes(error.stdout or b'');(a.output/(label+'.stderr')).write_bytes(error.stderr or b'');raise
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  r.check_returncode();return r.stdout
 def shell(label,command):return run(label,['shell',command]).decode().strip()
 def identity(label):
  values=shell(label+'-identity','getprop ro.build.fingerprint; cat /proc/sys/kernel/random/boot_id; settings get global bluetooth_on').splitlines()
  if values!=[FINGERPRINT,BOOT,'0']:raise ValueError('Donor identity/boot/Bluetooth mismatch')
  settings={key:shell(label+'-'+key,'settings get secure '+key) for key in KEYS}
  if settings['default_input_method']!=IME or settings['enabled_input_methods']!=IME:raise ValueError('Donor keyboard baseline changed')
  window=shell(label+'-window','dumpsys window')
  focus=[line.strip() for line in window.splitlines() if 'mCurrentFocus=Window{' in line]
  touch=[line.strip() for line in window.splitlines() if 'mInTouchMode=' in line]
  awake=[line.strip() for line in shell(label+'-power','dumpsys power').splitlines() if 'mWakefulness=' in line]
  if len(focus)!=1 or COMPONENT not in focus[0] or touch!=['mInTouchMode=false'] or awake!=['mWakefulness=Awake']:
   raise ValueError('Calendar/focus/touch/awake baseline ambiguous; no blind input')
  return dict(identity=values,settings=settings,focus=focus,touch_mode=touch,wakefulness=awake)
 try:
  before=identity('before');report['before']=before
  if shell('package-before','pm list packages '+PACKAGE) or PACKAGE in shell('process-before','ps -A'):
   raise ValueError('Fixture already present/live; observe existing operation')
  installed=True;ambiguous=True
  if b'Success' not in run('install',['install','--no-incremental',str(a.apk)],60):raise ValueError('Install not confirmed')
  ambiguous=False
  dump=shell('installed-package','dumpsys package '+PACKAGE)
  match=re.search(r'\buserId=(\d+)\b',dump)
  if not match or int(match[1])<10000 or 'sharedUser=' in dump:raise ValueError('Fixture UID/shared-user mismatch')
  report['uid']=int(match[1])
  paths=shell('installed-path','pm path '+PACKAGE).splitlines()
  if len(paths)!=1 or not paths[0].startswith('package:/data/app/') or not paths[0].endswith('/base.apk'):
   raise ValueError('Unexpected installed fixture path')
  if shell('installed-hash','sha256sum '+shlex.quote(paths[0][8:])).split()[0]!=APK:raise ValueError('Installed fixture hash mismatch')
  ambiguous=True
  terminal=run('instrument',['shell','am','instrument','-w','-r','-e','mode','boot','-e','suite','adapter-composite',PACKAGE+'/.DialogInstrumentation'],150)
  ambiguous=b'INSTRUMENTATION_CODE:' not in terminal
  if ambiguous:raise ValueError('Instrumentation outcome ambiguous; observe same job')
  report.update(terminal=True,instrumentation=terminal.decode(),passed=b'INSTRUMENTATION_RESULT: result=PASS' in terminal)
  for name in shell('owned-files','run-as '+PACKAGE+' ls files').splitlines():
   if not re.fullmatch(r'[A-Za-z0-9_.-]+',name):raise ValueError('Unsafe owned export filename')
   if name.endswith('.png') or name.endswith('.json'):
    data=run('export-'+name,['exec-out','run-as',PACKAGE,'cat','files/'+name])
    if name.endswith('.png') and not data.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('PNG transport mismatch')
    (a.output/name).write_bytes(data)
 except Exception as failure:
  report['failure']=str(failure)
 finally:
  if installed and not ambiguous:
   try:
    if shell('cleanup-boot','cat /proc/sys/kernel/random/boot_id')!=BOOT:raise ValueError('Cleanup boot changed')
    focus=[line for line in shell('cleanup-window','dumpsys window').splitlines() if 'mCurrentFocus=Window{' in line]
    if len(focus)!=1 or not (PACKAGE+'/' in focus[0] or COMPONENT in focus[0]):raise ValueError('Unexpected foreground; stop cleanup for owner review')
    paths=shell('cleanup-owned-path','pm path '+PACKAGE).splitlines()
    if len(paths)!=1 or not paths[0].startswith('package:/data/app/') or shell('cleanup-owned-hash','sha256sum '+shlex.quote(paths[0][8:])).split()[0]!=APK:raise ValueError('Owned fixture cleanup hash mismatch')
    if b'Success' not in run('owned-uninstall',['uninstall',PACKAGE],60):raise ValueError('Owned uninstall not confirmed')
    installed=False
    if shell('package-after','pm list packages '+PACKAGE) or PACKAGE in shell('process-after','ps -A'):raise ValueError('Fixture remains installed/live')
    shell('restore-calendar','am start -n '+COMPONENT)
    after=identity('after');report['after']=after
    if before['identity']!=after['identity'] or before['settings']!=after['settings']:raise ValueError('Original donor baseline drifted')
    report.update(fixture_removed=True,baseline_restored=True,same_calendar_window=before['focus']==after['focus'],handback_ready=True)
   except Exception as failure:report['cleanup_failure']=str(failure)
  report.update(ambiguous=ambiguous,installed_fixture_retained=installed)
  (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(report))
 if not report.get('handback_ready'):raise SystemExit('Lease cleanup incomplete; inspect same operation, do not repeat')
 if not report.get('passed'):raise SystemExit('Reference assertions failed; terminal evidence retained and baseline restored')


if __name__=='__main__':main()
