"""Bounded real Wi-Fi transition on image56; no synthetic broadcasts or messages."""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
BOOT='00000000-0000-0000-0000-000000000006'
APK='0b366f5deb8bde6147a13fb4a51fa0646e71e54ce692d0603ca0f3e5f27565e4'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--warm-home',action='store_true');p.add_argument('--ssid',default=os.environ.get('KAIDROID_WIFI_SSID'));a=p.parse_args()
 if not a.ssid:p.error('--ssid or KAIDROID_WIFI_SSID is required')
 a.output.mkdir(parents=True,exist_ok=False)
 adb=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED'];r={'passed':False,'messages_requested':False,'synthetic_broadcasts':False};log=None;changed=False
 def run(label,args):
  x=subprocess.run(args,capture_output=True,timeout=40);(a.output/(label+'.stdout')).write_bytes(x.stdout);(a.output/(label+'.stderr')).write_bytes(x.stderr);x.check_returncode();return x.stdout.decode().replace('\r','').strip()
 def sh(label,cmd):return run(label,adb+['shell',cmd])
 def guard(label):
  x=sh(label,'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui').splitlines()
  if x[:5]!=['DEVICE_SERIAL_REQUIRED','56',BOOT,'0','Enforcing']:raise ValueError('Binding failed')
  return x
 def queues(label):run(label,[sys.executable,str(Path(__file__).with_name('check_messaging_queues.py')),'--image','56','--boot',BOOT,'--apk-sha256',APK,'--output',str(a.output/label)])
 try:
  before=guard('identity-before');wifi=sh('wifi-before','cmd wifi status')
  if a.ssid not in wifi or '&VALIDATED' not in wifi:raise ValueError('Expected saved Wi-Fi unavailable')
  if sh('mms-before','pidof com.android.mms; true'):raise ValueError('Require naturally absent Messaging process')
  queues('queues-before')
  with (a.output/'live-logcat.txt').open('wb') as out,(a.output/'live-logcat.stderr').open('wb') as err:
   log=subprocess.Popen(adb+['logcat','-b','all','-v','threadtime','-T','1'],stdout=out,stderr=err)
   try:
    time.sleep(2)
    if a.warm_home:
     sh('launch','am start -W -n com.android.mms/.ui.ConversationList');sh('home','input keyevent 3');time.sleep(2)
     sh('uid-state','am get-uid-state 10100');sh('receivers-before','dumpsys activity broadcasts com.android.mms')
     if not sh('warm-pid','pidof com.android.mms; true'):raise ValueError('Warm process died before network trigger')
     queues('queues-warm')
    changed=True;sh('wifi-disable','svc wifi disable');time.sleep(8);sh('wifi-disconnected','cmd wifi status');sh('jobs-disconnected','dumpsys jobscheduler com.android.mms')
    sh('wifi-enable','svc wifi enable');changed=False
    for n in range(6):
     time.sleep(5);status=sh('wifi-reconnect-'+str(n),'cmd wifi status')
     if '&VALIDATED' in status and a.ssid in status:break
    else:raise ValueError('Wi-Fi did not validate in window')
    time.sleep(15);sh('jobs-after','dumpsys jobscheduler com.android.mms');sh('process-after','dumpsys activity processes com.android.mms');sh('services-after','dumpsys activity services com.android.mms')
   finally:
    if log.poll() is None:log.terminate()
    log.wait(timeout=10)
  if guard('identity-after')!=before:raise ValueError('System process lifetime changed')
  queues('queues-after');text=(a.output/'live-logcat.txt').read_text(errors='replace')
  r.update(no_fatal_exception='FATAL EXCEPTION' not in text,no_anr='ANR in ' not in text,wifi_restored=True)
  r['transport_checks_passed']=r['no_fatal_exception'] and r['no_anr'];r['worker_execution_requires_log_review']=True; r['messaging_regression_proven']=False
 except Exception as e:r['failure']=str(e);raise
 finally:
  if changed:
   try:sh('wifi-finally-enable','svc wifi enable')
   except Exception as e:r['restore_error']=str(e)
  (a.output/'result.json').write_text(json.dumps(r,indent=2)+'\n')
 print(json.dumps(r))
if __name__=='__main__':main()
