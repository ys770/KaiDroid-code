import subprocess,time,json,re,hashlib
from pathlib import Path
out=Path('artifacts/runtime/image52-sleep-wake01');out.mkdir(exist_ok=False)
a=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED','shell']
seq=0
report=dict(image=52,cycles=[],settings_changed=False,passed=False)
def sh(label,cmd):
 global seq
 seq+=1;r=subprocess.run(a+[cmd],capture_output=True,timeout=25)
 (out/(str(seq)+'-'+label+'.stdout')).write_bytes(r.stdout)
 (out/(str(seq)+'-'+label+'.stderr')).write_bytes(r.stderr)
 r.check_returncode();return r.stdout.decode().strip()
command='getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui; pidof android.hardware.camera.provider@2.4-service'
before=sh('identity-before',command)
assert before.splitlines()==['52','00000000-0000-0000-0001-000000000003','0','Enforcing','1154','1333','510']
def guard():assert sh('identity',command)==before
def state(want):
 for i in range(10):
  text=sh('power-'+want,'dumpsys power')
  if re.search(r'mWakefulness='+want+r'\b',text):return
  time.sleep(1)
 raise RuntimeError('Power state not observed: '+want)
assert 'com.android.launcher3/com.android.launcher3.Launcher' in sh('focus-before','dumpsys window')
assert not sh('camera-absent','pidof com.tcl.camera || true')
assert all(x=='0' for x in re.findall(r'mCallState=(\d+)',sh('calls','dumpsys telephony.registry')))
state('Awake');sleep_requested=False
try:
 for i in range(3):
  guard();sleep_requested=True;sh('sleep','input keyevent 223');state('Asleep');time.sleep(5)
  guard();sh('wake','input keyevent 224');state('Awake');sleep_requested=False
  time.sleep(3);guard()
  assert 'com.android.launcher3/com.android.launcher3.Launcher' in sh('focus-after','dumpsys window')
  wifi=sh('wifi','cmd wifi status');assert '&VALIDATED' in wifi and 'Supplicant state: COMPLETED' in wifi
  reply=sh('ip','ping -c 2 -W 3 1.1.1.1');assert '2 packets transmitted, 2 received' in reply
  h=sh('provider-hash','sha256sum /proc/510/root/vendor/lib/libmmcamera2_stats_modules.so').split()[0]
  assert h=='41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0'
  report['cycles'].append(dict(asleep_observed=True,awake_observed=True,launcher_focus=True,wifi_validated=True,ip_replies=2,provider_hash_verified=True,same_processes=True))
 report['passed']=True
except Exception as e:report['error']=repr(e)
finally:
 if sleep_requested:
  try:guard();sh('restore-wake','input keyevent 224');state('Awake');report['restored_awake']=True
  except Exception as e:report['cleanup_error']=repr(e)
 report['limits']=['Software sleep/wake while USB-connected, not deep suspend or battery-drain proof.','No physical hinge/button or camera capture after wake in this test.']
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
assert report['passed']
