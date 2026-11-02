"""Run bounded View-tree footer controls on the existing emulator only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

SERIAL='emulator-5580'
FINGERPRINT='Android/sdk_phone_x86_64/generic_x86_64:11/RSR1.210722.013.A2/10067904:userdebug/test-keys'
PACKAGE='org.kaidroid.imefooterprobe'
APK='f016fcf3bc5629c7238f9b30a5dd03ff30da271800e5273bf09dea004b383a54'


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('adb','apk','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 if hashlib.sha256(a.apk.read_bytes()).hexdigest()!=APK:raise ValueError('Unreviewed SDK fixture')
 a.output.mkdir(parents=True,exist_ok=False)
 index=0
 def run(*args,timeout=20,allow_failure=False):
  nonlocal index
  index+=1
  result=subprocess.run([str(a.adb),'-s',SERIAL,*args],capture_output=True,timeout=timeout)
  (a.output/(str(index)+'.stdout')).write_bytes(result.stdout)
  (a.output/(str(index)+'.stderr')).write_bytes(result.stderr)
  if not allow_failure:result.check_returncode()
  return result.stdout.decode('utf-8').strip()
 if run('get-state')!='device' or run('shell','getprop','ro.kernel.qemu')!='1' or run('shell','getprop','ro.build.fingerprint')!=FINGERPRINT:
  raise ValueError('Only identified existing SDK emulator authorized')
 boot=run('shell','cat','/proc/sys/kernel/random/boot_id')
 if run('shell','pm','path',PACKAGE,allow_failure=True):raise ValueError('Probe already installed; inspect existing run, never replace/restart')
 activity=run('shell','dumpsys','activity')
 if re.search(r'Active instrumentations?:|InstrumentationRecord\{',activity,re.I):raise ValueError('Instrumentation active; observe same job')
 run('install',str(a.apk),timeout=60)
 (a.output/'launch.json').write_text(json.dumps(dict(serial=SERIAL,boot_id=boot,apk_sha256=APK,launched_once=True,terminal=False))+'\n',encoding='utf-8')
 # Timeout deliberately propagates; no retry, force-stop or uninstall on uncertainty.
 result=run('shell','am','instrument','-w',PACKAGE+'/.FooterInstrumentation',timeout=60)
 if 'INSTRUMENTATION_RESULT: result=PASS' not in result:raise ValueError('SDK fixture failed; retain installed probe and evidence')
 report=json.loads(run('shell','run-as',PACKAGE,'cat','files/report.json'))
 if report.get('passed') is not True or len(report.get('cases',[]))!=13 or any(c.get('passed') is not True for c in report['cases']):raise ValueError('Incomplete SDK controls')
 for name in ('negative-symbols','candidate-symbols','candidate-ordinary','candidate-words'):
  index+=1
  data=subprocess.run([str(a.adb),'-s',SERIAL,'exec-out','run-as',PACKAGE,'cat','files/'+name+'.png'],capture_output=True,timeout=20)
  data.check_returncode()
  if not data.stdout.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('Missing SDK bitmap')
  (a.output/(name+'.png')).write_bytes(data.stdout)
 if run('shell','cat','/proc/sys/kernel/random/boot_id')!=boot:raise ValueError('Emulator rebooted')
 if run('shell','pidof',PACKAGE,allow_failure=True):raise ValueError('Probe still running; no cleanup or restart')
 run('uninstall',PACKAGE)
 report.update(serial=SERIAL,fingerprint=FINGERPRINT,boot_id=boot,apk_sha256=APK,terminal=True,probe_removed=True,
  physical_devices_touched=False,native_source_compiled=False,installed_on_nokia=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(report))


if __name__=='__main__':main()
