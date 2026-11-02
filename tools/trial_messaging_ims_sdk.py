"""One emulator-only execution of the frozen relocated IMS bytecode controls."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

APK='69d2a6e13cb26240b4e5994de4eced65e48198f2808d457a90099fd4adc5b525'
PACKAGE='org.kaidroid.mmsimsprobe'
FINGERPRINT='Android/sdk_phone_x86_64/generic_x86_64:11/RSR1.210722.013.A2/10067904:userdebug/test-keys'


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('adb','apk','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 if hashlib.sha256(a.apk.read_bytes()).hexdigest()!=APK:raise ValueError('Wrong frozen SDK probe')
 a.output.mkdir(parents=True,exist_ok=False)
 def run(label,*args,timeout=30,allow_failure=False):
  # A timeout propagates, leaving the existing run/package for inspection.
  r=subprocess.run([str(a.adb),'-s','emulator-5580',*args],capture_output=True,timeout=timeout)
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  if not allow_failure:r.check_returncode()
  return r.stdout.decode('utf-8').strip()
 if run('qemu','shell','getprop','ro.kernel.qemu')!='1' or run('fingerprint','shell','getprop','ro.build.fingerprint')!=FINGERPRINT:raise ValueError('Not identified existing emulator')
 boot=run('boot','shell','cat','/proc/sys/kernel/random/boot_id')
 if run('package-before','shell','pm','path',PACKAGE,allow_failure=True):raise ValueError('Existing fixture: observe, never replace/retry')
 if re.search(r'Active instrumentations?:|InstrumentationRecord\{',run('activities','shell','dumpsys','activity'),re.I):raise ValueError('Instrumentation already active')
 run('install','install',str(a.apk),timeout=60)
 (a.output/'launch.json').write_text(json.dumps(dict(apk_sha256=APK,boot_id=boot,launched_once=True,terminal=False))+'\n',encoding='utf-8')
 output=run('instrument','shell','am','instrument','-w',PACKAGE+'/.ImsInstrumentation',timeout=60)
 if 'INSTRUMENTATION_RESULT: result=PASS' not in output or 'INSTRUMENTATION_CODE: -1' not in output:raise ValueError('SDK bytecode controls failed; retain evidence/package')
 rows=[line.removeprefix('INSTRUMENTATION_RESULT: report=') for line in output.splitlines() if line.startswith('INSTRUMENTATION_RESULT: report=')]
 if len(rows)!=1:raise ValueError('Missing exact terminal report')
 report=json.loads(rows[0])
 if report.get('passed') is not True or len(report.get('cases',[]))!=12 or any(c.get('passed') is not True for c in report['cases']):raise ValueError('Incomplete SDK bytecode case set')
 if run('boot-after','shell','cat','/proc/sys/kernel/random/boot_id')!=boot or run('process-after','shell','pidof',PACKAGE,allow_failure=True):raise ValueError('Emulator changed or fixture still live')
 run('uninstall','uninstall',PACKAGE)
 report.update(apk_sha256=APK,boot_id=boot,terminal=True,probe_removed=True,physical_devices_touched=False,installed_on_nokia=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
