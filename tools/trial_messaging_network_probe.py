"""Execute one terminal lifecycle suite on existing emulator5580, never a phone."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

PACKAGE='org.kaidroid.messagingnetworkprobe'
FINGERPRINT='Android/sdk_phone_x86_64/generic_x86_64:11/RSR1.210722.013.A2/10067904:userdebug/test-keys'
SUITES={'background':PACKAGE+'.BackgroundStartInstrumentation',
 'idle':None,
 'boot':'org.kaidroid.messagingbootprobe.BootInstrumentation',
 'race':'org.kaidroid.messagingbootprobe.QueueRaceInstrumentation',
 'network':PACKAGE+'.NetworkWorkInstrumentation'}


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('adb','build','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--suite',choices=SUITES,required=True);a=p.parse_args()
 apk=a.build/'network-probe.apk';build=json.loads((a.build/'result.json').read_text())
 if hashlib.sha256(apk.read_bytes()).hexdigest()!=build['apk_sha256']:raise ValueError('SDK fixture changed')
 a.output.mkdir(parents=True,exist_ok=False)
 def run(label,*args,timeout=30,allow_failure=False):
  r=subprocess.run([str(a.adb),'-s','emulator-5580',*args],capture_output=True,timeout=timeout)
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  if not allow_failure:r.check_returncode()
  return r.stdout.decode('utf-8').strip()
 if run('qemu','shell','getprop','ro.kernel.qemu')!='1' or run('fingerprint','shell','getprop','ro.build.fingerprint')!=FINGERPRINT:raise ValueError('Not exact existing SDK emulator')
 boot=run('boot','shell','cat','/proc/sys/kernel/random/boot_id')
 if run('package-before','shell','pm','path',PACKAGE,allow_failure=True):raise ValueError('Existing fixture, observe its job before acting')
 if re.search(r'Active instrumentations?:|InstrumentationRecord\{',run('activities','shell','dumpsys','activity'),re.I):raise ValueError('Instrumentation active')
 run('install','install',str(apk),timeout=60)
 state=dict(suite=a.suite,apk_sha256=build['apk_sha256'],boot_id=boot,launched_once=True,terminal=False)
 (a.output/'result.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
 # No retries, force-stop or cleanup after ambiguous timeout.
 if a.suite=='idle':
  launch=run('activity','shell','am','start','-n',PACKAGE+'/.ProbeActivity')
  if 'Starting: Intent' not in launch:raise ValueError('No conclusive activity dispatch')
  # This diagnostic Activity finishes immediately, so -W can wait forever for
  # a never-drawn window. Observe its one existing launch, never relaunch it.
  initialized=False
  for attempt in range(30):
   activities=run('activity-state-'+str(attempt),'shell','dumpsys','activity','activities')
   broadcasts=run('receiver-state-'+str(attempt),'shell','dumpsys','activity','broadcasts')
   if PACKAGE not in activities and re.search(r'ReceiverList\{[^\n]* '+re.escape(PACKAGE)+r'/',broadcasts):
    initialized=True;break
   time.sleep(0.1)
  if not initialized:raise ValueError('Existing diagnostic launch still unresolved')
  run('idle','shell','am','make-uid-idle',PACKAGE)
  output=run('broadcast','shell','am','broadcast','-a',PACKAGE+'.TEST_IDLE','-p',PACKAGE)
  if 'Broadcast completed:' not in output:raise ValueError('Ambiguous receiver trigger')
  report=json.loads(run('receiver','shell','run-as',PACKAGE,'cat','files/idle-receiver.json'))
  expected='accepted' if build.get('work_helper_sha256') else 'denied'
  state.update(terminal=True,passed=report.get(expected) is True,report=report,physical_devices_touched=False)
  if build.get('work_helper_sha256'):
   worker=''
   for attempt in range(85):
    worker=run('worker-'+str(attempt),'shell','run-as',PACKAGE,'cat','files/idle-worker.json',allow_failure=True)
    if worker:break
    time.sleep(0.1)
   state['worker']=json.loads(worker) if worker else {}
   state['passed']=state['passed'] and all(state['worker'].get(n) is True for n in ('worker_ran','job_finished','sms_boot_not_invoked'))
  run('uninstall','uninstall',PACKAGE);state['own_probe_removed']=True
  (a.output/'result.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8');print(json.dumps(state))
  if not state['passed']:raise ValueError('Idle receiver did not reproduce expected baseline/candidate behavior')
  return
 output=run('instrument','shell','am','instrument','-w',PACKAGE+'/'+SUITES[a.suite],timeout=55)
 if 'INSTRUMENTATION_CODE:' not in output:raise ValueError('Ambiguous instrumentation; retain package')
 state.update(terminal=True,passed='INSTRUMENTATION_RESULT: result=PASS' in output and 'INSTRUMENTATION_CODE: -1' in output,
  output=output,physical_devices_touched=False)
 if not state['passed']:run('crash-buffer','logcat','-d','-b','crash','-t','100')
 rows=[line.removeprefix('INSTRUMENTATION_RESULT: report=') for line in output.splitlines() if line.startswith('INSTRUMENTATION_RESULT: report=')]
 if len(rows)==1:state['report']=json.loads(rows[0])
 if run('boot-after','shell','cat','/proc/sys/kernel/random/boot_id')!=boot:raise ValueError('Emulator rebooted')
 run('uninstall','uninstall',PACKAGE)
 state['own_probe_removed']=True
 (a.output/'result.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8');print(json.dumps(state))
 if not state['passed']:raise ValueError('Terminal SDK suite did not pass; evidence preserved')


if __name__=='__main__':main()
