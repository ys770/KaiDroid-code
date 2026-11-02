"""Freeze or run one guarded read-only measurement arm. Never reboot/install/navigate."""
import argparse,json,os,re,shlex,shutil,signal,subprocess,sys,time,uuid
from pathlib import Path
sys.dont_write_bytecode=True
import matched_memory56_contract as c

def packet_check(root,pin):
 if root.is_symlink() or c.sha(root/'packet.json')!=pin:raise ValueError('Frozen packet hash differs')
 m=json.loads((root/'packet.json').read_text())
 if m['schema_version']!=1 or m['order']!=list(c.ORDER) or m['schedule']!=dict(log_start=c.LOG_START,bindings=list(c.CHECKPOINTS),censuses=list(c.CENSUSES),maps=list(c.MAPS)) or set(m['sources_sha256'])!=set(c.SOURCES):raise ValueError('Packet plan/source set differs')
 expected={'packet.json','bindings.json'}|{'sources/'+n for n in c.SOURCES}
 if any(p.is_symlink() for p in root.rglob('*')) or {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}!=expected:raise ValueError('Packet paths differ')
 if c.sha(root/'bindings.json')!=m['bindings_sha256']:raise ValueError('Bindings hash differs')
 for n,pin in m['sources_sha256'].items():
  if c.sha(root/'sources'/n)!=pin:raise ValueError('Frozen source changed '+n)
 return m,c.validate_bindings(json.loads((root/'bindings.json').read_text()))
def freeze(bindings,out):
 c.validate_bindings(json.loads(bindings.read_text()));out.mkdir(parents=True,exist_ok=False);(out/'sources').mkdir();shutil.copyfile(bindings,out/'bindings.json')
 for n in c.SOURCES:shutil.copyfile(Path(__file__).with_name(n),out/'sources'/n)
 m=dict(schema_version=1,order=list(c.ORDER),schedule=dict(log_start=c.LOG_START,bindings=list(c.CHECKPOINTS),censuses=list(c.CENSUSES),maps=list(c.MAPS)),bindings_sha256=c.sha(out/'bindings.json'),sources_sha256={n:c.sha(out/'sources'/n) for n in c.SOURCES},read_only=True,no_gc=True,reboot=False,install=False)
 c.dump(out/'packet.json',m);pin=c.sha(out/'packet.json');packet_check(out,pin);print(json.dumps(dict(packet=str(out),packet_sha256=pin,device_commands_run=0)))
def guard_command(expected):
 return ('getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; getprop sys.boot_completed; cat /proc/uptime; pidof system_server; pidof com.android.systemui; '+f"cat /proc/{expected['server_pid']}/stat /proc/{expected['ui_pid']}/stat")
def checkpoint_command(bindings,image):
 paths={**c.expected_core(image),bindings['mms']['apk_path']:bindings['mms']['sha256']}
 parts=['echo KV_UPTIME','cat /proc/uptime','echo KV_PACKAGE','pm path com.android.mms','echo KV_HASHES','sha256sum '+' '.join(shlex.quote(p) for p in paths)]
 for ns in c.SETTINGS:
  expression='^('+'|'.join(re.escape(k) for k in bindings['settings'][ns])+')='
  parts+=['echo KV_'+ns.upper(),'settings list '+ns+' | grep -E '+shlex.quote(expression)+' || true']
 parts+=['echo KV_PROPERTIES']
 for prop in bindings['properties']:parts+=['printf '+shlex.quote(prop+'=')+'; getprop '+prop]
 parts+=['echo KV_POWER','cat /sys/class/power_supply/battery/uevent','echo KV_WINDOW','dumpsys window','echo KV_END_UPTIME','cat /proc/uptime']
 return '; '.join(parts)
def child_command(kind,target,tools,output,expected,adb,python):
 common=['--adb',adb,'--serial',c.SERIAL,'--image',expected['image'],'--boot',expected['boot']]
 if kind=='census':return [python,str(tools/'capture_timed_memory_audit.py'),*common,'--system-server-pid',str(expected['server_pid']),'--systemui-pid',str(expected['ui_pid']),'--target-uptime',str(target),'--output',str(output)]
 if kind=='maps':return [python,str(tools/'capture_memory_maps.py'),*common,'--process',str(expected['server_pid'])+'=system_server','--process',str(expected['ui_pid'])+'=com.android.systemui','--runtime-metadata','--output',str(output)]
 raise ValueError('Unsupported collector')
def stop_tree(proc):
 if proc.poll() is not None:return
 if os.name=='nt':subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=10)
 else:os.killpg(proc.pid,signal.SIGTERM)
 try:proc.wait(timeout=5)
 except subprocess.TimeoutExpired:
  if os.name=='nt':proc.kill()
  else:os.killpg(proc.pid,signal.SIGKILL)
  proc.wait(timeout=5)

class Runner:
 def __init__(self,a):
  self.a=a;self.root=a.output.resolve();reserve=self.root.parent
  while not reserve.exists():reserve=reserve.parent
  if shutil.disk_usage(reserve).free<512*1024**2:raise ValueError('Reserve at least512MiB for bounded evidence')
  self.root.mkdir(parents=True,exist_ok=False);self.m,self.bindings=packet_check(a.packet,a.packet_sha256);shutil.copytree(a.packet,self.root/'inputs');self.tools=self.root/'inputs/sources';self.base=[a.adb,'-s',c.SERIAL];self.log=None;self.logfile=None;self.child=None;self.sequence=0;self.start=time.monotonic();self.expected=dict(image=a.image,boot=a.boot,server_pid=a.server_pid,ui_pid=a.ui_pid,server_start=a.server_start,ui_start=a.ui_start)
  self.r=dict(schema_version=1,experiment=self.bindings['experiment'],slot=a.slot,image=a.image,boot=a.boot,expected=self.expected,packet_sha256=a.packet_sha256,bindings_sha256=self.m['bindings_sha256'],source_sha256=self.m['sources_sha256'],capture_root=str(self.root),complete=False,classification='failed',eligible_for_matched_comparison=False,savings_proven=False,no_gc=True,state_changed=False,steps=[],checkpoints=[],children=[],failures=[],schedule=self.m['schedule'])
  self.r['host']=dict(python_version=sys.version.split()[0],python_executable=sys.executable,adb_executable=str(Path(a.adb).resolve()),python_sha256=c.sha(Path(sys.executable)),adb_sha256=c.sha(Path(a.adb)))
  for n in ('run_matched_memory56.py','matched_memory56_contract.py','summarize_matched_memory56.py'):
   if c.sha(Path(__file__).with_name(n))!=self.m['sources_sha256'][n]:raise ValueError('Execute the reviewed frozen harness sources')
  self.save()
 def save(self):c.dump(self.root/'arm.json',self.r)
 def note(self,reason):
  if reason not in self.r['failures']:self.r['failures'].append(reason)
 def read(self,label,command,timeout=25):
  self.sequence+=1;name=f'{self.sequence:03d}-'+label;begin=time.monotonic()
  try:result=subprocess.run(self.base+['exec-out',command],capture_output=True,timeout=timeout)
  except subprocess.TimeoutExpired as exc:
   (self.root/(name+'.partial')).write_bytes(exc.stdout or b'');raise
  (self.root/(name+'.stdout')).write_bytes(result.stdout);(self.root/(name+'.stderr')).write_bytes(result.stderr)
  self.r['steps'].append(dict(label=label,command=command,stdout=name+'.stdout',stderr=name+'.stderr',stdout_sha256=c.sha(self.root/(name+'.stdout')),stderr_sha256=c.sha(self.root/(name+'.stderr')),returncode=result.returncode,seconds=time.monotonic()-begin));self.save();result.check_returncode()
  if result.stderr:raise ValueError('Unexpected read stderr '+label)
  return result.stdout.decode(errors='strict').replace('\r\n','\n')
 def guard(self,label):
  raw=self.read(label,guard_command(self.expected));uptime=c.identity(raw.splitlines(),self.expected);self.anchor=(uptime,time.monotonic());return uptime
 def monitor(self):
  if time.monotonic()-self.start>600:raise TimeoutError('One-arm600second host bound exceeded')
  if self.log is not None:
   if self.log.poll() is not None and not self.r.get('log_stopped_by_harness'):self.note('natural_log_reader_exited_early')
   if (self.root/'natural-logcat.txt').stat().st_size>c.MAX_LOG_BYTES:
    self.note('natural_log_size_bound');self.stop_log('size_bound')
 def age(self,target,label):
  uptime,stamp=self.anchor;deadline=stamp+target-uptime
  while time.monotonic()<deadline:self.monitor();time.sleep(min(.25,max(0,deadline-time.monotonic())))
  actual=self.guard('age-'+label)
  if abs(actual-target)>c.TOLERANCE:raise ValueError('Missed scheduled age '+label)
  return actual
 def start_log(self):
  self.logfile=(self.root/'natural-logcat.txt').open('xb');self.logerr=(self.root/'natural-logcat.stderr').open('xb');self.log=subprocess.Popen(self.base+['logcat','-b','all','-v','threadtime'],stdout=self.logfile,stderr=self.logerr);self.r['log_pid']=self.log.pid;self.save()
 def stop_log(self,reason):
  if self.log is None:return
  if reason=='completed' and self.log.poll() is not None:self.note('natural_log_reader_exited_early')
  if self.log.poll() is None:
   self.log.terminate()
   try:self.log.wait(timeout=5)
   except subprocess.TimeoutExpired:self.log.kill();self.log.wait(timeout=5)
  self.r['log_stopped_by_harness']=reason;self.r['log_exit']=self.log.returncode
  if not self.logfile.closed:self.logfile.close();self.logerr.close()
  self.log=None
 def checkpoint(self,target):
  self.age(target,'binding-'+str(target));raw=self.read('bindings-'+str(target),checkpoint_command(self.bindings,self.a.image));result=c.checkpoint(raw,self.bindings,self.a.image);result['target']=target
  if abs(result['uptime_before']-target)>c.TOLERANCE:self.note('binding_'+str(target)+'_missed_age')
  for f in result['failures']:self.note('binding_'+str(target)+'_'+f)
  self.r['checkpoints'].append(result);self.save();self.guard('post-binding-'+str(target))
 def run_child(self,label,argv):
  output=self.root/(label+'.stdout');error=self.root/(label+'.stderr');begin=time.monotonic();env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}
  with output.open('xb') as out,error.open('xb') as err:
   self.child=subprocess.Popen(argv,stdout=out,stderr=err,env=env,start_new_session=os.name!='nt',creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0)
   while self.child.poll() is None:
    self.monitor()
    if time.monotonic()-begin>300:stop_tree(self.child);raise TimeoutError('Frozen collector exceeded300seconds; partial evidence retained, no retry')
    time.sleep(.25)
  code=self.child.returncode;self.child=None;self.r['children'].append(dict(label=label,argv=argv,exit=code,stdout=output.name,stderr=error.name,stdout_sha256=c.sha(output),stderr_sha256=c.sha(error),seconds=time.monotonic()-begin));self.save()
  if code:raise ValueError('Collector failed '+label+'; no replay')
 def inspect_window(self,label):
  command='echo KV_UPTIME; cat /proc/uptime; echo KV_WINDOW; dumpsys window; echo KV_END_UPTIME; cat /proc/uptime'
  raw=self.read('window-'+label,command);s=c.parse_sections(raw)
  if set(s)!={'KV_UPTIME','KV_WINDOW','KV_END_UPTIME'}:raise ValueError('Window capture closure differs')
  result=c.window_status('\n'.join(s['KV_WINDOW']),self.bindings['foreground_component']);result.update(label=label,uptime_before=float(s['KV_UPTIME'][0].split()[0]),uptime_after=float(s['KV_END_UPTIME'][0].split()[0]))
  for reason in result['failures']:self.note(label+'_'+reason)
  self.r.setdefault('windows',[]).append(result);self.save()
 def census(self,target):
  self.age(target-5,'arm-census-'+str(target));self.inspect_window('pre-census-'+str(target));folder=self.root/('census-'+str(target));argv=child_command('census',target,self.tools,folder,self.expected,str(Path(self.a.adb).resolve()),sys.executable);self.run_child('census-'+str(target),argv);self.guard('post-census-'+str(target));self.inspect_window('post-census-'+str(target))
 def maps(self,target):
  self.age(target,'maps-'+str(target));folder=self.root/('maps-'+str(target));argv=child_command('maps',target,self.tools,folder,self.expected,str(Path(self.a.adb).resolve()),sys.executable);self.run_child('maps-'+str(target),argv);self.guard('post-maps-'+str(target))
 def run(self):
  try:
   initial=self.guard('initial-identity')
   if initial>c.LOG_START-2:raise ValueError('Start before108seconds boot age; no late-arm fallback')
   self.r['initial_uptime']=initial;self.r['log_start_uptime']=self.age(c.LOG_START,'log-start');self.start_log()
   self.checkpoint(120);self.checkpoint(150);self.census(180);self.checkpoint(195);self.maps(225);self.checkpoint(270);self.census(300);self.checkpoint(315);self.maps(345);self.checkpoint(360)
   self.guard('final-identity');self.stop_log('completed')
   packet_check(self.root/'inputs',self.a.packet_sha256);packet_check(self.a.packet,self.a.packet_sha256)
   for n in ('run_matched_memory56.py','matched_memory56_contract.py','summarize_matched_memory56.py'):
    if c.sha(Path(__file__).with_name(n))!=self.m['sources_sha256'][n]:raise ValueError('Runtime source changed while armed')
   if c.sha(Path(sys.executable))!=self.r['host']['python_sha256'] or c.sha(Path(self.a.adb))!=self.r['host']['adb_sha256']:raise ValueError('Host executable changed while armed')
   events=c.log_events((self.root/'natural-logcat.txt').read_text(errors='replace'));self.r['natural_events']=events
   if events['fatal']:self.note('natural_fatal_exception')
   if events['anr']:self.note('natural_anr')
   if (self.root/'natural-logcat.stderr').read_bytes():self.note('natural_log_stderr')
   self.r['complete']=True;self.save()
   from summarize_matched_memory56 import verify_arm
   checked=verify_arm(self.root,allow_unfinalized=True);self.r.update(classification=checked['classification'],eligible_for_matched_comparison=checked['eligible_for_matched_comparison'],failures=checked['failures']);self.r['summary']=checked['measurements'];self.save()
  except BaseException as error:
   self.r.update(error=repr(error),classification='failed',eligible_for_matched_comparison=False);raise
  finally:
   if self.child is not None:stop_tree(self.child)
   self.stop_log('failed' if not self.r['complete'] else 'completed');self.r['raw_files_sha256']={p.relative_to(self.root).as_posix():c.sha(p) for p in self.root.rglob('*') if p.is_file() and p!=self.root/'arm.json'};self.save()
  print(json.dumps(dict(complete=self.r['complete'],classification=self.r['classification'],failures=self.r['failures'],savings_proven=False)))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='mode',required=True);s=sub.add_parser('freeze');s.add_argument('--bindings',type=Path,required=True);s.add_argument('--output',type=Path,required=True)
 s=sub.add_parser('run')
 for n in ('adb','image','boot','packet-sha256'):s.add_argument('--'+n,required=True)
 for n in ('packet','output'):s.add_argument('--'+n,type=Path,required=True)
 for n in ('slot','server-pid','ui-pid','server-start','ui-start'):s.add_argument('--'+n,type=int,required=True)
 a=p.parse_args()
 if a.mode=='freeze':freeze(a.bindings,a.output)
 else:
  if a.image not in c.LIBART or not 1<=a.slot<=4 or a.image!=c.ORDER[a.slot-1] or min(a.server_pid,a.ui_pid)<=1 or a.server_pid==a.ui_pid or min(a.server_start,a.ui_start)<=0 or str(uuid.UUID(a.boot))!=a.boot:p.error('Exact55/56 slot/UUID/currentPIDs/starttimes required')
  Runner(a).run()
