"""Shared strict policy for a read-only55/56 crossover measurement."""
import collections,hashlib,json,re,uuid,math
from pathlib import Path
SERIAL='DEVICE_SERIAL_REQUIRED';ORDER=('55','56','55','56')
LOG_START=110
CHECKPOINTS=(120,150,195,270,315,360);CENSUSES=(180,300);MAPS=(225,345)
TOLERANCE=2.0;MAX_CAPTURE_SECONDS=15.0;MAX_LOG_BYTES=32*1024**2
SETTINGS={'global':{'wifi_on','bluetooth_on','airplane_mode_on','mobile_data','preferred_network_mode','preferred_network_mode1','mobile_data1','stay_on_while_plugged_in'},'system':{'screen_off_timeout','screen_brightness','screen_brightness_mode'},'secure':{'default_input_method'}}
PROPERTIES={'gsm.sim.state','gsm.operator.numeric','gsm.network.type','ro.telephony.default_network','ro.config.low_ram','persist.radio.multisim.config'}
CORE={'/system/framework/framework.jar':'429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53','/system/framework/oat/arm/services.art':'06367ceca49dfd29ee2732a62b217f42399c04a631c07cb2a63226f822f17ff4','/system/framework/oat/arm/services.odex':'7ccc2039785860155f161ba8a8583adf50ee64c8364553f3718c8d3774b1b608','/system/framework/oat/arm/services.vdex':'55d079cc405a9eff0a8ec066af3f740dc4e3277ecaeebfde627a4c4eefd27035'}
LIBART={'55':'cbb433722989b7b3dd6e4f63e3ad001e91637d13deb232cc9ab16cd379ff8e62','56':'5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258'}
SOURCES=('run_matched_memory56.py','matched_memory56_contract.py','summarize_matched_memory56.py','capture_timed_memory_audit.py','audit_memory.py','capture_memory_maps.py','summarize_memory_audit.py','summarize_memory_maps.py','summarize_guarded_memory_maps.py')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,value):path.write_bytes((json.dumps(value,indent=2)+'\n').encode('utf-8'))
def exact_sha(value):return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None
def text(value):return isinstance(value,str) and len(value)<=512 and '\n' not in value and '\r' not in value and '\0' not in value
def component(value):
 if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+',value):raise ValueError('Exact foreground component required')
 pkg,cls=value.split('/');return pkg+'/'+(pkg+cls if cls.startswith('.') else cls)
def validate_bindings(r):
 if not isinstance(r,dict) or set(r)!={'schema_version','experiment','serial','preparation','mms','foreground_component','settings','properties','power','expected_process_commands'} or r['schema_version']!=1 or r['serial']!=SERIAL:raise ValueError('Exact bindings schema/handset required')
 if not isinstance(r['experiment'],str) or not re.fullmatch('[a-z0-9][a-z0-9-]{0,63}',r['experiment']):raise ValueError('Experiment id invalid')
 if not text(r['preparation']) or not r['preparation']:raise ValueError('Caller must declare identical operator preparation; harness never executes it')
 m=r['mms']
 if not isinstance(m,dict) or set(m)!={'package','apk_path','sha256'} or m['package']!='com.android.mms' or not isinstance(m['apk_path'],str) or not re.fullmatch(r'/(?:data/app|system/(?:priv-app|app))/[A-Za-z0-9_./~+=@-]+\.apk',m['apk_path']) or '..' in Path(m['apk_path']).parts or not exact_sha(m['sha256']):raise ValueError('Caller must supply exact active MMS APK path/SHA')
 component(r['foreground_component'])
 if not isinstance(r['settings'],dict) or set(r['settings'])!=set(SETTINGS):raise ValueError('All settings namespaces required')
 for ns,required in SETTINGS.items():
  values=r['settings'][ns]
  if not isinstance(values,dict) or not required<=set(values) or any(not re.fullmatch('[a-z][a-z0-9_.]*',k) or not text(v) for k,v in values.items()):raise ValueError('Exact settings values required '+ns)
 if not isinstance(r['properties'],dict) or not PROPERTIES<=set(r['properties']) or any(not re.fullmatch('[a-z][a-z0-9_.]*',k) or not text(v) for k,v in r['properties'].items()):raise ValueError('Exact radio/lowRAM properties required')
 if r['properties']['ro.config.low_ram']!='true':raise ValueError('LowRAM property must remain true')
 if not isinstance(r['power'],dict) or not {'POWER_SUPPLY_STATUS','POWER_SUPPLY_CHARGING_ENABLED'}<=set(r['power']) or any(not re.fullmatch('POWER_SUPPLY_[A-Z0-9_]+',k) or not text(v) for k,v in r['power'].items()):raise ValueError('Exact charging bindings required')
 pop=r['expected_process_commands']
 if pop is not None and (not isinstance(pop,list) or not pop or any(not text(v) or not v for v in pop)):raise ValueError('Process reference must be null or exact command list')
 return r
def expected_core(image):return {**CORE,'/apex/com.android.art/lib/libart.so':LIBART[image]}
def start_ticks(stat,pid):
 if not stat.startswith(str(pid)+' ('):raise ValueError('Wrong process PID')
 return int(stat.rsplit(')',1)[1].split()[19])
def identity(lines,expected):
 if len(lines)!=11 or lines[:6]!=[SERIAL,expected['image'],expected['boot'],'0','Enforcing','1'] or lines[7:9]!=[str(expected['server_pid']),str(expected['ui_pid'])]:raise ValueError('Wrong handset/image/boot/root/Enforcing/startup/PIDs')
 if start_ticks(lines[9],expected['server_pid'])!=expected['server_start'] or start_ticks(lines[10],expected['ui_pid'])!=expected['ui_start']:raise ValueError('Process lifetime changed')
 age=float(lines[6].split()[0])
 if not math.isfinite(age) or age<0:raise ValueError('Invalid boot age')
 return age
def parse_sections(raw):
 sections={};current=None
 for line in raw.splitlines():
  if re.fullmatch('KV_[A-Z_]+',line):
   if line in sections:raise ValueError('Repeated checkpoint section')
   current=line;sections[current]=[]
  elif current:sections[current].append(line)
 return sections
def checkpoint(raw,bindings,image):
 s=parse_sections(raw);required={'KV_UPTIME','KV_PACKAGE','KV_HASHES','KV_GLOBAL','KV_SYSTEM','KV_SECURE','KV_PROPERTIES','KV_POWER','KV_WINDOW','KV_END_UPTIME'}
 if set(s)!=required:raise ValueError('Checkpoint closure differs')
 begin=float(s['KV_UPTIME'][0].split()[0]);end=float(s['KV_END_UPTIME'][0].split()[0]);failures=[]
 if end<begin:raise ValueError('Checkpoint uptime reversed')
 packages=[x.removeprefix('package:') for x in s['KV_PACKAGE'] if x]
 if packages!=[bindings['mms']['apk_path']]:failures.append('active_mms_path_drift')
 hashes={}
 for line in s['KV_HASHES']:
  parts=line.split()
  if len(parts)!=2 or not exact_sha(parts[0]) or parts[1] in hashes:raise ValueError('Malformed/duplicate hash read')
  hashes[parts[1]]=parts[0]
 expected={**expected_core(image),bindings['mms']['apk_path']:bindings['mms']['sha256']}
 if set(hashes)!=set(expected):raise ValueError('Missing/extra file hashes')
 for path,pin in expected.items():
  if hashes[path]!=pin:
   if path==bindings['mms']['apk_path']:failures.append('mms_apk_hash_drift')
   else:raise ValueError('Core experiment image differs '+path)
 actual={}
 for ns in SETTINGS:
  values={}
  for line in s['KV_'+ns.upper()]:
   if '=' in line:
    k,v=line.split('=',1)
    if k in values:raise ValueError('Duplicate setting')
    values[k]=v
  actual[ns]={k:values.get(k,'null') for k in bindings['settings'][ns]}
  if actual[ns]!=bindings['settings'][ns]:failures.append('settings_drift_'+ns)
 props={}
 for line in s['KV_PROPERTIES']:
  k,sep,v=line.partition('=')
  if not sep or k in props:raise ValueError('Property read malformed')
  props[k]=v
 if props!=bindings['properties']:failures.append('radio_property_drift')
 power=dict(line.split('=',1) for line in s['KV_POWER'] if '=' in line)
 if any(power.get(k)!=v for k,v in bindings['power'].items()):failures.append('charging_state_drift')
 win=window_status('\n'.join(s['KV_WINDOW']),bindings['foreground_component']);failures.extend(win['failures']);found=win['foreground']
 return dict(uptime_before=begin,uptime_after=end,failures=failures,active_apk_paths=packages,file_hashes=hashes,settings=actual,properties=props,power=power,foreground=found)
def population(processes):return dict(sorted(collections.Counter(x['command'].strip() for x in processes).items()))
def timing_failures(label,start,end,target):
 result=[]
 if abs(start-target)>TOLERANCE:result.append(label+'_missed_age')
 if end<start or end>target+MAX_CAPTURE_SECONDS:result.append(label+'_capture_window_exceeded')
 return result
def log_events(text):
 lines=set(text.splitlines());return dict(fatal=sorted(x for x in lines if 'FATAL EXCEPTION' in x),anr=sorted(x for x in lines if re.search(r'\bam_anr\s*:|ANR in ',x)),gc=sorted(x for x in lines if re.search(r'GC freed|GC_FOR_ALLOC|concurrent copying GC|concurrent mark sweep GC',x)),lmk=sorted(x for x in lines if re.search(r'\bkillinfo\s*:|lmkd.*[Kk]ill|lowmemorykiller.*[Kk]ill',x)),process_death=sorted(x for x in lines if re.search(r'\bam_proc_died\s*:',x)))

def window_status(window,expected):
 focus=[line for line in window.splitlines() if 'mCurrentFocus=' in line];found=[];failures=[]
 for line in focus:
  m=re.search(r'\bu\d+\s+([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+)',line)
  if m:found.append(component(m[1]))
 if found!=[component(expected)]:failures.append('foreground_drift')
 if re.search(r'Application Error|Application Not Responding|App Not Responding|aerr_|ANR in ',window,re.I):failures.append('error_dialog')
 return dict(foreground=found,failures=failures)
