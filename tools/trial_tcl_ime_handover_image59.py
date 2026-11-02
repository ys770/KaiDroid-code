"""Leased image59 Clock-first then Notes; one Symbols request, no text/save/retry."""
import argparse,hashlib,io,json,re,shlex,struct,subprocess,time,uuid
from pathlib import Path
from PIL import Image
from check_tcl_ime_picker_layout import MODES,bounds,validate,xml_nodes
from check_tcl_clock_picker import check as clock_picker

SERIAL='DEVICE_SERIAL_REQUIRED'
FRAMEWORK='04eeb83ba7b062a6da7610d20829fc088f9cdf89d9474540e74b65da9f4e28bf'
SYSTEMUI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
KIKA='com.iqqijni.dvt912key/.keyboard_service.view.HDKeyboardService'
HOME='com.android.launcher3/com.android.launcher3.Launcher'
KEYS=('default_input_method','enabled_input_methods','selected_input_method_subtype','input_methods_subtype_history','show_ime_with_hard_keyboard')
PACKAGES=('com.android.settings','com.android.contacts','com.android.gallery3d','com.kaidroid.tclclock','com.android.calendar','com.android.note','com.android.deskclock')
PROFILES={
 'clock':dict(package='com.kaidroid.tclclock',component='com.kaidroid.tclclock/com.android.deskclock.DeskClock',editor_component='com.kaidroid.tclclock/com.android.deskclock.AlarmAddActivity',apk='b14ce4fecfd0bd8285ca455eb8ca679f98ffd334b481c4ca518e53f09842cd19',editor_id='android:id/title_edit_text_content',text='Alarm',mode='abc',reference='docs/screenshots/2026-10-27-tcl-clock-kika/kika-title-symbols.png',reference_sha256='1cbefe535dac8149915b47c43eefcde3abb5a705e2bf0877efdd35f9697f5794'),
 'notes':dict(package='com.android.note',component='com.android.note/.NotesListActivity',editor_component='com.android.note/com.android.note.NewNoteActivity',apk='7cfbef1984a10e82f6cd145c04b1d436b34678d64a77ae85029aad770df5f12d',editor_id='com.android.note:id/et_editor',text='',mode='Abc',reference='docs/screenshots/2026-10-27-tcl-symbols-reference/symbols-open.png',reference_sha256='0d473271fa1fa79cc45a7ac557aa6ab5a82d46998feca8fbd9086c617ab23244')}

def require(value,message):
 if not value:raise ValueError(message)

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def log_since(device_time):
 require(re.fullmatch(r'\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.000',device_time),'Canonical device log-start time required')
 # Integer -T arguments are line counts, not a session timestamp.
 return 'logcat -d -v epoch -T '+shlex.quote(device_time)

def window(text):
 rows=re.findall(r'mCurrentFocus=Window\{([0-9a-f]+) u0 ([^}]+)\}',text)
 require(len(rows)==1,'Missing/ambiguous current window')
 return list(rows[0])

def context(xml,phase):
 p=PROFILES[phase];nodes=xml_nodes(xml);texts=[n.get('text') for n in nodes]
 if validate(nodes)['passed']:return 'picker'
 if phase=='clock' and 'No Alarms' in texts and not any(n.get('class')=='android.widget.EditText' for n in nodes):return 'empty_list'
 if phase=='notes' and 'No note' in texts and not any(n.get('class')=='android.widget.EditText' for n in nodes):return 'empty_list'
 edits=[n for n in nodes if n.get('resource-id')==p['editor_id'] and n.get('class')=='android.widget.EditText']
 if len(edits)==1 and edits[0].get('text','')==p['text'] and (phase!='clock' or 'New Alarm' in texts):return 'editor'
 if phase=='clock' and 'New Alarm' in texts and not edits and not any(n.get('class')=='android.widget.EditText' for n in nodes):return 'form'
 return 'unknown'

def mode(xml):
 choices=[n['text'] for n in xml_nodes(xml) if n.get('text') in MODES and bounds(n.get('bounds'))==[0,290,80,320]]
 require(len(choices)==1,'Single editor mode footer missing');return choices[0]

def editor_signature(xml,phase):
 p=PROFILES[phase];edits=[n for n in xml_nodes(xml) if n.get('resource-id')==p['editor_id'] and n.get('class')=='android.widget.EditText']
 require(len(edits)==1 and edits[0].get('text','')==p['text'],'Original editor content not retained')
 return dict(text=edits[0].get('text',''),bounds=bounds(edits[0]['bounds']),focused=edits[0].get('focused')=='true',mode=mode(xml))

def selected(png,xml,phase,index):
 layout=validate(xml_nodes(xml));require(layout['passed'],'Six-mode layout differs')
 if phase=='clock':return clock_picker(png,xml,index)
 with Image.open(png) as source:
  rgb=source.convert('RGB');colors=[rgb.getpixel((5,(b[1]+b[3])//2)) for b in layout['row_text_bounds']]
 require(colors==[(68,132,204) if i==index else (255,255,255) for i in range(6)],'Notes selector/index differs')
 return dict(selected_index=index,six_mode_geometry_passed=True)

def panel(png,reference):
 with Image.open(png) as a,Image.open(reference) as b:
  require(a.size==b.size==(240,320),'Panel dimensions differ')
  left=list(a.convert('RGB').crop((0,224,240,290)).get_flattened_data());right=list(b.convert('RGB').crop((0,224,240,290)).get_flattened_data())
 hist={}
 for a,b in zip(left,right):
  delta=max(abs(x-y) for x,y in zip(a,b));hist[delta]=hist.get(delta,0)+1
 return dict(bounds=[0,224,240,290],pixels=15840,different_pixels=15840-hist.get(0,0),maximum_channel_delta=max(hist),
  maximum_channel_delta_histogram=hist,visible_reference_panel=max(hist)<=2,pixel_equality=hist.get(0,0)==15840,full_parity=False)

def clock_prior(report,boot):
 require(report.get('phase')=='clock' and report.get('image')==59 and report.get('boot')==boot and report.get('framework_sha256')==FRAMEWORK and report.get('passed') is True and report.get('symbols_requests')==1 and report.get('exact_home_window_restored') is True and report.get('fresh_clock_first_attested') is True,'Successful same-boot fresh Clock receipt required before Notes')
 require(all(report.get(k) is True for k in ('workflow_passed','all_settings_and_appfiles_restored','symbols_cancelled_without_text','numeric_callback_observed','mode_roundtrip_verified')) and all(report.get(k) is False for k in ('text_entered','save_invoked','command_state_ambiguous')) and all(report.get(k,{}).get('visible_reference_panel') is True for k in ('first_symbols_panel','settled_symbols_panel')),'Incomplete Clock workflow/restoration receipt')
 return report['before_home']

def fresh_editor_state(activities,processes):
 require(not any('ActivityRecord{' in s and any(p in s for p in ('com.kaidroid.tclclock/','com.android.note/')) for s in activities.splitlines()),'Clock/Notes already active; fresh editor provenance unproven')
 # AlarmInitReceiver legitimately starts Clock on BOOT_COMPLETED. A process
 # alone is not proof an editor or mode picker was used before this lease.
 return dict(no_prior_clock_notes_activities=True,existing_clock_notes_process_rows=[s.strip() for s in processes.splitlines() if s.split() and s.split()[-1] in ('com.kaidroid.tclclock','com.android.note')],complete_history_requires_hardware_fresh_boot_attestation=True)

class Trial:
 def __init__(self,args):
  self.a=args;self.p=PROFILES[args.phase];self.seq=0;self.ambiguous=False;self.owned=False;self.current=None;self.before=None;self.original_mode=None;self.mode_dirty=False
  self.report=dict(image=59,phase=args.phase,boot=args.boot,framework_sha256=FRAMEWORK,passed=False,symbols_requests=0,
   fresh_clock_first_attested=bool(args.fresh_clock_first),text_entered=False,save_invoked=False,physical_keys=False,full_parity=False,exact_home_window_restored=False,actions=[])
  args.output.mkdir(parents=True,exist_ok=False)
 def save(self):
  (self.a.output/'result.json').write_text(json.dumps(self.report,indent=2)+'\n',encoding='utf-8')
 def run(self,label,args,action=False):
  self.seq+=1;prefix=self.a.output/(str(self.seq).zfill(3)+'-'+label)
  if action:self.report['actions'].append(args);self.report['action_pending']=True;self.save()
  try:r=subprocess.run([self.a.adb,'-s',SERIAL]+args,capture_output=True,timeout=45)
  except subprocess.TimeoutExpired as e:
   self.ambiguous=True;prefix.with_suffix('.stdout').write_bytes(e.stdout or b'');prefix.with_suffix('.stderr').write_bytes(e.stderr or b'');raise
  prefix.with_suffix('.stdout').write_bytes(r.stdout);prefix.with_suffix('.stderr').write_bytes(r.stderr)
  if action:
   if r.returncode:self.ambiguous=True
   self.report['action_pending']=False;self.save()
  r.check_returncode();return r.stdout
 def shell(self,label,cmd,action=False):return self.run(label,['shell',cmd],action).decode('utf-8',errors='replace').replace('\r\n','\n').strip()
 def identity(self):
  require(self.shell('identity','getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; getprop sys.boot_completed').splitlines()==[SERIAL,'59',self.a.boot,'0','Enforcing','1'],'Exact image59 identity/root/boot required')
 def focus(self):return window(self.shell('window','dumpsys window'))
 def state(self,label):
  values={k:self.shell(label+'-'+k,'settings get secure '+k) for k in KEYS}
  values['bluetooth_on']=self.shell(label+'-bt','settings get global bluetooth_on')
  values['appfiles']={}
  for pkg in PACKAGES:
   values['appfiles'][pkg]=sorted(self.shell(label+'-files-'+pkg,'for d in /data/user/0/'+pkg+' /data/user_de/0/'+pkg+'; do if test -d "$d"; then find "$d" -type f -exec sha256sum {} +; fi; done').splitlines())
  return values
 def snapshot(self,label):
  self.identity();owner=self.focus();require(owner[1].startswith(self.p['package']+'/'),'App focus changed; stop input')
  remote='/data/local/tmp/kaidroid-image59-'+uuid.uuid4().hex+'.xml'
  self.shell(label+'-dump','uiautomator dump '+shlex.quote(remote));xml=self.shell(label+'-xml','cat '+shlex.quote(remote))
  png=self.run(label+'-screen',['exec-out','screencap','-p']);require(png[:8]==b'\x89PNG\r\n\x1a\n' and struct.unpack('>II',png[16:24])==(240,320),'Invalid PNG')
  require(self.focus()==owner,'Window changed during capture')
  (self.a.output/(label+'.xml')).write_text(xml,encoding='utf-8');(self.a.output/(label+'.png')).write_bytes(png)
  self.shell(label+'-ime','dumpsys input_method');self.shell(label+'-windows','dumpsys window -a')
  kind=context(xml,self.a.phase);self.current=(kind,owner,xml,label)
  self.report.setdefault('captures',{})[label]=dict(context=kind,owner=owner,png_sha256=hashlib.sha256(png).hexdigest(),xml_sha256=hashlib.sha256(xml.encode()).hexdigest())
  self.save();return kind
 def send(self,code,allowed):
  require(not self.ambiguous and self.current and self.current[0] in allowed,'No verified input context')
  require(code in (1,3,4,20,23),'Out-of-scope key')
  self.identity();require(self.focus()==self.current[1],'Input owner changed')
  self.shell('key-'+str(code),'input keyevent '+str(code),True);time.sleep(1)
 def choose(self,label,index):
  if index==5:require(self.report['symbols_requests']==0,'Symbols must never be repeated')
  self.send(1,('editor',));require(self.snapshot(label+'-picker')=='picker','Picker did not open')
  owner=self.current[1];selected(self.a.output/(label+'-picker.png'),self.current[2],self.a.phase,0)
  for i in range(index):
   require(self.current[1]==owner,'Picker owner changed')
   self.send(20,('picker',));require(self.snapshot(label+'-down'+str(i+1))=='picker','Picker disappeared')
   selected(self.a.output/(self.current[3]+'.png'),self.current[2],self.a.phase,i+1)
  if index==5:
   self.report['symbols_requests']=1;self.mode_dirty=True;self.save()
  self.send(23,('picker',));require(self.snapshot(label+'-editor')=='editor','Mode callback lost original editor')
 def home(self):
  self.send(3,('empty_list',));deadline=time.monotonic()+12;observed=[]
  while True:
   current=self.focus();observed.append(current)
   self.report['home_observations']=observed;self.save()
   if current==self.report['before_home']:break
   if time.monotonic()>=deadline:raise ValueError('Exact original Home window not restored')
   self.identity();time.sleep(.5)
  self.report['home_observations']=observed;self.report['exact_home_window_restored']=True
 def cleanup(self):
  if not self.owned or self.ambiguous:return dict(status='deferred_unowned_or_ambiguous')
  if self.mode_dirty:return dict(status='deferred_mode_restoration_unproven')
  kind=self.snapshot('cleanup-current')
  if kind=='picker':self.send(4,('picker',));kind=self.snapshot('cleanup-after-picker')
  if kind in ('editor','form'):
   # Only unchanged Alarm/default blank Note is classified as an owned editor.
   self.send(4,('editor','form'));kind=self.snapshot('cleanup-after-editor')
  if kind=='empty_list':self.home();return dict(status='exact_home_returned')
  return dict(status='deferred_unknown_context',context=kind)
 def execute(self):
  try:
   self.identity();home=self.focus();require(home[1]==HOME,'Start from Launcher');self.report['before_home']=home
   hashes=self.shell('framework','sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
   require([x.split()[0] for x in hashes.splitlines()]==[FRAMEWORK,SYSTEMUI],'Framework/SystemUI pin differs')
   for pkg,pin in [(self.p['package'],self.p['apk']),('com.iqqijni.dvt912key','f80ddc5b461d1d23cc05f9c212f43629991766f9630466b89fbdec8b34ea8e7f')]:
    path=self.shell('path-'+pkg,'pm path '+pkg);require(re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk',path),'Unexpected APK path')
    require(self.shell('hash-'+pkg,'sha256sum '+shlex.quote(path[8:])).split()[0]==pin,'APK differs: '+pkg)
   if self.a.phase=='clock':
    require(self.a.fresh_clock_first,'Fresh Clock-first lease attestation required')
    activities=self.shell('fresh-activities','dumpsys activity activities');processes=self.shell('fresh-processes','ps -A -o PID,NAME')
    self.report['fresh_editor_observations']=fresh_editor_state(activities,processes)
   else:
    prior=json.loads(self.a.clock_result.read_text());require(home==clock_prior(prior,self.a.boot),'Clock/Notes Home window lineage differs')
    self.report['clock_result_sha256']=sha(self.a.clock_result)
   self.before=self.state('before');require(self.before['default_input_method']==KIKA,'Original Kika must be selected')
   self.report['before_state']=self.before
   times=self.shell('epoch',"date +%s; date '+%m-%d %H:%M:%S.000'").splitlines()
   require(len(times)==2 and times[0].isdigit(),'Invalid log start epoch');log_since(times[1])
   self.report['log_start_epoch']=times[0];self.report['log_start_device_time']=times[1]
   launch=self.shell('launch','am start -W -n '+self.p['component'],True);require(re.search(r'^Status:\s*ok\s*$',launch,re.M),'Launch not definitive success')
   require(self.snapshot('entry')=='empty_list','Expected empty app; no edit input');self.owned=True
   self.send(1,('empty_list',));kind=self.snapshot('new-editor')
   if self.a.phase=='clock':
    require(kind in ('form','editor'),'Unsaved Alarm form absent')
    ids=['com.android.deskclock:id/alarm_add_time_item','com.android.deskclock:id/alarm_add_repeat_item','com.android.deskclock:id/alarm_add_ringtone_item','com.android.deskclock:id/alarm_add_vibrate_item','android:id/title_edit_text_content']
    for i,expected in enumerate(ids):
     self.send(20,('form','editor'));require(self.snapshot('title-focus'+str(i+1)) in ('form','editor'),'Alarm form lost')
     focused=[n.get('resource-id') for n in xml_nodes(self.current[2]) if n.get('focused')=='true'];require(focused==[expected],'Alarm focus order differs')
   require(self.current[0]=='editor','Original editor absent');self.original_mode=mode(self.current[2]);require(self.original_mode==self.p['mode'],'Unexpected original mode')
   self.report['original_mode']=self.original_mode
   self.report['editor_before']=editor_signature(self.current[2],self.a.phase)
   require(self.report['editor_before']['focused'],'Original editor not focused')
   root=Path(__file__).resolve().parents[1];reference=root/self.p['reference'];require(sha(reference)==self.p['reference_sha256'],'Donor reference differs')
   self.choose('first-symbols',5)
   # This is the first and only Symbols request; extra observations never resend.
   self.report['first_symbols_panel']=panel(self.a.output/'first-symbols-editor.png',reference)
   require(self.report['first_symbols_panel']['visible_reference_panel'],'First Symbols panel missing/displaced; preserve failure')
   require(self.snapshot('first-symbols-settled')=='editor','Settled Symbols observation lost editor')
   self.report['settled_symbols_panel']=panel(self.a.output/'first-symbols-settled.png',reference)
   require(self.report['settled_symbols_panel']['visible_reference_panel'],'Symbols panel disappeared without another action')
   self.send(4,('editor',));require(self.snapshot('symbols-cancelled')=='editor' and mode(self.current[2])==self.original_mode,'Symbols Back lost unchanged editor/mode')
   self.report['editor_after_symbols']=editor_signature(self.current[2],self.a.phase)
   require(self.report['editor_after_symbols']==self.report['editor_before'],'Symbols cancellation changed editor content/focus/bounds/mode')
   require(not panel(self.a.output/'symbols-cancelled.png',reference)['visible_reference_panel'],'Symbols panel still visible after Back')
   self.mode_dirty=False
   self.report['symbols_cancelled_without_text']=True
   self.mode_dirty=True;self.choose('numeric',4);require(mode(self.current[2])=='123','Numeric callback not observed');self.report['numeric_callback_observed']=True
   self.choose('restore',MODES.index(self.original_mode));require(mode(self.current[2])==self.original_mode,'Original mode not restored')
   require(editor_signature(self.current[2],self.a.phase)==self.report['editor_before'],'Mode restoration changed editor content/focus/bounds')
   self.mode_dirty=False;self.report['mode_roundtrip_verified']=True;self.report['workflow_passed']=True
  except Exception as e:self.report['failure']=repr(e)
  finally:
   try:
    self.report['cleanup']=self.cleanup()
    if self.report.get('exact_home_window_restored'):
     after=self.state('after');self.report['after_state']=after;self.report['all_settings_and_appfiles_restored']=after==self.before
     require(after==self.before,'IME/Bluetooth or app files changed; preservation not proven')
     self.report['passed']=bool(self.report.get('workflow_passed') and not self.report.get('failure'))
    if not self.ambiguous and 'log_start_epoch' in self.report:
     self.shell('fresh-log',log_since(self.report['log_start_device_time']))
   except Exception as e:self.report['cleanup_failure']=repr(e);self.report['passed']=False
   self.report['command_state_ambiguous']=self.ambiguous;self.save()
  return self.report

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',required=True);p.add_argument('--boot',type=lambda value:str(uuid.UUID(value)),required=True)
 p.add_argument('--phase',choices=PROFILES,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--fresh-clock-first',action='store_true');p.add_argument('--clock-result',type=Path)
 a=p.parse_args();require(a.phase=='clock' or a.clock_result is not None,'Notes requires same-boot Clock result')
 report=Trial(a).execute();print(json.dumps(report))
 if not report['passed']:raise RuntimeError('Image59 acceptance failed; retain state/results, never retry blindly')

if __name__=='__main__':main()
