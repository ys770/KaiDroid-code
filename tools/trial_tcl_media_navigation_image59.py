"""Leased Music tabs or Recorder idle/list; never Play, Record or grant access."""
import argparse,hashlib,json,re,shlex,struct,subprocess,time,uuid
from pathlib import Path
from check_tcl_ime_picker_layout import xml_nodes
from compare_runtime_permissions import snapshot as permissions
from image59_home_observer import observe as observe_home

SERIAL='DEVICE_SERIAL_REQUIRED'
FRAMEWORK='04eeb83ba7b062a6da7610d20829fc088f9cdf89d9474540e74b65da9f4e28bf'
SYSTEMUI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
HOME='com.android.launcher3/com.android.launcher3.Launcher'
TABS=('Playlists','Songs','Artists','Albums')
PROFILES={
 'music':dict(package='com.android.music',component='com.android.music/.MusicBrowserActivity',apk='851beeed55fa47d7611e72ce9882d667bc0ad456062503e8ce2262fa7b7dcad2',uid=10079,version=2024022201),
 'recorder':dict(package='com.android.soundrecorder',component='com.android.soundrecorder/.SoundRecorder',apk='85bafcfe73128f45db4b0651c829eb4b9c8f3bbaca8b2d9f674a8eb2b499a528',uid=10102,version=30)}

def require(value,message):
 if not value:raise ValueError(message)

def package_block(text,package):
 active=text.split('Hidden system packages:',1)[0]
 starts=list(re.finditer(r'^  Package \['+re.escape(package)+r'\][^\n]*\n',active,re.M))
 require(len(starts)==1,'One active package record required')
 start=starts[0];tail=active[start.end():]
 end=re.search(r'(?m)^(?:\S|  \S)',tail)
 # Later top-level Queries sections can contain their own User0 marker;
 # they are not part of the package runtime-permission user block.
 return active[start.start():start.end()+(end.start() if end else len(tail))]

def runtime_state(text,package):return permissions('Packages:\n'+package_block(text,package),package,0)

def classify(xml,profile):
 nodes=xml_nodes(xml)
 def text(resource):return [n.get('text','') for n in nodes if n.get('resource-id')==resource]
 if profile=='music':
  title=text('com.android.music:id/title')
  if len(title)==1 and title[0] in TABS:
   return dict(kind='music_tab',tab=title[0],empty_messages=text('com.android.music:id/tv_no_title'))
 else:
  if text('com.android.soundrecorder:id/main_title')==['Recorder'] and text('com.android.soundrecorder:id/timerView')==['00:00:00']:
   labels=[n.get('text') for n in nodes if n.get('text')]
   if 'List' in labels and 'Record' in labels:return dict(kind='recorder_idle',timer='00:00:00')
  if text('com.android.soundrecorder:id/file_list_title')==['Recordings']:
   return dict(kind='recordings_list',empty=text('com.android.soundrecorder:id/list_empty_text')==['No Recordings'])
 return dict(kind='unknown')

def storage_prompt(xml,owner):
 if owner[1]!='com.android.permissioncontroller/com.android.permissioncontroller.permission.ui.GrantPermissionsActivity':return False
 messages=[n.get('text','') for n in xml_nodes(xml) if n.get('resource-id')=='com.android.permissioncontroller:id/permission_message']
 return len(messages)==1 and 'Recorder' in messages[0] and any(word in messages[0].lower() for word in ('files','media','storage'))

class Trial:
 def __init__(self,a):
  self.a=a;self.p=PROFILES[a.app];self.seq=0;self.ambiguous=False;self.current=None;self.owned=False;self.before=None
  a.output.mkdir(parents=True,exist_ok=False)
  self.report=dict(scope='Music tab navigation or Recorder idle/list only',image=59,app=a.app,boot=a.boot,passed=False,play_requested=False,record_requested=False,permission_choices_made=False,full_parity=False,physical_keys=False,actions=[])
 def save(self):(self.a.output/'result.json').write_text(json.dumps(self.report,indent=2)+'\n',encoding='utf-8')
 def run(self,label,args,action=False):
  self.seq+=1;prefix=str(self.a.output/(str(self.seq).zfill(3)+'-'+label))
  if action:self.report['actions'].append(args);self.report['action_pending']=True;self.save()
  try:r=subprocess.run([self.a.adb,'-s',SERIAL]+args,capture_output=True,timeout=45)
  except subprocess.TimeoutExpired as e:
   self.ambiguous=True;Path(prefix+'.stdout').write_bytes(e.stdout or b'');Path(prefix+'.stderr').write_bytes(e.stderr or b'');raise
  Path(prefix+'.stdout').write_bytes(r.stdout);Path(prefix+'.stderr').write_bytes(r.stderr)
  if action:
   self.report['action_pending']=False
   if r.returncode:self.ambiguous=True
  r.check_returncode();return r.stdout
 def shell(self,label,command,action=False):return self.run(label,['shell',command],action).decode('utf-8',errors='replace').replace('\r\n','\n').strip()
 def identity(self):
  require(self.shell('identity','getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; getprop sys.boot_completed').splitlines()==[SERIAL,'59',self.a.boot,'0','Enforcing','1'],'Exact current59/root/boot required')
 def focus(self):
  text=self.shell('window','dumpsys window');rows=re.findall(r'mCurrentFocus=Window\{([0-9a-f]+) u0 ([^}]+)\}',text)
  require(len(rows)==1,'Missing/ambiguous focus');return list(rows[0])
 def state(self,label):
  pkg=self.p['package'];package=self.shell(label+'-package','dumpsys package '+pkg)
  grant=runtime_state(package,pkg);require(grant['uid']==self.p['uid'],'Unexpected installed UID')
  active=package_block(package,pkg)
  require(len(re.findall(r'\bversionCode='+str(self.p['version'])+r'\b',active))==1,'Wrong installed version')
  keys=('default_input_method','enabled_input_methods','selected_input_method_subtype','input_methods_subtype_history','show_ime_with_hard_keyboard')
  settings={k:self.shell(label+'-'+k,'settings get secure '+k) for k in keys};settings['bluetooth_on']=self.shell(label+'-bt','settings get global bluetooth_on')
  files=sorted(self.shell(label+'-files','for d in /data/user/0/'+pkg+' /data/user_de/0/'+pkg+'; do if test -d "$d"; then find "$d" -type f -exec sha256sum {} +; fi; done').splitlines())
  audio=self.shell(label+'-audio',"content query --uri content://media/external/audio/media --projection _id:_data:_display_name:mime_type --sort '_id ASC'")
  require(audio=='No result found.' or audio.startswith('Row: '),'Audio provider inventory not conclusive')
  return dict(settings=settings,permissions=grant,appfiles=files,audio_rows_sha256=hashlib.sha256(audio.encode()).hexdigest())
 def capture(self,label):
  self.identity();owner=self.focus()
  require(owner[1].startswith(self.p['package']+'/') or self.a.app=='recorder' and owner[1].startswith('com.android.permissioncontroller/'),'Unexpected app owner; no input')
  remote='/data/local/tmp/kaidroid-media59-'+uuid.uuid4().hex+'.xml';self.shell(label+'-dump','uiautomator dump '+shlex.quote(remote));xml=self.shell(label+'-xml','cat '+shlex.quote(remote))
  png=self.run(label+'-screen',['exec-out','screencap','-p']);require(png[:8]==b'\x89PNG\r\n\x1a\n' and struct.unpack('>II',png[16:24])==(240,320),'Invalid PNG')
  require(self.focus()==owner,'Capture owner changed')
  state=classify(xml,self.a.app)
  if storage_prompt(xml,owner):state=dict(kind='storage_prompt')
  (self.a.output/(label+'.xml')).write_text(xml,encoding='utf-8');(self.a.output/(label+'.png')).write_bytes(png)
  self.current=dict(owner=owner,state=state,label=label)
  self.report.setdefault('captures',{})[label]=dict(**self.current,png_sha256=hashlib.sha256(png).hexdigest(),xml_lf_sha256=hashlib.sha256(xml.encode()).hexdigest());self.save();return state
 def key(self,code,kinds):
  require(not self.ambiguous and self.current and self.current['state']['kind'] in kinds,'Unproven key context')
  require(code in (1,3,4,22),'Play/Record/selection keys prohibited')
  if code==1:require(self.a.app=='recorder' and self.current['state']['kind']=='recorder_idle','Only idle Recorder List LSK allowed')
  if code==22:require(self.a.app=='music' and self.current['state']['kind']=='music_tab','Only Music tab Right allowed')
  self.identity();require(self.focus()==self.current['owner'],'Input owner changed')
  self.shell('key-'+str(code),'input keyevent '+str(code),True);time.sleep(1)
 def home(self):
  self.key(3,('music_tab','recorder_idle','recordings_list'))
  def read():self.identity();return self.shell('home-window','dumpsys window')
  self.report['home_observation']=observe_home(read,self.report['before_home'])
  require(self.report['home_observation']['home_component_observed'],'Home not observed')
 def execute(self):
  try:
   self.identity();home=self.focus();require(home[1]==HOME,'Start from Launcher');self.report['before_home']=home
   hashes=self.shell('core-hashes','sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk');require([s.split()[0] for s in hashes.splitlines()]==[FRAMEWORK,SYSTEMUI],'Core hashes differ')
   pkg=self.p['package'];path=self.shell('apk-path','pm path '+pkg);require(re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk',path),'APK path differs')
   require(self.shell('apk-hash','sha256sum '+shlex.quote(path[8:])).split()[0]==self.p['apk'],'Actual active APK differs; system placeholder is not the TCL update')
   services=self.shell('services-before','dumpsys activity services '+pkg);require(not re.search(r'ServiceRecord\{[^\n]*'+re.escape(pkg),services),'Existing media service; do not disturb')
   self.before=self.state('before');self.report['before_state']=self.before
   launch=self.shell('launch','am start -W -n '+self.p['component'],True);require(re.search(r'^Status:\s*ok\s*$',launch,re.M),'Launch not definitive success')
   state=self.capture('entry');self.owned=True
   if self.a.app=='music':
    require(state['kind']=='music_tab','Music tab absent');start=TABS.index(state['tab'])
    for i in range(1,5):
     self.key(22,('music_tab',));state=self.capture('right'+str(i));require(state.get('tab')==TABS[(start+i)%4],'Music tab order/wrap differs')
    self.report['four_tabs_and_wrap_verified']=True
   else:
    require(state['kind']=='recorder_idle','Recorder not verified idle; no Record key authorized')
    self.key(1,('recorder_idle',));state=self.capture('list-requested')
    if state['kind']=='storage_prompt':
     self.report['list_blocked_by_storage_permission']=True;self.key(4,('storage_prompt',));state=self.capture('permission-cancelled')
     require(state['kind'] in ('recorder_idle','recordings_list'),'Storage prompt cancellation did not return owned Recorder')
    else:require(state['kind']=='recordings_list','Recording list absent')
    if state['kind']=='recordings_list':
     self.report['list_observed']=True;self.key(4,('recordings_list',));require(self.capture('list-back')['kind']=='recorder_idle','Back did not restore idle Recorder')
   self.report['bounded_navigation_completed']=True
  except Exception as e:self.report['failure']=repr(e)
  finally:
   try:
    if self.owned and not self.ambiguous and self.current['state']['kind'] in ('music_tab','recorder_idle','recordings_list'):
     self.home();after=self.state('after');self.report['after_state']=after;self.report['state_equal']=after==self.before
     require(after==self.before,'Permissions/settings/app files/audio rows changed; preservation unproven')
     self.report['passed']=bool(self.report.get('bounded_navigation_completed') and not self.report.get('failure'))
   except Exception as e:self.report['cleanup_failure']=repr(e);self.report['passed']=False
   self.report['command_state_ambiguous']=self.ambiguous;self.save()
  return self.report

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--adb',required=True);p.add_argument('--boot',required=True,type=lambda s:str(uuid.UUID(s)))
 p.add_argument('--app',choices=PROFILES,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 report=Trial(a).execute();print(json.dumps(report))
 if not report['passed']:raise RuntimeError('Media navigation failed; preserve state, no blind retry')

if __name__=='__main__':main()
