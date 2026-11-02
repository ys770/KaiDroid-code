"""Hardware-owned image55 empty reminder, allowing an idle warm process only with full sync-view emptiness.

No event, account, provider, manifest or settings writes. No retry/force-stop.
Requires the independently coordinated current handset lease and boot ID.
"""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET

SERIAL='DEVICE_SERIAL_REQUIRED'
FRAMEWORK='429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53'
APK='971e5f9d32ab5b4f8e616a6c5d44073d66a000631cd47c353abf5ca4bc540b0d'
PACKAGE='com.android.calendar'
COMPONENT=PACKAGE+'/.alerts.AlertActivity'
TABLES=('calendars','events','reminders','calendar_alerts')
PROVIDER='com.android.providers.calendar'
PROVIDER_APK='255247f97c0208b9504e3eadbca63b192b1c35f18e3bc768bda461ac7d5b0dbc'
SYNC_EVENTS='content://com.android.calendar/events?caller_is_syncadapter=true'
KEYS=('default_input_method','enabled_input_methods','selected_input_method_subtype',
      'input_methods_subtype_history','show_ime_with_hard_keyboard')


def require(value,message):
 if not value:raise ValueError(message)


def focus(text):
 rows=[line.strip() for line in text.splitlines() if 'mCurrentFocus=' in line]
 require(len(rows)==1 and 'Window{' in rows[0],'Ambiguous/missing current focus')
 return rows[0]


def empty_projection(text):
 require(text.strip()=='No result found.','Calendar projection not conclusively empty')


def no_notifications(text):
 require('Notification List:' in text,'Missing notification-list observation')
 require(not any('NotificationRecord' in line and PACKAGE in line for line in text.splitlines()),
         'Calendar notification present; do not launch/continue')


def idle_calendar(activities,services):
 require(not any('ActivityRecord{' in line and PACKAGE+'/' in line for line in activities.splitlines()),'Existing Calendar activity; do not disturb')
 require(not any('ServiceRecord{' in line and PACKAGE+'/' in line for line in services.splitlines()),'Calendar service active; no concurrent work')


def empty_dialog(xml):
 start=xml.find('<?xml');end=xml.rfind('</hierarchy>')
 require(start>=0 and end>start,'Missing complete UI hierarchy')
 nodes=list(ET.fromstring(xml[start:end+len('</hierarchy>')]).iter('node'))
 title=[n for n in nodes if n.get('text')=='Calendar' and n.get('package')==PACKAGE]
 require(len(title)==1 and title[0].get('bounds')=='[0,254][240,290]','Empty Calendar title geometry absent')
 center=[n for n in nodes if n.get('package')==PACKAGE and n.get('text') in ('OK','Select') and n.get('bounds')=='[80,290][159,320]']
 require(len(center)==1,'Original Calendar center label/footer geometry absent')
 lists=[n for n in nodes if n.get('class') in ('android.widget.ListView','android.app.TctDialog$DialogListView') and n.get('package')==PACKAGE]
 # Actual55 adapter-empty fixture measures list[0,290,240,290]. UIAutomator
 # may omit that zero-height node; header/footer must still meet exactly.
 require(len(lists)<=1 and all(len(list(n))==0 and n.get('bounds')=='[0,290][240,290]' for n in lists),'Unexpected nonempty/list geometry')
 require(not any(n.get('class')=='android.widget.EditText' for n in nodes),'Unexpected editable activity')


def reminder_window(text):
 current=focus(text);key=current.removeprefix('mCurrentFocus=')
 require(re.fullmatch(r'Window\{[0-9a-f]+ u0 Calendar\}',key),'Unexpected Calendar popup title')
 apps=re.findall(r'mFocusedApp=ActivityRecord\{[0-9a-f]+ u0 com\.android\.calendar/(?:\.alerts\.AlertActivity|com\.android\.calendar\.alerts\.AlertActivity) t([0-9]+)\}',text)
 require(len(apps)==1,'Exact AlertActivity not the focused app')
 records=dict(re.findall(r'(?ms)^  Window #[0-9]+ (Window\{[^}]+\}):\n(.*?)(?=^  Window #|\Z)',text))
 require(key in records,'Focused popup record absent')
 def owned(block):
  return (re.search(r'\bmOwnerUid=10085\b.*\bpackage=com\.android\.calendar\b',block) is not None
   and re.search(r'\brootTaskId='+apps[0]+r'\b',block) is not None)
 popup=records[key]
 require(owned(popup) and 'ty=APPLICATION ' in popup and 'isOnScreen=true' in popup and 'isVisible=true' in popup,'Popup owner/task/surface changed')
 bases=[block for name,block in records.items() if re.fullmatch(r'Window\{[0-9a-f]+ u0 com\.android\.calendar/com\.android\.calendar\.alerts\.AlertActivity\}',name)]
 require(len(bases)==1 and owned(bases[0]) and 'ty=BASE_APPLICATION ' in bases[0],'Matching AlertActivity base window absent')
 return current


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',type=Path,required=True);p.add_argument('--boot-id',required=True)
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',a.boot_id),'Invalid boot ID')
 a.output.mkdir(parents=True,exist_ok=False)
 state=dict(image=55,framework_sha256=FRAMEWORK,calendar_apk_sha256=APK,boot_id=a.boot_id,
  passed=False,launch_count=0,back_count=0,ambiguous_action=False,provider_writes_requested=False,
  settings_writes_requested=False,physical_keys_tested=False,full_parity=False)
 def run(label,args,timeout=30,action=False):
  if action:
   state['ambiguous_action']=True;save()
  try:r=subprocess.run([str(a.adb),'-s',SERIAL,*args],capture_output=True,timeout=timeout)
  except subprocess.TimeoutExpired as error:
   (a.output/(label+'.stdout')).write_bytes(error.stdout or b'')
   (a.output/(label+'.stderr')).write_bytes(error.stderr or b'');raise
  (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
  r.check_returncode()
  if action:state['ambiguous_action']=False;save()
  return r.stdout
 def shell(label,command,**kwargs):return run(label,['shell',command],**kwargs).decode('utf-8').replace('\r\n','\n').strip()
 def save():(a.output/'result.json').write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8')
 def guard(label):
  require(shell(label,'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id')==SERIAL+'\n55\n'+a.boot_id,'Handset/image/boot changed')
  require(shell(label+'-framework','sha256sum /system/framework/framework.jar').split()[0]==FRAMEWORK,'Framework changed')
 def settings(label):return {n:shell(label+'-'+n,'settings get secure '+n) for n in KEYS}
 root_prefix=''
 def root(label,command,**kwargs):return shell(label,root_prefix+shlex.quote(command) if root_prefix else command,**kwargs)
 def rows(label):
  result={}
  for table in TABLES:
   result[table]=root(label+'-'+table,'content query --uri content://com.android.calendar/'+table+' --projection _id')
   empty_projection(result[table])
  result['all_sync_events']=root(label+'-all-sync-events','content query --uri '+shlex.quote(SYNC_EVENTS)+' --projection _id')
  empty_projection(result['all_sync_events'])
  return result
 def capture(label):
  window=shell(label+'-window','dumpsys window');current=reminder_window(window)
  tree=run(label+'-xml',['exec-out','uiautomator','dump','/dev/tty'],60).decode('utf-8')
  empty_dialog(tree)
  image=run(label+'-png',['exec-out','screencap','-p'])
  require(image.startswith(b'\x89PNG\r\n\x1a\n'),'Invalid screenshot')
  (a.output/(label+'.png')).write_bytes(image)
  return current
 try:
  guard('before')
  before_focus=focus(shell('before-window','dumpsys window'))
  require('com.android.launcher3/' in before_focus,'Home must already own focus')
  process=shell('before-process','ps -A')
  activities=shell('before-activities','dumpsys activity activities')
  services=shell('before-services','dumpsys activity services')
  idle_calendar(activities,services)
  state['warm_process_observed']=bool(re.search(r'\bcom\.android\.calendar\s*$',process,re.M))
  path=shell('apk-path','pm path '+PACKAGE)
  require(re.fullmatch(r'package:/(?:system|product|system_ext|data)/[A-Za-z0-9_./=+~-]+\.apk',path),'Unexpected/multiple installed Calendar paths')
  require(shell('apk-hash','sha256sum '+path[len('package:'):]).split()[0]==APK,'Installed Calendar provenance mismatch')
  provider=shell('provider-path','pm path '+PROVIDER)
  require(re.fullmatch(r'package:/(?:system|product|system_ext|data)/[A-Za-z0-9_./=+~-]+\.apk',provider),'Unexpected/multiple Calendar provider paths')
  require(shell('provider-hash','sha256sum '+provider[len('package:'):]).split()[0]==PROVIDER_APK,'Calendar provider differs from reviewed image55 source')
  if shell('shell-uid','id -u')!='0':
   root_prefix='su -c '
   require(root('existing-root','id -u')=='0','Existing noninteractive root unavailable')
  before_settings=settings('before-ime');bluetooth=shell('before-bluetooth','settings get global bluetooth_on')
  before_rows=rows('before-rows');no_notifications(shell('before-notifications','dumpsys notification'))
  guard('prelaunch');require(focus(shell('prelaunch-window','dumpsys window'))==before_focus,'Starting Home changed')
  state['launch_count']=1
  output=root('launch','am start -W -n '+COMPONENT,timeout=45,action=True)
  require('Status: ok' in output and not re.search(r'Error:|Exception|Warning: Activity not started',output),'No conclusive fresh activity launch')
  guard('opened');opened=capture('empty-reminder')
  require(rows('opened-rows')==before_rows,'Provider projections changed before Back')
  no_notifications(shell('opened-notifications','dumpsys notification'))
  guard('preback');require(reminder_window(shell('preback-window','dumpsys window'))==opened,'Dialog focus changed; no Back')
  state['back_count']=1;shell('back','input keyevent 4',action=True)
  guard('after')
  require(focus(shell('after-window','dumpsys window'))==before_focus,'Exact original Home not restored')
  require(rows('after-rows')==before_rows,'Calendar projection changed')
  no_notifications(shell('after-notifications','dumpsys notification'))
  require(settings('after-ime')==before_settings and shell('after-bluetooth','settings get global bluetooth_on')==bluetooth,'IME/Bluetooth changed')
  state.update(passed=True,empty_real_adapter_dialog_opened=True,back_returned_original_home=True,
   all_four_normal_and_global_sync_event_projections_empty_unchanged=True,same_boot_ime_bluetooth=True,
   provider_write_absence='Zero global sync-view Events makes receiver-cache matching-event update unreachable; zero CalendarAlerts bypasses alert generation. Source reasoning plus projections, not a database write trace',
   donor_pixel_comparison=False)
 except Exception as error:
  state['failure']=str(error);raise
 finally:save()
 print(json.dumps(state))


if __name__=='__main__':main()
