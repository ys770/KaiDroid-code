"""Bounded read-only continuity capture; never reconnects, reboots or restarts ADB."""
import argparse,json,subprocess,time,uuid
from pathlib import Path

SERIAL='DEVICE_SERIAL_REQUIRED'
COMMAND='getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; getprop sys.boot_completed; pidof system_server; pidof com.android.systemui; pidof adbd; getprop sys.usb.state; getprop sys.usb.config; cat /proc/uptime'

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',default='/opt/kaidroid/source/Documents/platform-tools/adb.exe')
 p.add_argument('--image',required=True)
 p.add_argument('--boot',required=True,type=lambda x:str(uuid.UUID(x)))
 p.add_argument('--output',required=True,type=Path)
 p.add_argument('--seconds',type=int,default=300)
 a=p.parse_args()
 if not 30<=a.seconds<=900:p.error('Duration must be30..900 seconds')
 a.output.mkdir(parents=True,exist_ok=False)
 start=time.monotonic();samples=[];initial=None;reason=None
 while time.monotonic()-start<a.seconds:
  index=len(samples);tick=time.monotonic();row={'index':index,'elapsed_seconds':tick-start}
  try:
   r=subprocess.run([a.adb,'-s',SERIAL,'exec-out',COMMAND],capture_output=True,timeout=8)
   (a.output/(str(index)+'.stdout')).write_bytes(r.stdout);(a.output/(str(index)+'.stderr')).write_bytes(r.stderr)
   row['exit_code']=r.returncode
   fields=r.stdout.decode(errors='replace').replace('\r\n','\n').strip().splitlines()
   row['transport_reply']=r.returncode==0 and len(fields)==10
   if row['transport_reply']:
    names=['serial','image','boot','completed','system_server','systemui','adbd','usb_state','usb_config','uptime']
    row.update(zip(names,fields))
    if fields[:4]!=[SERIAL,a.image,a.boot,'1']:
     reason='Handset/image/boot/completion changed';row['identity_matches']=False
    else:
     row['identity_matches']=True
     if initial is None:initial=fields[4:7]
     row['core_pids_unchanged']=fields[4:6]==initial[:2]
     row['adbd_pid_unchanged']=fields[6]==initial[2]
   else:row['failure']='ADB reply absent or malformed'
  except subprocess.TimeoutExpired as e:
   row['transport_reply']=False;row['failure']='ADB client timed out; no reconnect requested'
   (a.output/(str(index)+'.partial.stdout')).write_bytes(e.stdout or b'')
   (a.output/(str(index)+'.partial.stderr')).write_bytes(e.stderr or b'')
  if not row['transport_reply']:
   query="Get-CimInstance Win32_PnPEntity -Filter \"PNPDeviceID LIKE '%VID_05C6%' OR Name LIKE '%Nokia%'\" | Select-Object Name,PNPDeviceID,Status,ConfigManagerErrorCode | ConvertTo-Json -Depth 3"
   try:
    usb=subprocess.run(['powershell','-NoProfile','-Command',query],capture_output=True,timeout=12)
    (a.output/(str(index)+'.host-usb.json')).write_bytes(usb.stdout);row['usb_inventory_exit']=usb.returncode
   except subprocess.TimeoutExpired:row['usb_inventory_timeout']=True
  row['probe_seconds']=time.monotonic()-tick;samples.append(row)
  with (a.output/'samples.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(row)+'\n')
  if reason:break
  time.sleep(max(0,min(10-row['probe_seconds'],a.seconds-(time.monotonic()-start))))
 good=[r for r in samples if r.get('identity_matches')]
 result=dict(image=a.image,boot=a.boot,duration_seconds=time.monotonic()-start,samples=len(samples),successful_identity_samples=len(good),failed_transport_samples=sum(not r['transport_reply'] for r in samples),identity_stop=reason,core_pids_unchanged=bool(good) and all(r['core_pids_unchanged'] for r in good),adbd_pid_unchanged=bool(good) and all(r['adbd_pid_unchanged'] for r in good),configuration_changed=False,reconnect_requested=False,scope='Bounded idle observation; does not establish startup, deep-suspend or general transport reliability')
 (a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
 if reason:raise SystemExit(1)

if __name__=='__main__':main()
