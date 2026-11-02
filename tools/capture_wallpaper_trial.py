"""Capture wallpaper allocation/geometry only after a completed matched memory census."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from capture_timed_memory_audit import start_ticks

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--adb',required=True);p.add_argument('--protocol',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 report=json.loads((a.protocol/'protocol.json').read_text())
 if not report.get('complete') or report.get('error'):raise ValueError('Require terminal successful census')
 timing=json.loads((a.protocol/'timed/timing.json').read_text())
 if not report['complete'] or report.get('error') or report['timed_exit']!=0 or report['observer_exit']!=0 or timing['state']!='complete':raise ValueError('Require terminal successful census')
 if report['image'] not in ['46','47'] or timing['boot']!=report['boot']:raise ValueError('Wrong protocol identity')
 server,ui=map(int,report['measurement_pids']);expected_starts=timing['process_start_ticks']
 a.output.mkdir(parents=True,exist_ok=False);base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED'];result=dict(image=report['image'],boot=report['boot'],complete=False,read_only=True,post_census=True,files={})
 def capture(n,args):
  r=subprocess.run(base+args,capture_output=True,timeout=30);(a.output/n).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr);r.check_returncode()
  if r.stderr:raise ValueError('Unexpected stderr: '+n)
  result['files'][n]=hashlib.sha256(r.stdout).hexdigest();return r.stdout
 def sh(n,c):return capture(n+'.txt',['shell',c]).decode().replace('\r','').strip()
 def guard(n):
  lines=sh(n,f'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui; cat /proc/uptime; cat /proc/{server}/stat /proc/{ui}/stat').splitlines()
  if lines[:6]!=[report['image'],report['boot'],'0','Enforcing',str(server),str(ui)]:raise ValueError('Identity/process changed')
  if [start_ticks(lines[7],server),start_ticks(lines[8],ui)]!=list(expected_starts):raise ValueError('PID lifetime changed')
  if float(lines[6].split()[0])<timing['actual_snapshot_uptime']['after']:raise ValueError('Not after census')
 try:
  guard('before');w=sh('window','dumpsys window')
  if not any('mCurrentFocus=' in l and 'com.android.launcher3/com.android.launcher3.Launcher' in l for l in w.splitlines()):raise ValueError('Launcher not focused')
  for n,c in [('wallpaper','dumpsys wallpaper'),('surfaceflinger','dumpsys SurfaceFlinger'),('dmabuf','cat /sys/kernel/debug/dma_buf/bufinfo'),('power','dumpsys power')]:sh(n,c)
  capture('launcher.png',['exec-out','screencap','-p']);guard('after');result['complete']=True
 finally:(a.output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
if __name__=='__main__':main()
