"""Read-only wallpaper comparison guard for the image46/47 matched trial."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--adb',required=True);p.add_argument('--image',choices=['46','47'],required=True)
 p.add_argument('--boot',required=True);p.add_argument('--freeze',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args()
 if not re.fullmatch('[a-f0-9-]{36}',a.boot):p.error('Exact boot UUID required')
 manifest=json.loads((a.freeze/'manifest.json').read_text())
 for n in ['configuration.txt','wallpaper-files.txt']:
  if hashlib.sha256((a.freeze/n).read_bytes()).hexdigest()!=manifest['files'][n]:raise ValueError('Freeze changed: '+n)
 a.output.mkdir(parents=True,exist_ok=False);report=dict(image=a.image,boot=a.boot,read_only=True,complete=False)
 def sh(n,c):
  r=subprocess.run([a.adb,'-s','DEVICE_SERIAL_REQUIRED','shell',c],capture_output=True,timeout=25)
  (a.output/(n+'.txt')).write_bytes(r.stdout);(a.output/(n+'.stderr')).write_bytes(r.stderr);r.check_returncode()
  if r.stderr:raise ValueError('Unexpected stderr: '+n)
  return r.stdout.decode().replace('\r','').strip()
 def identity(n):
  if sh(n,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce').splitlines()!=[a.image,a.boot,'0','Enforcing']:raise ValueError('Device identity changed')
 try:
  identity('before')
  hashes=sh('assets','sha256sum /system/framework/framework-res.apk /system/framework/framework.jar /data/system/users/0/wallpaper_info.xml').splitlines()
  expected=['42adf722d771a6d18eeb0ba1b78ceb1e1f7c4c7add196b3544957e9a25239b72','11d1dba340b19d5966c7794bf7a21a7bfc8b16ab2f1e3fb9f6bf7e57c15e16f1','52c1295a96020f70fe68bbed8ef3f7884730a0c17845b1187179d1467040a2db']
  if [line.split()[0] for line in hashes]!=expected:raise ValueError('Framework/default asset or wallpaper info changed')
  paths=sh('wallpaper-paths','find /data/system/users/0 -maxdepth 1 -name "wallpaper*"').splitlines()
  if paths!=['/data/system/users/0/wallpaper_info.xml']:raise ValueError('Custom wallpaper state appeared')
  if sh('wallpaper-property','getprop ro.config.wallpaper; getprop ro.config.lock_wallpaper'):raise ValueError('Default wallpaper override appeared')
  config=sh('configuration','settings get system screen_off_timeout; settings get system screen_brightness; settings get system screen_brightness_mode; settings get system accelerometer_rotation; settings get system user_rotation; settings get global stay_on_while_plugged_in; settings get global low_power; settings get secure default_input_method; getprop ro.config.low_ram; getprop dalvik.vm.madvise-random; wm size; wm density')
  if config!=(a.freeze/'configuration.txt').read_text().replace('\r','').strip():raise ValueError('Display/configuration differs from freeze')
  identity('after');report['complete']=True
 finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps(report))
if __name__=='__main__':main()
