import subprocess,json,re,hashlib
from pathlib import Path
out=Path('artifacts/runtime/image52-gnss-request02');out.mkdir(exist_ok=False)
a=['/opt/kaidroid/source/Documents/platform-tools/adb.exe','-s','DEVICE_SERIAL_REQUIRED'];seq=0
apk=Path('work/gnss-probe01/gnss-probe.apk');expected='e7cb22ca6e4a99369f6b6b71a3faaee0efc70c442c72263e4d50793b7bf9f132';assert hashlib.sha256(apk.read_bytes()).hexdigest()==expected
def run(label,args,timeout=25):
 global seq
 seq+=1;prefix=out/(str(seq)+'-'+label);prefix.with_suffix('.started.json').write_text(json.dumps(args))
 r=subprocess.run(a+args,capture_output=True,timeout=timeout);prefix.with_suffix('.stdout').write_bytes(r.stdout);prefix.with_suffix('.stderr').write_bytes(r.stderr);r.check_returncode();return r.stdout.decode().strip()
def sh(label,cmd):return run(label,['shell',cmd])
ident='getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; pidof system_server; pidof com.android.systemui'
before=sh('identity-before',ident);assert before.splitlines()==['52','00000000-0000-0000-0001-000000000003','1154','1333']
assert not sh('existing','pm list packages org.kaidroid.gnssprobe')
assert not sh('process-before','pidof org.kaidroid.gnssprobe || true')
mode=sh('mode-before','settings get secure location_mode');assert mode=='3'
assert 'com.android.launcher3/com.android.launcher3.Launcher' in sh('window-before','dumpsys window')
assert 'Success' in run('install',['install','--no-incremental',str(apk)],60)
path=sh('installed-path','pm path org.kaidroid.gnssprobe');assert path.startswith('package:/data/app/') and '\n' not in path
assert sh('installed-hash','sha256sum '+path[8:]).split()[0]==expected
pkg=sh('package','dumpsys package org.kaidroid.gnssprobe');uid=int(re.search(r'userId=(\d+)',pkg)[1]);assert uid>=10000 and 'sharedUserId=' not in pkg
sh('grant','pm grant org.kaidroid.gnssprobe android.permission.ACCESS_FINE_LOCATION')
assert sh('identity-launch',ident)==before
# Timeout is ambiguous: leave evidence and observe the existing instrumentation; do not rerun/uninstall.
text=run('instrument',['shell','am instrument -w -r org.kaidroid.gnssprobe/.GnssInstrumentation'],120)
assert 'INSTRUMENTATION_CODE:' in text
fields=dict(re.findall(r'^INSTRUMENTATION_RESULT: ([^=]+)=(.*)$',text,re.M))
assert sh('identity-after',ident)==before
assert sh('recheck-hash','sha256sum '+path[8:]).split()[0]==expected
assert 'Success' in run('uninstall',['uninstall','org.kaidroid.gnssprobe'],45)
assert not sh('removed','pm list packages org.kaidroid.gnssprobe')
assert not sh('process-after','pidof org.kaidroid.gnssprobe || true')
assert sh('mode-after','settings get secure location_mode')==mode
location=sh('location-after','dumpsys location');gps=location.split('    gps provider:',1)[1];assert 'request=ProviderRequest[OFF]' in gps and 'mStarted=false' in gps
sh('home','input keyevent 3');assert sh('final-identity',ident)==before
r=dict(image=52,apk_sha256=expected,ordinary_uid=uid,instrumentation_success='INSTRUMENTATION_CODE: -1' in text,results=fields,owned_package_removed=True,gps_request_off_after=True,same_boot_and_system_processes=True,location_setting_unchanged=True,coordinates_in_report=False,limits=['One60second window with uncontrolled indoor/antenna conditions; no broad reception or accuracy claim.'])
(out/'result.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
