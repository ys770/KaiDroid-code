"""Read-only identity, privilege and data-version gates for the image39 Messaging trial."""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--adb',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
adb=[str(a.adb),'-s','DEVICE_SERIAL_REQUIRED'];report={'passed':False,'launched_app':False}
def shell(name,cmd):
 r=subprocess.run(adb+['shell',cmd],capture_output=True,timeout=90);(a.output/(name+'.stdout')).write_bytes(r.stdout);(a.output/(name+'.stderr')).write_bytes(r.stderr);r.check_returncode();return r.stdout.decode().replace('\r','').strip()
try:
 for name,cmd,expected in [('serial','getprop ro.serialno','DEVICE_SERIAL_REQUIRED'),('image','getprop ro.kaidroid.image','39'),('completed','getprop sys.boot_completed','1'),('root','id -u','0'),('selinux','getenforce','Enforcing'),('verifiedboot','getprop ro.boot.verifiedbootstate','green'),('locked','getprop ro.boot.flash.locked','1')]:assert shell(name,cmd)==expected,name
 report['boot']=shell('boot','cat /proc/sys/kernel/random/boot_id')
 pkg=shell('messaging','dumpsys package com.android.mms');assert 'userId=10100' in pkg and 'versionCode=2403041' in pkg
 flags=re.search(r'privateFlags=\[([^\]]+)\]',pkg);assert flags and 'PRIVILEGED' in flags.group(1)
 for permission in ('INTERACT_ACROSS_USERS','READ_PRIVILEGED_PHONE_STATE','WRITE_APN_SETTINGS'):assert 'android.permission.'+permission+': granted=true' in pkg,permission
 report['messaging_privileged']=True;report['messaging_uid']=10100
 path=shell('messaging-path','pm path com.android.mms');assert path.startswith('package:') and '\n' not in path
 report['messaging_path']=path[8:];report['messaging_sha256']=shell('messaging-hash','sha256sum '+path[8:]).split()[0]
 assert report['messaging_sha256'] in {'210871a165dd08acafa3db9228ae840976e4e7496bb7997b49f1588e0ad241b9','3618ef4ac1f199e3782bd1adbf13b88c55307e4c794cf429dd5625a601b710bf'}
 roles=shell('roles','dumpsys role');sms=re.search(r'name=android\.app\.role\.SMS\s+holders=([^\s}]+)',roles);assert sms and sms.group(1)=='com.android.messaging';report['sms_default']=sms.group(1)
 path=shell('provider-path','pm path com.android.providers.telephony');assert path.startswith('package:') and '\n' not in path
 assert shell('provider-hash','sha256sum '+path[8:]).split()[0]=='704d6c9ae89093c2d031c9fbd799ea352bb8ff9046073536ca63b45f48762f5c'
 report['schemas']={}
 for label,root in [('ce','/data/user/0'),('de','/data/user_de/0')]:
  value=shell('schema-'+label,"sqlite3 'file:"+root+"/com.android.providers.telephony/databases/mmssms.db?mode=ro' 'PRAGMA user_version;'");assert value=='68';report['schemas'][label]=68
 report['mmsrecipientchip']=shell('setting','settings get system mmsrecipientchip')
 shell('window','dumpsys window');shell('crashes','logcat -b crash -d -t 120')
 report['passed']=True
except Exception as error:
 report['error']=repr(error);raise
finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
