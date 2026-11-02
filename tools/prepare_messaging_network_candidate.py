"""Build an isolated MMS JobWorkItem APK over exact installed IMS-guard6486.

No signing, installation, role/provider mutation or shared build-host access.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from messaging_network_toolchain import verify as verify_toolchain
from compress_apk_dex import is_signature
from audit_tcl_target_api import parse

BASE='6486b20af5b777500590981f3aa32914ed72a91e97e41f8994a2ef857f68ba2e'
PINS={'MmsSystemEventReceiver':'ff1f97538d6782af3cf607f29567c7bf179a9e64f037e2e3ab1f9d86cdb25672',
 'MmsJobService':'272fa8975c76f3c1e7233160613f570f2ea2c8b726430df28a8663e61ed30954'}
HELPERS={'KaiBootRecovery.java':'c2dfe633574469b29ba6b7555ecbdb0e678f3abd77824ed435ec4a7f0da57d4f',
 'KaiMmsWork.java':'162dc56db8c759af966708f166cf6dc031f68566f1841f3f7b9a13343d3321c8'}
WORK='Lcom/android/mms/transaction/KaiMmsWork;'


def sha(data):return hashlib.sha256(data).hexdigest()


def patch(name,data):
 if sha(data)!=PINS[name]:raise ValueError('Exact installed source class changed: '+name)
 text=data.decode('utf-8').replace('\r\n','\n')
 if name=='MmsSystemEventReceiver':
  pattern=r'^    invoke-virtual (\{[^}]+\}), Landroid/content/Context;->startService\(Landroid/content/Intent;\)Landroid/content/ComponentName;$'
  if len(re.findall(pattern,text,re.M))!=3:raise ValueError('Expected exactly three original wakeup calls: direct, connectivity, SIM-loaded')
  return re.sub(pattern,lambda m:'    invoke-static '+m[1]+', '+WORK+'->enqueue(Landroid/content/Context;Landroid/content/Intent;)V',text,flags=re.M).encode()
 for method,action,locals_count in [('onStartJob','start',4),('onStopJob','stop',1)]:
  anchor='.method public '+method+'(Landroid/app/job/JobParameters;)Z\n    .locals '+str(locals_count)+'\n'
  prefix='''
    invoke-static {p1}, WORK->isJob(Landroid/app/job/JobParameters;)Z
    move-result v0
    if-eqz v0, :kai_network_original
    invoke-static {p0, p1}, WORK->ACTION(Landroid/app/job/JobService;Landroid/app/job/JobParameters;)V
    const/4 v0, 0x1
    return v0
    :kai_network_original
'''.replace('WORK',WORK).replace('ACTION',action)
  if text.count(anchor)!=1:raise ValueError('Original JobService branch changed')
  text=text.replace(anchor,anchor+prefix)
 return text.encode()


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('apk','helper-dir','sdk','jdk','apktool','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args()
 if sha(a.apk.read_bytes())!=BASE:raise ValueError('Not exact installed IMS-guard baseline')
 for name,pin in HELPERS.items():
  if sha((a.helper_dir/name).read_bytes())!=pin:raise ValueError('SDK-reviewed helper changed: '+name)
 with zipfile.ZipFile(a.apk) as package:
  classes,_,_,_=parse(package.read('classes2.dex'))
  if not classes or any(not c.startswith('Lcom/android/mms/transaction/KaiBootRecovery') for c in classes):raise ValueError('Existing secondary DEX is not solely accepted boot helper')
 toolchain=verify_toolchain(a.jdk,a.sdk)
 a.output.mkdir(parents=True,exist_ok=False);decoded=a.output/'decoded'
 jdk=a.jdk.resolve();bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar'
 exe='.exe' if os.name=='nt' else '';env=dict(os.environ,JAVA_HOME=str(jdk));env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','');index=0
 def run(args):
  nonlocal index
  index+=1;r=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=180)
  (a.output/(str(index)+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 java=jdk/'bin'/('java'+exe)
 run([java,'-jar',a.apktool.resolve(),'d','-r','--no-assets','-o',decoded,a.apk])
 changed={}
 for name in PINS:
  path=decoded/('smali/com/android/mms/transaction/'+name+'.smali');path.write_bytes(patch(name,path.read_bytes()));changed[name]=sha(path.read_bytes())
 rebuilt=a.output/'rebuilt.apk';run([java,'-jar',a.apktool.resolve(),'b',decoded,'-o',rebuilt])
 classes=a.output/'classes';classes.mkdir();dex=a.output/'dex';dex.mkdir()
 run([jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*[a.helper_dir/n for n in HELPERS]])
 run([java,'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 raw=a.output/'unaligned.apk'
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(rebuilt) as built,zipfile.ZipFile(raw,'x') as new:
  for info in old.infolist():
   if not is_signature(info.filename):
    data=(built.read('classes.dex') if info.filename=='classes.dex' else
     (dex/'classes.dex').read_bytes() if info.filename=='classes2.dex' else old.read(info.filename))
    new.writestr(copy.copy(info),data)
 candidate=a.output/'Messaging-network-work-unsigned.apk';run([bt/('zipalign'+exe),'-f','4',raw,candidate])
 run([bt/('zipalign'+exe),'-c','4',candidate])
 with zipfile.ZipFile(a.apk) as old,zipfile.ZipFile(candidate) as new:
  names={n for n in old.namelist() if not is_signature(n)}
  if names!=set(new.namelist()) or len(new.namelist())!=len(names) or new.testzip() is not None:raise ValueError('Archive entry/CRC change')
  if {n for n in names if old.read(n)!=new.read(n)}!={'classes.dex','classes2.dex'}:raise ValueError('Unexpected non-DEX payload change')
 report=dict(toolchain=toolchain,baseline_sha256=BASE,candidate_sha256=sha(candidate.read_bytes()),source_class_pins=PINS,changed_smali_sha256=changed,
  helper_source_sha256=HELPERS,compiled_helper_dex_sha256=sha((dex/'classes.dex').read_bytes()),
  changed_payload=['classes.dex','classes2.dex'],all_manifest_resources_other_payloads_identical=True,aligned4=True,
  expected_primary_method_changes=['MmsSystemEventReceiver.onReceive','MmsSystemEventReceiver.wakeUpService','MmsJobService.onStartJob','MmsJobService.onStopJob'],
  sms_boot_recovery_not_invoked_by_network_work=True,ims_guard_retained=True,method_audit_passed=False,signed=False,installed=False,full_parity=False)
 (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
