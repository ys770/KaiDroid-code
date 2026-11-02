"""Build isolated network-work lifecycle diagnostic; no devices or host operations."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

BASE_HELPER='372fe9dd6b3acc2d10225b5e5b402d06626ca6c8a168aedf87c91ef7d0ca54a2'


def main():
 p=argparse.ArgumentParser(description=__doc__);root=Path(__file__).resolve().parents[1]
 for name in ('sdk','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--helper',type=Path,default=root/'framework/apps/Messaging/src/com/android/mms/transaction/KaiBootRecovery.java')
 p.add_argument('--helper-sha256',default=BASE_HELPER)
 p.add_argument('--work-helper',type=Path);p.add_argument('--work-helper-sha256')
 a=p.parse_args()
 def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
 if sha(a.helper)!=a.helper_sha256:raise ValueError('Unreviewed lifecycle helper')
 if a.work_helper and sha(a.work_helper)!=a.work_helper_sha256:raise ValueError('Unreviewed work helper')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar';jdk=a.jdk.resolve()
 exe='.exe' if os.name=='nt' else '';env=dict(os.environ,JAVA_HOME=str(jdk));env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','');index=0
 def run(args):
  nonlocal index
  index+=1;r=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=120)
  (out/(str(index)+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 fixture=root/'tests/messagingnetwork'
 generated=out/'FixtureDispatch.java'
 action='com.android.mms.transaction.KaiMmsWork.enqueue(context,intent);' if a.work_helper else 'context.startService(intent);'
 generated.write_text('package org.kaidroid.messagingnetworkprobe;\npublic final class FixtureDispatch { public static boolean usesJob() { return '+('true' if a.work_helper else 'false')+'; } public static void enqueue(android.content.Context context, android.content.Intent intent) { '+action+' } }\n',encoding='utf-8')
 sources=list((root/'tests/messagingboot/src').rglob('*.java'))+[a.helper]
 sources.append(generated)
 sources+=[n for n in (fixture/'src').rglob('*.java') if a.work_helper or n.name!='NetworkWorkInstrumentation.java']
 if a.work_helper:
  sources=[n for n in sources if n.name not in ('MmsJobService.java','TransactionService.java')]
  sources+=[a.work_helper,fixture/'fixtures/MmsJobService.java',fixture/'fixtures/TransactionService.java']
 classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir();unsigned=out/'unsigned.apk'
 run([bt/('aapt'+exe),'package','-f','-M',fixture/'AndroidManifest.xml','-I',android,'-F',unsigned])
 run([jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*sources])
 java=jdk/'bin'/('java'+exe)
 run([java,'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
 aligned=out/'aligned.apk';run([bt/('zipalign'+exe),'-f','4',unsigned,aligned])
 key=out/'diagnostic-only.p12';run([jdk/'bin'/('keytool'+exe),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=Messaging network lifecycle diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
 apk=out/'network-probe.apk';signer=[java,'-jar',bt/'lib/apksigner.jar']
 run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
 run([*signer,'verify','--verbose','--print-certs',apk])
 report=dict(apk_sha256=sha(apk),helper_sha256=sha(a.helper),work_helper_sha256=sha(a.work_helper) if a.work_helper else None,
  source_inputs={n.as_posix():sha(n) for n in sources},permissions=[],scope='SDK lifecycle fixture only; no actual messages, SIM, provider or networking',installed=False)
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(dict(apk=str(apk),sha256=report['apk_sha256'])))


if __name__=='__main__':main()
