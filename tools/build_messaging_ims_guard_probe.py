"""Build actual original/patched IMS smali method controls with fake SDK transports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile
from prepare_messaging_ims_guard import SOURCE,patch,sha

OWNER='Lcom/android/mms/util/ImsConnectionManager;'
METHODS=('register','unregister','onSimStateChanged')


def imported(data,name):
 text=data.decode('utf-8').replace('\r\n','\n')
 blocks=re.findall(r'^\.method .*?^\.end method',text,re.M|re.S)
 selected={method:[b for b in blocks if ' '+method+'(' in b.splitlines()[0]] for method in METHODS}
 if any(len(rows)!=1 for rows in selected.values()):raise ValueError('Missing/duplicate imported method')
 result={k:v[0] for k,v in selected.items()}
 mapping={OWNER:'Lorg/kaidroid/mmsimsprobe/'+name+';',
  'Landroid/telephony/SubscriptionManager;':'Lorg/kaidroid/mmsimsprobe/FakeSubscriptions;',
  'Landroid/telephony/ims/ImsMmTelManager':'Lorg/kaidroid/mmsimsprobe/FakeIms',
  'Landroid/telephony/ims/ImsException;':'Lorg/kaidroid/mmsimsprobe/FakeImsException;',
  'Lcom/android/mms/MmsApp;':'Lorg/kaidroid/mmsimsprobe/FakeApp;'}
 for key,block in result.items():
  for old,new in mapping.items():block=block.replace(old,new)
  result[key]=block
 return result


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source-smali','sdk','jdk','apktool','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();data=a.source_smali.read_bytes()
 if sha(data)!=SOURCE:raise ValueError('Exact installed-class source required')
 original=imported(data,'OriginalManager');candidate=imported(patch(data),'GuardedManager')
 root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar';jdk=a.jdk.resolve()
 exe='.exe' if os.name=='nt' else '';env=dict(os.environ,JAVA_HOME=str(jdk));env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
 index=0
 def run(args):
  nonlocal index
  index+=1;r=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=150)
  (out/(str(index)+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 src=out/'src';src.mkdir();classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir()
 for name in ('OriginalManager','GuardedManager'):
  (src/(name+'.java')).write_text('package org.kaidroid.mmsimsprobe;\npublic final class '+name+''' {
 private FakeIms mImsMmTelManager;
 private FakeIms.RegistrationCallback mCallback=new FakeIms.RegistrationCallback();
 private static boolean mIsImsRegistered;
 public void register() {}
 public void unregister() {}
 public void onSimStateChanged(int state) {}
}
''',encoding='utf-8')
 fixture=root/'tests/mmsims';unsigned=out/'unsigned.apk'
 run([bt/('aapt'+exe),'package','-f','-M',fixture/'AndroidManifest.xml','-I',android,'-F',unsigned])
 run([jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*fixture.rglob('*.java'),*src.glob('*.java')])
 run([jdk/'bin'/('java'+exe),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
 decoded=out/'decoded';java=jdk/'bin'/('java'+exe)
 run([java,'-jar',a.apktool.resolve(),'d','-r','--no-assets','-o',decoded,unsigned])
 proof={}
 for name,bodies in [('OriginalManager',original),('GuardedManager',candidate)]:
  path=decoded/('smali/org/kaidroid/mmsimsprobe/'+name+'.smali');text=path.read_text(encoding='utf-8')
  for method,body in bodies.items():
   expression=r'^\.method public '+method+r'\(.*?^\.end method'
   if len(re.findall(expression,text,re.M|re.S))!=1:raise ValueError('Fixture placeholder changed')
   text=re.sub(expression,lambda m:body,text,count=1,flags=re.M|re.S)
  path.write_text(text,encoding='utf-8',newline='\n')
  proof[name]={k:sha(v.encode()) for k,v in bodies.items()}
 rebuilt=out/'rebuilt.apk';run([java,'-jar',a.apktool.resolve(),'b',decoded,'-o',rebuilt])
 aligned=out/'aligned.apk';run([bt/('zipalign'+exe),'-f','4',rebuilt,aligned])
 key=out/'diagnostic-only.p12';run([jdk/'bin'/('keytool'+exe),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=IMS bytecode SDK diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
 signer=[java,'-jar',bt/'lib/apksigner.jar'];apk=out/'ims-probe.apk'
 run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
 run([*signer,'verify','--verbose','--print-certs',apk])
 report=dict(apk_sha256=sha(apk.read_bytes()),source_smali_sha256=SOURCE,patched_smali_sha256=sha(patch(data)),
  imported_method_sha256=proof,scope='Actual method instructions with relocated owners and fake subscription/IMS/application transports',
  original_application_constructor_callbacks_not_imported=True,telephony_permissions=[],installed=False,full_parity=False)
 (out/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report))


if __name__=='__main__':main()
