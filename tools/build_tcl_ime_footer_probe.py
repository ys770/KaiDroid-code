"""Build relocated footer helper SDK View-tree controls; no device or host build actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile
from prepare_tcl_ime_footer_candidate import HELPER


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('sdk','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 bt=a.sdk/'build-tools/35.0.0';android=a.sdk/'platforms/android-30/android.jar';exe='.exe' if os.name=='nt' else ''
 env=dict(os.environ,JAVA_HOME=str(a.jdk));env['PATH']=str(a.jdk/'bin')+os.pathsep+env.get('PATH','');index=0
 def run(args):
  nonlocal index
  index+=1;r=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=120)
  (out/(str(index)+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 source=out/'src';source.mkdir();helper=source/'TclImeFooterLayout.java'
 helper.write_text(HELPER.replace('package android.inputmethodservice;','package org.kaidroid.imefooterprobe;',1),encoding='utf-8')
 classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir()
 manifest=root/'tests/imefooter/AndroidManifest.xml';sources=sorted((root/'tests/imefooter/src').rglob('*.java'))+[helper]
 unsigned=out/'unsigned.apk'
 run([bt/('aapt'+exe),'package','-f','-M',manifest,'-I',android,'-F',unsigned])
 run([a.jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*sources])
 run([a.jdk/'bin'/('java'+exe),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
 aligned=out/'aligned.apk';run([bt/('zipalign'+exe),'-f','4',unsigned,aligned])
 key=out/'diagnostic-only.p12'
 run([a.jdk/'bin'/('keytool'+exe),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Footer SDK Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
 signer=[a.jdk/'bin'/('java'+exe),'-jar',bt/'lib/apksigner.jar'];apk=out/'footer-probe.apk'
 run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
 run([*signer,'verify','--verbose','--print-certs',apk])
 report=dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),helper_source_sha256=hashlib.sha256(HELPER.encode()).hexdigest(),
  source_inputs={str(n.relative_to(root)):hashlib.sha256(n.read_bytes()).hexdigest() for n in sources[:-1]+[manifest]},
  scope='SDK real View layout/state only; full native InputMethodService, real Kika and fullscreen service not tested',
  permissions=[],shared_uid=False,platform_definitions=False,installed=False)
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(dict(apk=str(apk),sha256=report['apk_sha256'])))


if __name__=='__main__':main()
