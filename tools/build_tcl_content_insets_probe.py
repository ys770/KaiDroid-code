"""Build a real SDK child-inset/layout fixture with exact source expressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile
from prepare_tcl_content_insets import patch, OLD, NEW, sha


def main():
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('sdk','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--baseline-source',type=Path,required=True)
 p.add_argument('--candidate-source',type=Path,required=True)
 a=p.parse_args();root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 bt=a.sdk/'build-tools/35.0.0';android=a.sdk/'platforms/android-30/android.jar';exe='.exe' if os.name=='nt' else ''
 env=dict(os.environ,JAVA_HOME=str(a.jdk));env['PATH']=str(a.jdk/'bin')+os.pathsep+env.get('PATH','');index=0
 def run(args):
  nonlocal index
  index+=1;r=subprocess.run(list(map(str,args)),capture_output=True,env=env,timeout=120)
  (out/(str(index)+'.log')).write_bytes(r.stdout+r.stderr);r.check_returncode()
 baseline=a.baseline_source.read_bytes();candidate=a.candidate_source.read_bytes()
 if candidate!=patch(baseline):raise ValueError('Unexpected candidate source')
 source=out/'src';source.mkdir();fixture=source/'InsetsInstrumentation.java'
 original=root/'tests/contentinsets/InsetsInstrumentation.java'
 template=original.read_text()
 for marker,expression in [('CANDIDATE_EXPRESSION',NEW),('BASELINE_EXPRESSION',OLD)]:
  if template.count('// '+marker)!=1:raise ValueError('Unexpected fixture expression template')
  template=template.replace('// '+marker,expression)
 fixture.write_bytes(template.encode())
 classes=out/'classes';classes.mkdir();dex=out/'dex';dex.mkdir()
 manifest=root/'tests/contentinsets/AndroidManifest.xml';sources=[fixture]
 unsigned=out/'unsigned.apk'
 run([bt/('aapt'+exe),'package','-f','-M',manifest,'-I',android,'-F',unsigned])
 run([a.jdk/'bin'/('javac'+exe),'--release','8','-classpath',android,'-d',classes,*sources])
 run([a.jdk/'bin'/('java'+exe),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
 with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(dex/'classes.dex','classes.dex')
 aligned=out/'aligned.apk';run([bt/('zipalign'+exe),'-f','4',unsigned,aligned])
 key=out/'diagnostic-only.p12'
 run([a.jdk/'bin'/('keytool'+exe),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Footer SDK Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
 signer=[a.jdk/'bin'/('java'+exe),'-jar',bt/'lib/apksigner.jar'];apk=out/'content-insets-probe.apk'
 run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
 run([*signer,'verify','--verbose','--print-certs',apk])
 report=dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),baseline_source_sha256=sha(baseline),candidate_source_sha256=sha(candidate),
  generated_fixture_sha256=sha(fixture.read_bytes()),source_inputs={str(n.relative_to(root)):sha(n.read_bytes()) for n in [original,manifest]},
  scope='SDK real WindowInsets and standard child views in a simulated Decor shell; native DecorView/Kika/fullscreen/floating windows not tested',
  permissions=[],shared_uid=False,platform_definitions=False,installed=False)
 (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(dict(apk=str(apk),sha256=report['apk_sha256'])))


if __name__=='__main__':main()
