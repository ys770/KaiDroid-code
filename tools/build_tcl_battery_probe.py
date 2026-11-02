"""Build the exact battery presentation and original staged resources for Android QA."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','jdk','resources','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--diagnostic-keystore',type=Path)
    a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1];source=root/'tests/batteryprobe'
    jdk=a.jdk.resolve();bt=a.sdk.resolve()/'build-tools/35.0.0'
    android=a.sdk.resolve()/'platforms/android-30/android.jar'
    suffix='.exe' if os.name=='nt' else ''
    env=os.environ.copy();env['JAVA_HOME']=str(jdk);env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
    def run(args):
        args=[str(x) for x in args]
        r=subprocess.run(args,capture_output=True,text=True,env=env,timeout=120)
        with (out/'build.log').open('a',encoding='utf-8') as f:f.write(json.dumps(args)+'\n'+r.stdout+r.stderr)
        r.check_returncode()
    for name in ('classes','dex','generated'):(out/name).mkdir()
    unsigned=out/'unsigned.apk'
    run([bt/('aapt'+suffix),'package','-f','-m','--auto-add-overlay','--extra-packages','com.android.systemui',
         '-M',source/'AndroidManifest.xml','-S',a.resources.resolve(),'-I',android,'-J',out/'generated','-F',unsigned])
    renderer=root/'framework/packages/SystemUI/src/com/android/systemui/TclBatteryPresentation.java'
    metadata=root/'framework/packages/SystemUI/src/com/android/systemui/TclBatteryInfo.java'
    sources=[*source.rglob('*.java'),renderer,metadata,*sorted((out/'generated').rglob('*.java'))]
    run([jdk/'bin'/('javac'+suffix),'--release','8','-classpath',android,'-d',out/'classes',*sources])
    run([jdk/'bin'/('java'+suffix),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30',
         '--lib',android,'--output',out/'dex',*sorted((out/'classes').rglob('*.class'))])
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(out/'dex/classes.dex','classes.dex')
    aligned=out/'aligned.apk';run([bt/('zipalign'+suffix),'-f','4',unsigned,aligned])
    key=a.diagnostic_keystore.resolve(strict=True) if a.diagnostic_keystore else out/'diagnostic-only.p12'
    if not a.diagnostic_keystore:
        run([jdk/'bin'/('keytool'+suffix),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android',
             '-alias','diagnostic','-dname','CN=KaiDroid Local Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
    signer=[jdk/'bin'/('java'+suffix),'-jar',bt/'lib/apksigner.jar'];apk=out/'battery-probe.apk'
    run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([*signer,'verify','--verbose','--print-certs',apk]);run([bt/('zipalign'+suffix),'-c','4',apk])
    files=[source/'AndroidManifest.xml',*source.rglob('*.java'),renderer,metadata,Path(__file__).resolve()]
    report=dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
                sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
                resources={str(f.relative_to(a.resources)):hashlib.sha256(f.read_bytes()).hexdigest()
                           for f in sorted(a.resources.rglob('*')) if f.is_file()},installed=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(apk=str(apk),sha256=report['apk_sha256'])))


if __name__=='__main__':main()
