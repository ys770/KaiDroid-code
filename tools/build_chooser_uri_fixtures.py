"""Build two permission-free diagnostic APKs for real cross-UID chooser URI checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
import zipfile

PNG_SHA='16650e169d47929a137a76188c90bc0d373f53947549f1a00f591ddd51588701'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','jdk','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--diagnostic-keystore',type=Path)
    a=p.parse_args();root=Path(__file__).resolve().parents[1];source=root/'tests/choosernative'
    png=root/'tests/fixtures/gallery-parity01/KaiDroid-Gallery-Parity01.png'
    if hashlib.sha256(png.read_bytes()).hexdigest()!=PNG_SHA:raise ValueError('Wrong owned fixture image')
    for kind in ('sender','receiver'):
        manifest=ET.parse(source/kind/'AndroidManifest.xml').getroot()
        if manifest.findall('uses-permission') or '{http://schemas.android.com/apk/res/android}sharedUserId' in manifest.attrib:
            raise ValueError('Fixtures must have no permission requests or shared UID')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    jdk=a.jdk.resolve();bt=a.sdk.resolve()/'build-tools/35.0.0';android=a.sdk.resolve()/'platforms/android-30/android.jar'
    suffix='.exe' if os.name=='nt' else '';env=os.environ.copy();env['JAVA_HOME']=str(jdk)
    env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
    def run(args):
        args=list(map(str,args));r=subprocess.run(args,capture_output=True,text=True,env=env,timeout=120)
        with (out/'build.log').open('a',encoding='utf-8') as f:f.write(json.dumps(args)+'\n'+r.stdout+r.stderr)
        r.check_returncode();return r.stdout
    key=a.diagnostic_keystore.resolve(strict=True) if a.diagnostic_keystore else out/'diagnostic-only.p12'
    if not a.diagnostic_keystore:run([jdk/('bin/keytool'+suffix),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android',
        '-alias','diagnostic','-dname','CN=KaiDroid Local Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
    reports={};signer=[jdk/('bin/java'+suffix),'-jar',bt/'lib/apksigner.jar']
    for kind in ('sender','receiver'):
        work=out/kind;work.mkdir();(work/'classes').mkdir();(work/'dex').mkdir()
        assets=[]
        if kind=='sender':
            (work/'assets').mkdir();shutil.copyfile(png,work/'assets'/png.name);assets=['-A',work/'assets']
        unsigned=work/'unsigned.apk'
        run([bt/('aapt'+suffix),'package','-f','-M',source/kind/'AndroidManifest.xml',*assets,'-I',android,'-F',unsigned])
        run([jdk/('bin/javac'+suffix),'--release','8','-classpath',android,'-d',work/'classes',*sorted((source/kind).rglob('*.java'))])
        run([jdk/('bin/java'+suffix),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,
             '--output',work/'dex',*sorted((work/'classes').rglob('*.class'))])
        with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as z:z.write(work/'dex/classes.dex','classes.dex')
        aligned=work/'aligned.apk';run([bt/('zipalign'+suffix),'-f','4',unsigned,aligned])
        apk=out/(kind+'.apk');run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--out',apk,aligned])
        verification=run([*signer,'verify','--verbose','--print-certs',apk])
        certs=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',verification)
        if len(certs)!=1:raise ValueError('Unexpected diagnostic signer')
        run([bt/('zipalign'+suffix),'-c','4',apk])
        reports[kind]=dict(apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),certificate_sha256=certs[0],
            package='org.kaidroid.chooser'+kind,shared_uid=False,requested_permissions=[])
    assert reports['sender']['certificate_sha256']==reports['receiver']['certificate_sha256']
    report=dict(apps=reports,fixture_png_sha256=PNG_SHA,installed=False,
        sources={str(f.relative_to(root)):hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(source.rglob('*')) if f.is_file()},
        scope='Cross-UID owned PNG URI/grant/referrer fixture; no real messaging, Bluetooth transfer or network operations')
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))


if __name__=='__main__':main()
