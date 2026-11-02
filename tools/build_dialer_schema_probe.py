"""Build a provider-free test APK containing actual patched donor DEX and instrumentation."""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('sdk','jdk','candidate','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--diagnostic-keystore',type=Path)
    p.add_argument('--database-snapshot',type=Path,required=True)
    a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    sdk=a.sdk.resolve();jdk=a.jdk.resolve();bt=sdk/'build-tools/35.0.0'
    android=sdk/'platforms/android-30/android.jar'
    source=Path(__file__).resolve().parents[1]/'tests/dialerprobe'
    suffix='.exe' if os.name=='nt' else ''
    env=os.environ.copy();env['JAVA_HOME']=str(jdk)
    env['PATH']=str(jdk/'bin')+os.pathsep+env.get('PATH','')
    def run(args):
        result=subprocess.run([str(x) for x in args],capture_output=True,text=True,env=env,timeout=120)
        with (out/'build.log').open('a',encoding='utf-8') as log:
            log.write(result.stdout+result.stderr)
        result.check_returncode()
    classes=out/'classes';classes.mkdir()
    dex=out/'dex';dex.mkdir()
    unsigned=out/'unsigned.apk'
    if hashlib.sha256(a.database_snapshot.read_bytes()).hexdigest()!='b1b2661e7d1e9c34d6e7221074c2e8a604e9bd55ba439b0af7276ddb7755aae2':
        raise ValueError('Unexpected Nokia snapshot identity')
    assets=out/'assets';assets.mkdir();shutil.copyfile(a.database_snapshot,assets/'captured.db')
    run([bt/('aapt'+suffix),'package','-f','-M',source/'AndroidManifest.xml','-A',assets,'-I',android,'-F',unsigned])
    run([jdk/'bin'/('javac'+suffix),'--release','8','-classpath',android,'-d',classes,source/'SchemaInstrumentation.java'])
    run([jdk/'bin'/('java'+suffix),'-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','30','--lib',android,'--output',dex,*classes.rglob('*.class')])
    with zipfile.ZipFile(a.candidate) as donor,zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED) as archive:
        donor_dex=[n for n in donor.namelist() if n.startswith('classes') and n.endswith('.dex')]
        if set(donor_dex)!={'classes.dex','classes2.dex'}:
            raise ValueError('Unexpected donor DEX layout')
        for name in donor_dex:archive.writestr(name,donor.read(name))
        archive.write(dex/'classes.dex','classes3.dex')
    aligned=out/'aligned.apk'
    run([bt/('zipalign'+suffix),'-f','4',unsigned,aligned])
    key=a.diagnostic_keystore.resolve() if a.diagnostic_keystore else out/'diagnostic-only.p12'
    if not a.diagnostic_keystore:
        run([jdk/'bin'/('keytool'+suffix),'-genkeypair','-keystore',key,'-storepass','android','-keypass','android','-alias','diagnostic','-dname','CN=KaiDroid Local Diagnostic','-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt'])
    apk=out/'dialer-schema-probe.apk'
    signer=[jdk/'bin'/('java'+suffix),'-jar',bt/'lib/apksigner.jar']
    run([*signer,'sign','--ks',key,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([*signer,'verify','--verbose',apk])
    report=dict(candidate_sha256=hashlib.sha256(a.candidate.read_bytes()).hexdigest(),
        test_apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
        test_source_sha256=hashlib.sha256((source/'SchemaInstrumentation.java').read_bytes()).hexdigest(),
        snapshot_sha256=hashlib.sha256(a.database_snapshot.read_bytes()).hexdigest(),
        registered_providers=[],permissions=[],installed=False)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
