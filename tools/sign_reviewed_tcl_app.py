"""Align and sign one pinned reviewed TCL candidate; never install or alter phone data."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from compress_apk_dex import is_signature

APPS = {
    'messaging-network-work': dict(sha256='be600ed4447f59f662ad727806166ebcc5daad16294fc46c4f2070394dd932e1',
        package='com.android.mms', version='2403041', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'messaging-ims-guard': dict(sha256='c2cae7249302a594bb876da1f8382f2ac0f5a4b238eed458ed14e780aa6d8338',
        package='com.android.mms', version='2403041', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'messaging-boot-recovery': dict(sha256='cf8a36f6a10cb21edfcb7c4c869a0c3a57ec12a83560f024c52f59dd1942e30c',
        package='com.android.mms', version='2403041', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'camera-fixed30-trial': dict(sha256='0622ac06c750f8599b4f5cde9b48747154fea0242815cad2545db2ac58576028',
        package='com.tcl.camera', version='511004100', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'camera-buffer': dict(sha256='e5a48dcc8367df4384fb283736eaac200f474480678c050332216321085a7635',
        package='com.tcl.camera', version='511004100', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'dialer-fragment': dict(sha256='fad56ecab555a5a7eb1dd9f8492d2d979228074974e4f73f2afe95be7a19b96f',
        package='com.android.dialer', version='2900001', key='shared',
        certificate='28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd'),
    'launcher-clock-route': dict(sha256='1865887503dde1bbf7816d7afdd98d9ce1e0ae34d7857d7532bf72aa697702d5',
        package='com.android.launcher3', version='30', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'dialer-key-trace': dict(sha256='89deea0abfc21d8f4ec6237fc07de8558e2ff4bb5a938538f14639fcee28e3d2',
        package='com.android.dialer', version='2900001', key='shared',
        certificate='28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd'),
    'settings-ui-profile': dict(sha256='d395c2457b0a77189f3bb0703bc3fe1ed9f37d8e97153cc616f0be57f2921f5b',
        package='com.android.settings', version='202106338', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'messaging-key-counter': dict(sha256='c6694b2340793d4f5bd4fab80aa0d5b81aa7f97a3dc370bd96ed675cb391a82b',
        package='com.android.mms', version='2403041', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'messaging-key': dict(sha256='ba9bd5eb0719cc7543ede434aeb739f5188c7c1030dd491ebe35c97f55e6b47b',
        package='com.android.mms', version='2403041', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
    'dialer': dict(sha256='6ba27affd236fa752e7445c1f0d1591174f2c98352d160ca09ff670f489c14c2',
        package='com.android.dialer', version='2900001', key='shared',
        certificate='28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd'),
    'settings': dict(sha256='45a3a8b9d7239ecc3d56de9b56b8be3e579c6eb59b7705db168cb9403bb3151d',
        package='com.android.settings', version='202106338', key='platform',
        certificate='c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'),
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app',choices=APPS,required=True)
    for name in ('apk','output','sdk','java','keys'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();expected=APPS[a.app]
    if hashlib.sha256(a.apk.read_bytes()).hexdigest()!=expected['sha256']:
        raise ValueError('Candidate identity mismatch')
    a.output.mkdir(parents=True,exist_ok=False)
    bt=a.sdk/'build-tools/35.0.0'
    def run(label,args):
        r=subprocess.run(list(map(str,args)),capture_output=True,timeout=120)
        (a.output/(label+'.log')).write_bytes(r.stdout+r.stderr)
        r.check_returncode();return r.stdout.decode('utf-8')
    info=run('candidate-badging',[bt/'aapt.exe','dump','badging',a.apk])
    if "package: name='"+expected['package']+"' versionCode='"+expected['version']+"'" not in info:
        raise ValueError('Unexpected package/version')
    run('align',[bt/'zipalign.exe','-p','4',a.apk,a.output/'aligned.apk'])
    signer=[a.java,'-jar',bt/'lib/apksigner.jar']
    apk=a.output/'signed.apk'
    run('sign',[*signer,'sign','--v4-signing-enabled','false','--key',a.keys/(expected['key']+'.pk8'),
        '--cert',a.keys/(expected['key']+'.x509.pem'),'--out',apk,a.output/'aligned.apk'])
    verification=run('signature',[*signer,'verify','--verbose','--print-certs',apk])
    certificates=re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)',verification)
    if certificates!=[expected['certificate']]:raise ValueError('Wrong signer')
    run('alignment',[bt/'zipalign.exe','-c','-p','4',apk])
    with zipfile.ZipFile(a.apk) as src,zipfile.ZipFile(apk) as dst:
        names={n for n in src.namelist() if not is_signature(n)}
        if names!={n for n in dst.namelist() if not is_signature(n)}:raise ValueError('Payload names changed')
        for name in names:
            if src.read(name)!=dst.read(name) or src.getinfo(name).compress_type!=dst.getinfo(name).compress_type:
                raise ValueError('Payload/compression changed: '+name)
        if dst.getinfo('resources.arsc').compress_type!=0:raise ValueError('Resources must remain stored')
    report=dict(app=a.app,package=expected['package'],version=expected['version'],
        source_sha256=expected['sha256'],sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
        certificate=certificates[0],payload_preserved=True,aligned=True,installed=False)
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
