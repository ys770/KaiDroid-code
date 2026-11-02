"""Emulator-only URI fixture controls. No chooser candidate or phone operation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid

SERIAL='emulator-5580'
PACKAGES={'sender':'org.kaidroid.choosersender','receiver':'org.kaidroid.chooserreceiver'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','fixtures','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--install-run-remove',action='store_true')
    a=p.parse_args();inputs=json.loads((a.fixtures/'report.json').read_text())
    for kind,pkg in PACKAGES.items():
        if inputs['apps'][kind]['package']!=pkg or hashlib.sha256((a.fixtures/(kind+'.apk')).read_bytes()).hexdigest()!=inputs['apps'][kind]['apk_sha256']:
            raise ValueError('Wrong diagnostic APK')
    a.output.mkdir(parents=True,exist_ok=False)
    report=dict(serial=SERIAL,install_requested=a.install_run_remove,installed=[],controls={},complete=False)
    def run(label,*args,allow_failure=False):
        try:r=subprocess.run([str(a.adb),'-s',SERIAL,*args],capture_output=True,timeout=40)
        except subprocess.TimeoutExpired as error:
            report['timed_out_command']=label
            (a.output/(label+'.stdout')).write_bytes(error.stdout or b'');(a.output/(label+'.stderr')).write_bytes(error.stderr or b'')
            raise
        (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
        if not allow_failure:r.check_returncode()
        return r.stdout.decode().strip()
    def shell(label,command,allow_failure=False):return run(label,'shell',command,allow_failure=allow_failure)
    def result_for(label,nonce):
        end=time.monotonic()+10;i=0
        while time.monotonic()<end:
            text=shell(label+'-'+str(i),'run-as '+PACKAGES['receiver']+' cat files/result.json',True)
            if text.startswith('{'):
                result=json.loads(text)
                if result.get('fixture_nonce')==nonce:return result
            i+=1;time.sleep(0.1)
        raise TimeoutError('Observation only timed out; do not restart live activities')
    try:
        if shell('api','getprop ro.build.version.sdk')!='30':raise ValueError('Expected API30 emulator')
        if shell('qemu','getprop ro.kernel.qemu')!='1':raise ValueError('Not identified as emulator')
        for kind,pkg in PACKAGES.items():
            if shell('absent-'+kind,'pm path '+pkg,True):raise ValueError('Diagnostic package already exists; no overwrite')
        report['preflight_passed']=True
        if a.install_run_remove:
            for kind,pkg in PACKAGES.items():
                run('install-'+kind,'install',str(a.fixtures/(kind+'.apk')));report['installed'].append(pkg)
            for route in ('direct_granted','direct_no_grant'):
                nonce=str(uuid.uuid4())
                shell('launch-'+route,'am start -W -n '+PACKAGES['sender']+'/.SendActivity --es fixture_route '+route+
                      ' --es fixture_nonce '+nonce+' --ez diagnostic_only_targets true')
                result=result_for('result-'+route,nonce);report['controls'][route]=result
                if result.get('sender_uid')==result.get('receiver_uid'):raise ValueError('Cross-UID condition missing')
                if route=='direct_granted':
                    if not result.get('success') or result.get('uri_permission')!=0 or result.get('sha256')!=inputs['fixture_png_sha256']:
                        raise ValueError('Granted positive control did not read exact PNG')
                else:
                    if result.get('success') or result.get('uri_permission')!=-1 or 'SecurityException' not in result.get('error',''):
                        raise ValueError('Missing-grant negative control did not detect system denial')
                focus=shell('focus-'+route,'dumpsys input')
                if not re.search(r"FocusedWindows:\s*\n\s*displayId=0, name='Window\{[^\n]*org\.kaidroid\.chooserreceiver/",focus):
                    raise ValueError('Owned receiver must have focus before Back')
                shell('back-'+route,'input keyevent 4')
                shell('stop-owned-sender-'+route,'am force-stop '+PACKAGES['sender'])
            for kind,pkg in PACKAGES.items():
                paths=shell('cleanup-path-'+kind,'pm path '+pkg).splitlines()
                if len(paths)!=1 or not paths[0].startswith('package:/data/app/'):raise ValueError('Unexpected owned APK path')
                apk=paths[0][8:]
                if shell('cleanup-hash-'+kind,'sha256sum '+shlex.quote(apk)).split()[0]!=inputs['apps'][kind]['apk_sha256']:
                    raise ValueError('Diagnostic app changed; preserve it')
                run('uninstall-'+kind,'uninstall',pkg)
            report['diagnostics_removed']=True
        report['complete']=True
    except Exception as error:
        report['error']=str(error);raise
    finally:(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
