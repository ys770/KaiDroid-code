"""Donor-only owned Gallery fixture staging; default is read-only preflight."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET
from capture_tcl_ui_reference import SERIAL, FINGERPRINT

SHA = '16650e169d47929a137a76188c90bc0d373f53947549f1a00f591ddd51588701'
DIR = '/sdcard/DCIM/KaiDroidParity01'
FILE = DIR + '/KaiDroid-Gallery-Parity01.png'
GALLERY_SHA = '6c51c324fafe260a278a28c3a6f4563fc378c15e5742a7012ea800edcea39081'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--stage',action='store_true')
    a=p.parse_args();root=Path(__file__).resolve().parents[1]
    fixture=root/'tests/fixtures/gallery-parity01/KaiDroid-Gallery-Parity01.png'
    if hashlib.sha256(fixture.read_bytes()).hexdigest()!=SHA:raise ValueError('Wrong fixture')
    base=json.loads((a.baseline/'capture.json').read_text())
    labels=[n.attrib.get('text') for n in ET.parse(a.baseline/'hierarchy.xml').iter('node')]
    if not base['complete'] or base['fingerprint']!=FINGERPRINT or base['serial']!=SERIAL:
        raise ValueError('Wrong completed donor baseline')
    if not {'Gallery (0)','No photos found'}.issubset(labels):raise ValueError('Baseline Gallery must be empty')
    if a.stage and time.time()-(a.baseline/'capture.json').stat().st_mtime>600:
        raise ValueError('Capture a fresh empty-Gallery baseline before staging')
    a.output.mkdir(parents=True,exist_ok=False)
    report=dict(stage_requested=a.stage,remote_directory=DIR,remote_file=FILE,
        fixture_sha256=SHA,baseline=str(a.baseline),boot_id=base['boot_id'],phase='preflight')
    def run(label,*args):
        try:r=subprocess.run([str(a.adb),'-s',SERIAL,*args],capture_output=True,timeout=40)
        except subprocess.TimeoutExpired as error:
            (a.output/(label+'.stdout')).write_bytes(error.stdout or b'')
            (a.output/(label+'.stderr')).write_bytes(error.stderr or b'')
            report['timed_out_command']=label
            raise
        (a.output/(label+'.stdout')).write_bytes(r.stdout);(a.output/(label+'.stderr')).write_bytes(r.stderr)
        r.check_returncode();return r.stdout.decode('utf-8').strip()
    def shell(label,command):return run(label,'shell',command)
    try:
        if shell('identity','getprop ro.build.fingerprint')!=FINGERPRINT:raise ValueError('Wrong donor')
        if shell('boot-before','cat /proc/sys/kernel/random/boot_id')!=base['boot_id']:raise ValueError('Boot changed')
        paths=shell('gallery-path','pm path com.android.gallery3d').splitlines()
        if len(paths)!=1 or not paths[0].startswith('package:/'):raise ValueError('Unexpected Gallery paths')
        apk=paths[0][8:]
        if any(c not in '/._-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' for c in apk):raise ValueError('Unsafe APK path')
        if shell('gallery-hash','sha256sum '+apk).split()[0]!=GALLERY_SHA:raise ValueError('Gallery changed')
        if shell('parent','if [ -d /sdcard/DCIM ]; then echo PRESENT; fi')!='PRESENT':raise ValueError('DCIM parent absent')
        if shell('absent-path','if [ -e '+DIR+' ]; then echo EXISTS; else echo ABSENT; fi')!='ABSENT':raise ValueError('Fixture directory already exists; never overwrite')
        report['preflight_passed']=True
        if a.stage:
            shell('mkdir','mkdir '+DIR);report['phase']='owned_directory_created'
            run('push','push',str(fixture),FILE);report['phase']='file_pushed'
            if shell('fixture-hash','sha256sum '+FILE).split()[0]!=SHA:raise ValueError('Pushed fixture mismatch')
            report['owned_file_verified']=True
            shell('scan','am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://'+FILE)
            report['phase']='scan_requested'
        if shell('boot-after','cat /proc/sys/kernel/random/boot_id')!=base['boot_id']:raise ValueError('Boot changed')
        report['complete']=True
    except Exception as error:
        report['error']=str(error);raise
    finally:
        (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
