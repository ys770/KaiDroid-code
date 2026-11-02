"""Bounded image38 Notes soft-left regression; no text entry, save or data clearing."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

SERIAL = 'DEVICE_SERIAL_REQUIRED'
APK_SHA = '7cfbef1984a10e82f6cd145c04b1d436b34678d64a77ae85029aad770df5f12d'
FRAMEWORK_SHA = 'b385a3f9310a80e087009c74a2e25f5a53b362c5c8fee5f2ede2710fb1e0d44f'

def editor_is_blank(root):
    nodes = list(root.iter('node'))
    title = [n for n in nodes if n.get('resource-id') == 'com.android.note:id/tv_header_title']
    editor = [n for n in nodes if n.get('resource-id') == 'com.android.note:id/et_editor']
    return (len(title) == len(editor) == 1 and title[0].get('text') == 'New Note'
            and editor[0].get('text') == '' and editor[0].get('class') == 'android.widget.EditText')

def empty_list(root):
    return any(n.get('package') == 'com.android.note' and n.get('text') == 'No note'
               for n in root.iter('node')) and not any(
                   n.get('resource-id') == 'com.android.note:id/et_editor' for n in root.iter('node'))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--boot', required=True, type=lambda s: str(uuid.UUID(s)))
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    base = [a.adb, '-s', SERIAL]
    report = dict(image=38, boot=a.boot, passed=False, physical_key_validation=False,
                  text_entered=False, save_invoked=False)
    sequence = 0
    def shell(label, cmd):
        nonlocal sequence
        sequence += 1
        r = subprocess.run(base+['shell', cmd], capture_output=True, timeout=45)
        (a.output/f'{sequence:02d}-{label}.txt').write_bytes(r.stdout+r.stderr)
        r.check_returncode()
        return r.stdout.decode(errors='replace').replace('\r\n','\n').strip()
    def identity():
        got = shell('identity', 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getprop sys.boot_completed')
        if got.splitlines() != ['38', a.boot, '0', '1']: raise ValueError('Image/boot/root mismatch')
    def snapshot(label):
        identity()
        focus = shell(label+'-focus', 'dumpsys window')
        if not re.search(r'mCurrentFocus=.*com.android.note/', focus): raise ValueError('Notes not focused')
        remote = '/data/local/tmp/kaidroid-notes38-'+uuid.uuid4().hex+'.xml'
        shell(label+'-dump', 'uiautomator dump '+shlex.quote(remote))
        xml = shell(label+'-xml', 'cat '+shlex.quote(remote))
        root = ET.fromstring(xml)
        r = subprocess.run(base+['exec-out','screencap -p'],capture_output=True,timeout=30)
        r.check_returncode(); (a.output/(label+'.png')).write_bytes(r.stdout)
        return root
    try:
        identity()
        if shell('framework', 'sha256sum /system/framework/framework.jar').split()[0] != FRAMEWORK_SHA:
            raise ValueError('Wrong framework')
        apk = shell('path','pm path com.android.note')
        if not re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk', apk): raise ValueError('Unexpected APK path')
        if shell('hash','sha256sum '+shlex.quote(apk[8:])).split()[0] != APK_SHA: raise ValueError('Wrong Notes APK')
        launched = shell('launch','am start -W -n com.android.note/.NotesListActivity')
        if not re.search(r'^Status:\s*ok\s*$',launched,re.M): raise ValueError('Launch did not succeed')
        if not empty_list(snapshot('list-before')): raise ValueError('Expected empty list; no input sent')
        identity(); shell('soft-left','input keyevent 1'); time.sleep(2)
        if not editor_is_blank(snapshot('after-soft-left')): raise ValueError('Blank New Note editor not observed; no Back sent')
        report['soft_left_opened_blank_editor'] = True
        identity(); shell('back','input keyevent 4'); time.sleep(2)
        if not empty_list(snapshot('list-after')): raise ValueError('Back did not return empty list')
        report.update(back_returned_empty_list=True,passed=True)
    finally:
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))

if __name__ == '__main__': main()
