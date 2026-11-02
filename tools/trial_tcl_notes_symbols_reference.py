"""Bounded original TCL Notes Symbols/Back capture. Hardware lease required; never retry."""
import argparse
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import time
import uuid

from check_tcl_ime_picker_layout import xml_nodes,validate,bounds,MODES

SERIAL='DEVICE_SERIAL_REQUIRED'
FINGERPRINT='TCL/4058L1/Gflip6_USCC:11/RP1A.200720.011/PJEP:user/release-keys'
FRAMEWORK='70cc25b51f2067508b7dfa415084440321359054a881377b093dfddecd97afe8'
NOTES='13bb553f1341cca973ce35156b7fff2eb8210273e5c976970955dde803f448b5'
KIKA_APK='f80ddc5b461d1d23cc05f9c212f43629991766f9630466b89fbdec8b34ea8e7f'
KIKA='com.iqqijni.dvt912key/.keyboard_service.view.HDKeyboardService'
TT9='io.github.sspanak.tt9/.ime.TraditionalT9'
CALENDAR='com.android.calendar/com.android.calendar.AllInOneActivity'
KEYS=['default_input_method','enabled_input_methods','selected_input_method_subtype',
      'input_methods_subtype_history','show_ime_with_hard_keyboard']


def classify(text):
    nodes=xml_nodes(text)
    if validate(nodes)['passed']:return 'picker'
    editor=[n for n in nodes if n.get('resource-id')=='com.android.note:id/et_editor']
    title=[n for n in nodes if n.get('resource-id')=='com.android.note:id/tv_header_title']
    if len(editor)==len(title)==1 and editor[0].get('text')=='' and editor[0].get('class')=='android.widget.EditText' and title[0].get('text')=='New Note':
        return 'blank_editor'
    if editor:return 'unknown'
    if any(n.get('text')=='No note' and n.get('package')=='com.android.note' for n in nodes):return 'empty_list'
    return 'unknown'


def editor_mode(text):
    return [n.get('text') for n in xml_nodes(text) if n.get('text') in MODES+['kt9','KT9'] and
            bounds(n.get('bounds'))[1]>=290 and bounds(n.get('bounds'))[0]<80]


def selection(png,layout):
    from PIL import Image
    with Image.open(png) as image:
        colors=[image.convert('RGB').getpixel((5,(b[1]+b[3])//2)) for b in layout['row_text_bounds']]
    selected=[i for i,c in enumerate(colors) if c==(68,132,204)]
    if len(selected)!=1 or any(c not in ((68,132,204),(255,255,255)) for c in colors):
        raise ValueError('Original picker selection pixels ambiguous')
    return selected[0]


def key_allowed(kind,code,selected=None):
    return ((kind=='empty_list' and code==1) or (kind=='blank_editor' and code in (1,4)) or
            (kind=='picker' and (code in (4,20) or code==23 and selected==5)))


def ime_flags(text):
    return {key:(re.search(r'\b'+key+r'=(true|false)\b',text).group(1) if re.search(r'\b'+key+r'=(true|false)\b',text) else None)
            for key in ('mInputShown','mShowRequested','mVisibleBound')}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',type=Path,required=True)
    p.add_argument('--boot',required=True,type=lambda s:str(uuid.UUID(s)))
    p.add_argument('--baseline-window',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if not re.fullmatch('[0-9a-f]+',a.baseline_window):raise ValueError('Exact reviewed Calendar window token required')
    a.output.mkdir(parents=True,exist_ok=False)
    adb=[str(a.adb),'-s',SERIAL];sequence=0;ambiguous=False;mutated=False;owned=False;before=None
    report=dict(scope='Original Notes empty-editor Symbols/Back capture only',hardware_lease_required=True,
        text_entered=False,save_invoked=False,data_cleared=False,provider_commands=False,
        physical_key_validation=False,full_parity=False,visual_review_required=True)

    def run(label,args,timeout=35):
        nonlocal sequence,ambiguous
        sequence+=1;stem=a.output/(f'{sequence:03d}-'+label)
        try:r=subprocess.run(adb+args,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            ambiguous=True;stem.with_suffix('.stdout').write_bytes(error.stdout or b'');stem.with_suffix('.stderr').write_bytes(error.stderr or b'');raise
        stem.with_suffix('.stdout').write_bytes(r.stdout);stem.with_suffix('.stderr').write_bytes(r.stderr)
        r.check_returncode();return r.stdout

    def shell(label,command):return run(label,['shell',command]).decode(errors='replace').replace('\r\n','\n').strip()
    def identity():
        values=shell('identity','getprop ro.serialno; getprop ro.build.fingerprint; cat /proc/sys/kernel/random/boot_id; id -u; getprop sys.boot_completed; settings get global bluetooth_on').splitlines()
        if values!=[SERIAL,FINGERPRINT,a.boot,'2000','1','0']:raise ValueError('Wrong donor/build/boot/shell UID/Bluetooth; no input')
        if shell('root-availability','su -c '+shlex.quote('id -u'))!='0':raise ValueError('Existing donor su root unavailable')
    def window():
        text=shell('window','dumpsys window')
        matches=re.findall(r'mCurrentFocus=Window\{([0-9a-f]+) u0 ([^ }]+)\}',text)
        if len(matches)!=1:raise ValueError('Unknown/ambiguous foreground')
        return matches[0]
    def settings(label):return {key:shell(label+'-'+key,'settings get secure '+key) for key in KEYS}
    def baseline_window():
        if window()!=(a.baseline_window,CALENDAR):raise ValueError('Exact original Calendar window not restored')
        power=shell('power','dumpsys power')
        if not re.search(r'^\s*mWakefulness=Awake\s*$',power,re.M):raise ValueError('Donor not Awake')
        if not re.search(r'^\s*mInTouchMode=false\s*$',shell('touch','dumpsys window'),re.M):raise ValueError('Donor touch mode changed')
    def capture(label):
        identity();owner=window()
        remote='/data/local/tmp/kaidroid-tcl-symbols-'+uuid.uuid4().hex+'.xml'
        shell(label+'-dump','uiautomator dump '+remote)
        text=shell(label+'-xml','cat '+remote);(a.output/(label+'.xml')).write_text(text,encoding='utf-8')
        png=run(label+'-png',['exec-out','screencap','-p'])
        if not png.startswith(b'\x89PNG\r\n\x1a\n') or struct.unpack('>II',png[16:24])!=(240,320):raise ValueError('Capture not240x320 PNG')
        (a.output/(label+'.png')).write_bytes(png)
        ime=shell(label+'-ime','dumpsys input_method')
        if window()!=owner:raise ValueError('Foreground changed during capture')
        kind=classify(text)
        report.setdefault('captures',{})[label]=dict(owner=owner,kind=kind,mode=editor_mode(text),ime=ime_flags(ime))
        return kind,text,owner,ime
    def notes_capture(label,expected=None):
        row=capture(label);kind,text,owner,ime=row
        expected_activity='com.android.note/.NotesListActivity' if kind=='empty_list' else 'com.android.note/.NewNoteActivity'
        # dumpsys uses fully qualified activity names on this donor.
        activity=owner[1].replace('com.android.note/com.android.note.','com.android.note/.')
        if activity!=expected_activity or expected is not None and kind!=expected:
            raise ValueError('Notes state/owner changed: '+kind)
        if kind=='blank_editor' and editor_mode(text)!=['Abc']:raise ValueError('Blank editor Abc mode not proven')
        return row
    def send(code,kind,selected=None):
        if not key_allowed(kind,code,selected):raise ValueError('Unreviewed key/state; no input')
        label='pre-key-'+str(sequence)
        current=notes_capture(label,kind)
        if kind=='picker' and code==23:
            layout=validate(xml_nodes(current[1]))
            if selection(a.output/(label+'.png'),layout)!=5:
                raise ValueError('Symbols row not selected')
        if window()!=current[2]:raise ValueError('Exact Notes window changed before key')
        shell('key-'+str(code),'input keyevent '+str(code));time.sleep(1)

    try:
        identity();baseline_window();before=settings('before');report['before']=before
        if before['default_input_method']!=TT9 or before['enabled_input_methods']!=TT9:raise ValueError('Donor TT9-only baseline changed')
        for package,path,digest in [('com.android.note','/system/app/Note/Note.apk',NOTES),
                                  ('com.iqqijni.dvt912key','/system/app/KikaIME_USCC/KikaIME_USCC.apk',KIKA_APK)]:
            if shell('path-'+package,'pm path '+package)!='package:'+path:raise ValueError('Original APK path changed')
            if shell('hash-'+package,'sha256sum '+path).split()[0]!=digest:raise ValueError('Original APK hash changed')
        if shell('framework-hash','sha256sum /system/framework/framework.jar').split()[0]!=FRAMEWORK:raise ValueError('Original framework hash changed')
        report['baseline_capture']=capture('baseline-before')[2]
        mutated=True;shell('enable-kika','ime enable '+KIKA);shell('select-kika','ime set '+KIKA);time.sleep(1)
        if settings('temporary')['default_input_method']!=KIKA:raise ValueError('Kika selection not applied')
        result=shell('launch-notes','am start -W -n com.android.note/.NotesListActivity')
        if not re.search(r'^Status:\s*ok\s*$',result,re.M):raise ValueError('Notes launch not definitive')
        notes_capture('list-before','empty_list');owned=True
        send(1,'empty_list');notes_capture('editor-before','blank_editor')
        send(1,'blank_editor');kind,text,_,_=notes_capture('picker-before','picker')
        if selection(a.output/'picker-before.png',validate(xml_nodes(text)))!=0:raise ValueError('Picker did not start at first row')
        for index in range(1,6):
            send(20,'picker');_,text,_,_=notes_capture('picker-row-'+str(index),'picker')
            if selection(a.output/('picker-row-'+str(index)+'.png'),validate(xml_nodes(text)))!=index:raise ValueError('Unexpected selected mode row')
        send(23,'picker',5)
        _,_,_,ime=notes_capture('symbols-open','blank_editor')
        if 'mCurId='+KIKA not in ime or ime_flags(ime)['mInputShown']!='true':raise ValueError('Kika show request not observed')
        send(4,'blank_editor');notes_capture('symbols-after-back','blank_editor')
        # Capture service state as an observation; do not require mInputShown=false
        # or accessibility nodes for the original view-only Symbols panel.
        report['bounded_symbols_sequence_completed']=True
    except Exception as error:report['failure']=str(error)
    finally:
        if mutated and not ambiguous:
            try:
                identity()
                if owned:
                    for index in range(3):
                        kind,_,_,_=notes_capture('cleanup-'+str(index))
                        if kind=='empty_list':break
                        if kind not in ('picker','blank_editor'):raise ValueError('Unknown owned context; no cleanup input')
                        send(4,kind)
                    else:raise ValueError('Blank Notes cleanup bound reached')
                owner=window()[1].replace('com.android.note/com.android.note.','com.android.note/.')
                if owner not in ('com.android.note/.NotesListActivity',CALENDAR):raise ValueError('Unsafe foreground for baseline restoration')
                for key,value in before.items():
                    command=('settings delete secure '+key) if value=='null' else ('settings put secure '+key+' '+shlex.quote(value))
                    shell('restore-'+key,command)
                shell('restore-calendar','am start -W -n '+CALENDAR);time.sleep(1)
                identity();baseline_window()
                report['after']=settings('after')
                if report['after']!=before:raise ValueError('Five original IME values not restored')
                capture('baseline-after');report['baseline_restored']=True
            except Exception as error:report['cleanup_failure']=str(error)
        report.update(ambiguous=ambiguous,handback_ready=bool(report.get('baseline_restored')),
                      capture_complete=bool(report.get('bounded_symbols_sequence_completed') and report.get('baseline_restored')))
        (a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))
    if not report['handback_ready'] or not report['capture_complete']:raise SystemExit('Incomplete reference; inspect retained state/result, do not restart')


if __name__=='__main__':main()
