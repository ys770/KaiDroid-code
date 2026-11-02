"""Guarded image54 blank Notes picker capture/cancel. Hardware execution only."""
import argparse
import json
from pathlib import Path
import re
import shlex
import struct
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from check_tcl_ime_picker_layout import validate, xml_nodes, MODES, bounds

SERIAL='DEVICE_SERIAL_REQUIRED'
APK='7cfbef1984a10e82f6cd145c04b1d436b34678d64a77ae85029aad770df5f12d'
FRAMEWORK='a22876a0018b8aa4fee02eb2c4c61ebb835a9fb075f36c19ef86d6b52e216781'
SYSTEMUI='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'
KIKA='com.iqqijni.dvt912key/.keyboard_service.view.HDKeyboardService'


def classify(text):
    nodes=xml_nodes(text)
    title=[n for n in nodes if n.get('resource-id')=='com.android.note:id/tv_header_title']
    editor=[n for n in nodes if n.get('resource-id')=='com.android.note:id/et_editor']
    if (len(title)==len(editor)==1 and title[0].get('text')=='New Note'
            and editor[0].get('text')=='' and editor[0].get('class')=='android.widget.EditText'):
        return 'blank_editor'
    if editor:return 'unknown'
    if any(n.get('text')=='No note' and n.get('package')=='com.android.note' for n in nodes):
        return 'empty_list'
    lists=[n for n in nodes if n.get('class') in ('android.widget.ListView','com.android.internal.widget.RecyclerView')]
    texts=[n.get('text','') for n in nodes if n.get('text')]
    modes=[re.sub(r'^\d+\. ','',t) for t in texts]
    # Recognize the known old malformed menu too, so geometry failure does not
    # abandon an owned blank editor. Unknown dialogs remain untouched.
    if (len(lists)==1 and sum(t in MODES for t in modes)>=2
            and ('Select' in texts or 'Input mode' in texts)):
        return 'picker'
    return 'unknown'


def guarded_cleanup(inspect, send, owned, picker_attempted, ambiguous):
    if not owned:return dict(status='not_owned',actions=[])
    if ambiguous:return dict(status='deferred_ambiguous_command',actions=[])
    actions=[]
    kind=inspect('cleanup-current')
    if kind=='picker' and picker_attempted:
        send(4,'picker');actions.append('cancel_picker')
        kind=inspect('cleanup-after-picker')
    if kind=='blank_editor':
        send(4,'blank_editor');actions.append('cancel_blank_editor')
        kind=inspect('cleanup-after-editor')
    if kind=='empty_list':
        send(3,'empty_list');actions.append('home')
        return dict(status='home_requested',actions=actions)
    return dict(status='deferred_unknown_context',context=kind,actions=actions)


def selected_row(png, layout):
    """Check rendered selection; this picker does not export selected=true in XML."""
    from PIL import Image
    with Image.open(png) as image:
        colors=[image.convert('RGB').getpixel((5,(b[1]+b[3])//2))
                for b in layout['row_text_bounds']]
    active=[i for i,c in enumerate(colors) if c==(68,132,204)]
    if len(active)!=1 or any(c not in ((68,132,204),(255,255,255)) for c in colors):
        raise ValueError('Picker selection pixels ambiguous')
    return active[0]



def symbols_visual_state(blank_png, panel_png, cancelled_png):
    """Compare a blank lower-editor region, excluding the cursor/status/footer.

    This establishes panel appearance/disappearance only, not donor layout parity.
    """
    from PIL import Image, ImageChops
    crops=[]
    for path in (blank_png,panel_png,cancelled_png):
        with Image.open(path) as image:
            if image.size!=(240,320):raise ValueError('Wrong Symbols capture dimensions')
            crops.append(image.convert('RGB').crop((20,190,235,290)))
    data=ImageChops.difference(crops[0],crops[1]).tobytes()
    changed=sum(any(data[i:i+3]) for i in range(0,len(data),3))/(len(data)//3)
    restored=ImageChops.difference(crops[0],crops[2]).getbbox() is None
    return dict(panel_region_changed_fraction=changed,blank_region_restored=restored,
                passed=changed>=0.1 and restored,full_layout_parity=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',required=True)
    p.add_argument('--boot',required=True,type=lambda value:str(uuid.UUID(value)))
    p.add_argument('--output',required=True,type=Path)
    roundtrip=p.add_mutually_exclusive_group()
    roundtrip.add_argument('--mode-roundtrip',action='store_true',help='Select123 then restoreAbc in an owned blank editor')
    roundtrip.add_argument('--symbols-roundtrip',action='store_true',help='Open Symbols then cancel without inserting a character')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    adb=[args.adb,'-s',SERIAL]
    report=dict(image=54,boot=args.boot,passed=False,text_entered=False,save_invoked=False,
                mode_selection_changed=False,physical_key_validation=False)
    owned=False;picker_attempted=False;ambiguous=False;sequence=0;before=None;current_component=None

    def run(label,command,timeout=45):
        nonlocal ambiguous,sequence
        sequence+=1
        try:r=subprocess.run(adb+command,capture_output=True,timeout=timeout)
        except subprocess.TimeoutExpired as error:
            ambiguous=True
            (args.output/f'{sequence:02d}-{label}.stdout').write_bytes(error.stdout or b'')
            (args.output/f'{sequence:02d}-{label}.stderr').write_bytes(error.stderr or b'')
            raise
        (args.output/f'{sequence:02d}-{label}.stdout').write_bytes(r.stdout)
        (args.output/f'{sequence:02d}-{label}.stderr').write_bytes(r.stderr)
        r.check_returncode();return r.stdout

    def shell(label,cmd):return run(label,['shell',cmd]).decode(errors='replace').replace('\r\n','\n').strip()
    def identity():
        got=shell('identity','getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getprop sys.boot_completed')
        if got.splitlines()!=[SERIAL,'54',args.boot,'0','1']:raise ValueError('Image/serial/boot/root mismatch')
    def focus():
        text=shell('window','dumpsys window')
        rows=[line for line in text.splitlines() if 'mCurrentFocus=' in line and 'null' not in line]
        if len(rows)!=1:raise ValueError('Ambiguous current focus')
        return rows[0]
    def state(label):
        return {key:shell(label+'-'+key,'settings get '+scope+' '+key)
                for scope,key in [('secure','default_input_method'),('secure','enabled_input_methods'),
                    ('secure','selected_input_method_subtype'),('secure','input_methods_subtype_history'),
                    ('global','bluetooth_on')]}
    def snapshot(label):
        nonlocal current_component
        identity();window=focus()
        if 'com.android.note/' not in window:raise ValueError('Notes not focused; no cleanup input authorized')
        current_component='NewNoteActivity' if 'NewNoteActivity' in window else (
            'NotesListActivity' if 'NotesListActivity' in window else None)
        if current_component is None:raise ValueError('Unknown Notes component')
        remote='/data/local/tmp/kaidroid-notes54-'+uuid.uuid4().hex+'.xml'
        shell(label+'-dump','uiautomator dump '+shlex.quote(remote))
        text=shell(label+'-xml','cat '+shlex.quote(remote))
        kind=classify(text)
        (args.output/(label+'.xml')).write_text(text,encoding='utf-8')
        png=run(label+'-screen',['exec-out','screencap','-p'],30)
        if png[:8]!=b'\x89PNG\r\n\x1a\n' or struct.unpack('>II',png[16:24])!=(240,320):
            raise ValueError('Invalid screen capture')
        (args.output/(label+'.png')).write_bytes(png)
        report.setdefault('contexts',{})[label]=kind
        if kind=='blank_editor':
            modes=[n.get('text') for n in xml_nodes(text) if n.get('text') in MODES+['kt9','KT9']
                   and bounds(n['bounds'])[1]>=290 and bounds(n['bounds'])[0]<80]
            report.setdefault('editor_modes',{})[label]=modes
        return kind
    def send(code,kind):
        identity();window=focus()
        component='NotesListActivity' if kind=='empty_list' else 'NewNoteActivity'
        if 'com.android.note/' not in window or component not in window:raise ValueError('Input owner changed')
        shell('key-'+str(code),'input keyevent '+str(code));time.sleep(1)

    def choose(label,index):
        if snapshot(label+'-before')!='picker':raise ValueError('Owned picker not visible')
        layout=validate(xml_nodes((args.output/(label+'-before.xml')).read_text()))
        if not layout['passed']:raise ValueError('Picker layout changed')
        if selected_row(args.output/(label+'-before.png'),layout)!=0:
            raise ValueError('Picker did not start at first row')
        owner=focus()
        for _ in range(index):
            if focus()!=owner:raise ValueError('Picker window changed during navigation')
            send(20,'picker')
        if snapshot(label+'-selected')!='picker':raise ValueError('Picker disappeared')
        if selected_row(args.output/(label+'-selected.png'),layout)!=index:
            raise ValueError('D-pad selection did not reach expected mode')
        if focus()!=owner:raise ValueError('Picker owner changed before Center')
        send(23,'picker')

    try:
        identity()
        if 'com.android.launcher3/' not in focus():raise ValueError('Start from Launcher')
        hashes=shell('framework','sha256sum /system/framework/framework.jar /system/system_ext/priv-app/SystemUI/SystemUI.apk')
        if [line.split()[0] for line in hashes.splitlines()]!=[FRAMEWORK,SYSTEMUI]:raise ValueError('Wrong framework/SystemUI')
        path=shell('notes-path','pm path com.android.note')
        if not re.fullmatch(r'package:/[A-Za-z0-9_./+=~\-]+\.apk',path):raise ValueError('Unexpected Notes APK path')
        if shell('notes-hash','sha256sum '+shlex.quote(path[8:])).split()[0]!=APK:raise ValueError('Wrong Notes APK')
        before=state('before')
        if before['default_input_method']!=KIKA:raise ValueError('Original Kika not selected')
        launch=shell('launch','am start -W -n com.android.note/.NotesListActivity')
        if not re.search(r'^Status:\s*ok\s*$',launch,re.M):raise ValueError('Notes launch not definitive success')
        if snapshot('list-before')!='empty_list':raise ValueError('Expected empty list; no input sent')
        owned=True;send(1,'empty_list')
        if snapshot('editor-before')!='blank_editor':raise ValueError('Blank editor not proven')
        if len(report['editor_modes']['editor-before'])!=1:raise ValueError('Original mode action not proven')
        picker_attempted=True;send(1,'blank_editor')
        snapshot('picker')
        layout=validate(xml_nodes((args.output/'picker.xml').read_text(encoding='utf-8')))
        (args.output/'layout.json').write_text(json.dumps(layout,indent=2)+'\n',encoding='utf-8')
        report['layout']=layout
        if not layout['passed']:raise ValueError('Native Notes picker geometry differs')
        report['capture_and_layout_passed']=True
        if args.mode_roundtrip:
            if report['editor_modes']['editor-before']!=['Abc']:
                raise ValueError('Roundtrip requires original Abc mode')
            report['mode_selection_changed']=True  # May change even if subsequent observation fails.
            choose('numeric',4)
            if snapshot('numeric-editor')!='blank_editor' or report['editor_modes']['numeric-editor']!=['123']:
                raise ValueError('Numeric callback did not update the blank editor')
            report['numeric_callback_observed']=True
            send(1,'blank_editor');choose('restore',2)
            if snapshot('restored-editor')!='blank_editor' or report['editor_modes']['restored-editor']!=['Abc']:
                raise ValueError('Abc callback did not restore the blank editor')
            report['original_mode_restored']=True
            # Leave an owned picker open for the existing guarded cancellation path.
            send(1,'blank_editor')
        if args.symbols_roundtrip:
            if report['editor_modes']['editor-before']!=['Abc']:
                raise ValueError('Symbols trial requires original Abc mode')
            report['mode_selection_changed']=True
            choose('symbols',5)
            kind=snapshot('symbols-editor')
            ime=shell('symbols-ime','dumpsys input_method')
            if kind!='blank_editor' or 'mInputShown=true' not in ime or ('mCurId='+KIKA) not in ime:
                raise ValueError('Symbols did not show original Kika on the blank editor')
            xml=(args.output/'symbols-editor.xml').read_text()
            # Kika draws this panel without exporting accessibility nodes.
            # Service state proves the IME request, not visible pixels; keep
            # the PNG for independent visual review rather than inferring it.
            report['symbols_ime_shown_reported']=True
            report['symbols_accessibility_nodes_present']='package="com.iqqijni.dvt912key"' in xml
            report['symbols_panel_visual_review_required']=True
            send(4,'blank_editor')
            if snapshot('symbols-cancelled')!='blank_editor':
                raise ValueError('Symbols Back did not retain blank editor')
            ime=shell('symbols-cancelled-ime','dumpsys input_method')
            # Original TCL leaves mInputShown=true after hiding the Symbols view.
            report['symbols_ime_still_shown_after_back']='mInputShown=true' in ime
            visual=symbols_visual_state(args.output/'editor-before.png',
                args.output/'symbols-editor.png',args.output/'symbols-cancelled.png')
            report['symbols_visual_cancellation']=visual
            if not visual['passed'] or report['editor_modes']['symbols-cancelled']!=['Abc']:
                raise ValueError('Symbols Back did not visually restore blank Abc editor')
            report['original_mode_restored']=True
            report['symbols_cancelled_without_text']=True
            send(1,'blank_editor')
    except Exception as error:report['failure']=str(error)
    finally:
        try:
            if report['mode_selection_changed'] and not report.get('original_mode_restored'):
                raise ValueError('Mode restoration unproven; retain current state for inspection without blind input')
            cleanup=guarded_cleanup(snapshot,send,owned,picker_attempted,ambiguous)
            report['cleanup']=cleanup
            if cleanup['status']=='home_requested':
                identity()
                if 'com.android.launcher3/' not in focus():raise ValueError('Cleanup Home not focused')
                if state('after')!=before:raise ValueError('IME/Bluetooth state changed')
                original=report.get('editor_modes',{}).get('editor-before')
                returned=report.get('editor_modes',{}).get('cleanup-after-picker')
                if report.get('capture_and_layout_passed') and original!=returned:
                    raise ValueError('Editor mode label changed on cancellation')
                report['home_and_ime_bt_restored']=True
                report['passed']=bool(report.get('capture_and_layout_passed') and not report.get('failure'))
        except Exception as error:report['cleanup_failure']=str(error)
        report['command_state_ambiguous']=ambiguous
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))
    if not report['passed']:raise RuntimeError('Notes picker acceptance failed; inspect retained result and cleanup state')


if __name__=='__main__':main()
