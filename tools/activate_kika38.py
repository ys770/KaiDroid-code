"""Verify packaged Kika on image38; optionally select it, preserving LatinIME fallback."""
import argparse,json,re,shlex,subprocess,uuid
from pathlib import Path

KIKA='com.iqqijni.dvt912key/.keyboard_service.view.HDKeyboardService'
LATIN='com.android.inputmethod.latin/.LatinIME'
KEYS=('default_input_method','enabled_input_methods','selected_input_method_subtype')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb',required=True);p.add_argument('--boot',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--activate',action='store_true')
    a=p.parse_args();boot=str(uuid.UUID(a.boot));a.output.mkdir(parents=True,exist_ok=False)
    root=Path(__file__).resolve().parents[1]
    provenance=json.loads((root/'docs/evidence/tcl-ime-module-build.json').read_text())
    base=[a.adb,'-s','DEVICE_SERIAL_REQUIRED'];seq=0
    report=dict(image=38,boot=boot,activate_requested=a.activate,configured=False,runtime_validated=False)
    before=None;mutated=False;timed_out=False
    def shell(label,command):
        nonlocal seq,timed_out
        seq+=1
        try:r=subprocess.run(base+['shell',command],capture_output=True,timeout=30)
        except subprocess.TimeoutExpired:
            timed_out=True;report['unknown_remote_command']=command;raise
        (a.output/f'{seq:02d}-{label}.txt').write_bytes(r.stdout+r.stderr)
        r.check_returncode();return r.stdout.decode().replace('\r\n','\n').strip()
    def identity():
        if shell('identity','getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getprop sys.boot_completed').splitlines()!=['38',boot,'0','1']:
            raise ValueError('Wrong image/boot/root')
    def settings():return {key:shell(key,'settings get secure '+key) for key in KEYS}
    try:
        identity()
        expected_path='/system/app/KaiDroidTclIme/KaiDroidTclIme.apk'
        if shell('apk-path','pm path com.iqqijni.dvt912key')!='package:'+expected_path:raise ValueError('Unexpected IME APK path')
        expected={expected_path:provenance['donor_apk_sha256']}
        for name,entry in provenance['built_files'].items():
            path='/'+entry['destination']
            if not re.fullmatch(r'/system/lib/[A-Za-z0-9_.-]+',path):raise ValueError('Invalid provenance path')
            expected[path]=entry['sha256']
        hashes=shell('payload-hashes','sha256sum '+' '.join(shlex.quote(x) for x in expected))
        actual={line.split(maxsplit=1)[1].strip():line.split()[0] for line in hashes.splitlines()}
        if actual!=expected:raise ValueError('Packaged IME/config/native data changed')
        for name in ('libIQQILib.so','libIQQI-jni-Resource.so'):
            if shell('native-link','readlink /system/app/KaiDroidTclIme/lib/arm/'+name)!='/system/lib/'+name:raise ValueError('Native link changed')
        methods=shell('ime-list','ime list -a -s')
        if KIKA not in methods.splitlines() or LATIN not in methods.splitlines():raise ValueError('IME service/fallback absent')
        before=settings();report['before']=before;report['payload_verified']=True
        if before['default_input_method']!=LATIN or before['enabled_input_methods']!=LATIN:raise ValueError('Keyboard settings changed; review before activation')
        if not a.activate:return
        identity();mutated=True
        shell('enable','ime enable '+KIKA);shell('select','ime set '+KIKA)
        after=settings();report['after']=after
        if after['default_input_method']!=KIKA or {x.split(';')[0] for x in after['enabled_input_methods'].split(':')}!={KIKA,LATIN}:raise ValueError('Selection/fallback verification failed')
        report['configured']=True
    except Exception as e:
        report['error']=str(e)
        if mutated and not timed_out and before:
            identity();shell('restore-selection','ime set '+shlex.quote(before['default_input_method']))
            for key in KEYS:
                value=before[key]
                shell('restore-'+key,'settings delete secure '+key if value=='null' else 'settings put secure '+key+' '+shlex.quote(value))
            report['restored']=settings()==before
        raise
    finally:(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__':main()
