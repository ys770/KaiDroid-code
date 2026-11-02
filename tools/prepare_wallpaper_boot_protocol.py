"""Freeze a46/47 fork of reviewed03 boot/census tools; never contacts a phone."""
import argparse
import hashlib
import json
from pathlib import Path

from capture_data_apk_guard import parse_manifest

PINS={'trial_memory_boot.py':'f077ed78bed56b1472bf56174bcb2ccfa7df2065f6a4b85acb39ec74d7b8b8d0',
      'observe_startup_light.py':'e82dfc84cd9916b02faee994f8cf4868ea3ce4b952053be03f9421312e07af9b',
      'capture_timed_memory_audit.py':'4fe2f4b37392c92c232c75eab4b15d3c4e3e3855cbbb14d44682892d8ba87e67',
      'audit_memory.py':'495b87d1cb74e6be78fdb8352629c1a76ce5e14dccd9ad22e104e8b0e87c7509'}


def replace(text,old,new):
    if text.count(old)!=1: raise ValueError('Frozen protocol marker changed: '+old)
    return text.replace(old,new,1)


def prepare(source,freeze,core,output):
    texts={}
    for name,pin in PINS.items():
        raw=(source/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=pin: raise ValueError('Protocol03 source pin mismatch: '+name)
        texts[name]=raw.decode()
    manifest=json.loads((freeze/'manifest.json').read_text())
    if manifest['image']!=46: raise ValueError('Expected fresh46 freeze')
    for name,pin in manifest['files'].items():
        if hashlib.sha256((freeze/name).read_bytes()).hexdigest()!=pin: raise ValueError('Parent freeze changed')
    data=parse_manifest((freeze/'data-apks.txt').read_text())
    old=[]
    for line in core.read_text().splitlines():
        digest,path=line.split(None,1)
        if path.startswith('/data/app/'):
            matches=[name for name,pin in data.items() if pin==digest]
            if len(matches)!=1: raise ValueError('Core APK content not unique/preserved in current46 freeze')
            path=matches[0]
        old.append((digest,path))
    if len(old)!=6 or old[0]!=('5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708','/system/system_ext/priv-app/SystemUI/SystemUI.apk'):
        raise ValueError('Unexpected six core APK definitions')
    trial=texts['trial_memory_boot.py']
    trial=replace(trial,"a.image not in ('42','43','44')","a.image not in ('46','47')")
    trial=replace(trial,"a.image=='44' and a.madvise_random!='true'","a.image in ('46','47') and a.madvise_random!='true'")
    trial=replace(trial,'Image44 requires explicit true VM-property guard','Images46/47 require explicit true VM-property guard')
    trial=replace(trial,"p.add_argument('--apk-hashes',type=Path,required=True);", "p.add_argument('--data-apk-manifest',type=Path,required=True);p.add_argument('--apk-hashes',type=Path,required=True);")
    marker="    hash_command='sha256sum '+' '.join(shlex.quote(path) for path in expected)\n"
    added="""    def full_data_guard(label):
        run(label,[sys.executable,str(tools/'capture_data_apk_guard.py'),'--adb',a.adb,
            '--image',a.image,'--boot',boot,'--expected',str(a.data_apk_manifest),
            '--core-apk-hashes',str(a.apk_hashes),'--output',str(a.output/label)])
"""
    trial=replace(trial,marker,marker+added)
    trial=replace(trial,"        if not a.reboot:report['complete']=True;return", "        full_data_guard('data-apks-before')\n        if not a.reboot:report['complete']=True;return")
    trial=replace(trial,"        run('one-reboot',base+['reboot'])", "        run('observer-argument-preflight',[sys.executable,str(tools/'observe_startup_light.py'),'--image',a.image,'--help'])\n        run('one-reboot',base+['reboot'])")
    trial=replace(trial,"        shell('terminal-window','dumpsys window windows');", "        full_data_guard('data-apks-after')\n        shell('terminal-window','dumpsys window windows');")
    # Include the new guard in the same before/after source immutability checks.
    trial=replace(trial,"('trial_memory_boot.py','observe_startup_light.py','capture_timed_memory_audit.py','audit_memory.py')", "('trial_memory_boot.py','observe_startup_light.py','capture_timed_memory_audit.py','audit_memory.py','capture_data_apk_guard.py')")
    texts['trial_memory_boot.py']=trial
    observer=texts['observe_startup_light.py']
    line=next(line for line in observer.splitlines() if "p.add_argument('--image', choices=" in line)
    texts['observe_startup_light.py']=replace(observer,line,"p.add_argument('--image', choices=('46','47'), default='46')")
    guard=Path(__file__).with_name('capture_data_apk_guard.py').read_text()
    guard=replace(guard,"args.image not in ('43','44')","args.image not in ('46','47')")
    texts['capture_data_apk_guard.py']=replace(guard,'Exact image43/44 and boot required','Exact image46/47 and boot required')
    output.mkdir(parents=True,exist_ok=False);(output/'tools').mkdir()
    hashes={}
    for name,text in texts.items():
        raw=text.encode();(output/'tools'/name).write_bytes(raw);hashes[name]=hashlib.sha256(raw).hexdigest()
    for image in [46,47]:
        rows=list(old)
        if image==47:rows[0]=('2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87',rows[0][1])
        (output/('image'+str(image)+'-core-apks.txt')).write_bytes(''.join(digest+'  '+path+'\n' for digest,path in rows).encode())
    (output/'retained-data-apks.txt').write_bytes((freeze/'data-apks.txt').read_bytes())
    result=dict(fork='wallpaper46/47 protocol04',source03_sha256=PINS,source04_sha256=hashes,
        frozen_data_apks=len(data),full_apk_manifest_sha256=hashlib.sha256((output/'retained-data-apks.txt').read_bytes()).hexdigest(),
        changes=['Exact46/47 identities and required true madvise property; observer timing/handling unchanged.',
                 'Full retained data APK guard before reboot and after300s census; five script hashes frozen.',
                 'Fresh46 data-path mapping for six core APKs;47 changes only SystemUI expected content.'],
        limits=['No phone command. Parent must review before a single authorized reboot; no retry.',
                'Existing03 and43/44 results remain untouched. Actual wallpaper asset and post-census allocator/visual guards are separate.'])
    (output/'protocol.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source','freeze','core','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.source,a.freeze,a.core,a.output),indent=2))
