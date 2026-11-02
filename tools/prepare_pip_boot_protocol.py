"""Freeze a49/50 fork of protocol04 against the owner's fresh49 freeze; no device use."""
import argparse,hashlib,json
from pathlib import Path
from capture_data_apk_guard import parse_manifest

PINS={'trial_memory_boot.py':'3c2fed19b7610d25acdd654972c659e82fbb5eec0ab4d7add727fcad50582728','observe_startup_light.py':'89a3a82bc75ebd2aea017f08d79687260f8005210dd0ae5a038c75e350207290','capture_timed_memory_audit.py':'4fe2f4b37392c92c232c75eab4b15d3c4e3e3855cbbb14d44682892d8ba87e67','audit_memory.py':'495b87d1cb74e6be78fdb8352629c1a76ce5e14dccd9ad22e104e8b0e87c7509','capture_data_apk_guard.py':'c4f545dc31fd419c769b9facb7a3dcf9cf56250e04e9417b45c2157248db2073'}
OLD='2f539f3e339c5a325006b1c54024358b036ae1e6f6881a2ed316d0daf2a6ba87'
NEW='aa0ad791381611a46dae335be191784eb914ebb8fdaea5d8281ab2872571ea46'

def once(s,a,b):
    if s.count(a)!=1:raise ValueError('Unexpected frozen marker: '+a)
    return s.replace(a,b,1)

def prepare(source,freeze,core,out):
    m=json.loads((freeze/'manifest.json').read_text())
    if m['image']!=49:raise ValueError('Require fresh49 freeze')
    for n,h in m['files'].items():
        if hashlib.sha256((freeze/n).read_bytes()).hexdigest()!=h:raise ValueError('Freeze changed: '+n)
    data=parse_manifest((freeze/'data-apks.txt').read_text())
    if len(data)!=19:raise ValueError('Require exact19 data APKs')
    texts={}
    for n,h in PINS.items():
        raw=(source/n).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=h:raise ValueError('Frozen04 changed: '+n)
        texts[n]=raw.decode()
    t=texts['trial_memory_boot.py'];t=once(t,"a.image not in ('46','47')","a.image not in ('49','50')");t=once(t,"a.image in ('46','47')","a.image in ('49','50')");t=once(t,'Images46/47 require explicit true VM-property guard','Images49/50 require explicit true VM-property guard');texts['trial_memory_boot.py']=t
    texts['observe_startup_light.py']=once(texts['observe_startup_light.py'],"choices=('46','47'), default='46'","choices=('49','50'), default='49'")
    g=texts['capture_data_apk_guard.py'];g=once(g,"args.image not in ('46','47')","args.image not in ('49','50')");texts['capture_data_apk_guard.py']=once(g,'Exact image46/47 and boot required','Exact image49/50 and boot required')
    rows=[]
    for line in core.read_text().splitlines():
        h,p=line.split(None,1)
        if p.startswith('/data/app/') and data.get(p)!=h:raise ValueError('Current49 core/data APK differs')
        rows.append((h,p))
    if len(rows)!=6 or rows[0]!=(OLD,'/system/system_ext/priv-app/SystemUI/SystemUI.apk'):raise ValueError('Wrong baseline six core APKs')
    out.mkdir(parents=True,exist_ok=False);(out/'tools').mkdir()
    hashes={}
    for n,t in texts.items():
        raw=t.encode();(out/'tools'/n).write_bytes(raw);hashes[n]=hashlib.sha256(raw).hexdigest()
    for image in [49,50]:
        arm=list(rows)
        if image==50:arm[0]=(NEW,rows[0][1])
        (out/('image'+str(image)+'-core-apks.txt')).write_bytes(''.join(h+'  '+p+'\n' for h,p in arm).encode())
    for src,dest in [('data-apks.txt','retained-data-apks.txt'),('configuration.txt','frozen-configuration.txt')]: (out/dest).write_bytes((freeze/src).read_bytes())
    result=dict(fork='PiP49/50 protocol05',source04_sha256=PINS,source05_sha256=hashes,freeze_manifest_sha256=hashlib.sha256((freeze/'manifest.json').read_bytes()).hexdigest(),data_apk_count=19,data_apk_manifest_sha256=m['files']['data-apks.txt'],configuration_sha256=m['files']['configuration.txt'],changes=['Only49/50 identities, requiredtrue VM guard and SystemUI expectedhash; five-script immutability/full19 guards retained.','No change to180s observer,200/220/230 interventions or300s noGC census collectors.'],limits=['Owner review/exclusive phone window required for a single explicit reboot. No phone command occurred during preparation.','Pre-reboot freeze is not a timed baseline; PiP diagnostic/lifecycle controls must run after the timed census.','Whole physical working-set denominator is not established by process PSS or this protocol.'])
    (out/'protocol.json').write_text(json.dumps(result,indent=2)+'\n');return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ['source','freeze','core','output']:p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args();print(json.dumps(prepare(a.source,a.freeze,a.core,a.output),indent=2))
