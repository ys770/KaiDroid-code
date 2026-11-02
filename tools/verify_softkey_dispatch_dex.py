"""Verify soft-key callback definitions and DecorView call site, not runtime behavior."""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path
from audit_dex_references import read_dex

REQUIRED = {
    ('Landroid/widget/MenuBar;', 'onWindowCallbackHandledKey', '(Landroid/view/KeyEvent;)V'),
    ('Landroid/widget/MenuBar;', 'onKeyDown', '(ILandroid/view/KeyEvent;)Z'),
    ('Landroid/widget/MenuBar;', 'onKeyUp', '(ILandroid/view/KeyEvent;)Z'),
    ('Lcom/android/internal/policy/DecorView;', 'dispatchKeyEvent', '(Landroid/view/KeyEvent;)Z'),
}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('jar','dexdump','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--allow-stale-sha1',action='store_true',help='Structural-only check of ART hiddenapi-transformed DEX; retain checksum checks')
    a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False)
    definitions=set(); dex=[]; calls=[]
    with zipfile.ZipFile(a.jar) as z:
        for name in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex',name): continue
            data=z.read(name)
            _,_,methods,stale=read_dex(data,definitions_only=True,allow_stale_sha1=a.allow_stale_sha1)
            definitions.update(methods)
            dex.append(dict(name=name,sha256=hashlib.sha256(data).hexdigest(),stale_header_sha1=stale))
            if ('Lcom/android/internal/policy/DecorView;', 'dispatchKeyEvent', '(Landroid/view/KeyEvent;)Z') not in methods: continue
            path=a.output/name;path.write_bytes(data)
            dump=subprocess.run([str(a.dexdump),'-d',str(path)],check=True,capture_output=True,text=True,errors='replace',timeout=120).stdout
            (a.output/(name+'.dump')).write_text(dump,encoding='utf-8')
            # Select class and method boundaries, then require the actual invoke.
            for block in re.split(r'(?m)^Class #\d+',dump)[1:]:
                if "Class descriptor  : 'Lcom/android/internal/policy/DecorView;'" not in block: continue
                for method in re.split(r'(?m)^    #\d+',block):
                    if not re.search(r"name\s+: 'dispatchKeyEvent'",method): continue
                    calls.extend(line.strip() for line in method.splitlines()
                                 if 'invoke-' in line and 'onWindowCallbackHandledKey' in line)
    if REQUIRED-definitions: raise ValueError('Missing concrete methods: '+repr(REQUIRED-definitions))
    if len(calls)!=1: raise ValueError('Expected one callback-handled invoke in DecorView.dispatchKeyEvent: '+repr(calls))
    report=dict(jar_sha256=hashlib.sha256(a.jar.read_bytes()).hexdigest(),dex=dex,
                required_concrete_methods=sorted(REQUIRED),decor_dispatch_invokes=calls,runtime_verified=False)
    (a.output/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(concrete_methods=len(REQUIRED),decor_calls=len(calls),runtime_verified=False)))


if __name__=='__main__':main()
