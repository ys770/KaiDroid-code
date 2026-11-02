"""Compile only the isolated camera candidate object on the authorized build host.

Reads existing source/generated headers. Does not run Ninja builds, alter shared
sources/output, link a service, install anything or require Docker privileges.
"""
import argparse
import base64
import hashlib
import json
import subprocess
from pathlib import Path


REMOTE = r'''
import base64,hashlib,json,pathlib,shlex,subprocess,sys,tempfile
p=json.load(sys.stdin)
root=pathlib.Path('/opt/kaidroid/kaidroid-build-20261023')
stage=pathlib.Path(tempfile.mkdtemp(prefix='memory-lazy-camera-object-',dir=root))
for name,item in p['files'].items():
    if name not in ('service.cpp','include/hidl/LegacySupport.h','include/hidl/HidlLazyUtils.h'):
        raise ValueError('Unexpected input file')
    data=base64.b64decode(item['data'])
    if hashlib.sha256(data).hexdigest()!=item['sha256']: raise ValueError('Transfer mismatch')
    path=stage/name
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)
argv=shlex.split(p['command'])
if argv.pop(0)!='PWD=/proc/self/cwd': raise ValueError('Unexpected compile environment')
if not argv[0].startswith('prebuilts/clang/') or not argv[0].endswith('/clang++'):
    raise ValueError('Unexpected compiler')
if argv[-1]!='hardware/interfaces/camera/provider/2.4/default/service.cpp' or '-c' not in argv:
    raise ValueError('Expected single original service compilation')
argv=[arg.replace('/build/',str(root)+'/') for arg in argv]
argv[argv.index('-o')+1]=str(stage/'service.o')
argv[argv.index('-MF')+1]=str(stage/'service.o.d')
argv[-1]=str(stage/'service.cpp')
argv.insert(1,'-I'+str(stage/'include'))
compiler=root/'aosp'/argv[0]
report=dict(stage=str(stage),command=argv,compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
            inputs={k:v['sha256'] for k,v in p['files'].items()},linked=False,installed=False)
r=subprocess.run(argv,cwd=root/'aosp',capture_output=True,timeout=90)
(stage/'compile.stdout').write_bytes(r.stdout)
(stage/'compile.stderr').write_bytes(r.stderr)
report['returncode']=r.returncode
if r.returncode==0:
    report['object_sha256']=hashlib.sha256((stage/'service.o').read_bytes()).hexdigest()
report['diagnostics']=r.stderr.decode(errors='replace')
(stage/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--module',type=Path,required=True)
    p.add_argument('--command-json',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.exists(): raise ValueError('Use a new result path')
    prepared=json.loads((a.module/'preparation.json').read_text())
    if not prepared['constructor_export'] or not prepared['register_export']:
        raise ValueError('Missing preparation gate')
    files={}
    for name in ('service.cpp','include/hidl/LegacySupport.h','include/hidl/HidlLazyUtils.h'):
        data=(a.module/name).read_bytes()
        digest=hashlib.sha256(data).hexdigest()
        if name.startswith('include/') and prepared['headers'][Path(name).name]!=digest:
            raise ValueError('Prepared header changed')
        files[name]=dict(data=base64.b64encode(data).decode(),sha256=digest)
    command=json.loads(a.command_json.read_text())
    if command['returncode']!=0: raise ValueError('Ninja command query failed')
    payload=json.dumps(dict(files=files,command=command['command']))
    # Python code and payload are transported on stdin; no shell-built filenames.
    script='import json\nexec('+repr(REMOTE)+')\n'
    # -c source contains only our fixed code, quoted by shlex; input remains JSON.
    import shlex
    remote_command='python3 -c '+shlex.quote(script)
    r=subprocess.run(['ssh','-o','BatchMode=yes','BUILD_USER@192.0.2.1',remote_command],
                     input=payload,capture_output=True,text=True,timeout=110)
    a.output.write_text(r.stdout)
    r.check_returncode()
    report=json.loads(r.stdout)
    print(json.dumps({k:v for k,v in report.items() if k!='command'},indent=2))
    if report['returncode']: raise SystemExit(report['returncode'])


if __name__=='__main__':
    main()
