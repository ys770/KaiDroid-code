"""Link the memory experiment in new remote scratch, without a shared build.

Uses image-extracted runtime libraries and snapshots existing build artifacts. This
does not establish installed linker namespace reachability or camera behavior.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


REMOTE = r'''
import base64,hashlib,json,pathlib,shlex,subprocess,sys,tempfile
p=json.load(sys.stdin)
root=pathlib.Path('/opt/kaidroid/kaidroid-build-20261023')
stage=pathlib.Path(tempfile.mkdtemp(prefix='memory-lazy-camera-link-',dir=root))
inputs={}
def snapshot(source,name):
    data=source.read_bytes()
    dest=stage/name
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(data)
    inputs[name]={'source':str(source),'sha256':hashlib.sha256(data).hexdigest()}
    return str(dest)
for name,item in p['files'].items():
    if name not in ('service.o','libhidlbase.so','libbinder.so','libutils.so','libc++.so',
                    'android.hardware.camera.provider@2.4.so','libc.so','libm.so','libdl.so','liblog.so','libcutils.so'):
        raise ValueError('Unexpected transferred input')
    data=base64.b64decode(item['data'])
    if hashlib.sha256(data).hexdigest()!=item['sha256']: raise ValueError('Transfer hash mismatch')
    (stage/name).write_bytes(data)
    inputs[name]={'source':item['source'],'sha256':item['sha256']}
original=shlex.split(p['command'])
if original[0]!='prebuilts/clang/host/linux-x86/clang-r383902b/bin/clang++':
    raise ValueError('Unreviewed compiler')
compiler=root/'aosp'/original[0]
flags=original[original.index('-target'):]
if any(x.startswith('@') or x in ('-o','-c') for x in flags): raise ValueError('Unexpected output in flags')
# Preserve the existing ARM32 platform executable link flags. Copy every input
# used by this link so another lane's build cannot change it during the link.
crt=[]
archives=[]
for arg in original[1:original.index('-o')]:
    if arg.startswith(('-', '@')): continue
    src=pathlib.Path(arg.replace('/build/',str(root)+'/'))
    if not src.is_absolute(): src=root/'aosp'/src
    if src.name in ('crtbegin_dynamic.o','crtend.o'):
        crt.append(snapshot(src,src.name))
    elif src.name in ('libclang_rt.builtins-arm-android.a','libatomic.a'):
        archives.append(snapshot(src,src.name))
if len(crt)!=2 or len(archives)!=2: raise ValueError('Missing platform link inputs')
system=[str(stage/name) for name in ('libc.so','libm.so','libdl.so','liblog.so')]
provider_path=str(stage/'android.hardware.camera.provider@2.4.so')
libs=[str(stage/name) for name in ('libbinder.so','libhidlbase.so','libutils.so','libc++.so','libcutils.so')]
output=stage/'kaidroid-camera-lazy-experiment'
argv=[str(compiler),crt[0],str(stage/'service.o'),'-Wl,--start-group',*archives,
      '-Wl,--end-group',provider_path,*libs,*system,crt[1],'-o',str(output),*flags]
result=subprocess.run(argv,cwd=root/'aosp',capture_output=True,text=True,timeout=60)
report=dict(stage=str(stage),inputs=inputs,command=argv,
            compiler_sha256=hashlib.sha256(compiler.read_bytes()).hexdigest(),
            returncode=result.returncode,stdout=result.stdout,stderr=result.stderr,
            installed=False,runtime_verified=False,
            runtime_image_sha256=p['runtime_image_sha256'],
            scope='Isolated link against image-extracted runtime. Namespace resolution, transitive closure and ABI behavior unproven.')
if result.returncode==0:
    report['binary_sha256']=hashlib.sha256(output.read_bytes()).hexdigest()
    report['binary_bytes']=output.stat().st_size
(stage/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--object', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--command-json', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Use a new output path')
    manifest = json.loads((args.runtime/'manifest.json').read_text())
    paths = {'service.o': args.object}
    for name in ('libhidlbase.so', 'libbinder.so', 'libutils.so', 'libc++.so', 'libcutils.so',
                 'android.hardware.camera.provider@2.4.so', 'liblog.so', 'libc.so', 'libm.so', 'libdl.so'):
        paths[name] = args.runtime/name
    files = {}
    for name, path in paths.items():
        data = path.read_bytes()
        if name != 'service.o' and hashlib.sha256(data).hexdigest() != manifest['files'][name]['sha256']:
            raise ValueError('Runtime file changed: '+name)
        files[name] = dict(source=path.as_posix(), sha256=hashlib.sha256(data).hexdigest(),
                           data=base64.b64encode(data).decode())
    command = json.loads(args.command_json.read_text())
    if command['returncode'] != 0:
        raise ValueError('Original link command query failed')
    payload = json.dumps(dict(files=files, command=command['command'],
                              runtime_image_sha256=manifest['image_sha256']))
    result = subprocess.run(['ssh', '-o', 'BatchMode=yes', 'BUILD_USER@192.0.2.1',
                             'python3 -c '+shlex.quote(REMOTE)],
                            input=payload, capture_output=True, text=True, timeout=90)
    result.check_returncode()
    report = json.loads(result.stdout)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k: v for k, v in report.items() if k not in ('inputs', 'command')}, indent=2))
    if report['returncode']:
        raise SystemExit(report['returncode'])


if __name__ == '__main__':
    main()
