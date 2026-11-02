"""Capture one local APK's sole DEX/disassembly with source/tool/output hashes."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

from verify_lazy_wifi_apk import inspect


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(apk,dexdump,output):
    classes,methods,entries,dex=inspect(apk)
    if len(dex)!=1 or dex[0]['name']!='classes.dex': raise ValueError('Require sole classes.dex')
    output.mkdir(parents=True,exist_ok=False)
    manifest=dict(complete=False,apk_sha256=sha(apk),dexdump_sha256=sha(dexdump),
                  classes=len(classes),concrete_methods=len(methods),noncode_entries=len(entries))
    try:
        with zipfile.ZipFile(apk) as package: (output/'classes.dex').write_bytes(package.read('classes.dex'))
        if sha(output/'classes.dex')!=dex[0]['sha256']: raise ValueError('DEX extraction mismatch')
        command=[str(dexdump),'-d',str(output/'classes.dex')]
        with (output/'dexdump.stderr').open('wb') as err:
            process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=err)
            with (output/'classes.dump.gz').open('wb') as raw:
                with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as compressed:
                    shutil.copyfileobj(process.stdout,compressed)
            result=process.wait()
        manifest.update(command=command,returncode=result,
                        files={name:sha(output/name) for name in ['classes.dex','classes.dump.gz','dexdump.stderr']})
        if result: raise ValueError('Disassembler failed')
        if sha(apk)!=manifest['apk_sha256'] or sha(dexdump)!=manifest['dexdump_sha256']:
            raise ValueError('APK/tool changed during capture')
        manifest['complete']=True
        return manifest
    finally:
        (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['apk','dexdump','output']: parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(capture(args.apk,args.dexdump,args.output),indent=2))
