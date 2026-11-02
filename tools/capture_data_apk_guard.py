"""Read-only, boot-bound /data/app APK manifest; optionally require an exact match."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def parse_manifest(text):
    result = {}
    for line in text.splitlines():
        digest, path = line.split(None,1)
        if not re.fullmatch('[a-f0-9]{64}',digest) or not path.startswith('/data/app/') or not path.endswith('.apk') or path in result:
            raise ValueError('Invalid/duplicate data APK manifest row')
        result[path] = digest
    if not result:
        raise ValueError('Empty data APK manifest')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('adb','image','boot'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected',type=Path)
    parser.add_argument('--core-apk-hashes',type=Path)
    args=parser.parse_args()
    if args.image not in ('43','44') or not re.fullmatch('[a-f0-9-]{36}',args.boot):
        parser.error('Exact image43/44 and boot required')
    args.output.mkdir(parents=True,exist_ok=False)
    commands=[]
    def shell(label,command,timeout=30):
        argv=[args.adb,'-s','DEVICE_SERIAL_REQUIRED','shell','-T',command]
        (args.output/(label+'.started.json')).write_text(json.dumps(argv)+'\n')
        result=subprocess.run(argv,capture_output=True,timeout=timeout)
        (args.output/(label+'.stdout')).write_bytes(result.stdout)
        (args.output/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,returncode=result.returncode,stdout_sha256=hashlib.sha256(result.stdout).hexdigest()))
        result.check_returncode()
        if result.stderr:raise ValueError('Unexpected remote stderr; inspect preserved evidence')
        return result.stdout.decode().replace('\r\n','\n').strip()
    def guard(label):
        lines=shell(label,'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce').splitlines()
        if lines != [args.image,args.boot,'0','Enforcing']:raise ValueError('Identity changed')
    report=dict(image=args.image,boot=args.boot,complete=False,read_only=True,commands=commands)
    try:
        guard('initial-identity')
        rows=parse_manifest(shell('all-data-apks',"find /data/app -type f -name '*.apk' -exec sha256sum {} +",120))
        guard('terminal-identity')
        if args.expected and rows != parse_manifest(args.expected.read_text(encoding='utf-8-sig')):
            raise ValueError('Full retained data APK set/path/hash changed')
        if args.core_apk_hashes:
            for line in args.core_apk_hashes.read_text(encoding='utf-8-sig').splitlines():
                digest,path=line.split(None,1)
                if path.startswith('/data/app/') and rows.get(path)!=digest:
                    raise ValueError('Core APK path/hash not present in full manifest')
        manifest=''.join(digest+'  '+path+'\n' for path,digest in sorted(rows.items()))
        (args.output/'manifest.txt').write_bytes(manifest.encode())
        report.update(complete=True,apk_count=len(rows),manifest_sha256=hashlib.sha256(manifest.encode()).hexdigest(),
                      expected_match=True if args.expected else None)
    except Exception as error:
        report['error']=repr(error)
        raise
    finally:
        (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))


if __name__=='__main__':main()
