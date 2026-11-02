"""Read-only comparison, with explicit handling of captured flattened runtime APEX links."""
import argparse, hashlib, json, subprocess, re
from pathlib import Path
from probe_android_filesystems import query
from audit_apk_native import dynamic_symbols


def main():
    parser=argparse.ArgumentParser(description='Compare unversioned native symbol names against a captured Nokia Android 10 system image. Not runtime validation.')
    parser.add_argument('--native-report',type=Path,required=True)
    parser.add_argument('--system',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=args.output
    root.mkdir(parents=True,exist_ok=True)
    source=args.system
    report=json.loads(args.native_report.read_text())
    providers={}
    provenance=[]
    for name in sorted({n for lib in report['libraries'] for n in lib['needed_outside_apk']}):
        if not re.fullmatch(r'[A-Za-z0-9_.+\-]+', name) or name in ('.', '..'):
            raise ValueError('Unsafe dependency name: '+name)
        logical='/system/lib/'+name
        stat=query(source,'stat '+logical).decode()
        if 'Type: symlink' in stat:
            match=re.search(r'Fast link dest: "(.*?)"',stat)
            if not match:
                raise ValueError('Unsupported symlink representation: '+logical)
            target=match.group(1)
            if not target.startswith('/apex/com.android.runtime/') or '..' in Path(target).parts:
                raise ValueError('Unresolved link: '+target)
            logical=target.replace('/apex/com.android.runtime/','/system/apex/com.android.runtime.release/',1)
        data=query(source,'cat '+logical)
        if data[:4]!=b'\x7fELF': raise ValueError('Non-ELF provider: '+logical)
        provenance.append({'path':logical,'sha256':hashlib.sha256(data).hexdigest()})
        dst=root/'nokia-runtime'/name
        dst.parent.mkdir(parents=True,exist_ok=True)
        dst.write_bytes(data)
        raw=subprocess.run(['readelf','--dyn-syms','--wide',str(dst)],check=True,capture_output=True,text=True).stdout
        dst.with_suffix('.symbols.txt').write_text(raw)
        for symbol in dynamic_symbols(raw):
            if symbol['section']!='UND' and symbol['binding'] in ('GLOBAL','WEAK','UNIQUE') and symbol['visibility'] in ('DEFAULT','PROTECTED'):
                providers.setdefault(symbol['name'].split('@')[0],[]).append(name)

    results=[]
    for lib in report['libraries']:
        if not lib['is_elf']: continue
        strong={s['name'].split('@')[0] for s in lib['undefined_symbols'] if s['binding']!='WEAK'}
        results.append({'entry':lib['entry'],'strong_undefined':len(strong),'unmatched_names':sorted(strong-providers.keys()),'dynamic_loading':sorted(strong & {'dlopen','dlsym'})})
    (root/'nokia-runtime-symbol-comparison.json').write_text(json.dumps({'scope':'Unversioned symbol name presence only against captured Nokia Android 10 system libraries; not Android 11 or runtime validation.','providers':provenance,'libraries':results},indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__ == '__main__':
    main()
