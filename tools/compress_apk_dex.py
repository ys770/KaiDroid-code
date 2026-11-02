"""Losslessly compress only APK DEX entries; output must be aligned and re-signed."""
import argparse
import copy
import hashlib
import json
import re
import zipfile
from pathlib import Path


def is_signature(name):
    return name.upper() == 'META-INF/MANIFEST.MF' or bool(
        re.fullmatch(r'META-INF/[^/]+\.(SF|RSA|DSA|EC)', name, re.IGNORECASE))


signature_entry = is_signature


def compress(source, output, expected):
    if hashlib.sha256(source.read_bytes()).hexdigest()!=expected:
        raise ValueError('Source identity mismatch')
    changes=[]
    with zipfile.ZipFile(source) as src,zipfile.ZipFile(output,'x') as dst:
        names=src.namelist()
        if len(names)!=len(set(names)):raise ValueError('Duplicate ZIP entries')
        for entry in src.infolist():
            if signature_entry(entry.filename):
                continue
            target=copy.copy(entry)
            if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex',entry.filename):
                target.compress_type=zipfile.ZIP_DEFLATED
                changes.append(entry.filename)
            dst.writestr(target,src.read(entry.filename),compresslevel=9)
    with zipfile.ZipFile(source) as src,zipfile.ZipFile(output) as dst:
        if set(dst.namelist()) != {name for name in src.namelist() if not signature_entry(name)}:
            raise ValueError('Non-signature entry set changed')
        for entry in dst.infolist():
            if src.read(entry.filename)!=dst.read(entry.filename):
                raise ValueError('Uncompressed payload changed')
            if entry.filename not in changes and entry.compress_type!=src.getinfo(entry.filename).compress_type:
                raise ValueError('Unexpected packaging change')
        if dst.testzip():raise ValueError('ZIP integrity failed')
    return dict(source_sha256=expected,output_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
        source_bytes=source.stat().st_size,output_bytes=output.stat().st_size,
        compressed_entries=changes,payload_unchanged=True,resource_and_native_compression_unchanged=True,
        non_signature_entry_set_unchanged=True,unsigned=True,installed=False)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--sha256',required=True)
    p.add_argument('--report',type=Path,required=True)
    a=p.parse_args();r=compress(a.source,a.output,a.sha256)
    with a.report.open('x') as stream:json.dump(r,stream,indent=2);stream.write('\n')
    print(json.dumps(r))
