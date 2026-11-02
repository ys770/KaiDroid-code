"""Verify signed TCL build outputs against selected payloads and a target platform APK."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path


def certificate(tool, apk):
    result = subprocess.run([str(tool), 'verify', '--verbose', '--print-certs', str(apk)],
                            check=True, capture_output=True, encoding='utf-8')
    certs = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([0-9a-f]+)$', result.stdout, re.M)
    if len(certs) != 1:
        raise ValueError('Expected exactly one signer: ' + str(apk))
    return certs[0]


def payload(apk):
    with zipfile.ZipFile(apk) as archive:
        if archive.testzip() is not None:
            raise ValueError('Bad ZIP CRC: ' + str(apk))
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('Duplicate APK entries')
        return {n: hashlib.sha256(archive.read(n)).hexdigest() for n in names
                if not n.upper().startswith('META-INF/') and not n.endswith('/')}


def resource_packaging(apk):
    with zipfile.ZipFile(apk) as archive, apk.open('rb') as stream:
        entry = archive.getinfo('resources.arsc')
        stream.seek(entry.header_offset)
        header = stream.read(30)
        if header[:4] != b'PK\x03\x04':
            raise ValueError('Invalid local ZIP header')
        name_length, extra_length = struct.unpack_from('<HH', header, 26)
        offset = entry.header_offset + 30 + name_length + extra_length
        return dict(resource_compression=entry.compress_type, resource_data_offset=offset,
                    resource_stored=entry.compress_type == zipfile.ZIP_STORED,
                    resource_aligned4=offset % 4 == 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('prepared', 'built', 'platform_apk', 'apksigner', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    platform = certificate(args.apksigner, args.platform_apk)
    provenance = json.loads((args.prepared / 'provenance.json').read_text(encoding='utf-8'))
    outputs = json.loads((args.built / 'outputs.json').read_text(encoding='utf-8'))
    records = {a['module']: a for a in outputs['outputs']}
    results = []
    for app in provenance['apps']:
        name = app['name']
        original = args.prepared / name / (name + '.apk')
        built = args.built / ('KaiDroidTcl' + name + '.apk')
        sha = hashlib.sha256(built.read_bytes()).hexdigest()
        if sha != records['KaiDroidTcl' + name]['sha256']:
            raise ValueError('Build output hash mismatch')
        if hashlib.sha256(original.read_bytes()).hexdigest() != app['sha256']:
            raise ValueError('Prepared input hash mismatch')
        if payload(original) != payload(built):
            raise ValueError('APK payload changed during build: ' + name)
        signer = certificate(args.apksigner, built)
        if signer != platform:
            raise ValueError('Platform signer mismatch: ' + name)
        packaging = resource_packaging(built)
        # These integration candidates must meet Android R's packaging rule;
        # verify the data offset, not the ZIP local header's offset.
        if not packaging['resource_stored'] or not packaging['resource_aligned4']:
            raise ValueError('R+ resources packaging invalid: ' + name + ' ' + str(packaging))
        results.append(dict(name=name, sha256=sha, signer_sha256=signer,
                            payload_entries_preserved=True, signature_verified=True,
                            **packaging))
    report = dict(apps=results, platform_apk_sha256=hashlib.sha256(args.platform_apk.read_bytes()).hexdigest(),
                  installed=False, runtime_permissions_verified=False, parity_verified=False)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
