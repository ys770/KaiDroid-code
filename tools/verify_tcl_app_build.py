"""Verify built app identities, platform signatures, alignment and payload preservation."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import zipfile
from pathlib import Path

PLATFORM_CERT = 'c8a2e9bccf597c2fb6dc66bee293fc13f2fc47ec77bc6b2b0d52c11f51192ab8'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def content(archive):
    if len(archive.namelist()) != len(set(archive.namelist())) or archive.testzip():
        raise ValueError('Duplicate or corrupt ZIP entries')
    return {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()
            if not n.startswith('META-INF/') and not n.endswith('/')}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('inputs', 'outputs', 'apks', 'java', 'build-tools', 'report'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if a.report.exists():
        raise FileExistsError(a.report)
    provenance = json.loads((a.inputs / 'provenance.json').read_text())
    inputs = {'KaiDroidTcl' + app['name']: app for app in provenance['apps']}
    outputs = json.loads(a.outputs.read_text())['outputs']
    if len(outputs) != len(inputs) or {row['module'] for row in outputs} != set(inputs):
        raise ValueError('Output inventory differs from prepared modules')
    verified = []
    for row in outputs:
        name = row['module']
        if not re.fullmatch(r'KaiDroidTcl[A-Za-z0-9]+', name):
            raise ValueError('Invalid module name')
        apk = a.apks / (name + '.apk')
        app = inputs[name]
        source = a.inputs / app['name'] / (app['name'] + '.apk')
        if sha(apk) != row['sha256'] or sha(source) != app['sha256']:
            raise ValueError('Input/output hash mismatch: ' + name)
        result = subprocess.run([str(a.java), '-jar', str(a.build_tools / 'lib/apksigner.jar'),
                                 'verify', '--print-certs', str(apk)], check=True, capture_output=True, text=True)
        certs = re.findall(r'Signer #\d+ certificate SHA-256 digest: ([a-f0-9]+)', result.stdout)
        if certs != [PLATFORM_CERT]:
            raise ValueError('Unexpected signer: ' + name)
        subprocess.run([str(a.build_tools / 'zipalign.exe'), '-c', '4', str(apk)],
                       check=True, capture_output=True)
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(apk) as built:
            before, after = content(original), content(built)
            if before != after:
                raise ValueError('Build changed non-signature payload: ' + name)
            info = built.getinfo('resources.arsc')
            data = apk.read_bytes()
            length, extra = struct.unpack_from('<HH', data, info.header_offset + 26)
            offset = info.header_offset + 30 + length + extra
            if info.compress_type != 0 or offset % 4:
                raise ValueError('Resource table is compressed or unaligned: ' + name)
        verified.append(dict(module=name, package=app['package'], sha256=row['sha256'],
                             platform_signature_verified=True, zip_alignment_verified=True,
                             payload_entries_unchanged=len(after), resource_data_offset=offset))
    report = dict(apps=verified, scope=__doc__, installed=False, runtime_verified=False,
                  limitations='No native linker, permission policy, shared UID migration or hardware behavior verification')
    a.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(verified=len(verified), installed=False)))


if __name__ == '__main__':
    main()
