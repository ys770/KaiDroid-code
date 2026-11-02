"""Verify the transferred image26 archive and independently extract critical files."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import sys

RAW_SHA = 'b72ae0054f608e21b156feeaa63dc88c0a929dab036cf6bcf791e6ab732d48e4'
GZIP_SHA = '8aa7a23238ad75fc6b0842eaf10da93eb6956f902705dda00437d55be096905e'
EXPECTED = {
    'build.prop': 'c3b85e0ac1161a0640a1ef7f2ee295fdb8c25983b0eb5d60136a5c534046d88e',
    'lib/libsurfaceflinger.so': '3f0d105fba18197628bd1183cfc92cb963feddb7c324264a76b9e75131b22639',
    'framework/framework.jar': 'c1b2c382621fd3cbf943e9a83e53877fb6bf8d40f4dabf42ce516175975816b8',
    'framework/services.jar': '9a1c14c244204c35ec57b5aec3530a4e22e8aeff47792389db7f02fc8cd23bd4',
    'etc/selinux/plat_file_contexts': 'cbf143e50c87b5aba44c49b9ce98e9151dfa83e739fdab82d4963e468aef7748',
    'etc/init/kaidroid-data.rc': '363fdb4b81eabaec622a18e743f8c98354c8ebef637f8b40a669713a7aded126',
}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify(transfer, output):
    for value in (RAW_SHA, GZIP_SHA, *EXPECTED.values()):
        assert len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    manifest = json.loads((transfer / 'manifest.json').read_text())
    assert manifest == dict(raw_sha256=RAW_SHA, raw_bytes=834666496,
                            gzip_sha256=GZIP_SHA, gzip_bytes=429782327)
    archive = transfer / 'system.raw.img.gz'
    if archive.stat().st_size != manifest['gzip_bytes']:
        raise ValueError('Archive incomplete or unexpected size; do not consume a live download')
    assert sha(archive) == GZIP_SHA
    from dissect.extfs import ExtFS
    output.mkdir(parents=True, exist_ok=False)
    raw = output / 'system.raw.img'
    with gzip.open(archive, 'rb') as source, raw.open('xb') as destination:
        shutil.copyfileobj(source, destination)
    assert raw.stat().st_size == 834666496 and sha(raw) == RAW_SHA
    with raw.open('rb') as stream:
        fs = ExtFS(stream)
        for name, expected in EXPECTED.items():
            dest = output / name.replace('/', '_')
            with fs.get('/system/' + name).open() as source, dest.open('xb') as target:
                shutil.copyfileobj(source, target)
            assert sha(dest) == expected, name
    props = (output / 'build.prop').read_text().splitlines()
    assert props.count('ro.kaidroid.image=26') == 1
    assert props.count('ro.kaidroid.rgb565_client_target=true') == 1
    result = dict(raw_sha256=RAW_SHA, raw_bytes=834666496, gzip_crc_valid=True,
                  independently_extracted_sha256=EXPECTED, installed=False)
    (output / 'verification.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--transfer', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--extfs-python', type=Path)
    a = p.parse_args()
    if a.extfs_python:
        sys.path.insert(0, str(a.extfs_python))
    verify(a.transfer, a.output)
