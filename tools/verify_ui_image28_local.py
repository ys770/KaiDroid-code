"""Independently verify transferred image28 with dissect.extfs; no device access."""
import argparse
import hashlib
import json
from pathlib import Path
from dissect.extfs import ExtFS

RAW_SHA = 'abb062da07d3bd83b525cf8d6a169ae38e55841503d3d7a052f4d5bc8a60c2eb'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--transfer', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
raw = a.transfer / 'system.raw.img'
manifest = json.loads((a.transfer / 'verification-02.json').read_text())
assert raw.stat().st_size == manifest['raw_bytes'] == 834666496
with raw.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == manifest['raw_sha256'] == RAW_SHA
a.output.mkdir(parents=True, exist_ok=False)
verified = {}
with raw.open('rb') as stream:
    fs = ExtFS(stream)
    for name, expected in manifest['packaged_sha256'].items():
        data = fs.get('/system/' + name).open().read()
        actual = hashlib.sha256(data).hexdigest()
        assert actual == expected, name
        (a.output / name.replace('/', '_')).write_bytes(data)
        verified[name] = actual
    prop = fs.get('/system/build.prop').open().read()
    assert b'ro.kaidroid.image=28\n' in prop
report = dict(raw_sha256=RAW_SHA, raw_bytes=raw.stat().st_size,
              independently_extracted_files=verified, installed=False)
(a.output / 'verification.json').write_text(json.dumps(report, indent=2))
print(json.dumps({'verified_files': len(verified), 'raw_sha256': RAW_SHA}))
