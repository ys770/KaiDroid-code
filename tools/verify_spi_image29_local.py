"""Independently extract image29 and check image28 runtime preservation."""
import argparse
import hashlib
import json
from pathlib import Path
from dissect.extfs import ExtFS

RAW_SHA = 'c3d456e9f1890692081788b2afbf5882c6b17ae148a81dd16ef1d3f6695d2ba0'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
baseline = json.loads((root / 'docs/evidence/image28-local-transfer.json').read_text())
assert baseline['raw_sha256'] == 'abb062da07d3bd83b525cf8d6a169ae38e55841503d3d7a052f4d5bc8a60c2eb'
expected = dict(baseline['independently_extracted_files'])
expected.update({'build.prop': '8511a9b965f3ea57f49f2cc5fe68352357262bbddbbf2da0841d6e5bf188fd37',
    'lib/libsurfaceflinger.so': '01f59fbd38cc93e6b96c50d49ce892a17af70782ce9a5bdd7d901d6771b071f1'})
assert a.image.stat().st_size == 834666496
with a.image.open('rb') as f:
    assert hashlib.file_digest(f, 'sha256').hexdigest() == RAW_SHA
a.output.mkdir(parents=True, exist_ok=False)
with a.image.open('rb') as f:
    fs = ExtFS(f)
    for name, digest in expected.items():
        data = fs.get('/system/' + name).open().read()
        assert hashlib.sha256(data).hexdigest() == digest, name
        (a.output / name.replace('/', '_')).write_bytes(data)
    props = fs.get('/system/build.prop').open().read().decode().splitlines()
    for prop in ['ro.kaidroid.image=29', 'ro.kaidroid.rgb565_client_target=true',
                 'ro.kaidroid.force_client_composition=true']:
        assert props.count(prop) == 1, prop
report = dict(raw_sha256=RAW_SHA, raw_bytes=a.image.stat().st_size,
              independently_extracted_files=expected, installed=False)
(a.output / 'verification.json').write_text(json.dumps(report, indent=2))
print(json.dumps({'verified_files': len(expected), 'raw_sha256': RAW_SHA}))
