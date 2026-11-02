"""Independently verify image33 sparse parser and preserved image32 runtime."""
import argparse
import hashlib
import json
from pathlib import Path
from dissect.extfs import ExtFS

RAW_SHA = '864284a5c7be2ff6ae74e13bc4578a323dd8fc53648a0ce6d4d409c14ba455e4'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
baseline = json.loads((root / 'docs/evidence/image32-local-transfer.json').read_text())
assert baseline['raw_sha256'] == '89b28f08c71bf834d096bf7ed829be981eafc4149bd8325aa25da5226365be54'
expected = dict(baseline['independently_extracted_files'])
staging = json.loads((root / 'docs/evidence/image33-staging.json').read_text())
assert staging['revision'] == 33 and staging['service_disabled']
expected.update(staging['changes'])
expected['apex/com.android.permission/priv-app/PermissionController/PermissionController.apk'] = 'b94c069e92ff1ccfdf80c15f25b4155d8647d520f8a47834f71dedff2bfdfb30'
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
    for prop in ['ro.kaidroid.image=33', 'ro.kaidroid.rgb565_client_target=true',
                 'ro.kaidroid.force_client_composition=true']:
        assert props.count(prop) == 1, prop
    init = fs.get('/system/bin/init').open().read()
    assert b'Loaded input-matched KaiDroid precompiled policy' in init
    assert b'Compiling SELinux policy' in init
    rc = fs.get('/system/etc/init/kaidroid-hall.rc').open().read().decode()
    assert '\n    disabled\n' in rc and '\non ' not in rc
report = dict(raw_sha256=RAW_SHA, raw_bytes=a.image.stat().st_size,
              independently_extracted_files=expected, installed=False)
(a.output / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'verified_files': len(expected), 'raw_sha256': RAW_SHA}))
