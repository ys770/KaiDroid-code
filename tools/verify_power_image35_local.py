"""Independently verify image35 power policy and preserved image34 runtime."""
import argparse
import hashlib
import json
from pathlib import Path
from dissect.extfs import ExtFS

RAW_SHA = 'd6d6366dac3b569dc7b5bb18c5e1187affb8899883f938e131d06959116db76e'
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
root = Path(__file__).resolve().parents[1]
baseline = json.loads((root / 'docs/evidence/image34-local-transfer.json').read_text())
assert baseline['raw_sha256'] == '2f8bef040e48c028cf3386325ced4c9ece4e9eee18431d02a7c344541c730468'
expected = dict(baseline['independently_extracted_files'])
staging = json.loads((root / 'docs/evidence/image35-staging.json').read_text())
assert staging['revision'] == 35 and staging['service_disabled']
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
    for prop in ['ro.kaidroid.image=35', 'ro.kaidroid.power_endcall=true', 'ro.kaidroid.rgb565_client_target=true',
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
