"""Verify image33's native idmap parser in an isolated output directory."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import uuid

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--boot-id', required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell']


def run(name, command):
    r = subprocess.run(base + [command], capture_output=True, timeout=60)
    (a.output / (name + '.stdout')).write_bytes(r.stdout)
    (a.output / (name + '.stderr')).write_bytes(r.stderr)
    r.check_returncode()
    return r.stdout.decode(errors='replace')


def guard(label):
    fields = run(label, 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u').split()
    if fields != ['33', a.boot_id, '0']:
        raise ValueError('Unexpected image/boot/root identity')


guard('before')
target = '/system/framework/framework-res.apk'
overlay = '/system/product/overlay/IconPackRoundedAndroid/IconPackRoundedAndroidOverlay.apk'
for name, path, digest in [
    ('target', target, 'f1bad2e1e59543c5d7d2f437e33a41d443739ab39df7c10a4fd2731447a3adad'),
    ('overlay', overlay, 'c0a771ebc684646467d126cb5df765c1335794f58248c28e9774af2126b21424'),
    ('library', '/system/lib/libandroidfw.so', '05743c6479447b5292981a5383b230a1f3ff92b8fec8af421ccfe1b28df13c35')]:
    if run(name + '-hash', 'sha256sum ' + path).split()[0] != digest:
        raise ValueError('Unexpected ' + name + ' hash')
remote = '/data/local/tmp/kaidroid-idmap33-' + uuid.uuid4().hex
run('mkdir', 'mkdir ' + remote)
run('create', 'idmap2 create --target-apk-path ' + target + ' --overlay-apk-path ' + overlay +
    ' --idmap-path ' + remote + '/pair.idmap --policy public --policy product')
dump = run('dump', 'idmap2 dump --idmap-path ' + remote + '/pair.idmap')
actual = []
for line in dump.splitlines():
    match = re.match(r'\s*(0x[0-9a-f]{8}) -> (0x[0-9a-f]{8}) (\S+)', line)
    if match:
        actual.append((match[1], match[2], match[3]))
expected = json.loads((Path(__file__).resolve().parents[1] /
                       'docs/evidence/sparse-overlay-expected-names01.json').read_text())
pairs = [(r['target_id'], r['overlay_id'], r['name']) for r in expected['matching_names']]
if sorted(actual) != sorted(pairs):
    raise ValueError('Native device mapping differs from independent fixture')
guard('after')
report = dict(image=33, boot_id=a.boot_id, matched_pairs=len(actual),
              overlayable_enforced=True, output_directory=remote,
              scope='Actual handset idmap2 with installed library; isolated mapping output only. No overlay enablement or UI change; full UI and hardware support remain unverified.')
(a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
