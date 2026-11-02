"""Exercise the exact image32 APK pair using the newly built host idmap2."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--root', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
stage = a.root / 'sparse-lookup-build01'
assert (stage / 'build.exit').read_text().strip() == '0'
target = a.root / 'engineering-policy-stage-32/compact-system/framework/framework-res.apk'
overlay = a.root / 'engineering-policy-stage-32/compact-system/product/overlay/IconPackRoundedAndroid/IconPackRoundedAndroidOverlay.apk'
hashes = {}
for name, path, expected in [
    ('target', target, 'f1bad2e1e59543c5d7d2f437e33a41d443739ab39df7c10a4fd2731447a3adad'),
    ('overlay', overlay, 'c0a771ebc684646467d126cb5df765c1335794f58248c28e9774af2126b21424')]:
    hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    assert hashes[name] == expected
a.output.mkdir(exist_ok=False)
env = os.environ.copy()
env['LD_LIBRARY_PATH'] = str(a.root / 'out-eng-02/host/linux-x86/lib64')
tool = stage / 'idmap2-host'
command = [str(tool), 'create', '--target-apk-path', str(target),
           '--overlay-apk-path', str(overlay), '--idmap-path', str(a.output / 'pair.idmap'),
           '--policy', 'public', '--policy', 'product']
r = subprocess.run(command, env=env, capture_output=True, timeout=60)
(a.output / 'create.stdout').write_bytes(r.stdout)
(a.output / 'create.stderr').write_bytes(r.stderr)
report = dict(apk_sha256=hashes, tool_sha256=hashlib.sha256(tool.read_bytes()).hexdigest(),
              policies=['public', 'product'], overlayable_enforced=True, create_exit=r.returncode,
              scope='Host Android idmap implementation; not handset runtime validation.')
if r.returncode == 0:
    q = subprocess.run([str(tool), 'dump', '--idmap-path', str(a.output / 'pair.idmap')],
                       env=env, capture_output=True, timeout=60)
    (a.output / 'dump.stdout').write_bytes(q.stdout)
    (a.output / 'dump.stderr').write_bytes(q.stderr)
    report['dump_exit'] = q.returncode
    report['idmap_sha256'] = hashlib.sha256((a.output / 'pair.idmap').read_bytes()).hexdigest()
(a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report))
print(r.stderr.decode(errors='replace'))
