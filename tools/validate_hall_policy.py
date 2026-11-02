"""Compile saved image29 policy with a generated hinge system_ext policy, offline."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--build-root', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
root = a.build_root.resolve(strict=True)
base = root / 'engineering-spi-stage-29/compact-system'
policy = base / 'etc/selinux'
common = [policy / 'plat_sepolicy.cil', policy / 'mapping/29.0.cil',
          policy / 'kaidroid/29.0.compat.cil', policy / 'kaidroid/plat_pub_versioned.cil',
          policy / 'kaidroid/vendor_sepolicy.cil']
old = base / 'system_ext/etc/selinux/system_ext_sepolicy.cil'
candidate = root / 'hall-policy-stage02/system_ext_sepolicy.cil'
assert hashlib.sha256(candidate.read_bytes()).hexdigest() == 'f1ed711433c6af43a1d49980ca3a37dc8d80258b41ac33bccdd1b2b401f2ca42'
assert (base / 'build.prop').read_text().count('ro.kaidroid.image=29') == 1
compiler = root / 'out-eng-02/host/linux-x86/bin/secilc'
a.output.mkdir(parents=True, exist_ok=False)
rows = []
for name, tail in [('baseline', old), ('candidate', candidate)]:
    dest = a.output / name
    dest.mkdir()
    inputs = common + [tail]
    command = [str(compiler), '-m', '-M', 'true', '-G', '-c', '30',
               *map(str, inputs), '-o', str(dest / 'policy.30'), '-f', str(dest / 'file_contexts')]
    result = subprocess.run(command, capture_output=True)
    (dest / 'stdout.txt').write_bytes(result.stdout)
    (dest / 'stderr.txt').write_bytes(result.stderr)
    rows.append(dict(name=name, exit_code=result.returncode,
                     inputs={str(f.relative_to(root)): hashlib.sha256(f.read_bytes()).hexdigest() for f in inputs}))
    print(name, result.returncode, result.stderr.decode(errors='replace')[:1500], flush=True)
(a.output / 'result.json').write_text(json.dumps(dict(runs=rows, neverallow_checks=True,
    policy_loaded=False, device_validation=False), indent=2) + '\n')
raise SystemExit(0 if all(r['exit_code'] == 0 for r in rows) else 1)
