"""Compare complete canonical CIL exports, preserving statement order/structure."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--checkpolicy', required=True, type=Path)
p.add_argument('--candidate', required=True, type=Path)
p.add_argument('--loaded', required=True, type=Path)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
report = {'policy_version':30, 'checkpolicy_sha256':hashlib.sha256(a.checkpolicy.read_bytes()).hexdigest()}
exports = []
for name, source in [('candidate', a.candidate), ('loaded', a.loaded)]:
    dest = a.output/(name+'.cil')
    r = subprocess.run([str(a.checkpolicy), '-b', '-C', '-S', '-M', '-c', '30',
                        '-o', str(dest), str(source)], capture_output=True)
    (a.output/(name+'.log')).write_bytes(r.stdout+r.stderr)
    r.check_returncode()
    data = dest.read_bytes()
    exports.append(data)
    report[name] = {'binary_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
                    'canonical_cil_sha256':hashlib.sha256(data).hexdigest(),
                    'canonical_cil_bytes':len(data)}
report['canonical_cil_byte_identical'] = exports[0] == exports[1]
report['scope'] = 'Complete checkpolicy -b -C -S exports compared byte-for-byte; no policy loaded or changed.'
(a.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
raise SystemExit(0 if report['canonical_cil_byte_identical'] else 1)
