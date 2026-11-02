"""Locate direct DEX invoke sites for unresolved methods in an API audit.

Method-table entries are not executed-call evidence. This identifies concrete
invoke instructions, not runtime reachability. No calls does not exclude
reflection, native dispatch, other packages or an untested code path.
"""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

INVOKE = re.compile(r'(L[^\s]+;)\.([^:\s]+):(\([^\s]*\)[^\s]+)')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('apk', 'audit', 'dexdump', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    audit = json.loads(a.audit.read_text())
    apk_hash = hashlib.sha256(a.apk.read_bytes()).hexdigest()
    if apk_hash != audit['apk_sha256']:
        raise ValueError('APK does not match API audit')
    missing = {(r['owner'], r['name'], r['descriptor']): dict(r, callsites=[])
               for r in audit['unresolved'] if r['kind'] == 'methods'}
    a.output.mkdir(parents=True)
    dex_rows = []
    with zipfile.ZipFile(a.apk) as z:
        for name in z.namelist():
            if not re.fullmatch(r'classes\d*\.dex', name):
                continue
            data = z.read(name)
            dex = a.output / name
            dex.write_bytes(data)
            proc = subprocess.Popen([str(a.dexdump), '-d', str(dex)], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
            owner = method = descriptor = None
            for line in proc.stdout:
                if "Class descriptor" in line:
                    owner = line.split("'")[1]
                    method = descriptor = None
                elif "name          : '" in line:
                    method = line.split("'")[1]
                elif "type          : '" in line:
                    descriptor = line.split("'")[1]
                elif 'invoke-' in line:
                    match = INVOKE.search(line)
                    if match and match.groups() in missing:
                        missing[match.groups()]['callsites'].append(dict(dex=name, owner=owner,
                            method=method, descriptor=descriptor, instruction=line.strip()))
            error = proc.stderr.read()
            if proc.wait() != 0:
                raise ValueError('dexdump failed: ' + error)
            dex_rows.append(dict(file=name, sha256=hashlib.sha256(data).hexdigest()))
    rows = sorted(missing.values(), key=lambda r: (r['owner'], r['name'], r['descriptor']))
    report = dict(scope=__doc__, apk_sha256=apk_hash,
                  audit_sha256=hashlib.sha256(a.audit.read_bytes()).hexdigest(), dex=dex_rows,
                  unresolved_methods=len(rows), methods_with_direct_calls=sum(bool(r['callsites']) for r in rows),
                  direct_call_count=sum(len(r['callsites']) for r in rows), methods=rows,
                  runtime_reachability_verified=False)
    (a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ('unresolved_methods', 'methods_with_direct_calls', 'direct_call_count')}))


if __name__ == '__main__':
    main()
