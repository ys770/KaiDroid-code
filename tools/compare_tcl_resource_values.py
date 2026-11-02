"""Compare direct decoded definitions by name, retaining qualifier differences.

This is not transitive equivalence: referenced resource values, overlays and
runtime theme resolution remain separate. File-backed resources are hash-checked.
"""
import argparse
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path


def definitions(text):
    ids = dict(re.findall(r'spec resource (0x[0-9a-f]+) ([^ :]+:[^ :]+):', text))
    result = {}
    name = config = None
    for line in text.splitlines():
        match = re.fullmatch(r'      config (.*):', line)
        if match:
            config = re.sub(r' flags=0x[0-9a-f]+ \[sparse\]$', '', match[1])
            name = None
        match = re.match(r'        resource (0x[0-9a-f]+) ([^ :]+:[^ :]+): (.*)', line)
        if match:
            name = match[2]
            if config is None or config in result.setdefault(name, {}):
                raise ValueError('Missing or duplicate configuration')
            result[name][config] = [match[3]]
        elif name and line.startswith('          '):
            result[name][config].append(line.strip())
        else:
            name = None
    if not ids or not result:
        raise ValueError('Empty resource parse')

    def normalize(line):
        # Only typed references, bag keys/parents and string-pool offsets.
        line = re.sub(r'(t=0x03 d=)0x[0-9a-f]+', r'\1STRING_POOL', line)
        line = re.sub(r'((?:Parent=|Resolved=|Key=|\(reference\) |\(attribute\) ))(0x[0-9a-f]+)',
                      lambda m: m[1] + ids.get(m[2], m[2]), line)
        line = re.sub(r'(t=0x0[12] d=)(0x[0-9a-f]+)',
                      lambda m: m[1] + ids.get(m[2], m[2]), line)
        return line
    return {n: {c: [normalize(v) for v in values] for c, values in configs.items()}
            for n, configs in result.items()}


def compare(donor, target, names, aapt):
    decoded, payloads = [], []
    for path in (donor, target):
        result = subprocess.run([str(aapt), 'dump', '--values', 'resources', str(path)],
                                check=True, capture_output=True, encoding='utf-8', errors='surrogateescape')
        decoded.append(definitions(result.stdout))
        files = {}
        with zipfile.ZipFile(path) as archive:
            for name in names:
                for lines in decoded[-1].get(name, {}).values():
                    for line in lines:
                        match = re.fullmatch(r'\(string8?\) "(res/[^\"]+)"', line)
                        if match:
                            filename = match[1]
                            files[filename] = hashlib.sha256(archive.read(filename)).hexdigest()
        payloads.append(files)
    rows = []
    for name in names:
        d, t = (data.get(name) for data in decoded)
        paths = set()
        for data in (d, t):
            for lines in (data or {}).values():
                for line in lines:
                    match = re.fullmatch(r'\(string8?\) "(res/[^\"]+)"', line)
                    if match:
                        paths.add(match[1])
        same_files = all(payloads[0].get(p) == payloads[1].get(p) for p in paths)
        rows.append(dict(name=name, direct_definitions_equal=d is not None and d == t,
                         file_payloads_equal=same_files,
                         direct_equivalence=d is not None and d == t and same_files,
                         donor=d, target=t,
                         file_hashes={p: [x.get(p) for x in payloads] for p in sorted(paths)}))
    return rows


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('donor', 'target', 'aapt', 'audit', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    audit = json.loads(a.audit.read_text())
    for field, path in [('donor_sha256', a.donor), ('reference_sha256', a.target)]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != audit[field]:
            raise ValueError('Resource input disagrees with audit')
    names = [r['donor_name'] for r in audit['references'] if r['state'] != 'same-id']
    report = dict(scope=__doc__, donor_sha256=audit['donor_sha256'],
                  target_sha256=audit['reference_sha256'],
                  rows=compare(a.donor, a.target, names, a.aapt))
    with a.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, ensure_ascii=True)
        stream.write('\n')
    print(json.dumps({'direct_equivalent': sum(r['direct_equivalence'] for r in report['rows']),
                      'total': len(names)}))


if __name__ == '__main__':
    main()
