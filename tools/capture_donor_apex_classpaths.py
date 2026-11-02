"""Read-only capture of exact mounted APEX JARs declared by a pinned donor.

Does not enumerate private storage, mutate the phone, or claim complete dynamic
class-loader coverage. Existing output directories are never reused.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--fingerprint', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    base = [str(args.adb), '-s', args.serial]

    def shell(command):
        return subprocess.run(base + ['shell', command], check=True, capture_output=True,
                              text=True, encoding='utf-8', timeout=30).stdout.strip()

    def identity():
        return dict(fingerprint=shell('getprop ro.build.fingerprint'),
                    boot_id=shell('cat /proc/sys/kernel/random/boot_id'))

    def phone_hash(path):
        value = shell('sha256sum ' + path).split()[0]
        if not re.fullmatch('[0-9a-f]{64}', value):
            raise ValueError('Invalid phone hash')
        return value

    before = identity()
    if before['fingerprint'] != args.fingerprint:
        raise ValueError('Donor fingerprint mismatch')
    classpaths = {name: shell('echo $' + name) for name in
                  ('BOOTCLASSPATH', 'SYSTEMSERVERCLASSPATH')}
    paths = sorted({p for value in classpaths.values() for p in value.split(':')
                    if p.startswith('/apex/')})
    if not paths or any(not re.fullmatch(r'/apex/[A-Za-z0-9_.@-]+/javalib/[A-Za-z0-9_.-]+\.jar', p)
                        for p in paths):
        raise ValueError('Unexpected APEX classpath path')
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(before=before, classpaths=classpaths, entries=[], complete=False,
                  scope=__doc__)
    manifest = args.output / 'manifest.json'
    for path in paths:
        target = args.output / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        expected = phone_hash(path)
        subprocess.run(base + ['pull', path, str(target)], check=True,
                       capture_output=True, timeout=120)
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected or phone_hash(path) != expected:
            raise ValueError('Source/local hash disagreement: ' + path)
        report['entries'].append(dict(path=path, sha256=actual, bytes=target.stat().st_size))
        manifest.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    report['after'] = identity()
    if report['after'] != before:
        raise ValueError('Donor identity/boot changed; retain capture for review')
    report['complete'] = True
    manifest.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(archives=len(paths), bytes=sum(r['bytes'] for r in report['entries']),
                         identity_stable=True, phone_local_hashes_match=True)))


if __name__ == '__main__':
    main()
