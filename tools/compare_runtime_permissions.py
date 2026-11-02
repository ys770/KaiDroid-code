"""Compare saved Android package runtime grants/flags; never operates a device.

This checks runtime permission state only, not app-ops, roles, app data or APKs.
Missing permission entries remain distinct from explicit denied entries.
"""
import argparse
import json
import re
from pathlib import Path


def snapshot(text, package, user):
    # Ignore the separate hidden-system-package baseline, if present.
    active = text.split('Hidden system packages:', 1)[0]
    blocks = re.split(r'^  Package \[', active, flags=re.M)[1:]
    matches = [b for b in blocks if b.startswith(package + ']')]
    if len(matches) != 1:
        raise ValueError('Expected exactly one active package block')
    block = matches[0]
    uid = re.search(r'^\s+userId=(\d+)\s*$', block, re.M)
    users = list(re.finditer(r'^    User (\d+):.*$', block, re.M))
    selected = [(i, m) for i, m in enumerate(users) if int(m[1]) == user]
    if uid is None or len(selected) != 1:
        raise ValueError('Missing package UID or requested user')
    i, match = selected[0]
    section = block[match.end():users[i + 1].start() if i + 1 < len(users) else len(block)]
    markers = list(re.finditer(r'^      runtime permissions:\s*$', section, re.M))
    if len(markers) != 1:
        raise ValueError('Missing or ambiguous runtime permission section')
    entries = {}
    for line in section[markers[0].end():].splitlines():
        if not line.strip():
            continue
        if not line.startswith('        '):
            break
        parsed = re.fullmatch(r'        ([\w.]+): granted=(true|false), flags=\[([^\]]*)\]\s*', line)
        if not parsed or parsed[1] in entries:
            raise ValueError('Malformed or duplicate runtime permission entry')
        flags = sorted(f.strip() for f in parsed[3].split('|') if f.strip())
        entries[parsed[1]] = dict(granted=parsed[2] == 'true', flags=flags)
    return dict(package=package, user=user, uid=int(uid[1]), permissions=entries)


def compare(before, after):
    changes = {p: dict(before=before['permissions'].get(p), after=after['permissions'].get(p))
               for p in sorted(before['permissions'].keys() | after['permissions'].keys())
               if before['permissions'].get(p) != after['permissions'].get(p)}
    identity_equal = all(before[k] == after[k] for k in ('package', 'user', 'uid'))
    return dict(runtime_permissions_equal=identity_equal and not changes,
                identity_equal=identity_equal, changes=changes,
                app_ops_verified=False, data_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', type=Path, required=True)
    parser.add_argument('--after', type=Path, required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--user', type=int, default=0)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    states = [snapshot(p.read_text(encoding='utf-8-sig'), args.package, args.user)
              for p in (args.before, args.after)]
    result = compare(*states)
    args.output.write_text(json.dumps(dict(before=states[0], after=states[1], **result),
                                     indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))
    raise SystemExit(0 if result['runtime_permissions_equal'] else 1)


if __name__ == '__main__':
    main()
