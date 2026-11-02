"""Compare complete image39/40 filesystem content and basic inode metadata.

Requires dissect.extfs. Reads raw images only; does not flash or infer boot success.
Filesystem timestamps, inode allocation and xattrs are outside this comparison.
"""
import argparse
import hashlib
import json
import stat
from pathlib import Path
from dissect.extfs import ExtFS

BASE = 'c99dd873b544eaa5648de0e2c524fbe025d9f4e946fd0978dda8a11abb66284b'
APK = '/system/system_ext/priv-app/SystemUI/SystemUI.apk'
NEW = 'f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'


def inventory(path):
    rows = {}
    with path.open('rb') as stream:
        fs = ExtFS(stream)

        def visit(node, name):
            row = dict(mode=int(node.inode.i_mode), uid=int(node.inode.i_uid),
                       gid=int(node.inode.i_gid), kind=node.filetype)
            if node.filetype == stat.S_IFREG:
                with node.open() as data:
                    row['sha256'] = hashlib.file_digest(data, 'sha256').hexdigest()
            elif node.filetype == stat.S_IFLNK:
                row['target'] = node.link
            rows[name] = row
            if node.filetype == stat.S_IFDIR:
                for child in node.iterdir():
                    if child.filename not in ('.', '..'):
                        visit(child, name.rstrip('/') + '/' + child.filename)

        visit(fs.get('/'), '/')
        props = fs.get('/system/build.prop').open().read()
    return rows, props


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--candidate-sha256', required=True)
    args = parser.parse_args()
    for path, expected in ((args.baseline, BASE), (args.candidate, args.candidate_sha256)):
        assert path.stat().st_size == 834666496, 'Partition size mismatch'
        with path.open('rb') as stream:
            assert hashlib.file_digest(stream, 'sha256').hexdigest() == expected
    before, oldprops = inventory(args.baseline)
    after, newprops = inventory(args.candidate)
    assert before.keys() == after.keys(), 'Filesystem entry set changed'
    changed = [name for name in before if before[name] != after[name]]
    assert set(changed) == {APK, '/system/build.prop'}, changed
    for name in changed:
        assert {k:v for k,v in before[name].items() if k != 'sha256'} == {
            k:v for k,v in after[name].items() if k != 'sha256'}, 'Metadata changed'
    assert after[APK]['sha256'] == NEW
    assert oldprops.splitlines().count(b'ro.kaidroid.image=39') == 1
    assert newprops == oldprops.replace(b'ro.kaidroid.image=39', b'ro.kaidroid.image=40')
    report = dict(baseline_sha256=BASE, candidate_sha256=args.candidate_sha256,
                  filesystem_entries=len(before), changed=sorted(changed),
                  content_and_basic_metadata_verified=True, installed=False,
                  exclusions=['timestamps', 'inode allocation', 'extended attributes'],
                  avb_verification='Separate build artifact required')
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
