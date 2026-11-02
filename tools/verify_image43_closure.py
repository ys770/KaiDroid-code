"""Compare complete image42/43 filesystem content and basic inode metadata.

Requires dissect.extfs. Reads raw images only; does not flash or infer boot success.
Filesystem timestamps and inode allocation are outside this comparison.
"""
import argparse
import hashlib
import json
import stat
from pathlib import Path
from dissect.extfs import ExtFS
from verify_image40_xattrs import inventory as xattr_inventory

BASE = 'a2622f8cd59aeef409f7d316f5802dfe667298396b5c47c2da71700c69c10ceb'
APK = '/system/system_ext/priv-app/SystemUI/SystemUI.apk'
OLD = 'f5329036de55c182abb6c4f7b4f5e2169923a63f83d119dc602c993c635af7c0'
NEW = '5baff8afce1704ce8ed72301ebe7422ccf41d6ef8eaf540aa25556136a15d708'


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
    assert before[APK]['sha256'] == OLD
    assert after[APK]['sha256'] == NEW
    assert oldprops.splitlines().count(b'ro.kaidroid.image=42') == 1
    assert newprops == oldprops.replace(b'ro.kaidroid.image=42', b'ro.kaidroid.image=43')
    oldattrs, _ = xattr_inventory(args.baseline)
    newattrs, counts = xattr_inventory(args.candidate)
    assert oldattrs == newattrs, 'Extended attributes differ'
    report = dict(all_extended_attributes_identical=True, compared_xattrs=sum(counts.values()), baseline_sha256=BASE, candidate_sha256=args.candidate_sha256,
                  filesystem_entries=len(before), changed=sorted(changed),
                  content_and_basic_metadata_verified=True, installed=False,
                  exclusions=['timestamps', 'inode allocation'],
                  avb_verification='Separate build artifact required')
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
