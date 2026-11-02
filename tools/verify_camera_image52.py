"""Verify complete raw camera52 content/metadata/labels against immutable51."""
import argparse
import json
from pathlib import Path
from stage_camera_image52_retry02 import RAW, MANIFEST, PARTITION, PAYLOADS, DIRECTORY, FC, append_context, sha


def compare_raw(before, after, bx, ax, oldprops, newprops, oldfc, newfc):
    added = {'/system/' + name for name in [DIRECTORY, *PAYLOADS]}
    changed = {'/system/build.prop', '/system/' + FC}
    if set(after) - set(before) != added or set(before) - set(after):
        raise ValueError('Unexpected filesystem path delta')
    if {name for name in before if before[name] != after[name]} != changed:
        raise ValueError('Unexpected existing content delta')
    for name in changed:
        if {k: v for k, v in before[name].items() if k != 'sha256'} != {k: v for k, v in after[name].items() if k != 'sha256'}:
            raise ValueError('Existing file inode metadata changed')
    if oldprops.splitlines().count(b'ro.kaidroid.image=51') != 1 or newprops != oldprops.replace(b'ro.kaidroid.image=51', b'ro.kaidroid.image=52'):
        raise ValueError('Unexpected build properties')
    if newfc != append_context(oldfc):
        raise ValueError('Runtime label rules differ')
    if set(bx) != set(before) or set(ax) != set(after) or any(bx[name] != ax[name] for name in bx):
        raise ValueError('Existing xattrs changed or path coverage incomplete')
    for name in added:
        relative = name.removeprefix('/system/')
        directory = relative == DIRECTORY
        expected = dict(mode=0o40755 if directory else 0o100644, uid=0, gid=0,
                        kind=0o40000 if directory else 0o100000)
        if not directory:
            expected['sha256'] = PAYLOADS[relative]
        if after[name] != expected:
            raise ValueError('Wrong added payload/inode metadata: ' + name)
        label = 'vendor_file' if relative == DIRECTORY or relative.startswith(DIRECTORY + '/') else 'system_file'
        if ax[name] != {'security.selinux': ('u:object_r:' + label + ':s0\0').encode().hex()}:
            raise ValueError('Wrong new path label/xattrs: ' + name)
    return sorted(added), sorted(changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['baseline', 'candidate', 'manifest', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--candidate-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    for path, pin in [(args.baseline, RAW), (args.candidate, args.candidate_sha256)]:
        if path.stat().st_size != PARTITION or sha(path) != pin:
            raise ValueError('Wrong raw input')
    if sha(args.manifest) != args.manifest_sha256:
        raise ValueError('Unreviewed stage manifest')
    m = json.loads(args.manifest.read_text())
    if m.get('image') != 52 or m.get('baseline_image') != 51 or m.get('base_raw_sha256') != RAW or m.get('base_manifest_sha256') != MANIFEST or m.get('optional_fec') is not False or m.get('signed_hashtree_required') is not True:
        raise ValueError('Wrong reviewed stage identity')
    from verify_image43_closure import inventory
    from verify_image40_xattrs import inventory as xattrs
    from dissect.extfs import ExtFS
    def read(path, name):
        with path.open('rb') as stream:
            return ExtFS(stream).get(name).open().read()
    before, oldprops = inventory(args.baseline)
    after, newprops = inventory(args.candidate)
    bx, _ = xattrs(args.baseline)
    ax, counts = xattrs(args.candidate)
    added, changed = compare_raw(before, after, bx, ax, oldprops, newprops,
                                 read(args.baseline, '/system/' + FC), read(args.candidate, '/system/' + FC))
    report = dict(image=52, baseline_image=51, baseline_sha256=RAW,
                  candidate_sha256=args.candidate_sha256, manifest_sha256=args.manifest_sha256,
                  existing_entries_verified=len(before), added=added, changed=changed,
                  all_other_contents_and_inode_metadata_identical=True,
                  existing_xattrs_unchanged=True, added_uid_gid_modes_labels_verified=True,
                  total_xattrs=sum(counts.values()), installed=False,
                  limitations=['AVB/FEC descriptors require separate packager verification.',
                               'Filesystem timestamps and inode allocation excluded.',
                               'No boot-time bind mapping, camera APK or functional capture validation.'])
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
