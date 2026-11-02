"""Verify exact image43/44 content, inode metadata, xattrs and property delta."""
import argparse
import hashlib
import json
from pathlib import Path

from stage_madvise_random_image44 import BASE_RAW, candidate_properties
from verify_image43_closure import inventory
from verify_image40_xattrs import inventory as xattr_inventory


def verify(baseline, candidate, expected):
    for path, digest in ((baseline,BASE_RAW),(candidate,expected)):
        if path.stat().st_size != 834666496:
            raise ValueError('Wrong partition length')
        with path.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest() != digest:
                raise ValueError('Wrong raw image identity')
    before, oldprops = inventory(baseline)
    after, newprops = inventory(candidate)
    if before.keys() != after.keys():
        raise ValueError('Filesystem entry set changed')
    changed = [name for name in before if before[name] != after[name]]
    if changed != ['/system/build.prop']:
        raise ValueError('Unexpected changed inode content/metadata: '+str(changed))
    old, new = before[changed[0]], after[changed[0]]
    if {k:v for k,v in old.items() if k!='sha256'} != {k:v for k,v in new.items() if k!='sha256'}:
        raise ValueError('Build.prop inode metadata differs')
    if newprops != candidate_properties(oldprops):
        raise ValueError('Unexpected property delta')
    oldattrs, _ = xattr_inventory(baseline)
    newattrs, counts = xattr_inventory(candidate)
    if oldattrs != newattrs:
        raise ValueError('Extended attributes differ')
    return dict(baseline_image=43,candidate_image=44,baseline_sha256=BASE_RAW,
        candidate_sha256=expected,compared_entries=len(before),changed=changed,
        all_other_content_mode_uid_gid_and_symlinks_identical=True,
        all_extended_attributes_identical=True,compared_xattrs=sum(counts.values()),
        exact_property_delta=True,installed=False,
        limitations=['Timestamps and inode allocation excluded. AVB verification is a separate packer gate.',
                    'Offline closure does not establish boot, effective property, runtime hints, RAM saving or hardware behavior.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','candidate','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--candidate-sha256',required=True)
    args = parser.parse_args()
    report = verify(args.baseline,args.candidate,args.candidate_sha256)
    with args.output.open('x') as output:
        output.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
