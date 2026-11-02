"""Independent, fixed image59 -> image60 raw filesystem contract; no device I/O."""
import argparse
import json
from pathlib import Path
from image56_contract import raw_inventory, sha, dump

BASE = 'ca8153c0d5f3165fa6b79b4f1b31663babef6a58d71590092edd5910ea723aad'
TARGET = 'b2f83a0a1c8bee8adbf79be9ccb8a27b7de066d8495242d2ab16d872e18511f3'
CHANGES = {
    'build.prop': '8b65a0c5bb748a838ccc77717fabe39640ae8a3f06d4a5f5bc456bc9755a6b77',
    'bin/init': '0e921696b2e64fcafa7b2b805d9e9a0bd09b162456691279e1b096c8afe3413d',
    'lib/libsurfaceflinger.so': 'f663d261b46b46fc17b3bb6541f7055622d4c22abc6015eea917c364eef2e645',
    'system_ext/etc/selinux/system_ext_sepolicy.cil': '0ca8bbca68b0b6c052ef76047c1885c89b4488f7605e3c9f11d78578f9799a27',
    'etc/selinux/kaidroid/precompiled_sepolicy': 'f57d2d9bb34fa7f2dcc0e2fc3499b98067c174343c736b0d3a5a631cdb4dbbb9',
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def compare(before, after):
    old, ox, op = before
    new, nx, np = after
    require(old.keys() == new.keys(), 'Filesystem path set differs')
    require(ox == nx, 'Filesystem xattrs differ')
    changed = {n for n in old if old[n] != new[n]}
    require(changed == {'/system/' + n for n in CHANGES}, 'Not exact five-file delta')
    for name, digest in CHANGES.items():
        key = '/system/' + name
        require(new[key]['sha256'] == digest, 'Candidate bytes differ: ' + name)
        require({k:v for k,v in old[key].items() if k != 'sha256'} ==
                {k:v for k,v in new[key].items() if k != 'sha256'}, 'Metadata differs: ' + name)
    require(op.count(b'ro.kaidroid.image=59') == 1 and b'ro.kaidroid.frame_backlight=' not in op, 'Unexpected baseline properties')
    require(np == op.replace(b'ro.kaidroid.image=59', b'ro.kaidroid.image=60') +
            b'\nro.kaidroid.frame_backlight=true\n', 'Unexpected property change')
    return dict(image=60, baseline_image=59, baseline_raw_sha256=BASE,
                raw_sha256=TARGET, entries=len(old), xattrs=sum(len(x) for x in nx.values()),
                changed={n:dict(before=old[n], after=new[n]) for n in sorted(changed)},
                all_metadata_and_xattrs_preserved=True, passed=True, installed=False)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'Output already exists')
    for path, digest in ((args.baseline, BASE), (args.candidate, TARGET)):
        require(path.stat().st_size == 834666496 and sha(path) == digest, 'Raw size/hash mismatch')
    result = compare(raw_inventory(args.baseline), raw_inventory(args.candidate))
    dump(args.output, result)
    print(json.dumps(result))

if __name__ == '__main__':
    main()
