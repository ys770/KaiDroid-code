"""Independently inspect candidate ext4 file hashes, AVB result and labels."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--attempt', default='01')
    a = p.parse_args()
    if not a.attempt.isdigit():
        raise ValueError('Attempt must contain digits only')
    raw = a.stage / 'compact-image/system.raw.img'
    if raw.stat().st_size != 834666496:
        raise ValueError('Unexpected raw image partition size')
    staging = json.loads((a.stage / 'staging.json').read_text())
    extracted = a.stage / ('verify-packaged-' + a.attempt)
    extracted.mkdir()
    expected = {name:staging['changes'][name] for name in staging['full_tree_diff']}
    preserved = ['build.prop', 'lib/libsurfaceflinger.so', 'etc/selinux/plat_sepolicy.cil',
                 'etc/selinux/plat_file_contexts', 'etc/kaidroid-bluetooth/libbt-vendor-brt.so',
                 'etc/init/kaidroid-bluetooth.rc', 'apex/com.android.wifi/apex_manifest.pb',
                 'apex/com.android.wifi/apex_pubkey']
    for name in preserved:
        if name not in expected:
            expected[name] = staging['baseline_tree'][name]['sha256']
    labels = {}
    for name, digest in expected.items():
        dest = extracted / name.replace('/', '_')
        subprocess.run(['/usr/sbin/debugfs', '-R', f'dump /system/{name} {dest}', str(raw)], check=True, capture_output=True)
        if not dest.exists() or sha(dest) != digest:
            raise ValueError('Packaged hash mismatch: ' + name)
        outputs = []
        for img in (raw, a.baseline / 'compact-image/system.raw.img'):
            result = subprocess.run(['/usr/sbin/debugfs', '-R', f'ea_list /system/{name}', str(img)], check=True, capture_output=True, text=True)
            label = [line.strip() for line in result.stdout.splitlines() if 'security.selinux' in line]
            if len(label) != 1:
                raise ValueError('SELinux label missing: ' + name)
            outputs.append(label[0])
        if outputs[0] != outputs[1]:
            raise ValueError('SELinux label changed: ' + name)
        labels[name] = outputs[0]
    alias = subprocess.run(['/usr/sbin/debugfs', '-R', 'stat /system/framework/arm/boot-framework.vdex', str(raw)], check=True, capture_output=True, text=True).stdout
    if 'symlink' not in alias or '../boot-framework.vdex' not in alias:
        raise ValueError('VDEX alias was not preserved')
    avb = (a.stage / 'avb-verification.txt').read_text()
    if not avb.strip():
        raise ValueError('AVB verification output missing')
    report = dict(raw_sha256=sha(raw), raw_bytes=raw.stat().st_size,
                  sparse_sha256=sha(a.stage / 'compact-image/system.img'),
                  packaged_sha256=expected, selinux_labels=labels, vdex_alias_preserved=True,
                  avb_verification=avb, installed=False, physical_parity=False)
    with (a.stage / ('verification-' + a.attempt + '.json')).open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
