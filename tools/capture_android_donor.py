"""Read-only, serial-bound Android donor capture. Never flashes or reboots.

Streams system/product/vendor via root tar directly to host, with identity
checks before/after. Captures the mounted view, which may include modifications;
this is not a pristine partition backup or a complete handset recovery image.
"""
import argparse
import hashlib
import json
import subprocess
import tarfile
from datetime import datetime, timezone
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
                              text=True, timeout=30).stdout.strip()

    def identity():
        return {'fingerprint': shell('getprop ro.build.fingerprint'),
                'boot_id': shell('cat /proc/sys/kernel/random/boot_id'),
                'model': shell('getprop ro.product.model'),
                'root_id': shell("su -c 'id'")}

    before = identity()
    if before['fingerprint'] != args.fingerprint or 'uid=0(root)' not in before['root_id']:
        raise ValueError('Donor identity/root check failed')
    expected = b'A\nB\r\nC\0D'
    prefix = None
    for candidate in ('', 'stty -onlcr && '):
        probe = "su -c '" + candidate + r'printf "A\nB\r\nC\000D"' + "'"
        result = subprocess.run(base + ['exec-out', probe], capture_output=True, timeout=30)
        if result.returncode == 0 and result.stdout == expected:
            prefix = candidate
            break
    if prefix is None:
        raise RuntimeError('Root transport failed binary preflight; no capture started')
    args.output.mkdir(parents=True, exist_ok=False)
    for name, command in {
        'properties.txt': 'getprop', 'mounts.txt': 'cat /proc/mounts',
        'memory.txt': 'cat /proc/meminfo', 'packages.txt': 'pm list packages -f',
        'input-devices.txt': "su -c 'cat /proc/bus/input/devices'",
    }.items():
        (args.output / name).write_text(shell(command) + '\n', encoding='utf-8')
    started = datetime.now(timezone.utc).isoformat()
    (args.output / 'capture-start.json').write_text(json.dumps(
        {'serial': args.serial, 'before': before, 'started_utc': started}, indent=2), encoding='utf-8')
    partial = args.output / 'mounted-firmware.tar.partial'
    command = "su -c '" + prefix + "tar -C / -cf - system product vendor'"
    with partial.open('xb') as output, (args.output / 'tar-stderr.txt').open('wb') as errors:
        process = subprocess.run(base + ['exec-out', command], stdout=output, stderr=errors)
    if process.returncode:
        raise RuntimeError(f'Donor tar failed with exit {process.returncode}; retain partial and stderr')
    after = identity()
    if before != after:
        raise RuntimeError('Identity/boot/root changed during capture; retain partial for review')
    count, logical_bytes, regular_roots, archive_end = 0, 0, set(), 0
    with tarfile.open(partial, 'r:') as archive:
        for entry in archive:
            count += 1
            archive_end = entry.offset_data + ((entry.size + 511) // 512) * 512
            if entry.isfile():
                logical_bytes += entry.size
                regular_roots.add(entry.name.split('/')[0])
    if regular_roots != {'system', 'product', 'vendor'}:
        raise RuntimeError('Archive does not contain files from all expected roots')
    if partial.stat().st_size % 512:
        raise RuntimeError('Archive is not tar-block aligned')
    with partial.open('rb') as stream:
        stream.seek(archive_end)
        trailing = stream.read()
        if len(trailing) < 1024 or any(trailing):
            raise RuntimeError('Archive trailing data is not a complete zero-block terminator')
    digest = hashlib.sha256()
    with partial.open('rb') as stream:
        for block in iter(lambda: stream.read(8*1024*1024), b''):
            digest.update(block)
    archive_path = args.output / 'mounted-firmware.tar'
    partial.rename(archive_path)
    report = {'serial': args.serial, 'before': before, 'after': after,
              'started_utc': started, 'completed_utc': datetime.now(timezone.utc).isoformat(),
              'archive': archive_path.name, 'archive_bytes': archive_path.stat().st_size,
              'archive_sha256': digest.hexdigest(), 'tar_entries': count,
              'binary_transport_prefix': prefix,
              'regular_file_bytes': logical_bytes,
              'scope': 'Mounted system/product/vendor; no userdata or raw recovery backup. Source may be modified.'}
    (args.output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('archive_bytes', 'archive_sha256', 'tar_entries')}, indent=2))


if __name__ == '__main__':
    main()
