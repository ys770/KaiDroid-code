"""Clear only a reviewed engineering-trial boot message after system restoration.

Preserves full misc before/after and verifies all bytes beyond the known 1088-byte
message unchanged. Default is read-only. Never reboots or formats data.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from write_engineering_system import FINGERPRINT, ORIGINAL, SERIAL, SYSTEM


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--clear', action='store_true')
    parser.add_argument('--reason', choices=('set_policy_failed:/data/fota',
                                            'set_policy_failed:/data/hostapd', 'init_user0_failed'),
                        default='set_policy_failed:/data/fota')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    base = [args.adb, '-s', SERIAL]
    def run(*argv):
        result = subprocess.run(base+list(argv), capture_output=True, check=True, timeout=120)
        return result.stdout
    def read(command):
        return run('exec-out', command)
    if run('get-state').strip() != b'recovery':
        raise ValueError('Recovery required')
    if read('getprop ro.build.fingerprint').strip().decode() != FINGERPRINT:
        raise ValueError('Wrong firmware')
    if read('id -u').strip() != b'0':
        raise ValueError('Root required')
    if read('sha256sum '+SYSTEM).split()[0].decode() != ORIGINAL:
        raise ValueError('Original system must already be restored')
    misc = '/dev/block/bootdevice/by-name/misc'
    if read('readlink -f '+misc).strip() != b'/dev/block/mmcblk0p45':
        raise ValueError('Wrong misc path')
    if read('blockdev --getsize64 '+misc).strip() != b'1048576':
        raise ValueError('Wrong misc size')
    before = read('dd if='+misc+' bs=4096 count=256 2>/dev/null')
    if len(before) != 1048576 or hashlib.sha256(before).hexdigest() != read('sha256sum '+misc).split()[0].decode():
        raise ValueError('Capture mismatch')
    (args.output/'misc-before.bin').write_bytes(before)
    expected = bytearray(1088)
    expected[:13] = b'boot-recovery'
    reason = ('recovery\n--prompt_and_wipe_data\n--reason='+args.reason+'\n').encode()
    expected[64:64+len(reason)] = reason
    if before[:1088] != expected:
        raise ValueError('Unexpected BCB; no clearing permitted')
    result = {'exact_failed_policy_message': True, 'reason': args.reason, 'clear_requested': args.clear,
              'before_sha256': hashlib.sha256(before).hexdigest()}
    if args.clear:
        zero = args.output/'zero-message.bin'
        zero.write_bytes(bytes(1088))
        remote = '/tmp/kaidroid-clear-image02-bcb.bin'
        run('push', str(zero), remote)
        if read('sha256sum '+remote).split()[0].decode() != hashlib.sha256(bytes(1088)).hexdigest():
            raise ValueError('Staged bytes mismatch')
        read('dd if='+remote+' of='+misc+' bs=1088 count=1 conv=notrunc && sync')
        after = read('dd if='+misc+' bs=4096 count=256 2>/dev/null')
        (args.output/'misc-after.bin').write_bytes(after)
        if after != bytes(1088)+before[1088:]:
            raise ValueError('Full misc readback mismatch; do not reboot')
        result['after_sha256'] = hashlib.sha256(after).hexdigest()
        if result['after_sha256'] != read('sha256sum '+misc).split()[0].decode():
            raise ValueError('Remote hash mismatch; do not reboot')
        result['full_readback_verified'] = True
    (args.output/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
