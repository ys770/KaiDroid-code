"""Confirm two already-reviewed pairing dialogs using TCL right soft keys.

Operator must first verify matching passkeys and hold exclusive access to both
phones. This does not initiate pairing, change discoverability, or clear logs.
"""
import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--nokia-boot', required=True)
    parser.add_argument('--tcl-boot', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--matching-codes-reviewed', action='store_true', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    peers = [('nokia', 'DEVICE_SERIAL_REQUIRED', 'n139dl', args.nokia_boot),
             ('tcl', 'DEVICE_SERIAL_REQUIRED', 'Gflip6_USCC', args.tcl_boot)]

    def shell(peer, command):
        result = subprocess.run([args.adb, '-s', peer[1], 'shell', command],
                                capture_output=True, timeout=8)
        if result.returncode:
            raise RuntimeError(f'{peer[0]} command failed: {result.returncode}')
        return result.stdout.decode('utf-8', errors='replace')

    def guard(peer):
        if shell(peer, 'getprop ro.product.device').strip() != peer[2]:
            raise RuntimeError('device mismatch')
        if shell(peer, 'cat /proc/sys/kernel/random/boot_id').strip() != peer[3]:
            raise RuntimeError('boot changed')
        windows = shell(peer, 'dumpsys window')
        focused = [line for line in windows.splitlines() if 'mCurrentFocus=' in line]
        (args.output / f'{peer[0]}-focus.txt').write_text('\n'.join(focused), encoding='utf-8')
        if not any('com.android.settings.bluetooth.GFBluetoothPairingDialog}' in line
                   or 'com.android.settings/.bluetooth.GFBluetoothPairingDialog}' in line
                   for line in focused):
            raise RuntimeError(f'{peer[0]} pairing dialog is not focused')

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(guard, peers))
        if not args.apply:
            print('Both identity/boot/focus guards passed; no keys sent.')
            return
        def confirm(peer):
            start = time.monotonic()
            shell(peer, 'input keyevent 2')
            return {'peer': peer[0], 'elapsed_seconds': time.monotonic() - start,
                    'key_command_completed': True}
        results = list(pool.map(confirm, peers))
    (args.output / 'key-results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print('Right-soft-key commands completed. This does not prove service acceptance or bonding.')


if __name__ == '__main__':
    main()
