"""Bounded read-only boot observation for the engineering Nokia; never reboots."""
import argparse
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=300)
    parser.add_argument('--location', action='store_true',
                        help='Capture location socket labels and service state without changing them')
    parser.add_argument('--interval', type=float, default=2,
                        help='Polling interval in seconds (0.5..30)')
    args = parser.parse_args()
    if not 1 <= args.seconds <= 900:
        parser.error('Observation must be bounded to 1..900 seconds')
    if not 0.5 <= args.interval <= 30:
        parser.error('Polling interval must be 0.5..30 seconds')
    args.output.mkdir(parents=True, exist_ok=False)
    base = [args.adb, '-s', 'DEVICE_SERIAL_REQUIRED']
    started = time.monotonic()
    index = 0
    while time.monotonic() - started < args.seconds:
        index += 1
        event = {'utc': datetime.now(timezone.utc).isoformat(), 'index': index}
        try:
            state = subprocess.run(base+['get-state'], capture_output=True, timeout=5)
            event.update(state=state.stdout.decode(errors='replace').strip(),
                         exit=state.returncode, stderr=state.stderr.decode(errors='replace'))
            if state.returncode == 0 and event['state'] in ('device', 'recovery'):
                for name, command in {
                    'identity': 'getprop ro.build.fingerprint; getprop ro.product.model; id; getprop sys.boot_completed; cat /proc/sys/kernel/random/boot_id; cat /proc/uptime',
                    'logcat': 'logcat -b all -d -t 1500',
                    'dmesg': 'dmesg',
                    'runtime': 'getprop; cat /proc/mounts; ps -A',
                    'last-kernel': 'cat /proc/last_kmsg; ls -l /sys/fs/pstore; cat /sys/fs/pstore/console-ramoops*',
                    **({'location': 'getprop ro.kaidroid.image; getenforce; '
                        'getprop init.svc.blpsvc; pidof blpsvc; '
                        'ls -lZ /data/vendor/location/blp/sock-server; '
                        'grep sock-server /proc/net/unix'} if args.location else {}),
                    **({'recovery-log': 'cat /tmp/recovery.log'} if event['state'] == 'recovery' else {}),
                }.items():
                    try:
                        result = subprocess.run(base+['exec-out', command], capture_output=True, timeout=10)
                        (args.output/f'{index:03d}-{name}.stdout').write_bytes(result.stdout)
                        (args.output/f'{index:03d}-{name}.stderr').write_bytes(result.stderr)
                        event[name] = result.returncode
                    except subprocess.TimeoutExpired:
                        event[name] = 'timeout'
        except subprocess.TimeoutExpired:
            event['state'] = 'transport timeout'
        with (args.output/'events.jsonl').open('a') as stream:
            stream.write(json.dumps(event)+'\n')
        print(json.dumps(event), flush=True)
        time.sleep(min(args.interval, max(0, args.seconds-(time.monotonic()-started))))


if __name__ == '__main__':
    main()
