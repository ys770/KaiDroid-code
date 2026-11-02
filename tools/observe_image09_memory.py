"""Low-overhead, read-only stability observation for the image09 engineering Nokia."""
import argparse
import json
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=600)
    args = parser.parse_args()
    if not 30 <= args.seconds <= 1800:
        parser.error('Use a bounded 30..1800 second observation')
    args.output.mkdir(exist_ok=False)
    base = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']
    command = ('getprop ro.build.fingerprint; cat /proc/sys/kernel/random/boot_id; '
               'cat /proc/uptime; getprop sys.boot_completed; '
               'getprop sys.system_server.start_count; getprop init.svc.lmkd; '
               'cat /sys/module/lowmemorykiller/parameters/enable_lmk; '
               'cat /proc/meminfo; cat /proc/swaps; cat /sys/block/zram0/mm_stat')
    started = time.monotonic()
    first_boot = None
    index = 0
    while time.monotonic()-started < args.seconds:
        index += 1
        record = {'index': index, 'host_elapsed': time.monotonic()-started}
        try:
            result = subprocess.run(base+[command], capture_output=True, timeout=20)
            (args.output/f'{index:03d}.stdout').write_bytes(result.stdout)
            (args.output/f'{index:03d}.stderr').write_bytes(result.stderr)
            lines = result.stdout.decode(errors='replace').splitlines()
            if result.returncode or len(lines) < 7:
                record['error'] = 'Incomplete snapshot'
            elif lines[0] != 'KaiDroid/kaidroid_n139dl/n139dl:11/RP1A.200720.009/eng.builde.20261023.123636:eng/test-keys':
                raise RuntimeError('Unexpected image; stop observation')
            else:
                first_boot = first_boot or lines[1]
                record.update(boot_unchanged=lines[1] == first_boot, uptime=lines[2],
                              boot_completed=lines[3], framework_start_count=lines[4],
                              lmkd=lines[5], kernel_lmk_enabled=lines[6])
        except subprocess.TimeoutExpired:
            record['error'] = 'Snapshot timeout; no device mutation'
        with (args.output/'events.jsonl').open('a') as stream:
            stream.write(json.dumps(record)+'\n')
        print(json.dumps(record), flush=True)
        time.sleep(min(30, max(0, args.seconds-(time.monotonic()-started))))


if __name__ == '__main__':
    main()
