"""One boot-pinned RAM-only swap experiment; keep existing swap active."""
import json
import argparse
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume-allocated', action='store_true')
    args = parser.parse_args()
    suffix = '-resume' if args.resume_allocated else ''
    output = Path('artifacts/runtime/engineering-android11-extra-zram-20261023' + suffix)
    output.mkdir(exist_ok=False)
    base = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']

    def run(name, command):
        started = time.monotonic()
        result = subprocess.run(base + [command], capture_output=True, timeout=30)
        (output / (name + '.stdout')).write_bytes(result.stdout)
        (output / (name + '.stderr')).write_bytes(result.stderr)
        with (output / 'events.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(name=name, command=command, exit=result.returncode,
                                         seconds=time.monotonic()-started)) + '\n')
        result.check_returncode()
        return result.stdout.decode().strip()

    assert run('identity', 'cat /proc/sys/kernel/random/boot_id; id -u').splitlines() == [
        '00000000-0000-0000-0001-000000000004', '0']
    expected = ['zram0', 'zram1'] if args.resume_allocated else ['zram0']
    assert run('devices', 'ls /sys/block | grep zram').splitlines() == expected
    run('before', 'cat /proc/meminfo; cat /proc/swaps; cat /sys/block/zram0/mm_stat')
    # Reading hot_add allocates one virtual RAM device. Never repeat on uncertain outcome.
    if not args.resume_allocated:
        assert run('allocate', 'cat /sys/class/zram-control/hot_add') == '1'
    assert run('path', 'readlink -f /sys/block/zram1') == '/sys/devices/virtual/block/zram1'
    assert run('size-before', 'cat /sys/block/zram1/disksize') == '0'
    # This kernel lacks the writeback attribute; never create/configure backing storage.
    assert run('backing', 'if [ -e /sys/block/zram1/backing_dev ]; then cat /sys/block/zram1/backing_dev; else echo unsupported; fi') in ('none', 'unsupported')
    assert '/dev/block/zram1' not in run('inactive', 'cat /proc/swaps')
    run('algorithm', 'echo lzo > /sys/block/zram1/comp_algorithm')
    run('size', 'echo 268435456 > /sys/block/zram1/disksize')
    assert run('size-after', 'cat /sys/block/zram1/disksize') == '268435456'
    run('mkswap', 'mkswap /dev/block/zram1')
    run('swapon', 'swapon /dev/block/zram1')
    swaps = run('after', 'cat /proc/swaps')
    assert '/dev/block/zram0' in swaps and '/dev/block/zram1' in swaps
    print('Additional RAM-only swap active; no existing swap reset or disk backing')


if __name__ == '__main__':
    main()
