"""Enable only unused RAM zram on the pinned image06 boot; never touches disk swap."""
import json
import subprocess
from pathlib import Path


def main():
    output = Path('artifacts/runtime/engineering-android06-zram-probe-20261023')
    output.mkdir(exist_ok=False)
    command = '''test "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0001-000000000007 &&
test "$(id -u)" = 0 &&
test "$(cat /sys/block/zram0/disksize)" = 0 &&
test "$(wc -l < /proc/swaps)" = 1 &&
echo lzo > /sys/block/zram0/comp_algorithm &&
echo 268435456 > /sys/block/zram0/disksize &&
mkswap /dev/block/zram0 && swapon /dev/block/zram0
rc=$?; echo ZRAM_STATUS:$rc
cat /proc/swaps; cat /sys/block/zram0/mm_stat'''
    result = subprocess.run(['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED',
                             'exec-out', command], capture_output=True, timeout=90)
    data = dict(command=command, exit=result.returncode,
                stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
    (output/'result.json').write_text(json.dumps(data, indent=2))
    print(json.dumps(data))
    if result.returncode or b'ZRAM_STATUS:0' not in result.stdout:
        raise RuntimeError('Stop: inspect exact probe result before further actions')


if __name__ == '__main__':
    main()
