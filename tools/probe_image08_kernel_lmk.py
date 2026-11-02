"""Restore the selected kernel LMK on the pinned engineering image08 boot."""
import json
import subprocess
from pathlib import Path


def main():
    output = Path('artifacts/runtime/engineering-android08-kernel-lmk-probe-20261023')
    output.mkdir(exist_ok=False)
    command = '''test "$(cat /proc/sys/kernel/random/boot_id)" = 00000000-0000-0000-0001-000000000005 &&
test "$(id -u)" = 0 &&
test "$(cat /sys/module/lowmemorykiller/parameters/enable_lmk)" = 0 &&
echo 1 > /sys/module/lowmemorykiller/parameters/enable_lmk
rc=$?; echo LMK_STATUS:$rc
cat /sys/module/lowmemorykiller/parameters/enable_lmk
cat /sys/module/lowmemorykiller/parameters/minfree
cat /sys/module/lowmemorykiller/parameters/adj
getprop sys.system_server.start_count
cat /proc/uptime'''
    result = subprocess.run(['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED',
                             'exec-out', command], capture_output=True, timeout=30)
    data = dict(command=command, exit=result.returncode,
                stdout=result.stdout.decode(errors='replace'), stderr=result.stderr.decode(errors='replace'))
    (output/'result.json').write_text(json.dumps(data, indent=2))
    print(json.dumps(data))
    if result.returncode or b'LMK_STATUS:0' not in result.stdout:
        raise RuntimeError('Stop and inspect probe result before further actions')


if __name__ == '__main__':
    main()
