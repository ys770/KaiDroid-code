"""Try the existing bounded HCI startup-timeout override on the pinned image09 boot."""
import json
import subprocess
import time
from pathlib import Path


def main():
    output = Path('artifacts/runtime/engineering-android09-bluetooth-timeout-20261023')
    output.mkdir(exist_ok=False)
    base = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']
    def run(command, name):
        started = time.monotonic()
        result = subprocess.run(base+[command], capture_output=True, timeout=30)
        (output/(name+'.stdout')).write_bytes(result.stdout)
        (output/(name+'.stderr')).write_bytes(result.stderr)
        with (output/'commands.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(name=name, command=command, exit=result.returncode,
                                         seconds=time.monotonic()-started))+'\n')
        if result.returncode:
            raise RuntimeError('Command failed: '+name)
        return result.stdout.decode(errors='replace').strip()
    assert run('cat /proc/sys/kernel/random/boot_id; id -u', 'identity').splitlines() == [
        '00000000-0000-0000-0001-000000000002', '0']
    assert run('getprop bluetooth.enable_timeout_ms', 'prior-timeout') == ''
    run('dumpsys bluetooth_manager', 'before-state')
    run('setprop bluetooth.enable_timeout_ms 10000', 'set-timeout')
    assert run('getprop bluetooth.enable_timeout_ms', 'verify-timeout') == '10000'
    run('svc bluetooth enable', 'enable')
    for index in range(3):
        time.sleep(10)
        run('dumpsys bluetooth_manager', f'state-{index}')
        print('Captured Bluetooth state', index, flush=True)
    run('logcat -b all -d', 'logcat')
    run('logcat -b crash -d', 'crash')
    run('getprop sys.boot_completed; getprop sys.system_server.start_count; cat /proc/uptime', 'framework')
    print('Probe complete; inspect adapter state, not merely command exit')


if __name__ == '__main__':
    main()
