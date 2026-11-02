"""Bounded dynamic-debug trace of three display validators on the pinned boot."""
import argparse
import json
import subprocess
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--boot-id', default='00000000-0000-0000-0001-000000000005')
    parser.add_argument('--image', default='8')
    args = parser.parse_args()
    out = args.output
    out.mkdir(exist_ok=False)
    base = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']
    control = '/sys/kernel/debug/dynamic_debug/control'
    funcs = ['__layer_param_check', '__validate_single_layer', '__validate_layers']
    def run(command, name, timeout=20):
        result = subprocess.run(base + [command], capture_output=True, timeout=timeout)
        (out/(name+'.stdout')).write_bytes(result.stdout)
        (out/(name+'.stderr')).write_bytes(result.stderr)
        if result.returncode:
            raise RuntimeError('Command failed: '+name)
        return result.stdout.decode(errors='replace')
    identity = run('cat /proc/sys/kernel/random/boot_id; id -u', 'identity').splitlines()
    assert identity == [args.boot_id, '0']
    assert run('getprop ro.kaidroid.image', 'image').strip() == args.image
    before = run('cat '+control, 'before')
    for fn in funcs:
        rows = [line for line in before.splitlines() if ']'+fn+' ' in line]
        assert rows and all(' =_ ' in line for line in rows), fn
    enabled = []
    try:
        for fn in funcs:
            enabled.append(fn)
            run("echo 'func "+fn+" +p' > "+control, 'enable-'+fn)
        active = run('cat '+control, 'enabled')
        for fn in funcs:
            rows = [line for line in active.splitlines() if ']'+fn+' ' in line]
            assert rows and all(' =p ' in line for line in rows), fn
        run('cat /proc/uptime; dmesg', 'pre-wake')
        run('input keyevent 224', 'wake', timeout=30)
        time.sleep(3)
        run('cat /proc/uptime; dmesg', 'post-wake')
    finally:
        errors = []
        for fn in enabled:
            try:
                run("echo 'func "+fn+" -p' > "+control, 'restore-'+fn)
            except Exception as error:
                errors.append(str(error))
        after = run('cat '+control, 'after')
        for fn in enabled:
            rows = [line for line in after.splitlines() if ']'+fn+' ' in line]
            if not rows or not all(' =_ ' in line for line in rows):
                errors.append('Debug flags not restored: '+fn)
        (out/'restoration.json').write_text(json.dumps({'errors': errors}, indent=2))
        if errors:
            raise RuntimeError('; '.join(errors))
    print('Trace captured; all three debug selections restored')


if __name__ == '__main__':
    main()
