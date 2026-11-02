"""Identity-bound UART trace of one Bluetooth off/on cycle, restoring enabled state.

Uses the HAL's existing UART reads through strace, never opens the UART itself.
Not a cold-boot reproducer. Requires an enabled, disconnected adapter.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def run(a):
    adb = [str(a.adb), '-s', a.serial]
    def shell(command, timeout=20):
        p = subprocess.run(adb + ['shell', command], capture_output=True, timeout=timeout)
        if p.returncode:
            raise RuntimeError(f'Command failed ({p.returncode}): {command}')
        # Windows adb shell can return CRLF even though the device emits LF.
        return p.stdout.decode(errors='replace').replace('\r\n', '\n')

    def save(name, command):
        text = shell(command)
        (a.output / name).write_text(text)
        return text

    if shell('getprop ro.build.fingerprint').strip() != a.fingerprint:
        raise ValueError('Fingerprint mismatch')
    if shell('cat /proc/sys/kernel/random/boot_id').strip() != a.boot_id:
        raise ValueError('Boot mismatch')
    if shell('getprop ro.kaidroid.image').strip() != a.revision:
        raise ValueError('Revision mismatch')
    if shell('id -u').strip() != '0':
        raise ValueError('Root required')
    state = shell('timeout 8 dumpsys bluetooth_manager')
    if not re.search(r'^\s+state: ON$', state, re.M) or 'ConnectionState: STATE_DISCONNECTED' not in state:
        raise ValueError('Expected enabled, disconnected Bluetooth adapter')
    pid = shell('pidof android.hardware.bluetooth@1.0-service-qti-lazy').strip()
    if not pid.isdigit():
        raise ValueError('Expected exactly one existing Bluetooth HAL')
    if not re.search(r'^TracerPid:\s+0$', shell(f'cat /proc/{pid}/status'), re.M):
        raise ValueError('HAL already traced')
    a.output.mkdir(parents=True, exist_ok=False)
    (a.output / 'manager-before.txt').write_text(state)
    save('uart-before.txt', 'cat /proc/tty/driver/msm_serial_hs')
    save('strace-version.txt', 'strace -V')
    command = ('timeout -s INT 60 strace -f -tt -T -xx -v -y -s 64 '
               '-e trace=read,readv,write,writev,ioctl,openat,close -P /dev/ttyHS0 -p ' + pid)
    disabled = False
    enable_requested = False
    tracer = None
    with (a.output / 'uart-trace.txt').open('wb') as stream:
        try:
            tracer = subprocess.Popen(adb + ['shell', command], stdout=stream, stderr=stream)
            time.sleep(2)
            traced = shell(f'cat /proc/{pid}/status')
            if re.search(r'^TracerPid:\s+0$', traced, re.M) or tracer.poll() is not None:
                raise RuntimeError('Trace attachment failed; no radio change')
            # Mark before calling: an ADB timeout does not prove disable failed.
            disabled = True
            save('disable.txt', 'svc bluetooth disable')
            # Require actual OFF before requesting re-enable.
            for attempt in range(10):
                current = save(f'manager-off-{attempt}.txt', 'timeout 8 dumpsys bluetooth_manager')
                if re.search(r'^\s+state: OFF$', current, re.M):
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Adapter did not reach OFF within observation window')
            save('enable.txt', 'svc bluetooth enable')
            enable_requested = True
        finally:
            try:
                if disabled and not enable_requested:
                    # Idempotent request to restore the original enabled state.
                    save('restore-enable.txt', 'svc bluetooth enable')
            finally:
                # Even a failed restoration command must not skip tracer cleanup.
                if tracer:
                    try:
                        tracer.wait(timeout=70)
                    except subprocess.TimeoutExpired:
                        tracer.kill()
                        tracer.wait()
                        raise RuntimeError('Host timeout; inspect bounded phone tracer before retrying')
    # Lazy HAL can exit on OFF; enable is asynchronous and may replace its PID.
    # Observe recovery rather than treating temporary absence as terminal.
    for attempt in range(12):
        after = save(f'manager-after-{attempt}.txt', 'timeout 8 dumpsys bluetooth_manager')
        if re.search(r'^\s+state: ON$', after, re.M):
            break
        time.sleep(5)
    save('uart-after.txt', 'cat /proc/tty/driver/msm_serial_hs')
    post_pid = shell('pidof android.hardware.bluetooth@1.0-service-qti-lazy; true').strip()
    post = save('hal-status-after.txt', f'cat /proc/{post_pid}/status') if post_pid.isdigit() else ''
    report = dict(boot_unchanged=shell('cat /proc/sys/kernel/random/boot_id').strip() == a.boot_id,
                  adapter_restored_on=bool(re.search(r'^\s+state: ON$', after, re.M)),
                  original_hal_survived=post_pid == pid,
                  trace_covers_replacement_hal=False if post_pid != pid else None,
                  tracer_detached=bool(re.search(r'^TracerPid:\s+0$', post, re.M)),
                  cold_start=False, tracer_host_exit=tracer.returncode,
                  sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in a.output.iterdir() if p.is_file()})
    (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    if not all(report[k] for k in ('boot_unchanged', 'adapter_restored_on', 'tracer_detached')):
        raise RuntimeError('Postflight incomplete; inspect evidence before further radio operations')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    for field in ('serial', 'fingerprint', 'boot-id', 'revision'):
        p.add_argument('--' + field, required=True)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args())
