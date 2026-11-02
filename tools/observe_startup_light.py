"""Observe a pinned image startup without repeated full dumps; never reboot or mutate."""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from startup_observation_result import summarize

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--adb', required=True)
p.add_argument('--output', required=True, type=Path)
p.add_argument('--seconds', default=240, type=int)
p.add_argument('--image', choices=('27', '28', '29', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60'), default='27')
p.add_argument('--pressure', action='store_true',
               help='Include bounded proc memory/swap/fault/CPU counters in each sample')
p.add_argument('--process-io', action='store_true',
               help='Capture stat/io/RSS/swap for SystemUI, system_server and Bluetooth')
a = p.parse_args()
if not 10 <= a.seconds <= 600:
    p.error('seconds must be 10..600')
a.output.mkdir(parents=True, exist_ok=False)
base = [a.adb, '-s', 'DEVICE_SERIAL_REQUIRED']
stream = None
stream_file = None
segments = 0
boot = None
start = time.monotonic()
try:
    while time.monotonic() - start < a.seconds:
        record = dict(elapsed=round(time.monotonic() - start, 3))
        try:
            command = (
                'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; '
                'getprop sys.boot_completed; cat /proc/uptime; '
                'pidof com.android.systemui; pidof com.android.bluetooth')
            if a.pressure:
                command += (
                    '; echo KAIDROID_PRESSURE; '
                    'grep -E "^(MemFree|MemAvailable|SwapTotal|SwapFree):" /proc/meminfo; '
                    'grep -E "^(pgmajfault|pswpin|pswpout|pgscan_direct|pgsteal_direct) " /proc/vmstat; '
                    'head -1 /proc/stat; cat /proc/loadavg')
            if a.process_io:
                command += (
                    '; echo KAIDROID_PROCESS_IO; '
                    'for name in system_server com.android.systemui com.android.bluetooth; do '
                    'for process in $(pidof "$name"); do '
                    'echo PROCESS "$name" "$process"; '
                    'cat /proc/$process/stat /proc/$process/io; '
                    'grep -E "^(VmRSS|VmSwap):" /proc/$process/status; '
                    'done; done')
            r = subprocess.run(base + ['shell', command],
                capture_output=True, text=True, timeout=5)
            lines = r.stdout.splitlines()
            if 'KAIDROID_PROCESS_IO' in lines:
                split = lines.index('KAIDROID_PROCESS_IO')
                record['process_io'] = lines[split+1:]
                lines = lines[:split]
            if 'KAIDROID_PRESSURE' in lines:
                split = lines.index('KAIDROID_PRESSURE')
                record['pressure'] = lines[split+1:]
                lines = lines[:split]
            record.update(returncode=r.returncode, output=lines)
            if len(lines) >= 2:
                if lines[0].strip() != a.image:
                    raise RuntimeError('Unexpected image: stop observation')
                if boot is not None and boot != lines[1].strip():
                    raise RuntimeError('Boot changed during observation')
                boot = lines[1].strip()
                if stream is not None and stream.poll() is not None:
                    record['previous_logcat_exit'] = stream.returncode
                    stream_file.close()
                    stream = None
                if stream is None:
                    segments += 1
                    filename = 'logcat.txt' if segments == 1 else f'logcat-{segments:03d}.txt'
                    stream_file = (a.output / filename).open('xb')
                    stream = subprocess.Popen(base + ['logcat', '-b', 'all', '-v', 'threadtime'],
                                              stdout=stream_file, stderr=subprocess.DEVNULL)
                record['logcat_exit'] = stream.poll()
                record['logcat_segment'] = segments
        except subprocess.TimeoutExpired:
            record['transport_timeout'] = True
        with (a.output / 'samples.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(record) + '\n')
        print(json.dumps(record), flush=True)
        time.sleep(min(10, max(0, a.seconds - (time.monotonic() - start))))
finally:
    observer_error = sys.exc_info()[0]
    final_logcat_exit = stream.poll() if stream is not None else None
    if stream is not None and stream.poll() is None:
        stream.terminate()
        try:
            stream.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stream.kill()
            stream.wait()
    if stream_file:
        stream_file.close()
    sample_path = a.output / 'samples.jsonl'
    samples = [json.loads(line) for line in sample_path.read_text().splitlines()] if sample_path.exists() else []
    result = summarize(samples, a.image, observer_error, final_logcat_exit)
    (a.output / 'observation-result.json').write_text(json.dumps(result, indent=2) + '\n')

if result['classification'] == 'incomplete':
    raise SystemExit(2)
