"""Bounded read-only memory sampling on the identified image14 engineering phone."""
import argparse
import json
from pathlib import Path
import subprocess
import time

ADB = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']
FINGERPRINT = 'KaiDroid/kaidroid_n139dl/n139dl:11/RP1A.200720.009/eng.builde.20261023.145618:eng/test-keys'
COMMAND = '''cat /proc/sys/kernel/random/boot_id; cat /proc/uptime
cat /proc/meminfo
cat /sys/block/zram0/mm_stat
grep -E '^(pswpin|pswpout|pgmajfault|allocstall|oom_kill) ' /proc/vmstat
for n in com.android.camera2 android.hardware.camera.provider@2.4-service cameraserver system_server com.android.systemui surfaceflinger; do
 for p in $(pidof "$n"); do
  echo "PROCESS $n $p"
  grep -E '^(VmRSS|VmSwap|VmPeak|VmSize|Threads):' /proc/$p/status
  cat /proc/$p/oom_score_adj
 done
done'''
STORAGE_COMMAND = '''
for f in /sys/fs/fuse/connections/*/waiting; do echo "FUSE_WAITING $f"; cat "$f"; done
for p in $(pidof com.android.providers.media.module); do
 echo "MEDIA_PROVIDER $p"
 ps -T -p "$p" -o TID,STAT,WCHAN,NAME
done
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=120)
    parser.add_argument('--storage', action='store_true',
                        help='Also sample FUSE queue depth and MediaProvider thread waits')
    args = parser.parse_args()
    if not 10 <= args.seconds <= 300:
        parser.error('Observation must be bounded to 10..300 seconds')
    guard = subprocess.run(ADB + ['getprop ro.build.fingerprint; cat /proc/sys/kernel/random/boot_id; id -u'],
                           capture_output=True, timeout=15, check=True).stdout.decode().splitlines()
    if len(guard) != 3 or guard[0] != FINGERPRINT or guard[2] != '0':
        raise RuntimeError('Unexpected handset build/access')
    args.output.mkdir(exist_ok=False)
    (args.output / 'guard.json').write_text(json.dumps(guard))
    started = time.monotonic()
    index = 0
    while time.monotonic() - started < args.seconds:
        index += 1
        event = {'index': index, 'elapsed': round(time.monotonic() - started, 3)}
        try:
            command = COMMAND + (STORAGE_COMMAND if args.storage else '')
            result = subprocess.run(ADB + [command], capture_output=True, timeout=12)
            (args.output / f'{index:03d}.txt').write_bytes(result.stdout)
            (args.output / f'{index:03d}.stderr').write_bytes(result.stderr)
            lines = result.stdout.decode(errors='replace').splitlines()
            if lines and lines[0] != guard[1]:
                raise RuntimeError('Boot changed during observation')
            event['returncode'] = result.returncode
            event['processes'] = [line for line in lines if line.startswith('PROCESS ')]
        except subprocess.TimeoutExpired as error:
            (args.output / f'{index:03d}.partial').write_bytes(error.stdout or b'')
            event['timeout'] = True
        with (args.output / 'events.jsonl').open('a') as stream:
            stream.write(json.dumps(event) + '\n')
        print(json.dumps(event), flush=True)
        time.sleep(min(3, max(0, args.seconds - (time.monotonic() - started))))


if __name__ == '__main__':
    main()
