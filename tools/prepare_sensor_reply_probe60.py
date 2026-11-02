"""Prepare a PID-filtered response/result correlation capture from retained trial02."""
import hashlib
import json
from pathlib import Path
import subprocess

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    previous = Path('work/sensor-kprobe60-02')
    manifest = json.loads((previous / 'build.json').read_text())
    for name, pin in manifest['files'].items():
        assert digest(previous / name) == pin
    assert digest(Path('tools/trial_sensor_listener_init_flags.c')) == manifest['source_sha256']
    output = Path('work/sensor-kprobe60-03')
    output.mkdir(exist_ok=False)
    worker = (previous / 'worker.sh').read_text().replace('kprobe60-02', 'kprobe60-03').replace('sensor60_02', 'sensor60_03')
    worker = worker.replace('E=kaidroid_sensor60_03/result', 'E=kaidroid_sensor60_03/result\nR=kaidroid_sensor60_03/reply')
    worker = worker.replace('if [ -d "$I" ]; then', 'if [ -d "$I" ]; then\n  if [ -e "$I/events/$R/enable" ]; then echo 0 > "$I/events/$R/enable"; fi', 1)
    worker = worker.replace('cleanup() {', '''cleanup() {
 if [ -e "$T/events/$R/enable" ]; then
  if [ -e "$I/events/$R/enable" ]; then echo 0 > "$I/events/$R/enable"; fi
  echo 0 > "$T/events/$R/enable"
  echo '-:kaidroid_sensor60_03/reply' >> "$T/kprobe_events"
 fi''', 1)
    worker = worker.replace('result=%r7:s32', 'result=%r7:s32 context=%r4:x32 owner=+28(%r4):u32')
    needle='cat "$I/events/$E/format" > "$P/format"'
    assert worker.count(needle) == 1
    worker = worker.replace(needle, '''echo 'p:kaidroid_sensor60_03/reply fastrpc_glink_notify_rx+0x84 result=%r0:s32 context=%r1:x32 owner=+28(%r1):u32' >> "$T/kprobe_events"
cat "$I/events/$R/format" > "$P/reply-format"
''' + needle)
    worker = worker.replace('echo 1 > "$I/events/$E/enable"', '''echo "owner == $child" > "$I/events/$R/filter"
cat "$I/events/$R/filter" > "$P/reply-filter"
echo 1 > "$I/events/$R/enable"
echo 1 > "$I/events/$E/enable"''')
    worker = worker.replace('echo 0 > "$I/events/$E/enable"\ncat "$I/trace"', 'echo 0 > "$I/events/$E/enable"\necho 0 > "$I/events/$R/enable"\ncat "$I/trace"')
    (output / 'worker.sh').write_bytes(worker.encode())
    wrapper = output / 'trial.c'
    wrapper.write_text((previous / 'trial.c').read_text().replace('kprobe60-02', 'kprobe60-03'))
    command = [arg.replace('sensor-kprobe60-02', 'sensor-kprobe60-03') for arg in manifest['command']]
    subprocess.run(command, check=True)
    report = {'command': command, 'source_sha256': manifest['source_sha256'],
              'files': {n: digest(output / n) for n in ('worker.sh', 'trial.c', 'trial')},
              'response_site': 'fastrpc_glink_notify_rx+0x84',
              'owner_offset': 28, 'owner_provenance': 'invoke c0697280 loads current task+0x360; c0697284 stores context+0x1c',
              'filter': 'result common_pid and reply context owner equal stopped test main PID',
              'sensor_started': False}
    (output / 'build.json').write_text(json.dumps(report, indent=2) + '\n')
    runner = Path('tools/run_sensor_kprobe_pipe60.py').read_text().replace('sensor-kprobe02', 'sensor-kprobe03').replace('sensor-kprobe60-02', 'sensor-kprobe60-03')
    (output / 'run.py').write_text(runner)

if __name__ == '__main__':
    main()
