"""Prepare a bounded post-attach driver-state capture from retained SMD trial04."""
import hashlib
import json
from pathlib import Path
import subprocess


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    previous = Path('work/sensor-kprobe60-04')
    output = Path('work/sensor-kprobe60-05')
    manifest = json.loads((previous / 'build.json').read_text())
    for name, pin in manifest['files'].items():
        assert sha(previous / name) == pin
    output.mkdir(exist_ok=False)
    worker = (previous / 'worker.sh').read_text().replace('kprobe60-04', 'kprobe60-05').replace('sensor60_04', 'sensor60_05')
    needle = 'kill -CONT "$child"\nset +e'
    assert worker.count(needle) == 1
    capture = '''kill -CONT "$child"
n=0
while [ "$n" -lt 50 ]; do
 if grep -q "ATTACH_READY tid=$child" "$P/trial.stdout" && grep -q '^State:.*T' "/proc/$child/status"; then break; fi
 n=$((n+1)); sleep 0.1
done
grep -q "ATTACH_READY tid=$child" "$P/trial.stdout"
grep -q '^State:.*T' "/proc/$child/status"
cat "/proc/$child/stat" > "$P/attached.stat"
ls -l /sys/kernel/debug/adsprpc > "$P/attached-list"
set -- /sys/kernel/debug/adsprpc/*_"$child"
[ "$#" = 1 ] && [ -f "$1" ]
cat "$1" > "$P/attached-driver"
cat /sys/kernel/debug/adsprpc/adsprpcd_628 > "$P/audio-driver"
kill -CONT "$child"
set +e'''
    worker = worker.replace(needle, capture)
    (output / 'worker.sh').write_bytes(worker.encode())
    source = (previous / 'trial.c').read_text().replace('kprobe60-04', 'kprobe60-05')
    source = '#define KAIDROID_SENSOR_ATTACH_STOP 1\n' + source
    (output / 'trial.c').write_text(source)
    command = [x.replace('sensor-kprobe60-04', 'sensor-kprobe60-05') for x in manifest['command']]
    subprocess.run(command, check=True)
    manifest.update(command=command, source_sha256=sha(Path('tools/trial_sensor_listener_init_flags.c')),
                    files={n: sha(output/n) for n in ('worker.sh', 'trial.c', 'trial')})
    (output / 'build.json').write_text(json.dumps(manifest, indent=2))
    (output / 'run.py').write_text((previous/'run.py').read_text().replace('sensor-kprobe04', 'sensor-kprobe05').replace('sensor-kprobe60-04', 'sensor-kprobe60-05'))


if __name__ == '__main__':
    main()
