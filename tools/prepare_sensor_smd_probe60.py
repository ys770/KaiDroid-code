"""Prepare fixed SMD-response capture04 from the preserved GLINK capture03."""
import hashlib
import json
from pathlib import Path
import subprocess

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    previous = Path('work/sensor-kprobe60-03')
    output = Path('work/sensor-kprobe60-04')
    manifest = json.loads((previous / 'build.json').read_text())
    for name, pin in manifest['files'].items():
        assert sha(previous / name) == pin
    assert sha(Path('tools/trial_sensor_listener_init_flags.c')) == manifest['source_sha256']
    output.mkdir(exist_ok=False)
    worker = (previous / 'worker.sh').read_text().replace('kprobe60-03', 'kprobe60-04').replace('sensor60_03', 'sensor60_04')
    old = 'fastrpc_glink_notify_rx+0x84 result=%r0:s32 context=%r1:x32 owner=+28(%r1):u32'
    new = 'smd_event_handler+0xf8 result=%r1:s32 context=%r0:x32 owner=+28(%r0):u32'
    assert worker.count(old) == 1
    worker = worker.replace(old, new).replace('cat "$I/trace" > "$P/trace"',
        'cat "$T/kprobe_profile" > "$P/kprobe-profile"\ncat "$I/trace" > "$P/trace"')
    (output / 'worker.sh').write_bytes(worker.encode())
    (output / 'trial.c').write_text((previous / 'trial.c').read_text().replace('kprobe60-03', 'kprobe60-04'))
    command = [arg.replace('sensor-kprobe60-03', 'sensor-kprobe60-04') for arg in manifest['command']]
    subprocess.run(command, check=True)
    manifest.update(command=command, files={n: sha(output / n) for n in ('worker.sh', 'trial.c', 'trial')},
                    response_site='smd_event_handler+0xf8',
                    response_function_sha256='268b3fd0b2503bbd105c00289f3dfe07504067837cf79271169fc971d257792d')
    (output / 'build.json').write_text(json.dumps(manifest, indent=2))
    (output / 'run.py').write_text((previous / 'run.py').read_text().replace('sensor-kprobe03', 'sensor-kprobe04').replace('sensor-kprobe60-03', 'sensor-kprobe60-04'))

if __name__ == '__main__':
    main()
