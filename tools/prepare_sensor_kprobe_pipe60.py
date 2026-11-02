"""Prepare the second fixed sensor capture, preserving the first trial bytes."""
import hashlib
import json
from pathlib import Path
import subprocess

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    output = Path('work/sensor-kprobe60-02')
    output.mkdir(exist_ok=False)
    source = Path('tools/trial_sensor_listener_init_flags.c')
    if sha(source) != '3491f49574f62425563c39fcbbd6326dec67709bef7628ee21036611f3f41ced':
        raise ValueError('Reviewed listener source changed')
    wrapper = output / 'trial.c'
    wrapper.write_text('#define SOURCE "/data/local/tmp/kaidroid-sensor-kprobe60-02/sensors"\n'
                       '#define KAIDROID_SENSOR_TRACE_STOP 1\n'
                       '#include "trial_sensor_listener_init_flags.c"\n', encoding='utf-8')
    original = Path('tools/trial_sensor_kprobe60.sh')
    worker = original.read_text().replace('kprobe60-01', 'kprobe60-02').replace('sensor60_01', 'sensor60_02')
    old = '"$P/trial" > "$P/trial.stdout" 2> "$P/trial.stderr" &'
    assert worker.count(old) == 1
    worker = worker.replace(old, '''# Listener writes to an anonymous pipe; shell-domain tee owns the log file.
( set +e; "$P/trial"; code=$?; echo "$code" > "$P/trial.exit"; exit 0 ) 2>&1 | tee "$P/trial.stdout" &''')
    worker = worker.replace('echo "$status" > "$P/trial.exit"',
                            '[ "$status" = 0 ]\n[ -s "$P/trial.exit" ]')
    worker = worker.replace('"$P/trial.stderr"', '"$P/trial.stdout"')
    (output / 'worker.sh').write_bytes(worker.encode('utf-8'))
    clang = '/opt/android-sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
    command = [clang, '--target=armv7a-linux-androideabi30', '-Wall', '-Wextra', '-Werror',
               '-O2', '-fPIE', '-pie', '-Wl,--export-dynamic', '-Itools', str(wrapper),
               '-ldl', '-o', str(output / 'trial')]
    subprocess.run(command, check=True)
    report = {'command': command, 'source_sha256': sha(source),
              'original_worker_sha256': sha(original),
              'files': {name: sha(output / name) for name in ('trial.c', 'worker.sh', 'trial')},
              'changes': ['New owned paths', 'Anonymous pipe log transport; shell tee writes log',
                          'Trial exit recorded separately from tee exit'],
              'sensor_started': False}
    (output / 'build.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
