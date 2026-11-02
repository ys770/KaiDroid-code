"""Single-use image60 sensor result capture with pipe logging and retained receipts."""
import hashlib
import json
from pathlib import Path
import subprocess

OUT = Path('artifacts/runtime/image60-sensor-kprobe02')
LOCAL = Path('work/sensor-kprobe60-02')
REMOTE = '/data/local/tmp/kaidroid-sensor-kprobe60-02'
ADB = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
IDENTITY = 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof surfaceflinger system_server com.android.systemui'
EXPECTED = ['DEVICE_SERIAL_REQUIRED', '60', '00000000-0000-0000-0000-000000000007', '0', 'Enforcing', '538 1166 1339']
REGISTRY = 'ls -laZ /mnt/vendor/persist/sensors; sha256sum /mnt/vendor/persist/sensors/sensors_settings'

def run(name, args, timeout=20):
    result = subprocess.run(ADB + args, capture_output=True, timeout=timeout)
    (OUT / (name + '.stdout')).write_bytes(result.stdout)
    (OUT / (name + '.stderr')).write_bytes(result.stderr)
    result.check_returncode()
    return result.stdout.decode().replace('\r', '').strip()

def main():
    OUT.mkdir(exist_ok=False)
    assert run('before', ['shell', IDENTITY]).splitlines() == EXPECTED
    run('registry-before', ['shell', REGISTRY])
    run('mounts-before', ['shell', 'cat /proc/self/mountinfo'])
    hashes = run('libraries', ['shell', 'sha256sum /vendor/lib/libadsp_default_listener.so /vendor/lib/libadsprpc.so']).splitlines()
    assert [line.split()[0] for line in hashes] == ['1497c80bcf6c610c77c5a6f0c73d76c4dac126f5d9233e90ae4845af1ffab03a', '76ff49ede4fe564d96cf17255f7b0baec2e3ce33a240ac004fcb658601fd87b5']
    run('idle', ['shell', 'test -z "$(pidof sensors.qti)" && test -z "$(pidof trial)"'])
    run('mkdir', ['shell', 'mkdir ' + REMOTE])
    run('registry-copy', ['shell', 'cp -a /mnt/vendor/persist/sensors ' + REMOTE + '/sensors && chcon u:object_r:sensors_persist_file:s0 ' + REMOTE + '/sensors ' + REMOTE + '/sensors/sensors_settings'])
    build = json.loads((LOCAL / 'build.json').read_text())
    for name in ('trial', 'worker.sh'):
        digest = hashlib.sha256((LOCAL / name).read_bytes()).hexdigest()
        assert digest == build['files'][name]
        run('push-' + name, ['push', str(LOCAL / name), REMOTE + '/' + name])
        assert run('hash-' + name, ['shell', 'sha256sum ' + REMOTE + '/' + name]).split()[0] == digest
    run('syntax', ['shell', 'chmod 700 ' + REMOTE + '/trial && sh -n ' + REMOTE + '/worker.sh'])
    # The worker and supervised listener have independent device-side deadlines.
    run('execution', ['shell', 'sh ' + REMOTE + '/worker.sh'], timeout=50)
    assert run('after', ['shell', IDENTITY]).splitlines() == EXPECTED
    run('registry-after', ['shell', REGISTRY])
    run('mounts-after', ['shell', 'cat /proc/self/mountinfo'])
    for name in ('registry', 'mounts'):
        assert (OUT / (name + '-before.stdout')).read_bytes() == (OUT / (name + '-after.stdout')).read_bytes()
    run('pull', ['pull', REMOTE, str(OUT / 'device')])
    run('sensors', ['shell', 'dumpsys sensorservice'])
    print((OUT / 'device/trial.stdout').read_text())
    print((OUT / 'device/trace').read_text())
    print('Worker completed; verify independent deadline separately before acceptance.')

if __name__ == '__main__':
    main()
