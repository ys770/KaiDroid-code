"""One-shot RAM-only executable-mode probe on the identified image06 handset."""
import json
import subprocess
import uuid
from pathlib import Path


def main():
    output = Path('artifacts/runtime/engineering-android06-mode-probe-20261023')
    output.mkdir(exist_ok=False)
    base = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED', 'exec-out']
    def run(command):
        marker = 'STATUS_' + uuid.uuid4().hex
        result = subprocess.run(base + ['( ' + command + ' ); rc=$?; printf "\\n' + marker + ':%s\\n" "$rc"'],
                                capture_output=True, timeout=20)
        with (output / 'journal.jsonl').open('a') as stream:
            stream.write(json.dumps(dict(command=command, exit=result.returncode,
                                        stdout=result.stdout.decode(errors='replace'),
                                        stderr=result.stderr.decode(errors='replace'))) + '\n')
        body, separator, status = result.stdout.rpartition(('\n' + marker + ':').encode())
        if result.returncode or not separator or status.strip() != b'0':
            raise RuntimeError('Probe stopped; inspect journal before any retry')
        return body.decode().strip()
    expected = ['KaiDroid/kaidroid_n139dl/n139dl:11/RP1A.200720.009/eng.builde.20261023.114603:eng/test-keys',
                '0', '00000000-0000-0000-0001-000000000007']
    assert run('getprop ro.build.fingerprint; id -u; cat /proc/sys/kernel/random/boot_id').splitlines() == expected
    target = '/odm/kaidroid/bin/kaidroid-memtrack-service'
    expected_hash = '908ff75c05c2af71aca29a67e7446d5efac281f482c62f19a7e5b1f04ec55d82'
    assert run('sha256sum ' + target).split()[0] == expected_hash
    scratch = '/mnt/kaidroid-memtrack-mode-probe'
    run('mkdir ' + scratch)
    run('mount -t tmpfs -o size=1m,mode=0755 tmpfs ' + scratch)
    run('cp ' + target + ' ' + scratch + '/service')
    run('chmod 0755 ' + scratch + '/service')
    run('chcon u:object_r:hal_memtrack_default_exec:s0 ' + scratch + '/service')
    assert run('sha256sum ' + scratch + '/service').split()[0] == expected_hash
    run('stop vendor.kaidroid-memtrack')
    run('mount --bind ' + scratch + '/service ' + target)
    run('ls -lZ ' + target)
    run('start vendor.kaidroid-memtrack')
    print('RAM-backed mode correction staged; inspect actual service and boot state')


if __name__ == '__main__':
    main()
