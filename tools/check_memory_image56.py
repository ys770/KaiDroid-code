"""Read-only acceptance capture for the exact image55-to-56 ART experiment.

Requires the actual new boot ID. Does not install, reboot, force GC or mutate apps.
Mapping checks establish image bypass/OAT retention, not memory savings.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import uuid

SERIAL = 'DEVICE_SERIAL_REQUIRED'
FILES = {
    '/apex/com.android.art/lib/libart.so': '5a8bb496549fefb2651e5783979e10a08887dba8de34a7ad59b3b62a5c584258',
    '/system/framework/framework.jar': '429890cdf42f5237b352f16084bf0851ea100a648407d77ea0dbd04f9a285f53',
    '/system/framework/oat/arm/services.art': '06367ceca49dfd29ee2732a62b217f42399c04a631c07cb2a63226f822f17ff4',
    '/system/framework/oat/arm/services.odex': '7ccc2039785860155f161ba8a8583adf50ee64c8364553f3718c8d3774b1b608',
    '/system/framework/oat/arm/services.vdex': '55d079cc405a9eff0a8ec066af3f740dc4e3277ecaeebfde627a4c4eefd27035',
}


def mapping_checks(text):
    rows = [line for line in text.splitlines() if re.match(r'^[0-9a-f]+-[0-9a-f]+ ', line)]
    if not rows:
        raise ValueError('No mappings captured')
    if any('[anon:dalvik-/system/framework/oat/arm/services.art]' in row for row in rows):
        raise ValueError('Services app image still mapped')
    for path in ('/system/framework/oat/arm/services.odex', '/apex/com.android.art/lib/libart.so'):
        if not any(row.split()[1] == 'r-xp' and row.split()[-1] == path for row in rows):
            raise ValueError('Expected executable mapping absent: ' + path)
    return {'services_image_mapping_absent': True, 'services_oat_executable': True,
            'art_runtime_executable': True}


def start_ticks(text):
    return int(text.rsplit(')', 1)[1].split()[19])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', required=True)
    p.add_argument('--boot', required=True, type=lambda s: str(uuid.UUID(s)))
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    report = dict(image=56, boot=a.boot, passed=False, savings_proven=False)

    def read(label, command):
        r = subprocess.run([a.adb, '-s', SERIAL, 'shell', command], capture_output=True, timeout=25)
        (a.output / (label + '.stdout')).write_bytes(r.stdout)
        (a.output / (label + '.stderr')).write_bytes(r.stderr)
        r.check_returncode()
        if r.stderr.strip():
            raise ValueError('Unexpected stderr: ' + label)
        return r.stdout.decode().replace('\r', '').strip()

    identity = 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; getprop sys.boot_completed; pidof system_server'
    try:
        before = read('identity-before', identity).splitlines()
        if len(before) != 7 or before[:6] != [SERIAL, '56', a.boot, '0', 'Enforcing', '1'] or not re.fullmatch(r'[1-9][0-9]*', before[6]):
            raise ValueError('Wrong handset, image, boot, privilege, SELinux or startup state')
        pid = before[6]
        for index, (path, expected) in enumerate(FILES.items()):
            if read('file-' + str(index), 'sha256sum ' + path).split()[0] != expected:
                raise ValueError('Unexpected file: ' + path)
        stat = read('stat-before', 'cat /proc/' + pid + '/stat')
        read('uptime-before', 'cat /proc/uptime')
        if read('cmdline', 'cat /proc/' + pid + '/cmdline').rstrip('\0') != 'system_server':
            raise ValueError('PID command changed')
        smaps = read('smaps', 'cat /proc/' + pid + '/smaps')
        checks = mapping_checks(smaps)
        read('uptime-after', 'cat /proc/uptime')
        if start_ticks(read('stat-after', 'cat /proc/' + pid + '/stat')) != start_ticks(stat):
            raise ValueError('System server lifetime changed')
        if read('identity-after', identity).splitlines() != before:
            raise ValueError('Identity changed during capture')
        report.update(checks, passed=True, pid=int(pid), start_ticks=start_ticks(stat),
                      limits=['No startup latency, workload, GC-cost or full ABI acceptance follows from these mapping checks.'])
    except Exception as error:
        report['failure'] = str(error)
        raise
    finally:
        report['capture_hashes'] = {f.name: hashlib.sha256(f.read_bytes()).hexdigest()
                                    for f in a.output.iterdir() if f.is_file()}
        (a.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
