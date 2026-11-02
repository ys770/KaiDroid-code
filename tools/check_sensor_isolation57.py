"""Read-only image57 sensor/isolation capability capture; never starts a daemon."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid

IDENTITY = 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; getenforce; pidof system_server; pidof com.android.systemui'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot', type=lambda value: str(uuid.UUID(value)), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'image': 57, 'read_only': True, 'passed': False,
              'daemon_started': False, 'mount_created': False}

    def capture(label, command):
        result = subprocess.run(['/opt/kaidroid/source/Documents/platform-tools/adb.exe',
                                 '-s', 'DEVICE_SERIAL_REQUIRED', 'shell', command],
                                capture_output=True, timeout=25)
        (args.output / (label + '.stdout')).write_bytes(result.stdout)
        (args.output / (label + '.stderr')).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout.decode().replace('\r\n', '\n').strip()

    try:
        before = capture('identity-before', IDENTITY).splitlines()
        if len(before) != 7 or before[:5] != ['DEVICE_SERIAL_REQUIRED', '57', args.boot, '0', 'Enforcing']:
            raise ValueError('Wrong handset/image/boot/security state')
        daemon_hash = capture('daemon-hash', 'sha256sum /vendor/bin/sensors.qti').split()[0]
        if daemon_hash != '1992f0cf34bb5bb1902e3502bcee58b6acc915f2a0281c9fdd65ddc5badc8d25':
            raise ValueError('Unexpected daemon')
        capture('tools', 'toybox --long; command -v unshare; command -v nsenter; command -v timeout; command -v runcon; true')
        capture('namespaces', 'ls -l /proc/self/ns/mnt /proc/1/ns/mnt; cat /proc/self/mountinfo')
        capture('credentials', 'id; cat /proc/self/attr/current; cat /proc/self/status')
        capture('registry-metadata', 'ls -ldZ /persist /persist/sensors /mnt/vendor/persist /mnt/vendor/persist/sensors; ls -laZ /mnt/vendor/persist/sensors; true')
        capture('service-state', 'getprop init.svc.vendor.sensors.qti; getprop init.svc.vendor-sensor-sh; pidof sensors.qti; true')
        capture('ipc-servers', 'cat /sys/kernel/debug/msm_ipc_router/dump_servers')
        capture('sensors', 'dumpsys sensorservice')
        after = capture('identity-after', IDENTITY).splitlines()
        if before != after:
            raise ValueError('Boot or core processes changed')
        report.update(passed=True, same_boot_and_core_processes=True, daemon_sha256=daemon_hash,
                      isolation_proven=False, limitation='Tool presence and mount metadata do not prove private mount capability or write isolation.')
    except Exception as error:
        report['failure'] = str(error)
    finally:
        report['captures'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                              for p in args.output.iterdir() if p.is_file()}
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if not report['passed']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
