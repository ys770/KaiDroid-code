"""One serial/boot-bound Wi-Fi reconnect; retain saved configuration and evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adb', required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    adb = [args.adb, '-s', 'DEVICE_SERIAL_REQUIRED', 'shell']
    identity_command = 'getprop ro.serialno; getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; id -u; pidof system_server; pidof com.android.systemui'
    report = dict(image=51, passed=False, cycles=0, saved_configuration_written=False)
    sequence = 0
    restore_needed = False
    ambiguous = False
    original = None

    def run(label, command, timeout=20, check=True):
        nonlocal sequence, ambiguous
        sequence += 1
        try:
            result = subprocess.run(adb + [command], capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            ambiguous = True
            raise
        prefix = args.output / f'{sequence:02d}-{label}'
        prefix.with_suffix('.stdout').write_bytes(result.stdout)
        prefix.with_suffix('.stderr').write_bytes(result.stderr)
        if check:
            result.check_returncode()
        return result.stdout.decode().replace('\r', '').strip()

    def guard():
        current = run('identity', identity_command)
        if current != original:
            raise RuntimeError('Handset/image/boot/system process identity changed')

    def wait_status(label, predicate):
        start = time.monotonic()
        for attempt in range(20):
            status = run(f'{label}-{attempt}', 'cmd wifi status')
            if predicate(status):
                return status, round(time.monotonic() - start, 3)
            time.sleep(2)
        raise RuntimeError(label + ' state not observed within bounded window')

    try:
        original = run('before', identity_command)
        fields = original.splitlines()
        if fields[:4] != ['DEVICE_SERIAL_REQUIRED', '51', args.boot, '0'] or len(fields) != 6:
            raise RuntimeError('Wrong initial identity')
        before = run('wifi-before', 'cmd wifi status')
        if 'Supplicant state: COMPLETED' not in before or '&VALIDATED' not in before:
            raise RuntimeError('Start from validated connected Wi-Fi')
        network = re.search(r'^Wifi is connected to (.+)$', before, re.M)
        if not network:
            raise RuntimeError('Cannot identify baseline network')
        restore_needed = True
        run('disable', 'svc wifi disable')
        wait_status('disabled', lambda value: value.splitlines()[0] == 'Wifi is disabled')
        guard()
        run('enable', 'svc wifi enable')
        enabled_at = time.monotonic()
        restore_needed = False
        after, elapsed = wait_status('reconnected', lambda value:
            'Supplicant state: COMPLETED' in value and '&VALIDATED' in value)
        if network.group(0) not in after:
            raise RuntimeError('Reconnected to a different network')
        report.update(cycles=1, disabled_observed=True, same_saved_network=True,
                      validated_after_enable=True, validation_observed_seconds=elapsed)
        # VALIDATED can be visible before the shell has a usable route. Retain
        # every failed data-plane probe rather than treating the flag as proof.
        report['connectivity_probes'] = []
        for attempt in range(10):
            reply = run(f'ready-{attempt}', 'ping -c 1 -W 2 1.1.1.1', 10, check=False)
            connected = bool(re.search(r'1 packets transmitted, 1 received', reply))
            report['connectivity_probes'].append(dict(
                elapsed_since_enable=round(time.monotonic() - enabled_at, 3),
                reply_received=connected))
            if connected:
                report['connectivity_observed_seconds'] = report['connectivity_probes'][-1]['elapsed_since_enable']
                break
            time.sleep(2)
        else:
            raise RuntimeError('Validated association did not recover IP traffic within probe window')
        for name, target in [('ip', '1.1.1.1'), ('dns', 'example.com')]:
            reply = run(name + '-ping', f'ping -c 5 -W 3 {target}', 30)
            match = re.search(r'(\d+) packets transmitted, (\d+) received', reply)
            if not match:
                raise RuntimeError('Missing ping statistics')
            report[name + '_ping'] = dict(sent=int(match[1]), received=int(match[2]))
            if int(match[2]) == 0:
                raise RuntimeError('No ping replies')
        guard()
        report.update(passed=True, same_boot_and_system_processes=True)
    except Exception as error:
        report['failure'] = str(error)
    finally:
        if restore_needed and not ambiguous:
            try:
                guard()
                run('restore-enabled', 'svc wifi enable')
                report['restore_enabled_requested'] = True
            except Exception as error:
                report['restore_failure'] = str(error)
        report['ambiguous_command'] = ambiguous
        report['limitations'] = ['One software off/on cycle; no throughput, roaming, suspend or sustained reliability proof.',
                                 'No physical radio or antenna measurement; packet loss is reported separately.']
        report['capture_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in args.output.iterdir() if p.is_file()}
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Wi-Fi reconnect trial failed; inspect retained evidence')


if __name__ == '__main__':
    main()
