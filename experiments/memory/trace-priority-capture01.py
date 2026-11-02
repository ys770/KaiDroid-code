"""Prepare/start/collect one bounded, fresh-instance image59 priority trace.

Preparation is entirely offline. Start and collect are explicit parent-owned actions.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import uuid

SERIAL = 'DEVICE_SERIAL_REQUIRED'
BOOT = '00000000-0000-0000-0000-000000000002'
CAP_SHA = '8d985956203a1680c60819a1b071d47774ee82bbef71923817b0362bf138cae5'
EVENTS = ('oom/oom_score_adj_update', 'sched/sched_process_fork',
          'sched/sched_process_exec', 'sched/sched_process_exit')
HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def validate_name(name):
    if not re.fullmatch(r'kaidroid-priority-[0-9a-f]{12}', name):
        raise ValueError('Invalid owned instance name')
    return name


def prepare(capability, output, seconds=30, nonce=None):
    if not 10 <= seconds <= 45:
        raise ValueError('Duration must be 10..45 seconds')
    raw = capability.read_bytes()
    if digest(raw) != CAP_SHA:
        raise ValueError('Capability input differs from reviewed image59 capture')
    cap = json.loads(raw)
    if not cap['inspection_valid'] or not cap['identity_verified']:
        raise ValueError('Invalid capability identity')
    expected = {'serial': SERIAL, 'image': '59', 'boot_id': BOOT}
    if cap['expected'] != expected:
        raise ValueError('Wrong capability identity')
    # Inspector strips trailing newlines; kernel format is a newline-terminated file.
    fmt = cap['reads']['root0.oom_format']['value'].rstrip('\n') + '\n'
    name = validate_name('kaidroid-priority-' + (nonce or uuid.uuid4().hex[:12]))
    work = '/data/local/tmp/' + name
    prefix = f"name='{name}'\nwork='{work}'\nboot='{BOOT}'\nseconds='{seconds}'\n"
    worker = prefix + (HERE / 'trace-priority-worker01.sh').read_text(encoding='utf-8')
    gate = f'''set -eu
[ "$(getprop ro.kaidroid.image)" = 59 ]
[ "$(cat /proc/sys/kernel/random/boot_id)" = '{BOOT}' ]
[ "$(id -u)" = 0 ]
'''
    launch = gate + f'''command -v setsid >/dev/null
command -v nohup >/dev/null
mkdir '{work}'
cat > '{work}/worker.sh' <<'KAIDROID_WORKER_EOF'
{worker}KAIDROID_WORKER_EOF
cat > '{work}/expected-oom-format.txt' <<'KAIDROID_FORMAT_EOF'
{fmt}KAIDROID_FORMAT_EOF
setsid nohup sh '{work}/worker.sh' </dev/null >'{work}/stdout.txt' 2>'{work}/stderr.txt' &
n=0
while [ ! -f '{work}/armed.txt' ]; do
  [ ! -f '{work}/finished.txt' ] || exit 81
  n=$((n+1)); [ "$n" -le 60 ] || exit 82
  sleep 0.1
done
[ ! -f '{work}/finished.txt' ]
[ "$(cat '/sys/kernel/tracing/instances/{name}/tracing_on')" = 1 ]
printf 'ARMED {name} duration={seconds}s; parent may now start chosen app\n'
'''
    collect = gate + f'''[ -f '{work}/finished.txt' ] || exit 83
cd '{work}'
tar -cf - .
'''
    output.mkdir(parents=True, exist_ok=False)
    files = {'worker.sh': worker, 'launch.sh': launch, 'collect.sh': collect}
    for filename, content in files.items():
        (output / filename).write_bytes(content.encode('utf-8'))
    plan = {'executed': False, 'expected': expected, 'name': name, 'remote_work': work,
            'duration_seconds': seconds, 'events': list(EVENTS),
            'configured_ring_kib': 256, 'initial_allocation_peak_measured': False,
            'capability_sha256': CAP_SHA,
            'hashes': {k: digest(v.encode()) for k, v in files.items()}}
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n', encoding='utf-8')
    return plan


def verified_script(packet, filename):
    plan = json.loads((packet / 'plan.json').read_text(encoding='utf-8'))
    validate_name(plan['name'])
    if plan['expected'] != {'serial': SERIAL, 'image': '59', 'boot_id': BOOT}:
        raise ValueError('Packet identity drift')
    # Check all launch inputs, not just the selected entry point.
    for key, expected in plan['hashes'].items():
        if key not in ('worker.sh', 'launch.sh', 'collect.sh'):
            raise ValueError('Unexpected packet file')
        if digest((packet / key).read_bytes()) != expected:
            raise ValueError('Packet changed after preparation')
    if set(plan['hashes']) != {'worker.sh', 'launch.sh', 'collect.sh'}:
        raise ValueError('Missing packet hashes')
    return (packet / filename).read_bytes()


def adb_call(adb, args, data=None, timeout=12):
    return subprocess.run([str(adb), '-s', SERIAL, *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          check=False)


def inspect_archive(data):
    """Read selected status files without extracting paths or trusting exit0 alone."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        for member in archive.getmembers():
            if member.isdir() and member.name in ('.', './'):
                continue
            name = member.name.removeprefix('./')
            if not member.isfile() or not re.fullmatch(r'[a-zA-Z0-9_.-]+', name):
                raise ValueError('Unexpected export entry; archive retained without extraction')
            if member.size > 4194305 or name in files:
                raise ValueError('Oversized/duplicate export member')
            files[name] = archive.extractfile(member).read()
    names = ('cleanup.txt', 'deadline.txt', 'timer-exit.txt', 'supervisor-exit.txt',
             'finished.txt', 'protected-comparison.txt', 'trace-bound.txt')
    states = {name: files.get(name, b'MISSING').decode(errors='replace').strip() for name in names}
    counters = {}
    for block in re.split(r'(?m)^cpu', files.get('loss-stats.txt', b'').decode(errors='replace'))[1:]:
        cpu, _, body = block.partition('\n')
        if cpu not in ('0', '1', '2', '3') or cpu in counters:
            continue
        counters[cpu] = {}
        for key in ('overrun', 'commit overrun', 'dropped events'):
            found = re.findall(r'^' + re.escape(key) + r':\s*(\d+)\s*$', body, re.M)
            if len(found) == 1:
                counters[cpu][key] = int(found[0])
    known = set(counters) == {'0', '1', '2', '3'} and all(len(v) == 3 for v in counters.values())
    loss = ('nonzero_loss_counters' if any(any(v.values()) for v in counters.values())
            else 'observed_counters_zero' if known else 'unknown')
    complete = (states['cleanup.txt'] == 'instance_retained_stopped' and
                states['deadline.txt'] == 'deadline_stopped' and
                states['timer-exit.txt'] == states['supervisor-exit.txt'] == '0' and
                states['finished.txt'] == 'finished' and
                states['protected-comparison.txt'] == 'equal' and
                states['trace-bound.txt'] == 'within_4MiB_bound' and 'trace.txt' in files and
                all(f'format-{i}.txt' in files for i in range(4)))
    return {'archive_sha256': digest(data), 'states': states, 'loss_counters': counters,
            'loss_status': loss, 'capture_and_cleanup_status_complete': complete,
            'trace_present': 'trace.txt' in files, 'event_delivery_or_race_absence_proven': False,
            'interpretation': 'Inspect trace/schema/clock and parent logs; counters do not prove event delivery.'}


def run_action(action, packet, adb):
    script = verified_script(packet, 'launch.sh' if action == 'start' else 'collect.sh')
    plan = json.loads((packet / 'plan.json').read_text(encoding='utf-8'))
    if action == 'start':
        # An existing attempt is terminal for this packet, even after a transport timeout.
        with (packet / 'start-attempt.json').open('x', encoding='utf-8') as out:
            json.dump({'attempted': True, 'automatic_retry': False}, out)
    serial = adb_call(adb, ['get-serialno'])
    if serial.returncode or serial.stdout.decode().strip() != SERIAL:
        raise ValueError('ADB serial mismatch; no device script sent')
    # A failed/timeout start must never be repeated automatically: worker may be armed.
    result = adb_call(adb, ['exec-out', 'sh', '-s'], script, timeout=12)
    if action == 'start':
        expected = (f"ARMED {plan['name']} duration={plan['duration_seconds']}s; "
                    'parent may now start chosen app')
        # exec-out host status has previously hidden remote nonzero status on
        # this device. Require the exact final device readiness receipt.
        # This is a sampled state which can age before the parent launches.
        armed = (result.returncode == 0 and not result.stderr and
                 result.stdout.decode(errors='replace').strip() == expected)
        (packet / 'start-result.json').write_text(json.dumps({
            'returncode': result.returncode,
            'remote_armed_receipt_verified': armed,
            'stdout': result.stdout.decode(errors='replace')[:4096],
            'stderr': result.stderr.decode(errors='replace')[:4096],
            'automatic_retry': False}, indent=2) + '\n')
        if not armed:
            raise ValueError('Missing/wrong remote ARMED receipt; host exit0 is insufficient')
        print(result.stdout.decode(errors='replace'), flush=True)
    else:
        if result.returncode:
            raise ValueError(f'Collect not complete/identity failed (rc={result.returncode})')
        if len(result.stdout) > 5 * 1024 * 1024:
            raise ValueError('Export exceeds 5MiB; remote original retained')
        # Preserve the original archive before inspecting it. No arbitrary-path extraction.
        with (packet / 'capture.tar').open('xb') as out:
            out.write(result.stdout)
        summary = inspect_archive(result.stdout)
        (packet / 'capture-result.json').write_text(json.dumps(summary, indent=2) + '\n')
        print(f'Captured own-instance artifacts: {packet / "capture.tar"}', flush=True)
        print(json.dumps(summary, indent=2), flush=True)
    if result.returncode:
        raise ValueError(f'Start failed/uncertain (rc={result.returncode}); do not retry automatically')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'start', 'collect'))
    parser.add_argument('--packet', required=True, type=Path)
    parser.add_argument('--capability', type=Path)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--adb', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            if args.capability is None:
                parser.error('prepare requires --capability')
            print(json.dumps(prepare(args.capability, args.packet, args.seconds), indent=2))
        else:
            if args.adb is None or not args.adb.is_absolute() or not args.adb.is_file():
                parser.error('start/collect require an existing absolute verified --adb path')
            run_action(args.action, args.packet, args.adb)
    except (ValueError, OSError, subprocess.TimeoutExpired, tarfile.TarError) as exc:
        print(f'FAILED/UNCERTAIN: {exc}. No automatic retry. Remote artifacts/instance retained.')
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
