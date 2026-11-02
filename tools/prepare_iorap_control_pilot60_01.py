"""Offline-only packet preparation. Never invokes adb, ssh or a device command."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets

ROOT = Path(__file__).resolve().parents[1]
BOOT = '00000000-0000-0000-0000-000000000007'
SERIAL = 'DEVICE_SERIAL_REQUIRED'
CORE = {'surfaceflinger': 538, 'system_server': 1166, 'com.android.systemui': 1339}
JOB_ID = 0
for char in 'iorapd':
    JOB_ID = (JOB_ID << 5) | (ord(char) - ord('a'))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(binding, output, nonce=None):
    if binding.get('image') != 60 or binding.get('boot') != BOOT or binding.get('serial') != SERIAL:
        raise ValueError('This packet is bound only to the reviewed image60 boot')
    processes = binding['processes']
    if set(processes) != set(CORE) | {'iorapd'}:
        raise ValueError('Exactly four PID/starttime bindings required')
    for name, row in processes.items():
        if set(row) != {'pid', 'start_ticks'}:
            raise ValueError('Unexpected identity fields')
        for value in row.values():
            if type(value) is not int or value <= 0:
                raise ValueError('Positive integer PID/start_ticks required')
        if name in CORE and row['pid'] != CORE[name]:
            raise ValueError('Reviewed core PID differs')
    if len({row['pid'] for row in processes.values()}) != 4:
        raise ValueError('Duplicate PIDs')
    nonce = secrets.token_hex(6) if nonce is None else nonce
    if not re.fullmatch('[0-9a-f]{12}', nonce):
        raise ValueError('Unsafe nonce')
    stage = '/data/local/tmp/kaidroid-iorap-control-' + nonce
    constants = (f"serial='{SERIAL}'\nboot='{BOOT}'\nnonce='{nonce}'\n"
                 f"stage='{stage}'\nwork=\"$stage/run\"\niorap_pid={processes['iorapd']['pid']}\n")
    bodies = {}
    for target, source in [('common.sh', 'common'), ('guardian.sh', 'guardian'), ('step.sh', 'step')]:
        text = (ROOT / f'experiments/memory/iorap-control-{source}01.sh').read_text(encoding='utf-8')
        text = text.replace('@@STAGE@@', stage).replace('@@JOB_ID@@', str(JOB_ID))
        if '@@' in text:
            raise ValueError('Unbound placeholder')
        if target == 'common.sh':
            text = constants + text
        bodies[target] = text.encode()
    bodies['identities.txt'] = ''.join(f"{name} {row['pid']} {row['start_ticks']}\n"
                                      for name, row in sorted(processes.items())).encode()
    checks = ''.join(f"printf '%s  %s\\n' '{sha(data)}' '{stage}/{name}' | sha256sum -c -\n"
                     for name, data in bodies.items())
    bodies['launch.sh'] = (f'#!/system/bin/sh\nset -eu\numask 077\n{checks}'
        f'[ ! -L "{stage}" ]\n[ "$(stat -c \'%u:%a\' "{stage}")" = 0:700 ]\n'
        f'. "{stage}/common.sh"\nguard\n'
        f'mkdir "{stage}/launched"\n'
        f'nohup setsid sh "{stage}/guardian.sh" </dev/null > "{stage}/guardian.log" 2>&1 &\n'
        f'printf "LAUNCHED {nonce} launcher_pid=%s; actual guardian in run/guardian-identity.txt; restoration not yet verified\\n" "$!"\n').encode()
    output.mkdir(parents=True, exist_ok=False)
    for name, data in bodies.items():
        (output / name).write_bytes(data)
    report = dict(classification='offline_image60_recording_control_validation_packet',
        executed=False, binding=binding, job_id=JOB_ID, nonce=nonce, remote_stage=stage,
        files={name: sha(data) for name, data in bodies.items()},
        helper_deadline_seconds=25, restoration_receipt_deadline_seconds=35, command_timeout_seconds=3,
        launcher_pid_assumed_helper=False,
        helper_binding='private nonce receipt plus actual PID/starttime/session/group/script cmdline; bound acknowledgement',
        restoration_initiated_on_helper_completion_failure_or_deadline=True,
        hard_recovery_during_kernel_stall_or_guardian_sigkill_proven=False,
        original_empty_value_restored_observably_not_deleted=True,
        previously_stale_native_state_recoverable=False,
        observable_gates=['no native in-flight Perfetto handles', 'scheduler exact waiting',
                          'awake and deviceidle ACTIVE'],
        orphan_native_maintenance_excluded=False, full_quiescence_proven=False,
        no_app_launches_or_profile_operations=True, matched_memory_saving_test=False)
    (output / 'packet.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binding', required=True, type=Path,
                        help='Fresh parent-captured boot and four PID/start_ticks identities')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(json.loads(args.binding.read_text(encoding='utf-8')), args.output), indent=2))
