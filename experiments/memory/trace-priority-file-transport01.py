"""Source fragment for generated priority drivers: files, shell-v2, no stdin."""
import time

_prepare_core = prepare


def prepare(capability, output, seconds=30, nonce=None):
    plan = _prepare_core(capability, output, seconds, nonce)
    path = output / 'collect.sh'
    text = path.read_text()
    if text.count('tar -cf - .\n') != 1:
        raise ValueError('Collect check boundary differs')
    text = text.replace('tar -cf - .\n', f"printf 'EXPORT_READY {plan['name']}\\n'\n")
    path.write_bytes(text.encode())
    plan['hashes']['collect.sh'] = digest(text.encode())
    plan['transport'] = 'push_hash_shell_v2_files_then_binary_tar_without_stdin'
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    return plan


def _journal(packet, row):
    with (packet / 'transport-journal.jsonl').open('a', encoding='utf-8') as out:
        out.write(json.dumps(row) + '\n')
        out.flush()


def _file_call(adb, args, packet, label, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(label, 45)
    command = [str(adb), '-s', SERIAL, *args]
    _journal(packet, {'state': 'starting', 'label': label, 'argv': command})
    # No caller or inherited stdin. ADB shell scripts are always named files.
    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _journal(packet, {'state': 'client_started', 'label': label, 'client_pid': proc.pid})
    try:
        stdout, stderr = proc.communicate(timeout=min(12, remaining))
    except subprocess.TimeoutExpired:
        # Terminate only this exact owned client. Remote execution can remain
        # uncertain; never infer worker cleanup or retry from the local kill.
        kill_error = None
        try:
            proc.kill()
        except OSError as error:
            kill_error = str(error)[:256]
        try:
            stdout, stderr = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.output or b'', error.stderr or b''
        partial = label + '-' + uuid.uuid4().hex[:12]
        (packet / (partial + '.partial.stdout')).write_bytes(stdout)
        (packet / (partial + '.partial.stderr')).write_bytes(stderr)
        _journal(packet, {'state': 'timeout_client_stop_attempted', 'label': label,
                          'client_pid': proc.pid, 'client_status': proc.poll(),
                          'kill_error': kill_error, 'partial_prefix': partial})
        raise
    _journal(packet, {'state': 'completed', 'label': label, 'client_pid': proc.pid,
                      'returncode': proc.returncode, 'stdout_bytes': len(stdout),
                      'stdout_sha256': digest(stdout), 'stderr_bytes': len(stderr),
                      'stderr_sha256': digest(stderr)})
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)


def _receipt(result, expected):
    if result.returncode or result.stderr or result.stdout.decode(errors='replace').strip() != expected:
        raise ValueError('Missing/wrong remote receipt: ' + expected)


def _identity_gate():
    return (f'set -eu\n[ "$(getprop ro.kaidroid.image)" = 60 ]\n'
            f'[ "$(cat /proc/sys/kernel/random/boot_id)" = "{BOOT}" ]\n'
            '[ "$(id -u)" = 0 ]\n')


def run_action(action, packet, adb):
    verified_script(packet, 'launch.sh' if action == 'start' else 'collect.sh')
    plan = json.loads((packet / 'plan.json').read_text())
    name = validate_name(plan['name'])
    work = '/data/local/tmp/' + name
    stage = work + '-transport'
    duration = plan['duration_seconds']
    if type(duration) is not int or not 10 <= duration <= 45 or plan['remote_work'] != work:
        raise ValueError('Plan/work/duration inconsistency')
    if plan.get('transport') != 'push_hash_shell_v2_files_then_binary_tar_without_stdin':
        raise ValueError('File transport packet required')
    prefix = f"name='{name}'\nwork='{work}'\nboot='{BOOT}'\nseconds='{duration}'\n"
    if not (packet / 'worker.sh').read_text().startswith(prefix) or prefix not in (packet / 'launch.sh').read_text():
        raise ValueError('Worker/plan identity inconsistency')
    if action == 'start':
        with (packet / 'start-attempt.json').open('x') as out:
            json.dump({'attempted': True, 'automatic_retry': False, 'stage': stage,
                       'remote_work': work, 'instance': name}, out)
    elif (packet / 'capture.tar').exists():
        raise FileExistsError('Capture archive already retained')
    deadline = time.monotonic() + 45

    def call(args, label):
        return _file_call(adb, args, packet, label, deadline)

    _receipt(call(['get-serialno'], 'serial'), SERIAL)
    if action == 'start':
        command = (_identity_gate() + f'[ ! -e "{work}" ]\n'
                   f'[ ! -e "/sys/kernel/tracing/instances/{name}" ]\n'
                   f'mkdir "{stage}"\nprintf "STAGE_CREATED {name}\\n"\n')
        _receipt(call(['shell', '-T', command], 'stage-create'), 'STAGE_CREATED ' + name)
        for filename in ('launch.sh', 'collect.sh'):
            result = call(['push', str((packet / filename).resolve()), stage + '/' + filename],
                          'push-' + filename.replace('.', '-'))
            if result.returncode:
                raise ValueError('Push failed; owned stage retained')
    # Existing scripts are verified before launch and before every collection.
    command = _identity_gate() + f'sha256sum "{stage}/launch.sh" "{stage}/collect.sh"\n'
    result = call(['shell', '-T', command], 'stage-hashes')
    expected = {stage + '/' + f: plan['hashes'][f] for f in ('launch.sh', 'collect.sh')}
    rows = result.stdout.decode(errors='replace').splitlines()
    observed = {}
    for row in rows:
        pieces = row.split()
        if len(pieces) != 2 or pieces[1] in observed:
            raise ValueError('Malformed/duplicate remote script hashes')
        observed[pieces[1]] = pieces[0]
    if result.returncode or result.stderr or observed != expected:
        raise ValueError('Remote script hash mismatch; no script executed')
    if action == 'start':
        result = call(['shell', '-T', f'sh "{stage}/launch.sh" </dev/null'], 'launch-file')
        expected = f'ARMED {name} duration={duration}s; parent may now start chosen app'
        good = result.returncode == 0 and not result.stderr and result.stdout.decode(errors='replace').strip() == expected
        (packet / 'start-result.json').write_text(json.dumps({
            'returncode': result.returncode, 'remote_armed_receipt_verified': good,
            'stdout': result.stdout.decode(errors='replace')[:4096],
            'stderr': result.stderr.decode(errors='replace')[:4096], 'automatic_retry': False}, indent=2) + '\n')
        _receipt(result, expected)
        print(expected, flush=True)
        return
    check = ['shell', '-T', f'sh "{stage}/collect.sh" </dev/null']
    _receipt(call(check, 'export-precheck'), 'EXPORT_READY ' + name)
    result = call(['exec-out', 'tar', '-cf', '-', '-C', work, '.'], 'export-tar')
    if len(result.stdout) > 5 * 1024 * 1024:
        raise ValueError('Export exceeds bound; remote original retained')
    with (packet / 'capture.tar').open('xb') as out:
        out.write(result.stdout)
    if result.returncode or result.stderr:
        raise ValueError('Export status/stderr unverified; archive retained')
    # Identity/finished state is checked after binary export too. Archive stays
    # retained even if that check fails; no verified summary is then issued.
    _receipt(call(check, 'export-postcheck'), 'EXPORT_READY ' + name)
    summary = inspect_archive(result.stdout)
    summary['file_transport_pre_post_identity_verified'] = True
    (packet / 'capture-result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2), flush=True)
