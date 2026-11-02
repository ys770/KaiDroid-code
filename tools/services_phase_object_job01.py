"""Future compile-only job/preflight and PID1 watcher. No Docker launch or firmware mode."""
import sys
sys.dont_write_bytecode = True  # Before local imports, even if manually invoked without -B.
import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
import services_phase_object_contract01 as c

STAGE = Path(c.HOST_ROOT) / c.NAME


def packet(root, pin):
    if root.resolve(strict=True) != root:
        raise ValueError('Packet root symlink')
    if not re.fullmatch('[a-f0-9]{64}', pin) or c.sha(root / 'manifest.json') != pin:
        raise ValueError('Packet manifest differs')
    manifest = json.loads((root / 'manifest.json').read_text())
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual != set(manifest['files']) | {'manifest.json', 'handoff.json'}:
        raise ValueError('Packet file closure differs')
    for name, digest in manifest['files'].items():
        path = root / name
        if '..' in Path(name).parts or path.is_symlink() or c.sha(path) != digest:
            raise ValueError('Packet input differs: ' + name)
    if any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Packet symlink')
    return json.loads((root / 'plan.json').read_text())


def external():
    if STAGE.resolve(strict=True) != STAGE or Path(c.BACKING).resolve(strict=True) != Path(c.BACKING):
        raise ValueError('Symlinked external stage/backing')
    left, right = STAGE.stat(), Path(c.BACKING).stat()
    if (left.st_dev, left.st_ino) != (right.st_dev, right.st_ino) or left.st_dev != 2048:
        raise ValueError('Stage does not bind the exact external backing inode')
    for path in (STAGE, Path(c.BACKING), Path('/mnt/ext1')):
        info = path.stat()
        if not path.is_dir() or (info.st_dev, info.st_uid, info.st_gid, info.st_mode & 0o777) != (2048, 1000, 1000, 0o700):
            raise ValueError('External directory device/owner/mode differs')
    if Path(c.HOST_ROOT).stat().st_dev != 66306:
        raise ValueError('Recorded host root volume changed')
    rows = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        a, b = line.split(' - ')
        a, b = a.split(), b.split()
        if a[4] == str(STAGE):
            rows.append((a[2], a[3], a[5], b[0], b[1], b[2]))
    if len(rows) != 1 or rows[0][0:2] != ('8:0', '/' + Path(c.BACKING).name) or rows[0][3:5] != ('ext4', '/dev/sda') or 'rw' not in rows[0][2].split(',') or 'rw' not in rows[0][5].split(','):
        raise ValueError('Exact external stage mount missing/ambiguous')
    if min(shutil.disk_usage(STAGE).free, shutil.disk_usage(c.HOST_ROOT).free) <= c.FLOOR:
        raise ValueError('Root/external free floor reached')


def size():
    total = 0
    for path in STAGE.rglob('*'):
        if path.is_symlink():
            raise ValueError('Stage symlink')
        if path.is_file():
            total += path.stat().st_size
    return total


def preflight(pin):
    if os.getuid() != 1000:
        raise ValueError('Assigned host UID1000 only')
    external()
    packet(STAGE / 'inputs', pin)
    if {p.name for p in STAGE.iterdir()} != {'inputs'}:
        raise ValueError('Fresh stage required; never reset an existing job')
    if shutil.disk_usage(STAGE).free < c.FLOOR + c.GROWTH:
        raise ValueError('External budget plus emergency floor unavailable')
    if not {0, 1}.issubset(os.sched_getaffinity(0)):
        raise ValueError('Reviewed CPUs unavailable')
    for name in ('ninja', 'soong_build', 'e2fsdroid', 'clang', 'clang++'):
        if subprocess.run(['pgrep', '-x', name], capture_output=True, timeout=5).returncode != 1:
            raise ValueError('Host work active or unknown')
    if subprocess.check_output(['sudo', '-n', 'docker', 'ps', '-q'], text=True, timeout=15).strip():
        raise ValueError('Existing container must finish first')
    for name in ('work', 'control'):
        (STAGE / name).mkdir(mode=0o700)
        for role in c.ROLES:
            (STAGE / name / role).mkdir(mode=0o700)
            if name == 'work':
                (STAGE / name / role / 'out').mkdir(mode=0o700)
                (STAGE / name / role / 'tmp').mkdir(mode=0o700)
    stat = STAGE.stat()
    c.dump(STAGE / 'host-proof.json', dict(packet_sha256=pin, stage_dev=stat.st_dev,
           stage_ino=stat.st_ino, initial_stage_bytes=size(), fresh=True))


def host_check(pin):
    external()
    packet(STAGE / 'inputs', pin)
    proof = json.loads((STAGE / 'host-proof.json').read_text())
    st = STAGE.stat()
    if proof['packet_sha256'] != pin or (proof['stage_dev'], proof['stage_ino']) != (st.st_dev, st.st_ino):
        raise ValueError('Frozen host binding changed')
    if size() - proof['initial_stage_bytes'] >= c.GROWTH:
        raise ValueError('Whole matrix stage growth bound reached')
    return proof


def bind(role, pin, cid):
    if os.getuid() != 1000 or not re.fullmatch('[a-f0-9]{64}', cid):
        raise ValueError('Assigned user and exact container ID required')
    host_check(pin)
    previous = c.ROLES[:c.ROLES.index(role)]
    for old in previous:
        result = json.loads((STAGE / 'control' / old / 'terminal.json').read_text())
        if not result['success']:
            raise ValueError('Previous role did not pass; no automatic continuation')
    info = json.loads(subprocess.check_output(['sudo', '-n', 'docker', 'inspect', cid], timeout=15))[0]
    c.validate_container(info, role, pin, cid)
    c.dump(STAGE / 'control' / role / 'launch.json', dict(cid=cid, packet_sha256=pin, role=role, monotonic=time.monotonic()))


def role_check(role, pin):
    if os.getuid() != 1000:
        raise ValueError('Assigned user only')
    host_check(pin)
    if {p.name for p in (STAGE / 'work' / role).iterdir()} != {'out', 'tmp'} or any((STAGE / 'control' / role).iterdir()) or any((STAGE / 'work' / role / 'out').iterdir()) or any((STAGE / 'work' / role / 'tmp').iterdir()):
        raise ValueError('Role already used; retain same handles')
    for previous in c.ROLES[:c.ROLES.index(role)]:
        if not json.loads((STAGE / 'control' / previous / 'terminal.json').read_text())['success']:
            raise ValueError('Earlier role did not pass')
    if subprocess.check_output(['sudo', '-n', 'docker', 'ps', '-q'], text=True, timeout=15).strip():
        raise ValueError('Another container active')
    for name in ('ninja', 'soong_build', 'e2fsdroid', 'clang', 'clang++'):
        if subprocess.run(['pgrep', '-x', name], capture_output=True, timeout=5).returncode != 1:
            raise ValueError('Host job active/unknown')


def unit_state(unit):
    raw = subprocess.check_output(['systemctl', 'show', unit, '--no-pager', '--property=MainPID,ActiveState,InvocationID'], text=True, timeout=15)
    return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)


def heartbeat(control, record):
    path = control / 'heartbeat.new'
    path.write_text(json.dumps({**record, 'monotonic': time.monotonic()}))
    os.replace(path, control / 'heartbeat.json')


def watch(role, pin):
    if os.geteuid() != 0:
        raise ValueError('Root PID1-supervised watcher required')
    _, unit = c.identities(role)
    invocation = os.environ.get('INVOCATION_ID', '')
    state = unit_state(unit)
    c.validate_watch_identity(os.geteuid(), os.getpid(), invocation, state)
    host_check(pin)
    control = STAGE / 'control' / role
    launch = json.loads((control / 'launch.json').read_text())
    cid = launch['cid']
    if launch['role'] != role or launch['packet_sha256'] != pin:
        raise ValueError('Launch receipt differs')
    base = dict(packet_sha256=pin, role=role, cid=cid, unit=unit, invocation_id=invocation, pid=os.getpid(), uid=0)
    inspect = lambda: json.loads(subprocess.check_output(['docker', 'inspect', cid], timeout=15))[0]
    info = inspect()
    c.validate_container(info, role, pin, cid)
    c.dump(control / 'ready.json', base)
    reason = None
    while True:
        heartbeat(control, base)
        info = inspect()
        c.validate_container(info, role, pin, cid)
        if not info['State']['Running']:
            break
        try:
            host_check(pin)
            if time.monotonic() - launch['monotonic'] >= c.DEADLINE:
                raise ValueError('Deadline reached')
        except ValueError as error:
            reason = str(error)
            subprocess.run(['docker', 'kill', cid], capture_output=True, check=True, timeout=15)
        time.sleep(2)
    post_error = None
    try:
        host_check(pin)
    except Exception as error:
        post_error = repr(error)
    inside_path = STAGE / 'work' / role / 'inside-result.json'
    inside_result = json.loads(inside_path.read_text()) if inside_path.exists() else {}
    c.dump(control / 'container.inspect.json', info)
    logs = subprocess.run(['docker', 'logs', cid], capture_output=True, timeout=30)
    (control / 'docker.stdout').write_bytes(logs.stdout)
    (control / 'docker.stderr').write_bytes(logs.stderr)
    c.dump(control / 'terminal.json', dict(**base, exit_code=info['State']['ExitCode'],
           oom_killed=info['State']['OOMKilled'], stop_reason=reason, post_error=post_error,
           success=info['State']['ExitCode'] == 0 and not info['State']['OOMKilled'] and reason is None and post_error is None and inside_result.get('success') is True,
           compiled_TU_provenance_complete=False, linked=False, installed=False))


def container_boundary():
    if os.getuid() != 1000 or sorted(os.sched_getaffinity(0)) != [0, 1]:
        raise ValueError('Container user/affinity differs')
    for name, expected in [('memory.max', '8589934592'), ('memory.swap.max', '0'), ('pids.max', '512')]:
        if (Path('/sys/fs/cgroup') / name).read_text().strip() != expected:
            raise ValueError('Cgroup cap differs')
    rows = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left = line.split(' - ')[0].split()
        rows.append((left[4], set(left[5].split(','))))
    c.validate_protected_mounts(rows)
    for required in ('/work', '/tmp'):
        matches = [flags for path, flags in rows if path == required]
        if not matches or 'rw' not in matches[-1] or Path(required).stat().st_dev != 2048:
            raise ValueError('Writable paths left external device')
    return rows


def live_barrier(role, pin):
    path = Path('/control/heartbeat.json')
    record = json.loads(path.read_text())
    if path.stat().st_uid != 0 or record['packet_sha256'] != pin or record['role'] != role or record['unit'] != c.identities(role)[1] or record['uid'] != 0 or not re.fullmatch('[a-f0-9]{32}', record['invocation_id']):
        raise ValueError('PID1 root watcher barrier differs')
    age = time.monotonic() - record['monotonic']
    if not 0 <= age <= 15:
        raise ValueError('Watcher heartbeat stale')
    if min(shutil.disk_usage('/work').free, shutil.disk_usage('/build').free) <= c.FLOOR:
        raise ValueError('Container free-space floor reached')


def inside(role, pin):
    container_boundary()
    plan = packet(Path('/inputs'), pin)
    control = Path('/control')
    for _ in range(120):
        if (control / 'ready.json').exists() and (control / 'heartbeat.json').exists():
            break
        time.sleep(1)
    else:
        raise ValueError('No PID1 watchdog barrier; compiler never started')
    live_barrier(role, pin)
    out = Path('/work')
    if (out / 'started.json').exists():
        raise ValueError('Never replay an existing compile role')
    record = json.loads(Path('/inputs/receipts/compile-record.json').read_text())
    source_pin = c.sha(Path('/inputs/sources/image' + role[:2] + '.cc'))
    def check_known_inputs():
        for host, digest in record['read_inputs'].items():
            if not host.startswith(c.HOST_ROOT + '/'):
                raise ValueError('Read input left assigned host root')
            path = Path('/build' + host[len(c.HOST_ROOT):])
            expected = source_pin if str(path) == '/build/aosp/art/runtime/oat_file_manager.cc' else digest
            if c.sha(path) != expected:
                raise ValueError('Frozen build input changed: ' + str(path))
    check_known_inputs()
    runtime = json.loads(Path('/inputs/receipts/runtime-container02.json').read_text())
    for row in runtime['files']:
        if str(Path(row['path']).resolve()) != row['resolved'] or c.sha(row['path']) != row['sha256']:
            raise ValueError('Builder runtime changed')
    c.dump(out / 'started.json', dict(role=role, packet_sha256=pin, compile_only=True, monotonic=time.monotonic()))
    results = []
    environment = {**os.environ, **plan['original_compile_environment'], **plan['runtime_environment']}
    for command in plan['roles'][role]:
        label = command['label']
        with (out / (label + '.stdout')).open('xb') as stdout, (out / (label + '.stderr')).open('xb') as stderr:
            proc = subprocess.Popen(command['argv'], cwd=plan['cwd'], env=environment, stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                while proc.poll() is None:
                    live_barrier(role, pin)
                    if sum(p.stat().st_size for p in out.rglob('*') if p.is_file()) >= c.GROWTH:
                        raise ValueError('Role output bound reached')
                    time.sleep(1)
            except BaseException:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                raise
        if proc.returncode != 0:
            raise ValueError('Compiler failed: ' + label)
        dep = {'syntax': 'syntax.d', 'production-thin-object': 'manager.thin.o.d', 'nonlto-arm-assembly-review-only': 'manager.review.s.d'}[label]
        pins = c.validate_dependencies((out / 'out' / dep).read_text(), record['read_inputs'], source_pin)
        for path, digest in pins.items():
            if c.sha(path) != digest:
                raise ValueError('Actual compiler dependency changed: ' + path)
        c.dump(out / (label + '.dependencies.json'), pins)
        results.append(dict(label=label, exit=proc.returncode, actual_dependencies=len(pins)))
    with (out / 'out/manager.thin.o').open('rb') as stream:
        if stream.read(4) not in (b'BC\xc0\xde', b'\xde\xc0\x17\x0b'):
            raise ValueError('Expected LLVM bitcode object, not a linked library')
    check_known_inputs()
    c.dump(out / 'inside-result.json', dict(success=True, commands=results, linked=False,
           known_read_inputs_unchanged=True, assembly_lowering_review_pending=True,
           final_ThinLTO_codegen_proven=False, savings_proven=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'role-check', 'bind', 'watch', 'inside', 'mount-check'))
    parser.add_argument('--role', choices=c.ROLES)
    parser.add_argument('--packet-sha', required=True)
    parser.add_argument('--container-id')
    args = parser.parse_args()
    if args.mode != 'preflight' and args.role is None:
        parser.error('--role required')
    if args.mode == 'preflight':
        preflight(args.packet_sha)
    elif args.mode == 'role-check':
        role_check(args.role, args.packet_sha)
    elif args.mode == 'bind':
        bind(args.role, args.packet_sha, args.container_id or '')
    elif args.mode == 'watch':
        watch(args.role, args.packet_sha)
    elif args.mode == 'mount-check':
        packet(Path('/inputs'), args.packet_sha)
        rows = container_boundary()
        print(json.dumps(dict(classification='read_only_container_mount_probe', compiler_executed=False,
              protected_mounts=[dict(path=path, flags=sorted(flags)) for path, flags in rows
                                if path == '/build' or path.startswith('/build/') or path in ('/', '/inputs', '/control', '/work', '/tmp')],
              actual_mount_probe_only=True)))
    else:
        inside(args.role, args.packet_sha)
