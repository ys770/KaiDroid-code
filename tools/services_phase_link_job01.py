"""Link-only driver for frozen plan04. No launch, compile frontend, cleanup or device mode."""
import sys
sys.dont_write_bytecode = True
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import struct
import subprocess
import time
import services_phase_link_contract01 as c

STAGE = Path(c.ROOT) / c.NAME


def tree(root, hash_files=False):
    rows = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in private link stage')
        if path.is_file():
            rows[path.relative_to(root).as_posix()] = dict(size=path.stat().st_size)
            if hash_files:
                rows[path.relative_to(root).as_posix()]['sha256'] = c.sha(path)
    return rows


def external():
    backing = Path(c.BACKING)
    if STAGE.resolve(strict=True) != STAGE or backing.resolve(strict=True) != backing:
        raise ValueError('Link stage/backing symlink')
    a, b = STAGE.stat(), backing.stat()
    if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
        raise ValueError('Link stage does not identify exact backing inode')
    for path in (STAGE, backing, Path('/mnt/ext1')):
        st = path.stat()
        if not path.is_dir() or (st.st_dev, st.st_uid, st.st_gid, st.st_mode & 0o777) != (2048, 1000, 1000, 0o700):
            raise ValueError('External link directory profile differs')
    if Path(c.ROOT).stat().st_dev != 66306:
        raise ValueError('Host root device differs')
    entries = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = line.split(' - ')
        left, right = left.split(), right.split()
        if left[4] == str(STAGE):
            entries.append((left, right))
    if len(entries) != 1:
        raise ValueError('Link bind missing/ambiguous')
    left, right = entries[0]
    if (left[2], left[3], right[0], right[1]) != ('8:0', '/' + backing.name, 'ext4', '/dev/sda') or 'rw' not in left[5].split(',') or 'rw' not in right[2].split(','):
        raise ValueError('External link bind changed')
    if min(shutil.disk_usage(STAGE).free, shutil.disk_usage(c.ROOT).free) <= c.FLOOR:
        raise ValueError('Link emergency free floor reached')


def idle():
    for name in ('ninja', 'soong_build', 'e2fsdroid', 'clang', 'clang++', 'ld.lld', 'lld'):
        if subprocess.run(['pgrep', '-x', name], capture_output=True, timeout=5).returncode != 1:
            raise ValueError('Host job active/unknown: ' + name)
    if subprocess.check_output(['sudo', '-n', 'docker', 'ps', '-q'], text=True, timeout=15).strip():
        raise ValueError('Another container is active')


def preflight(pin):
    if os.getuid() != 1000:
        raise ValueError('Assigned UID1000 required')
    external()
    c.packet(STAGE / 'inputs', pin)
    if {p.name for p in STAGE.iterdir()} != {'inputs'}:
        raise ValueError('Link stage is not fresh; never reset/retry it')
    idle()
    if not {0, 1}.issubset(os.sched_getaffinity(0)) or shutil.disk_usage(STAGE).free < c.GROWTH + c.FLOOR:
        raise ValueError('Reviewed link capacity/CPUs unavailable')
    for directory in ('work', 'control'):
        (STAGE / directory).mkdir(mode=0o700)
        for role in c.ROLES:
            path = STAGE / directory / role
            path.mkdir(mode=0o700)
            if directory == 'work':
                for name in ('unstripped', 'stripped', 'tmp'):
                    (path / name).mkdir(mode=0o700)
    st = STAGE.stat()
    c.dump(STAGE / 'host-proof.json', dict(packet_sha256=pin, device=st.st_dev, inode=st.st_ino,
           initial_bytes=sum(row['size'] for row in tree(STAGE).values())))


def host_check(pin):
    external()
    c.packet(STAGE / 'inputs', pin)
    proof = json.loads((STAGE / 'host-proof.json').read_text())
    st = STAGE.stat()
    if (proof['packet_sha256'], proof['device'], proof['inode']) != (pin, st.st_dev, st.st_ino):
        raise ValueError('Frozen link host identity differs')
    if sum(row['size'] for row in tree(STAGE).values()) - proof['initial_bytes'] >= c.GROWTH:
        raise ValueError('Whole link-matrix output budget reached')


def previous_roles(role):
    c.identity(role)
    for previous in c.ROLES[:c.ROLES.index(role)]:
        if json.loads((STAGE / 'control' / previous / 'terminal.json').read_text()).get('success') is not True:
            raise ValueError('Previous link role did not pass')


def role_check(role, pin):
    if os.getuid() != 1000:
        raise ValueError('Assigned UID1000 required')
    host_check(pin)
    idle()
    work, control = STAGE / 'work' / role, STAGE / 'control' / role
    if any(control.iterdir()) or {p.name for p in work.iterdir()} != {'unstripped', 'stripped', 'tmp'} or any(any((work / name).iterdir()) for name in ('unstripped', 'stripped', 'tmp')):
        raise ValueError('Link role has already been used')
    previous_roles(role)


def bind(role, pin, cid):
    if os.getuid() != 1000 or not re.fullmatch('[a-f0-9]{64}', cid):
        raise ValueError('Exact CID and assigned user required')
    host_check(pin)
    previous_roles(role)
    info = json.loads(subprocess.check_output(['sudo', '-n', 'docker', 'inspect', cid], timeout=15))[0]
    c.validate_container(info, role, pin, cid)
    c.dump(STAGE / 'control' / role / 'launch.json', dict(cid=cid, role=role, packet_sha256=pin, monotonic=time.monotonic()))


def unit_state(unit):
    text = subprocess.check_output(['systemctl', 'show', unit, '--no-pager', '--property=MainPID,InvocationID,ActiveState'], text=True, timeout=15)
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


def watch(role, pin):
    _, unit = c.identity(role)
    invocation = os.environ.get('INVOCATION_ID', '')
    c.watcher_identity(os.geteuid(), os.getpid(), invocation, unit_state(unit))
    host_check(pin)
    previous_roles(role)
    control = STAGE / 'control' / role
    launch = json.loads((control / 'launch.json').read_text())
    if (launch['role'], launch['packet_sha256']) != (role, pin):
        raise ValueError('Link launch record differs')
    cid = launch['cid']
    inspect = lambda: json.loads(subprocess.check_output(['docker', 'inspect', cid], timeout=15))[0]
    info = inspect()
    c.validate_container(info, role, pin, cid)
    record = dict(packet_sha256=pin, role=role, cid=cid, unit=unit, invocation_id=invocation, pid=os.getpid(), uid=0)
    c.dump(control / 'ready.json', record)
    reason = None
    try:
        while True:
            temporary = control / 'heartbeat.new'
            temporary.write_text(json.dumps({**record, 'monotonic': time.monotonic()}))
            os.replace(temporary, control / 'heartbeat.json')
            info = inspect()
            c.validate_container(info, role, pin, cid)
            if not info['State']['Running']:
                break
            try:
                host_check(pin)
                if time.monotonic() - launch['monotonic'] >= c.DEADLINE:
                    raise ValueError('Link deadline reached')
            except ValueError as error:
                reason = str(error)
                subprocess.run(['docker', 'kill', cid], check=True, capture_output=True, timeout=15)
            time.sleep(2)
    except BaseException as error:
        c.dump(control / 'watcher-failure.json', dict(error=repr(error), same_container=cid, relaunch_allowed=False))
        raise  # No heartbeat after failure; inside guard and independent timeout remain.
    post_error = None
    try:
        host_check(pin)
    except Exception as error:
        post_error = repr(error)
    inside = STAGE / 'work' / role / 'inside-result.json'
    result = json.loads(inside.read_text()) if inside.exists() else {}
    c.dump(control / 'container.inspect.json', info)
    logs = subprocess.run(['docker', 'logs', cid], capture_output=True, timeout=30)
    (control / 'docker.stdout').write_bytes(logs.stdout)
    (control / 'docker.stderr').write_bytes(logs.stderr)
    success = info['State']['ExitCode'] == 0 and not info['State']['OOMKilled'] and reason is None and post_error is None and result.get('success') is True
    c.dump(control / 'terminal.json', dict(**record, success=success, exit_code=info['State']['ExitCode'],
           oom_killed=info['State']['OOMKilled'], stop_reason=reason, post_error=post_error,
           final_code_ABI_review_complete=False, installed=False, savings_proven=False))


def container_boundary():
    if os.getuid() != 1000 or sorted(os.sched_getaffinity(0)) != [0, 1]:
        raise ValueError('Link container user/CPU affinity differs')
    for name, value in [('memory.max', '8589934592'), ('memory.swap.max', '0'), ('pids.max', '512')]:
        if (Path('/sys/fs/cgroup') / name).read_text().strip() != value:
            raise ValueError('Link cgroup cap differs')
    rows = [(line.split(' - ')[0].split()[4], set(line.split(' - ')[0].split()[5].split(',')))
            for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    c.protected_mounts(rows)
    for name in ('/work', '/tmp'):
        flags = [mode for path, mode in rows if path == name]
        if not flags or 'rw' not in flags[-1] or Path(name).stat().st_dev != 2048:
            raise ValueError('Link work/tmp left external backing')
    return rows


def live(role, pin):
    path = Path('/control/heartbeat.json')
    record = json.loads(path.read_text())
    if path.stat().st_uid != 0 or record['uid'] != 0 or (record['role'], record['packet_sha256'], record['unit']) != (role, pin, c.identity(role)[1]) or not re.fullmatch('[a-f0-9]{32}', record['invocation_id']):
        raise ValueError('Link PID1 heartbeat binding differs')
    if not 0 <= time.monotonic() - record['monotonic'] <= 15:
        raise ValueError('Link watchdog heartbeat stale')
    if min(shutil.disk_usage('/work').free, shutil.disk_usage('/build').free) <= c.FLOOR:
        raise ValueError('Link free floor reached')
    if sum(row['size'] for row in tree(Path('/work')).values()) >= c.GROWTH:
        raise ValueError('Private link output budget reached')


def stop_group(process):
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def run_phase(label, spec, work, cwd, guard):
    guard()
    process = None
    error = None
    try:
        with (work / (label + '.stdout')).open('xb') as stdout, (work / (label + '.stderr')).open('xb') as stderr:
            process = subprocess.Popen(spec['argv'], cwd=cwd, env={**os.environ, **spec['environment']},
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            while process.poll() is None:
                guard()
                time.sleep(1)
        if process.returncode:
            raise ValueError('Link pipeline phase failed: ' + label)
    except BaseException as exception:
        error = repr(exception)
        if process is not None and process.poll() is None:
            stop_group(process)
        raise
    finally:
        c.dump(work / (label + '.exit.json'), dict(argv=spec['argv'], exit=process.returncode if process else None, error=error))


def execute_phases(recipe, work, guard):
    for label in ('link', 'strip'):
        run_phase(label, recipe[label], work, recipe['cwd'], guard)


def check_inputs(plan, role):
    result = {}
    for path, row in plan['unchanged_read_inputs'].items():
        if not path.startswith('/build/') or Path(path).resolve(strict=True) != Path(path) or c.sha(path) != row['sha256']:
            raise ValueError('Link binary input drift: ' + path)
        result[path] = row['sha256']
    for host, row in plan['required_direct_tools'].items():
        path = '/build' + host[len(c.ROOT):]
        resolved = '/build' + row['resolved'][len(c.ROOT):]
        if str(Path(path).resolve(strict=True)) != resolved or c.sha(path) != row['sha256']:
            raise ValueError('Link/strip tool drift: ' + path)
        result[path] = row['sha256']
    script = Path('/build/aosp/build/soong/scripts/strip.sh')
    if c.sha(script) != c.sha(Path('/inputs/receipts/strip.sh')):
        raise ValueError('Actual strip script differs')
    result[str(script)] = c.sha(script)
    runtime = json.loads(Path('/inputs/receipts/runtime-container02.json').read_text())
    for row in runtime['files']:
        if str(Path(row['path']).resolve(strict=True)) != row['resolved'] or c.sha(row['path']) != row['sha256']:
            raise ValueError('Pinned builder native runtime drift')
        result[row['path']] = row['sha256']
    source = Path(plan['jobs'][role]['manager_input']['path'])
    if c.sha(source) != plan['jobs'][role]['manager_input']['sha256']:
        raise ValueError('Actual manager bitcode differs')
    result[str(source)] = c.sha(source)
    return result


def elf_header(path):
    with path.open('rb') as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:6] != b'\x7fELF\x01\x01' or struct.unpack_from('<HH', header, 16) != (3, 40):
        raise ValueError('Expected ARM32 little-endian shared linked ELF')


def inside(role, pin):
    container_boundary()
    plan = c.packet(Path('/inputs'), pin)
    for _ in range(120):
        if Path('/control/ready.json').exists() and Path('/control/heartbeat.json').exists():
            break
        time.sleep(1)
    else:
        raise ValueError('No root PID1 link barrier; linker never started')
    work = Path('/work')
    if {p.name for p in work.iterdir()} != {'unstripped', 'stripped', 'tmp'} or any(any((work / name).iterdir()) for name in ('unstripped', 'stripped', 'tmp')):
        raise ValueError('Link role output is not fresh')
    live(role, pin)
    c.dump(work / 'started.json', dict(role=role, packet_sha256=pin, frozen_plan_sha256=c.FROZEN, link_only=True))
    error = None
    before = None
    try:
        before = check_inputs(plan, role)
        c.dump(work / 'input-before.json', before)
        utilities = {}
        for name in ('bash', 'awk', 'xargs', 'rm', 'mv', 'cat'):
            path = shutil.which(name)
            if path is None or not str(Path(path).resolve()).startswith('/usr/bin/'):
                raise ValueError('Unreviewed builder shell utility')
            utilities[name] = dict(path=path, resolved=str(Path(path).resolve()), sha256=c.sha(path))
        c.dump(work / 'shell-utilities.json', utilities)
        execute_phases(plan['jobs'][role], work, lambda: live(role, pin))
        elf_header(work / 'unstripped/libart.so')
        elf_header(work / 'stripped/libart.so')
        if {p.name for p in (work / 'unstripped').iterdir()} != {'libart.so'} or {p.name for p in (work / 'stripped').iterdir()} != {'libart.so', 'libart.so.d'} or any((work / 'tmp').iterdir()) or not (work / 'link.map').is_file():
            raise ValueError('Unexpected persistent link/strip outputs or temporary leftovers')
        after = check_inputs(plan, role)
        c.dump(work / 'input-after.json', after)
        if after != before:
            raise ValueError('Link read-input set changed')
    except BaseException as exception:
        error = repr(exception)
        raise
    finally:
        inventory = tree(work, hash_files=True)
        c.dump(work / 'file-inventory.json', inventory)
        c.dump(work / 'inside-result.json', dict(success=error is None, role=role, packet_sha256=pin,
               error=error, known_inputs_verified=before is not None, completed_link_and_strip=error is None,
               final_code_ABI_review_complete=False, installed=False, savings_proven=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('preflight', 'role-check', 'bind', 'watch', 'inside', 'mount-check'))
    parser.add_argument('--role', choices=c.ROLES)
    parser.add_argument('--packet-sha', required=True)
    parser.add_argument('--container-id')
    args = parser.parse_args()
    if args.mode != 'preflight' and args.role is None:
        parser.error('--role is required')
    if args.mode == 'preflight':
        preflight(args.packet_sha)
    elif args.mode == 'role-check':
        role_check(args.role, args.packet_sha)
    elif args.mode == 'bind':
        bind(args.role, args.packet_sha, args.container_id or '')
    elif args.mode == 'watch':
        watch(args.role, args.packet_sha)
    elif args.mode == 'mount-check':
        c.packet(Path('/inputs'), args.packet_sha)
        print(json.dumps(dict(classification='link_mount_probe_only', rows=[(name, sorted(flags)) for name, flags in container_boundary()], linker_executed=False)))
    else:
        inside(args.role, args.packet_sha)
