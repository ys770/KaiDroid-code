"""Independent link-only execution contract for the byte-frozen plan04."""
import hashlib
import json
from pathlib import Path
import re

ROOT = '/opt/kaidroid/kaidroid-build-20261023'
NAME = 'memory-services-phase-link01'
BACKING = '/mnt/ext1/kaidroid-services-phase-link01'
BUILDER = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
FROZEN = 'c5470af17f91c48d501d7a14086c239b6cff85f3064df4e1f914a6b2e903ab34'
ROLES = ('55-off', '55-on', '56-off', '56-on')
FLOOR = 2 * 1024**3
GROWTH = 4 * 1024**3
DEADLINE = 1800


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def dump(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def identity(role):
    if role not in ROLES:
        raise ValueError('Exact link role required')
    return 'kaidroid-services-phase-link01-' + role, 'kaidroid-services-phase-link01-' + role + '-watch.service'


def packet(root, pin):
    root = Path(root)
    if root.resolve(strict=True) != root or not re.fullmatch('[a-f0-9]{64}', pin) or sha(root / 'manifest.json') != pin:
        raise ValueError('Execution packet identity differs')
    manifest = json.loads((root / 'manifest.json').read_text())
    if manifest['frozen_plan_manifest_sha256'] != FROZEN or sha(root / 'frozen-plan-manifest.json') != FROZEN:
        raise ValueError('Frozen plan04 identity differs')
    if any(p.is_symlink() for p in root.rglob('*')):
        raise ValueError('Execution input symlink')
    actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual != set(manifest['files']) | {'manifest.json', 'handoff.json'}:
        raise ValueError('Execution packet closure differs')
    for name, digest in manifest['files'].items():
        if Path(name).is_absolute() or '..' in Path(name).parts or sha(root / name) != digest:
            raise ValueError('Execution packet input differs')
    frozen = json.loads((root / 'frozen-plan-manifest.json').read_text())
    for name, digest in frozen['files'].items():
        if sha(root / name) != digest or manifest['files'].get(name) != digest:
            raise ValueError('Frozen plan/payload/recipe changed')
    plan = json.loads((root / 'plan.json').read_text())
    if plan['stage'] != NAME or plan['backing'] != BACKING or tuple(plan['roles']) != ROLES or plan['builder'] != BUILDER:
        raise ValueError('Link profile differs')
    return plan


def mounts(role):
    identity(role)
    stage = ROOT + '/' + NAME
    return [(ROOT, '/build', 'ro'), (stage + '/inputs', '/inputs', 'ro'),
            (stage + '/work/' + role, '/work', 'rw'),
            (stage + '/control/' + role, '/control', 'ro'),
            (stage + '/work/' + role + '/tmp', '/tmp', 'rw')]


def docker(role, pin, probe=False):
    name, _ = identity(role)
    args = ['sudo', '-n', 'docker', 'run', '-d', '--pull', 'never', '--name', name + ('-mountprobe' if probe else ''),
            '--label', 'kaidroid.link.packet=' + pin, '--label', 'kaidroid.link.role=' + role,
            '--read-only', '--network', 'none', '--user', '1000:1000', '--cpuset-cpus', '0,1',
            '--cpus', '2', '--memory', '8g', '--memory-swap', '8g', '--pids-limit', '512']
    for source, target, mode in mounts(role):
        if target == '/build':
            args += ['--mount', 'type=bind,src=' + source + ',dst=/build,readonly,bind-recursive=readonly,bind-propagation=rprivate']
        else:
            args += ['--mount', 'type=bind,src=' + source + ',dst=' + target + (',readonly' if mode == 'ro' else '')]
    return args + ['-e', 'TMPDIR=/work/tmp', '-e', 'PYTHONDONTWRITEBYTECODE=1', BUILDER,
                   'timeout', '--signal=TERM', '--kill-after=10s', '1800', 'python3', '-B',
                   '/inputs/tools/services_phase_link_job01.py', 'mount-check' if probe else 'inside',
                   '--role', role, '--packet-sha', pin]


def validate_container(info, role, pin, cid):
    name, _ = identity(role)
    host, config = info['HostConfig'], info['Config']
    if (info['Id'], info['Name'], info['Image']) != (cid, '/' + name, BUILDER):
        raise ValueError('Link container identity differs')
    if config.get('Labels', {}).get('kaidroid.link.packet') != pin or config.get('Labels', {}).get('kaidroid.link.role') != role:
        raise ValueError('Link packet/role label differs')
    if config.get('User') != '1000:1000' or config.get('Entrypoint') not in (None, []) or host.get('NetworkMode') != 'none' or host.get('ReadonlyRootfs') is not True:
        raise ValueError('Link container boundary differs')
    if host.get('Privileged') is not False or host.get('CapAdd') or host.get('Devices') or host.get('DeviceRequests') or host.get('PidMode') not in ('', None):
        raise ValueError('Unexpected link container privilege')
    if (host.get('Memory'), host.get('MemorySwap'), host.get('NanoCpus'), host.get('PidsLimit'), host.get('CpusetCpus')) != (8 * 1024**3, 8 * 1024**3, 2000000000, 512, '0,1'):
        raise ValueError('Link resource caps differ')
    environment = {'PYTHONDONTWRITEBYTECODE=1', 'TMPDIR=/work/tmp', 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                   'DEBIAN_FRONTEND=noninteractive', 'LANG=en_US.UTF-8', 'LC_ALL=en_US.UTF-8'}
    if len(config.get('Env', [])) != len(environment) or set(config['Env']) != environment:
        raise ValueError('Link builder environment differs')
    command = docker(role, pin)
    if config.get('Cmd') != command[command.index(BUILDER) + 1:]:
        raise ValueError('Link entry command differs')
    actual = {(row['Source'], row['Destination'], 'rw' if row['RW'] else 'ro') for row in info['Mounts']}
    if len(info['Mounts']) != 5 or actual != set(mounts(role)):
        raise ValueError('Link mount closure differs')
    declared = host.get('Mounts', [])
    if len(declared) != 5:
        raise ValueError('All link binds must be explicit --mount')
    if {(row.get('Source'), row.get('Target'), 'ro' if row.get('ReadOnly', False) else 'rw') for row in declared} != set(mounts(role)) or any(row.get('Type') != 'bind' for row in declared):
        raise ValueError('Declared link bind closure differs')
    root = next((row for row in declared if row.get('Target') == '/build'), {})
    options = root.get('BindOptions', {})
    if root.get('ReadOnly') is not True or options.get('ReadOnlyForceRecursive') is not True or options.get('Propagation') != 'rprivate' or options.get('ReadOnlyNonRecursive') or options.get('NonRecursive') or options.get('CreateMountpoint'):
        raise ValueError('Recursive readonly root bind differs')


def protected_mounts(rows):
    for required in ('/', '/build', '/inputs', '/control'):
        flags = [mode for name, mode in rows if name == required]
        if not flags or 'ro' not in flags[-1]:
            raise ValueError('Read-only link boundary missing')
    if any('rw' in mode for name, mode in rows if name.startswith('/build/')):
        raise ValueError('Writable nested link input mount')


def watcher_identity(uid, pid, invocation, state):
    if uid != 0 or not re.fullmatch('[a-f0-9]{32}', invocation) or state.get('MainPID') != str(pid) or state.get('InvocationID') != invocation:
        raise ValueError('Link watcher is not the root PID1 main process')
