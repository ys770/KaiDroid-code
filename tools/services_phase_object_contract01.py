"""Pure contract for a fresh compile-only diagnostic matrix, never link or stage firmware."""
import hashlib
import json
import shlex
from pathlib import Path, PurePosixPath

HOST_ROOT = '/opt/kaidroid/kaidroid-build-20261023'
NAME = 'memory-services-phase-object02'
BACKING = '/mnt/ext1/kaidroid-services-phase-object02'
BUILDER = 'sha256:fb26aedf6c5b06a1827172f34402fef8fafb233b0d4df6d4271a71ee263e610d'
ROLES = ('55-off', '55-on', '56-off', '56-on')
FLAG = 'KAIDROID_SERVICES_PHASE_DIAGNOSTICS'
COMPILE_RECORD = '21ddab6bdeaa492338fe49002800a26a88be3c77beede1f5eb25cea16442f8bc'
COMMANDS = '73a492f7b5cfe7b3b57048e09cbeff2fe607f1d5fd89206cbe960e4cead5ac2a'
ACQUISITION2 = '437a98e58a6e3529a4c7489a84b98eb6024227b6bdf02f2da9fab639458f965e'
STATIC = '/build/out-eng-02/soong/.intermediates/art/runtime/libart/android_arm_armv7-a-neon_static_com.android.art.release/obj/art/runtime/oat_file_manager.o'
DEADLINE = 1800
GROWTH = 4 * 1024**3
FLOOR = 2 * 1024**3


def sha(path):
    # The pinned builder uses Python 3.10: keep hashing independent of newer APIs.
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def dump(path, value):
    with Path(path).open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def compile_argv(command):
    words = shlex.split(command)
    if words.pop(0) != 'PWD=/proc/self/cwd':
        raise ValueError('Original compiler environment differs')
    if words[0] != 'prebuilts/clang/host/linux-x86/clang-r383902b/bin/clang++':
        raise ValueError('Original compiler differs')
    if words[-1] != 'art/runtime/oat_file_manager.cc' or words.count('-c') != 1:
        raise ValueError('Only the single manager compilation is allowed')
    if words.count('-o') != 1 or words[words.index('-o') + 1] != STATIC or words.count('-MF') != 1 or words[words.index('-MF') + 1] != STATIC + '.d':
        raise ValueError('Original manager output/dependency closure differs')
    for flag in ('-flto=thin', '-fsplit-lto-unit', '-O3', '-std=gnu++17', '-Wthread-safety'):
        if words.count(flag) != 1:
            raise ValueError('Original compiler flags differ: ' + flag)
    return words


def matrix(command, role):
    if role not in ROLES:
        raise ValueError('Unknown matrix role')
    base = compile_argv(command)
    base[base.index('-MF') + 1] = '/work/out/manager.thin.o.d'
    base[base.index('-o') + 1] = '/work/out/manager.thin.o'
    base.insert(len(base) - 1, '-D' + FLAG + '=' + ('1' if role.endswith('-on') else '0'))
    syntax = base.copy()
    syntax[syntax.index('-c')] = '-fsyntax-only'
    pos = syntax.index('-o')
    del syntax[pos:pos + 2]
    syntax[syntax.index('-MF') + 1] = '/work/out/syntax.d'
    assembly = [word for word in base if word not in ('-flto=thin', '-fsplit-lto-unit')]
    assembly[assembly.index('-c')] = '-S'
    assembly.insert(len(assembly) - 1, '-fno-lto')
    assembly[assembly.index('-o') + 1] = '/work/out/manager.review.s'
    assembly[assembly.index('-MF') + 1] = '/work/out/manager.review.s.d'
    return [dict(label='syntax', argv=syntax), dict(label='production-thin-object', argv=base),
            dict(label='nonlto-arm-assembly-review-only', argv=assembly)]


def identities(role):
    if role not in ROLES:
        raise ValueError('Unknown matrix role')
    return 'kaidroid-services-phase-object02-' + role, 'kaidroid-services-phase-object02-' + role + '-watch.service'


def validate_watch_identity(uid, pid, invocation, state):
    import re
    if uid != 0 or not re.fullmatch('[a-f0-9]{32}', invocation) or state.get('MainPID') != str(pid) or state.get('InvocationID') != invocation:
        raise ValueError('Watcher is not the exact root PID1 service main process')


def mounts(role):
    identities(role)
    stage = HOST_ROOT + '/' + NAME
    return [(HOST_ROOT, '/build', 'ro'), (stage + '/inputs', '/inputs', 'ro'),
            (stage + '/work/' + role, '/work', 'rw'),
            (stage + '/control/' + role, '/control', 'ro'),
            (stage + '/inputs/sources/image' + role[:2] + '.cc',
             '/build/aosp/art/runtime/oat_file_manager.cc', 'ro'),
            (stage + '/work/' + role + '/tmp', '/tmp', 'rw')]


def docker_argv(role, pin):
    name, _ = identities(role)
    args = ['sudo', '-n', 'docker', 'run', '-d', '--pull', 'never', '--name', name,
            '--label', 'kaidroid.phase.packet=' + pin, '--label', 'kaidroid.phase.role=' + role,
            '--read-only', '--network', 'none', '--user', '1000:1000', '--cpuset-cpus', '0,1',
            '--cpus', '2', '--memory', '8g', '--memory-swap', '8g', '--pids-limit', '512']
    for source, target, mode in mounts(role):
        if target == '/build':
            args += ['--mount', 'type=bind,src=' + source + ',dst=/build,readonly,bind-recursive=readonly,bind-propagation=rprivate']
        else:
            args += ['-v', source + ':' + target + ':' + mode]
    return args + ['-e', 'TMPDIR=/work/tmp', '-e', 'PYTHONDONTWRITEBYTECODE=1', BUILDER,
                   'timeout', '--signal=TERM', '--kill-after=10s', '1800',
                   'python3', '-B', '/inputs/tools/services_phase_object_job01.py', 'inside',
                   '--role', role, '--packet-sha', pin]


def validate_container(info, role, pin, cid):
    name, _ = identities(role)
    host, config = info['HostConfig'], info['Config']
    if info['Id'] != cid or info['Name'] != '/' + name or info['Image'] != BUILDER:
        raise ValueError('Container identity differs')
    expected_labels = {'kaidroid.phase.packet': pin, 'kaidroid.phase.role': role}
    if any(config.get('Labels', {}).get(k) != v for k, v in expected_labels.items()):
        raise ValueError('Packet/role binding differs')
    if config.get('User') != '1000:1000' or host.get('NetworkMode') != 'none' or host.get('ReadonlyRootfs') is not True or config.get('Entrypoint') not in (None, []):
        raise ValueError('Container boundary differs')
    expected_env = {'PYTHONDONTWRITEBYTECODE=1', 'TMPDIR=/work/tmp',
                    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                    'DEBIAN_FRONTEND=noninteractive', 'LANG=en_US.UTF-8', 'LC_ALL=en_US.UTF-8'}
    if len(config.get('Env', [])) != len(expected_env) or set(config['Env']) != expected_env:
        raise ValueError('Recorded builder environment differs')
    if host.get('Privileged') is not False or host.get('CapAdd') or host.get('Devices') or host.get('DeviceRequests') or host.get('PidMode') not in ('', None):
        raise ValueError('Unreviewed privilege/device/PID boundary')
    declared = host.get('Mounts', [])
    if len(declared) != 1:
        raise ValueError('Explicit recursive-readonly root bind required')
    root = declared[0]
    options = root.get('BindOptions', {})
    if (root.get('Type'), root.get('Source'), root.get('Target'), root.get('ReadOnly')) != ('bind', HOST_ROOT, '/build', True) or options.get('ReadOnlyForceRecursive') is not True or options.get('Propagation') != 'rprivate' or options.get('NonRecursive') or options.get('ReadOnlyNonRecursive') or options.get('CreateMountpoint'):
        raise ValueError('Root bind must force recursive read-only without fallback')
    if (host.get('Memory'), host.get('MemorySwap'), host.get('NanoCpus'), host.get('PidsLimit'), host.get('CpusetCpus')) != (8 * 1024**3, 8 * 1024**3, 2000000000, 512, '0,1'):
        raise ValueError('Resource caps differ')
    expected_command = docker_argv(role, pin)
    expected_command = expected_command[expected_command.index(BUILDER) + 1:]
    if config.get('Cmd') != expected_command:
        raise ValueError('Only the bounded compile-only command is allowed')
    actual = {(r['Source'], r['Destination'], 'rw' if r['RW'] else 'ro') for r in info['Mounts']}
    if len(info['Mounts']) != len(mounts(role)) or actual != set(mounts(role)):
        raise ValueError('Container mount closure differs')


def validate_protected_mounts(rows):
    for required in ('/', '/build', '/inputs', '/control', '/build/aosp/art/runtime/oat_file_manager.cc'):
        matches = [flags for path, flags in rows if path == required]
        if not matches or 'ro' not in matches[-1]:
            raise ValueError('Read-only mount missing: ' + required)
    if any('rw' in flags for path, flags in rows if path.startswith('/build/')):
        raise ValueError('Unexpected writable recursive build submount')


def validate_dependencies(text, read_inputs, source_pin):
    # Reviewed paths contain no spaces; escaped make continuations are accepted.
    if ':' not in text or '\\ ' in text or '\\#' in text:
        raise ValueError('Unreviewed make dependency syntax')
    dependencies = shlex.split(text.replace('\\\n', ' ').split(':', 1)[1])
    if not dependencies:
        raise ValueError('Missing compiler dependencies')
    result = {}
    for value in dependencies:
        path = PurePosixPath(value)
        if not path.is_absolute():
            path = PurePosixPath('/build/aosp') / path
        if '..' in path.parts or not str(path).startswith('/build/'):
            raise ValueError('Dependency left read-only build root')
        host = HOST_ROOT + str(path)[len('/build'):]
        pin = source_pin if str(path) == '/build/aosp/art/runtime/oat_file_manager.cc' else read_inputs.get(host)
        if pin is None:
            raise ValueError('New dependency needs a receipt: ' + str(path))
        result[str(path)] = pin
    return result
