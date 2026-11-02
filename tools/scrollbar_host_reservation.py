"""Read-only, fresh host/container reservation attestation for scrollbar builds.

No container names/IDs are allowlisted. Inspect output is reduced immediately;
environment variables and process arguments are never recorded or printed.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import posixpath
import re
import subprocess
import sys
import time

ROOT = '/opt/kaidroid/kaidroid-build-20261023'
BACKING = '/mnt/ext1/kaidroid-tcl-scrollbar-build01'
GIB = 1024 ** 3
BUILD_PROCESSES = {'ninja', 'soong_build', 'soong_ui', 'e2fsdroid'}


def require(value, message):
    if not value:
        raise ValueError(message)


def within(path, parent):
    return path == parent or path.startswith(parent.rstrip('/') + '/')


def normalized(path):
    require(isinstance(path, str) and path.startswith('/') and posixpath.normpath(path) == path,
            'Absolute canonical path required')
    return path


def conflicts(a, b):
    for key in ('resolved', 'physical'):
        normalized(a[key]); normalized(b[key])
    return (within(a['resolved'], b['resolved']) or within(b['resolved'], a['resolved']) or
            a['device'] == b['device'] and
            (within(a['physical'], b['physical']) or within(b['physical'], a['physical'])))


def mount_rows(text):
    def decode(value):
        return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
    result = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and '-' in fields, 'Incomplete host mountinfo')
        require(re.fullmatch(r'\d+:\d+', fields[2]), 'Invalid mount device')
        root = decode(fields[3])
        separator = fields.index('-')
        require(separator + 3 < len(fields), 'Incomplete host filesystem fields')
        namespace = None
        if fields[separator+1] == 'nsfs':
            match = re.fullmatch(r'(mnt|net|uts|ipc|pid|user|cgroup|time):\[([0-9]+)\]', root)
            require(match is not None, 'Malformed namespace mount root')
            namespace = dict(kind=match[1], inode=int(match[2]))
        else:
            normalized(root)
        result.append(dict(device=fields[2], root=root, namespace=namespace,
                           mountpoint=normalized(decode(fields[4]))))
    require(result, 'Missing host mount table')
    return result


def mount_location(resolved, existing, device, mounts):
    normalized(resolved); normalized(existing)
    choices = [m for m in mounts if m['device'] == device and within(existing, m['mountpoint'])]
    require(choices, 'Mount source device cannot be resolved')
    length = max(len(m['mountpoint']) for m in choices)
    choices = [m for m in choices if len(m['mountpoint']) == length]
    require(len(choices) == 1, 'Ambiguous host mount alias')
    chosen = choices[0]
    require(chosen['namespace'] is None, 'Namespace file selected as protected/container source')
    suffix = posixpath.relpath(resolved, chosen['mountpoint'])
    physical = posixpath.normpath(posixpath.join(chosen['root'], suffix))
    return physical


def path_record(path, mounts, allow_missing=False):
    p = Path(path).resolve(strict=not allow_missing)
    existing = p
    while not existing.exists():
        require(allow_missing and existing != existing.parent, 'Mount source missing')
        existing = existing.parent
    stat = existing.stat()
    device = str(os.major(stat.st_dev)) + ':' + str(os.minor(stat.st_dev))
    physical = mount_location(str(p),str(existing),device,mounts)
    return dict(requested=str(path), resolved=str(p), device=device, physical=physical)


def memory_bytes(value):
    match = re.fullmatch(r'([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|KiB|MB|MiB|GB|GiB|TB|TiB)', value)
    require(match is not None, 'Unknown Docker memory units')
    scales = dict(B=1, kB=1000, KB=1000, KiB=1024, MB=1000**2, MiB=1024**2,
                  GB=1000**3, GiB=1024**3, TB=1000**4, TiB=1024**4)
    return int(float(match[1]) * scales[match[2]])


def validate(snapshot):
    require(snapshot['running_before'] == snapshot['running_after'], 'Container set changed during attestation')
    ids = snapshot['running_before']
    require(len(ids) == len(set(ids)) and all(re.fullmatch(r'[a-f0-9]{64}', x) for x in ids), 'Full unique Docker IDs required')
    require(set(ids) == {c['id'] for c in snapshot['containers']} and len(ids) == len(snapshot['containers']), 'Inspect coverage differs')
    require(0 <= snapshot['elapsed_seconds'] <= 30, 'Host observation is stale/too slow')
    require(snapshot['memory_available_bytes'] >= 16 * GIB, 'Insufficient fresh RAM headroom')
    require(snapshot['root_free_bytes'] >= 20 * GIB and snapshot['external_free_bytes'] >= 34 * GIB,
            'Host storage floors do not support the original build budget')
    require(snapshot['cpu_count'] >= 4, 'Insufficient host CPU headroom')
    require(snapshot['shared_build_processes'] == [], 'Shared compiler/preparation process is active')
    require(snapshot['protected_paths'] and snapshot['protected_root'] == ROOT, 'Protected source/cache coverage absent')
    require({ROOT, BACKING} <= {p['requested'] for p in snapshot['protected_paths']},
            'Source and fixed backing coverage are both required')
    total_cpu = 0.0
    total_memory = 0
    total_pids = 0
    for container in snapshot['containers']:
        require(container['running'] is True and container['paused'] is False and
                container['restarting'] is False and container['dead'] is False and
                container['oom_killed'] is False and type(container['pid']) is int and container['pid'] > 0,
                'Container is not stably running')
        host = container['host']
        require(host['Privileged'] is False, 'Privileged unrelated container cannot be isolated by mount inspection')
        require(not any(host[k] for k in ('CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'VolumesFrom')),
                'Extra capabilities/devices/inherited volumes require independent isolation review')
        require(host['PidMode'] in ('', 'private') and host['IpcMode'] in ('', 'private', 'shareable') and
                host['UTSMode'] in ('', 'private') and host['CgroupnsMode'] in ('', 'private') and
                host['UsernsMode'] in ('', 'private'), 'Host/shared namespaces are not isolated')
        require(isinstance(host['NetworkMode'], str) and host['NetworkMode'] and
                host['NetworkMode'] != 'host' and not host['NetworkMode'].startswith('container:'),
                'Host/shared network namespace')
        require(host['SecurityOpt'] is None or isinstance(host['SecurityOpt'], list), 'Invalid security options')
        require(all(x in ('no-new-privileges', 'no-new-privileges:true') for x in (host['SecurityOpt'] or [])),
                'Nondefault security relaxation requires independent review')
        require(not container['kaidroid_marked'], 'Existing KaiDroid container; observe that job')
        require(not (set(container['process_names']) & BUILD_PROCESSES), 'Compiler process inside an existing container')
        for mount in container['mounts']:
            require(type(mount['rw']) is bool and mount['propagation'] in ('', 'private', 'rprivate'), 'Unattested/shared-propagation mount')
            if mount['type'] == 'tmpfs':
                require(mount['source'] is None, 'Unexpected tmpfs host source')
                continue
            require(mount['type'] in ('bind', 'volume') and mount['source'] is not None, 'Unattested mount type/source')
            for source in [mount['source']] + mount['nested_sources']:
                normalized(source['resolved'])
                require(not any(conflicts(source, protected) for protected in snapshot['protected_paths']),
                        'Container mount overlaps protected source/cache, including physical/nested aliases')
                require(posixpath.basename(source['resolved']) not in ('docker.sock', 'containerd.sock', 'podman.sock', 'crio.sock'),
                        'Container runtime control socket exposed, including read-only bind')
                require(not any(within(source['resolved'], tree) or within(tree, source['resolved'])
                                for tree in ('/proc', '/sys', '/dev', '/run', '/var/run', '/var/lib/docker')),
                        'Sensitive host control/device tree exposed')
        stats = container['stats']
        require(isinstance(stats['cpu_cores'], (int, float)) and math.isfinite(stats['cpu_cores']) and stats['cpu_cores'] >= 0,
                'Invalid fresh CPU observation')
        require(type(stats['memory_bytes']) is int and stats['memory_bytes'] >= 0 and
                type(stats['pids']) is int and stats['pids'] >= 1, 'Invalid fresh memory/PID observation')
        total_cpu += stats['cpu_cores']; total_memory += stats['memory_bytes']; total_pids += stats['pids']
    require(total_cpu <= 1 and total_memory <= 8 * GIB and total_pids <= 4096, 'Other container resource use exceeds reservation headroom')
    return dict(full_container_ids=ids, unrelated_containers=len(ids), other_cpu_cores=total_cpu,
                other_memory_bytes=total_memory, other_pids=total_pids,
                memory_available_bytes=snapshot['memory_available_bytes'], root_free_bytes=snapshot['root_free_bytes'],
                external_free_bytes=snapshot['external_free_bytes'],
                all_mounts_and_privileges_attested=True, original_build_caps_unchanged=True,
                unbounded_other_container_limits_possible=True, future_resource_use_guaranteed=False,
                containers=[dict(id=c['id'], host_limits=c.get('limits', {}), mounts=c['mounts']) for c in snapshot['containers']],
                observed_at_unix=snapshot['observed_at_unix'], elapsed_seconds=snapshot['elapsed_seconds'])


def verify(root, run):
    require(os.name == 'posix' and str(root) == ROOT, 'Use the exact Linux host root')
    start = time.monotonic()
    mounts_text = Path('/proc/self/mountinfo').read_text()
    mounts = mount_rows(mounts_text)
    protected = sorted({ROOT, BACKING} | {str(p) for p in Path('/mnt/ext1').glob('kaidroid-*')})
    paths = [path_record(p, mounts, allow_missing=True) for p in protected]
    def ids():
        lines = run(['sudo', '-n', 'docker', 'ps', '--no-trunc', '-q']).stdout.splitlines()
        require(all(re.fullmatch(r'[a-f0-9]{64}', x) for x in lines), 'Docker IDs not full length')
        return sorted(lines)
    before = ids()
    containers = []
    stats = {}
    if before:
        for line in run(['sudo', '-n', 'docker', 'stats', '--no-stream', '--no-trunc', '--format', '{{json .}}'] + before).stdout.splitlines():
            row = json.loads(line)
            cid = row['ID']
            require(cid in before and cid not in stats, 'Docker stats ID coverage changed')
            require(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?%', row['CPUPerc']), 'Invalid Docker CPU units')
            stats[cid] = dict(cpu_cores=float(row['CPUPerc'][:-1])/100,
                              memory_bytes=memory_bytes(row['MemUsage'].split('/')[0].strip()), pids=int(row['PIDs']))
        require(set(stats) == set(before), 'Incomplete Docker stats')
        inspected = json.loads(run(['sudo', '-n', 'docker', 'inspect'] + before).stdout)
        host_keys = ('Privileged', 'CapAdd', 'Devices', 'DeviceRequests', 'DeviceCgroupRules', 'VolumesFrom',
                     'PidMode', 'IpcMode', 'UTSMode', 'CgroupnsMode', 'UsernsMode', 'NetworkMode', 'SecurityOpt')
        for data in inspected:
            cid = data['Id']
            require(cid in before, 'Unexpected container inspection')
            state = data['State']; host = data['HostConfig']; config = data['Config']
            top = run(['sudo', '-n', 'docker', 'top', cid, '-eo', 'pid,comm']).stdout.splitlines()
            require(top and top[0].split() == ['PID', 'COMMAND'], 'Unexpected Docker process columns')
            names = []
            for line in top[1:]:
                fields = line.split(); require(len(fields) == 2 and fields[0].isdigit(), 'Ambiguous Docker process row')
                names.append(fields[1])
            reduced_mounts = []
            for mount in data['Mounts']:
                kind = mount['Type']
                source = None if kind == 'tmpfs' else path_record(mount['Source'], mounts)
                nested = []
                if source is not None:
                    for child in mounts:
                        if child['mountpoint'] != source['resolved'] and within(child['mountpoint'],source['resolved']):
                            nested.append(path_record(child['mountpoint'],mounts))
                reduced_mounts.append(dict(type=kind, rw=mount['RW'], propagation=mount.get('Propagation', ''),
                                           source=source,nested_sources=nested))
            containers.append(dict(id=cid, running=state['Running'], paused=state['Paused'], restarting=state['Restarting'],
                                   dead=state['Dead'], oom_killed=state['OOMKilled'], pid=state['Pid'],
                                   host={k: host[k] for k in host_keys}, process_names=names, mounts=reduced_mounts,
                                   limits={k: host[k] for k in ('Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit')},
                                   kaidroid_marked=('kaidroid' in config['Image'].lower() or 'kaidroid' in data['Name'].lower() or
                                                     any(k.startswith('kaidroid.') for k in (config['Labels'] or {}))), stats=stats[cid]))
    after = ids()
    processes = []
    for name in sorted(BUILD_PROCESSES):
        probe = subprocess.run(['pgrep', '-x', name], capture_output=True, text=True, timeout=15)
        require(probe.returncode in (0, 1), 'Cannot attest compiler process absence')
        if probe.returncode == 0:
            require(all(p.isdigit() for p in probe.stdout.splitlines()), 'Ambiguous compiler PID output')
            processes.append(name)
    mem = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    require(mem is not None, 'Missing host MemAvailable')
    free = lambda p: os.statvfs(p).f_bavail * os.statvfs(p).f_frsize
    snapshot = dict(running_before=before, running_after=after, containers=containers, protected_root=ROOT,
                    protected_paths=paths, shared_build_processes=processes, memory_available_bytes=int(mem[1])*1024,
                    cpu_count=os.cpu_count(), root_free_bytes=free(ROOT), external_free_bytes=free('/mnt/ext1'),
                    elapsed_seconds=time.monotonic()-start, observed_at_unix=time.time())
    result = validate(snapshot)
    result['sanitized_snapshot_sha256'] = hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    print('KAIDROID_RESERVATION_ATTESTATION ' + json.dumps(result, sort_keys=True), file=sys.stderr)
    return result
