"""Summarize a completed capture_memory_maps capture after verifying its provenance.

No device commands. Categories describe mapping labels, not allocation ownership
or removable memory. Process captures are sequential, not a whole-phone snapshot.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from summarize_memory_maps import summarize


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runtime_metadata(text,image,boot):
    rows=text.splitlines()
    if len(rows)!=5 or rows[:4]!=[image,boot,'0','Enforcing']:
        raise ValueError('Runtime metadata identity or SELinux mismatch')
    values=rows[4].split()
    if len(values)!=2:raise ValueError('Malformed uptime')
    uptime,idle=map(float,values)
    if not all(math.isfinite(x) and x>=0 for x in [uptime,idle]):raise ValueError('Invalid uptime')
    return uptime


def analyze(root, image, boot):
    manifest_path = root / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('complete') is not True or (manifest['image'], manifest['boot']) != (image, boot):
        raise ValueError('Incomplete capture or wrong image/boot')
    processes = manifest['processes']
    pids = [p['pid'] for p in processes]
    if not 1 <= len(pids) <= 4 or any(type(pid) is not int or pid <= 1 for pid in pids) or len(set(pids)) != len(pids):
        raise ValueError('Invalid or duplicate process identities')
    expected = {'identity-before', 'identity-after'}
    metadata_version=manifest.get('runtime_metadata_version')
    if metadata_version is not None:
        if type(metadata_version) is not int or metadata_version!=1:raise ValueError('Unsupported runtime metadata')
        expected.update(['metadata-before','metadata-after'])
    for pid in pids:
        expected.update(str(pid) + '-' + label for label in ['stat-before', 'cmdline', 'smaps', 'stat-after'])
    records = manifest['reads']
    if len(records) != len(expected) or {r['name'] for r in records} != expected:
        raise ValueError('Missing, extra or duplicate capture reads')
    for record in records:
        path = root / (record['name'] + '.txt')
        if record.get('returncode') != 0 or sha(path) != record['sha256'] or (root / (record['name'] + '.stderr')).read_bytes():
            raise ValueError('Capture exit, hash or stderr mismatch')
    for label in ['identity-before', 'identity-after']:
        if (root / (label + '.txt')).read_text().splitlines() != [image, boot, '0']:
            raise ValueError('Raw image/boot/root mismatch')
    results = []
    timing=None
    if metadata_version==1:
        ages=[runtime_metadata((root/('metadata-'+n+'.txt')).read_text(),image,boot) for n in ['before','after']]
        if ages[1]<ages[0] or ages!=[manifest['uptime_before'],manifest['uptime_after']]:raise ValueError('Runtime metadata timing mismatch')
        timing=dict(before=ages[0],after=ages[1],selinux='Enforcing')
    for process in processes:
        pid = str(process['pid'])
        for label in ['stat-before', 'stat-after']:
            stat = (root / (pid + '-' + label + '.txt')).read_text()
            if not stat.startswith(pid + ' (') or int(stat.rsplit(')', 1)[1].split()[19]) != process['start_ticks']:
                raise ValueError('PID or lifetime mismatch')
        command = (root / (pid + '-cmdline.txt')).read_bytes().split(b'\0')[0].decode().strip()
        if command != process['command']:
            raise ValueError('Command mismatch')
        path = root / (pid + '-smaps.txt')
        summary = summarize(path.read_text())
        results.append(dict(process=process, smaps_sha256=sha(path), **summary))
    return dict(image=image, boot=boot, source_capture=str(root), manifest_sha256=sha(manifest_path),
                analyzer_sha256=sha(Path(__file__)), classifier_sha256=sha(Path(__file__).with_name('summarize_memory_maps.py')),
                processes=results, runtime_metadata=timing, limits=[
                    'Verified capture hashes, successful exits, empty stderr, raw image/boot/root and process command/PID lifetime.',
                    ('Uptime brackets and Enforcing state verified; this remains a sequential diagnostic, not another timed census.' if timing else 'Collector does not record uptime or SELinux state; no exact temporal linkage to another census is claimed.'),
                    'Each process is captured sequentially. Label categories do not prove live allocation reachability, waste or achievable savings.',
                    'PSS, logical SwapPss and graphics allocator capacity are separate views and must not be added as unique physical memory.',
                ])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    for name in ['image', 'boot']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = analyze(a.capture, a.image, a.boot)
    with a.output.open('x') as file:
        file.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps([dict(command=row['process']['command'], total_KiB=row['total_KiB']) for row in result['processes']], indent=2))
