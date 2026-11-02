"""Revalidate a held lazy-camera binary's direct inputs against a local system image.

Reads image/census only. Does not extract blobs, relink, prepare an overlay, use
the build host or operate a phone. Requires the existing dissect.extfs runtime.
"""
import argparse
import hashlib
import json
from pathlib import Path

from dissect.extfs import ExtFS
from summarize_memory_audit import summarize
from summarize_kernel_attribution import slabs


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(a):
    with a.image.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != a.image_sha256:
            raise ValueError('Image identity differs')
    identity = (a.image.stat().st_size, a.image.stat().st_mtime_ns)
    link = json.loads(a.link_evidence.read_text()); prior = json.loads(a.previous_inputs.read_text())
    if link['link_exit_code'] != 0 or link['unresolved_strong_imports'] or sha(a.binary) != link['binary_sha256']:
        raise ValueError('Held binary/link evidence mismatch')
    runtime = {r['image_path']: r['sha256'] for r in link['runtime_files'].values()}
    if len(runtime) != 10 or len(link['needed']) != 10:
        raise ValueError('Unexpected direct runtime closure')
    extra = {p: pin for p, pin in prior['unchanged_files'].items() if p not in runtime}
    files = {}
    with a.image.open('rb') as stream:
        fs = ExtFS(stream)
        props = fs.get('/system/build.prop').open().read().decode()
        if props.splitlines().count('ro.kaidroid.image=' + a.revision) != 1:
            raise ValueError('Image property differs')
        for path, expected in (runtime | extra).items():
            if not path.startswith('/system/'): raise ValueError('Unexpected image path')
            actual = hashlib.sha256(fs.get(path).open().read()).hexdigest()
            files[path] = dict(expected_sha256=expected, actual_sha256=actual, equal=actual == expected,
                               kind='direct_runtime' if path in runtime else 'historical_context_file')
    if (a.image.stat().st_size, a.image.stat().st_mtime_ns) != identity:
        raise ValueError('Image changed during audit')
    manifest = json.loads((a.census / 'manifest.json').read_text())
    if manifest['image'] != a.revision or manifest['boot'] != a.boot:
        raise ValueError('Census identity differs')
    captures = manifest['captures']
    expected = {'identity-before', 'identity-middle', 'identity-after', 'system-before', 'system-after', 'processes', 'services', 'allocators'}
    if len(captures) != len(expected) or {r['name'] for r in captures} != expected:
        raise ValueError('Missing/duplicate census reads')
    for row in captures:
        if row['returncode'] != 0 or sha(a.census / (row['name'] + '.txt')) != row['sha256'] or (a.census / (row['name'] + '.stderr')).read_bytes():
            raise ValueError('Census hash/exit/stderr differs')
    for name in ['identity-before', 'identity-middle', 'identity-after']:
        if (a.census / (name + '.txt')).read_text().splitlines() != [a.revision, a.boot, '0']:
            raise ValueError('Raw census image/boot/root differs')
    census = summarize(a.census)
    if census['omitted']: raise ValueError('Census has omitted processes')
    camera = [p for p in census['processes'] if p['command'].strip() in
              ['/vendor/bin/hw/android.hardware.camera.provider@2.4-service', '/system/bin/cameraserver']]
    if len(camera) != 2: raise ValueError('Require provider and cameraserver observations')
    caches = slabs((a.census / 'allocators.txt').read_text())
    return dict(auditor_sha256=sha(Path(__file__)), image_revision=a.revision, image_sha256=a.image_sha256, binary_sha256=sha(a.binary),
        link_evidence_sha256=sha(a.link_evidence), prior_context_evidence_sha256=sha(a.previous_inputs), files=files,
        all_direct_runtime_files_equal=all(files[p]['equal'] for p in runtime),
        all_historical_context_files_equal=all(files[p]['equal'] for p in extra),
        census=dict(root=str(a.census), boot=a.boot, manifest_sha256=sha(a.census / 'manifest.json'),
                    observed_processes=census['userspace_processes'], omitted=[], camera_processes=camera),
        kernel_scan=dict(global_counters=[{k:s['meminfo'][k] for k in ['Slab','SReclaimable','SUnreclaim','KernelStack','PageTables']} for s in census['snapshots']],
                         slab_cache_count=len(caches), top_object_capacity_caches=caches[:8]),
        candidate_installed_by_this_audit=False, current_image_overlay_prepared_by_this_audit=False, memory_saving_proven=False,
        limits=['Direct runtime file identity carries existing versioned import compatibility only; it does not prove transitive/earlier-directory resolution or live namespaces.',
                'Historical policy/linkerconfig paths are checked as files; active policy selection and loaded policy identity are not established.',
                'No fresh vendor partition, provider executable, running library selection or kernel byte identity was read.',
                'Provider resident PSS and logical SwapPss are separate views. Do not convert logical swap to physical savings using the global compression ratio.',
                'Slab object capacity is not physical slab allocation; inactive objects and nominal geometry do not prove reclaimable pages.',
                'The census is one historical timed snapshot, not a camera workload peak, unique ownership or a before/after lazy-camera experiment.',
                'Callback delivery, zero-client exit, demand restart, repeated camera sessions, latency and physical memory remain trial gates.'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['image', 'binary', 'link-evidence', 'previous-inputs', 'census', 'output']: p.add_argument('--' + name, type=Path, required=True)
    for name in ['image-sha256', 'revision', 'boot']: p.add_argument('--' + name, required=True)
    a = p.parse_args(); report = audit(a)
    with a.output.open('x') as file: file.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(runtime_equal=report['all_direct_runtime_files_equal'], context_equal=report['all_historical_context_files_equal'],
                         camera_processes=report['census']['camera_processes']), indent=2))
