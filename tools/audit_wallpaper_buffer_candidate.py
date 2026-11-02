"""Bind saved allocator/geometry captures to a held wallpaper source candidate."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from summarize_dma_ion_capture import dma_buffers, summarize


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(work, capture):
    source = json.loads((work / 'source-manifest.json').read_text())
    for record in source['files']:
        if digest(work / 'source' / record['path']) != record['sha256']:
            raise ValueError('Source snapshot hash mismatch')
    old = []
    for image, name in [('43', 'image43-memory-madvise-baseline300-01'),
                        ('44', 'image44-memory-madvise300-01')]:
        report = summarize(Path('artifacts/runtime') / name / 'timed/census')
        if report['image'] != image:
            raise ValueError('Census image mismatch')
        old.append(report)
    identity = (capture / 'identity.txt').read_text().splitlines()
    if len(identity) != 3 or identity[0] != '44' or not re.fullmatch(r'[0-9a-f-]{36}', identity[1]) or not re.fullmatch(r'\d+ \d+', identity[2]):
        raise ValueError('Snapshot identity mismatch')
    text = (capture / 'surfaceflinger.txt').read_text()
    rows = re.findall(r'^\S+:\s+([\d.]+) KiB \|\s+(\d+)\s+\(\s*(\d+)\) x\s*(\d+) \|\s+(\d+) \|\s+(\d+) \| (\S+) \| com.android.systemui.ImageWallpaper#0$', text, re.M)
    if len(rows) != 1:
        raise ValueError('Expected one named wallpaper allocation')
    kib, width, stride, height, layers, fmt, usage = rows[0]
    allocation = dict(reported_capacity_bytes=int(float(kib)*1024), width=int(width),
                      stride_pixels=int(stride), height=int(height), layers=int(layers),
                      format=int(fmt), usage=usage, owner='com.android.systemui.ImageWallpaper#0')
    if allocation['reported_capacity_bytes'] != 5111808 or (allocation['width'], allocation['height'], allocation['stride_pixels'], allocation['format']) != (1243,1024,1664,3):
        raise ValueError('Reviewed wallpaper allocation changed')
    current_dma = dma_buffers((capture / 'dmabuf.txt').read_text())
    window = (capture / 'window.txt').read_text()
    wallpaper = (capture / 'wallpaper.txt').read_text()
    for expected in ['Requested w=1243 h=1024', '(388x320)', 'mHScale=0.31214803 mVScale=0.3125',
                     'width=240, height=320', 'mWallpaperZoomOut=0.0']:
        if expected not in window:
            raise ValueError('Reviewed window geometry changed: '+expected)
    if 'mWidth=480  mHeight=320' not in wallpaper or 'User 0: id=2' not in wallpaper:
        raise ValueError('Wallpaper settings changed')
    candidate = json.loads((work / 'candidate/candidate.json').read_text())
    patch = Path('experiments/memory/wallpaper-buffer01.patch')
    if candidate['patch_sha256'] != digest(patch):
        raise ValueError('Candidate patch hash mismatch')
    for file in candidate['files']:
        if digest(work / 'candidate' / file['path']) != file['candidate_sha256']:
            raise ValueError('Candidate source hash mismatch')
    controls = json.loads((work / 'controls02/result.json').read_text())
    if controls['source_hashes'] != candidate['files'] or controls['fixture_sha256'] != digest(Path('tests/fixtures/memory_wallpaper_host01.java')):
        raise ValueError('Host controls are stale')
    return dict(status='offline source candidate; no target build/installation',
                source_snapshot=source, saved_census_reports=old,
                current_snapshot=dict(capture=str(capture), image=identity[0], boot=identity[1],
                    system_server_pid=int(identity[2].split()[0]),system_ui_pid=int(identity[2].split()[1]),
                    files=[dict(path=str(p),bytes=p.stat().st_size,sha256=digest(p)) for p in sorted(capture.glob('*.txt'))],
                    wallpaper_allocation=allocation,
                    dma_exported_capacity_bytes=sum(r['size_bytes'] for r in current_dma),
                    dma_reported_objects=len(current_dma),
                    same_size_dma_objects=sum(r['size_bytes']==5111808 for r in current_dma),
                    wallpaper_window=[388,320], desired_wallpaper_size=[480,320],wallpaper_user0_id=2),
                geometry=json.loads((work / 'geometry-host01/result.json').read_text()),
                candidate=candidate, host_controls=controls,
                patch_apply=json.loads((work / 'apply-result.json').read_text()),
                limits=['Named SurfaceFlinger allocation is direct evidence of its reported wallpaper capacity; DMA same-size association lacks a cross-view object ID.',
                        'Saved43/44 censuses both85objects/8978432exported bytes; current snapshot87objects/9351168is a different state, not a candidate comparison.',
                        'No root/SELinux/uptime/PID-start-time evidence is present in this three-line current identity file.',
                        'Source viewport gate changes only the reviewed intrinsic1243x1024/actual429x353 combination; original drawing remains elsewhere.',
                        'Source texture quad and GL_LINEAR filtering remain; two-stage downsampling may change pixels and requires visual QA.',
                        'Original bitmap/file, wallpaper settings, hardware services and signed bootchain are not modified.',
                        'No measured candidate allocator capacity, physical RAM reduction, responsiveness gain or80percent completion.'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = audit(args.work, args.capture)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],current_wallpaper=report['current_snapshot']['wallpaper_allocation'],
                          geometry=report['geometry']['model']),indent=2))
