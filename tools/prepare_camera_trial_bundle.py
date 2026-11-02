"""Reproduce the two historical camera trial patches offline; never contact a device.

The bundle is experimental, not an installed image or full camera-support claim.
Original vendor libraries remain untouched. Deployment needs a separately reviewed
identity-bound temporary-overlay procedure and restoration checks.
"""
import argparse
import hashlib
import json
from pathlib import Path

from prepare_camera_aec_message_lifetime import candidate as patch_aec
from prepare_camera_picture_buffers import candidate as patch_buffers


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def prepare(aec, camera, output):
    inputs = [
        ('libmmcamera2_stats_modules.so', '/vendor/lib/libmmcamera2_stats_modules.so',
         aec.read_bytes(), patch_aec),
        ('camera.msm8937.so', '/vendor/lib/hw/camera.msm8937.so',
         camera.read_bytes(), patch_buffers),
    ]
    # Validate every original before creating any bundle file.
    prepared = [(name, target, raw, patch(raw)) for name, target, raw, patch in inputs]
    output.mkdir(parents=True, exist_ok=False)
    files = []
    for name, target, original, patched in prepared:
        assert len(original) == len(patched)
        with (output / name).open('xb') as stream:
            stream.write(patched)
        files.append(dict(file=name, intended_vendor_path=target,
                          original_sha256=digest(original), candidate_sha256=digest(patched),
                          bytes=len(patched),
                          changed_bytes=sum(x != y for x, y in zip(original, patched))))
    report = dict(format_version=1, files=files, installed=False,
                  scope='Historical AEC lifetime and picture-buffer candidates only',
                  limits=['No provider lazy-start change', 'No application APK included',
                          'Historical photo used corrected Camera2; TCL Camera compatibility untested',
                          'No current-image camera lifecycle, memory or image-quality validation'])
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('aec', 'camera', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.aec, args.camera, args.output), indent=2))
