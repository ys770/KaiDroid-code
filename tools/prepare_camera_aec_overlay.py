"""Prepare a private system-only AEC overlay bundle, never install or flash.

The source library is proprietary and stays in ignored output. The separately
reviewed image packer must merge the context fragment and retain the existing
init mounton policy. This bundle alone is not camera support: the compatible
camera APK and physical acceptance are separate requirements.
"""
import argparse
import hashlib
import json
from pathlib import Path

from prepare_camera_aec_message_lifetime import SOURCE_SHA256, candidate

CANDIDATE_SHA256 = '41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0'
RC = '''# System-only AEC lifetime correction; original vendor bytes are retained.
# post-fs-data precedes the captured boot action's class_start hal.
on post-fs-data
    mount none /system/etc/kaidroid-camera/libmmcamera2_stats_modules.so /vendor/lib/libmmcamera2_stats_modules.so bind
'''
CONTEXT = '/system/etc/kaidroid-camera(/.*)? u:object_r:vendor_file:s0\n'


def prepare(source, output):
    source = source.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('Output must be a fresh directory')
    original = source.read_bytes()
    patched = candidate(original)
    if hashlib.sha256(patched).hexdigest() != CANDIDATE_SHA256:
        raise ValueError('AEC candidate differs from tested artifact')
    files = {
        'system/etc/kaidroid-camera/libmmcamera2_stats_modules.so': patched,
        'system/etc/init/kaidroid-camera.rc': RC.encode(),
        'file_contexts.fragment': CONTEXT.encode(),
    }
    output.mkdir(parents=True)
    for name, data in files.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
    report = {
        'original_sha256': SOURCE_SHA256, 'candidate_sha256': CANDIDATE_SHA256,
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        'target_uid': 0, 'target_gid': 0, 'file_mode': '0644', 'directory_mode': '0755',
        'existing_policy_required': '(allow init vendor_file (file (mounton)))',
        'picture_buffer_hal_changed': False, 'camera_apk_included': False,
        'vendor_partition_written': False, 'installed': False,
        'reference_image': 48,
        'required_validation': [
            'Merge and compile context fragment in a separately reviewed image stage',
            'Verify full raw image metadata/xattr closure and original vendor hash',
            'Verify post-fs-data mount and provider mapped candidate after actual reboot',
            'Pair with separately validated camera APK, then photo/video and rollback tests',
        ],
    }
    (output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), indent=2))
