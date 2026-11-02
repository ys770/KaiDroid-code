"""One photo on image52's persistent AEC overlay; preserve media and app data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from camera_stream_state import require_mode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    adb = ['/opt/kaidroid/source/Documents/platform-tools/adb.exe', '-s', 'DEVICE_SERIAL_REQUIRED']
    target = '/vendor/lib/libmmcamera2_stats_modules.so'
    digest = '41e2723ff78ecd0e5a5c2cd94209626abaf15335e4274172de9797867e58b8c0'
    permissions = ['CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE']
    report = dict(image=52, passed=False, shutter_requests=0, media_deleted=False,
                  vendor_modified=False, provider_restarted=False)
    sequence = 0
    granted = []
    initial = None

    def run(label, command):
        nonlocal sequence
        sequence += 1
        prefix = args.output / f'{sequence:02d}-{label}'
        prefix.with_suffix('.started.json').write_text(json.dumps(command))
        r = subprocess.run(adb + command, capture_output=True, timeout=35)
        prefix.with_suffix('.stdout').write_bytes(r.stdout)
        prefix.with_suffix('.stderr').write_bytes(r.stderr)
        r.check_returncode()
        return r.stdout

    def sh(label, command):
        return run(label, ['shell', command]).decode().replace('\r', '').strip()

    def identity():
        return sh('identity', 'getprop ro.kaidroid.image; cat /proc/sys/kernel/random/boot_id; '
                  'id -u; getenforce; pidof system_server; pidof com.android.systemui')

    def guard():
        assert identity() == initial, 'Boot or system processes changed'

    def provider():
        pid = sh('provider-pid', 'pidof android.hardware.camera.provider@2.4-service')
        assert pid.isdigit()
        maps = sh('provider-maps', 'cat /proc/' + pid + '/maps')
        assert target in maps
        assert sh('provider-hash', 'sha256sum /proc/' + pid + '/root' + target).split()[0] == digest
        return pid

    def files(label):
        return set(sh(label, 'if test -d /data/media/0/DCIM; then find /data/media/0/DCIM -type f; fi').splitlines())

    try:
        initial = identity()
        fields = initial.splitlines()
        assert fields[:4] == ['52', args.boot, '0', 'Enforcing'] and len(fields) == 6
        mounts = sh('mounts', 'cat /proc/mounts')
        assert any(line.split()[1] == target for line in mounts.splitlines())
        original_pid = provider()
        pkg = sh('package-before', 'dumpsys package com.tcl.camera')
        assert 'userId=10104' in pkg
        for perm in permissions:
            assert re.search(r'android.permission.' + perm + r': granted=false', pkg)
        path = sh('apk-path', 'pm path com.tcl.camera')
        assert path.startswith('package:/data/app/') and '\n' not in path
        assert sh('apk-hash', 'sha256sum ' + path[8:]).split()[0] == 'cbc8276c752d46f157cdec987596c1a0c3e2c5e3f8f261f7811fd219e83c85e3'
        before = files('files-before')
        for perm in permissions:
            granted.append(perm)  # Restore even if the command's reply is lost.
            sh('grant-' + perm, 'pm grant com.tcl.camera android.permission.' + perm)
        sh('launch', 'am start -W -n com.tcl.camera/.CameraActivity')
        time.sleep(10)
        report['streams_before'] = require_mode(sh('streams-before', 'dumpsys media.camera'), 'photo')
        focus = sh('window', 'dumpsys window')
        assert any('mCurrentFocus=' in x and 'com.tcl.camera/com.tcl.camera.CameraActivity' in x for x in focus.splitlines())
        assert provider() == original_pid
        guard()
        report['shutter_requests'] = 1
        (args.output / 'result.json').write_text(json.dumps(report, indent=2))
        sh('shutter-once', 'input keyevent 23')
        new = set()
        for n in range(6):
            time.sleep(5)
            new = files('files-after-' + str(n)) - before
            if new:
                break
        assert len(new) == 1, 'Expected one new photo'
        remote = new.pop()
        assert re.fullmatch(r'/data/media/0/DCIM/[A-Za-z0-9_./-]+\.[jJ][pP][eE]?[gG]', remote)
        local = args.output / 'captured.jpg'
        run('pull-photo', ['pull', remote, str(local)])
        from PIL import Image
        with Image.open(local) as photo:
            photo.load()  # Decode pixels, not just the header.
            assert photo.format == 'JPEG' and min(photo.size) > 0
            report['photo_dimensions'] = list(photo.size)
        report['photo_sha256'] = hashlib.sha256(local.read_bytes()).hexdigest()
        assert sh('remote-photo-hash', 'sha256sum ' + remote).split()[0] == report['photo_sha256']
        report['streams_after'] = require_mode(sh('streams-after', 'dumpsys media.camera'), 'photo')
        assert provider() == original_pid
        guard()
        report['passed'] = True
    except Exception as error:
        report['error'] = repr(error)
    finally:
        if granted:
            try:
                guard()
                sh('stop', 'am force-stop com.tcl.camera')
                for perm in granted:
                    sh('revoke-' + perm, 'pm revoke com.tcl.camera android.permission.' + perm)
                pkg = sh('package-after', 'dumpsys package com.tcl.camera')
                assert all(re.search(r'android.permission.' + perm + r': granted=false', pkg) for perm in permissions)
                sh('home', 'input keyevent 3')
                assert provider() == original_pid
                guard()
                report['cleanup_complete'] = True
            except Exception as error:
                report['cleanup_error'] = repr(error)
                report['passed'] = False
        report['limits'] = ['One injected-key photo; physical shutter, orientation, image quality and video remain unverified.']
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Photo trial failed; inspect retained evidence before any retry')


if __name__ == '__main__':
    main()
