"""One bounded video on image52 persistent AEC overlay; retain all media."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

from camera_stream_state import require_mode, active_mode


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
    report = dict(image=52, passed=False, record_start_requests=0, record_stop_requests=0, media_deleted=False,
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
        mode = active_mode(sh('initial-streams', 'dumpsys media.camera'))
        report['initial_mode'] = mode
        focus = sh('window', 'dumpsys window')
        assert any('mCurrentFocus=' in x and 'com.tcl.camera/com.tcl.camera.CameraActivity' in x for x in focus.splitlines())
        if mode == 'photo':
            guard()
            sh('video-mode', 'input keyevent 20')
        for attempt in range(12):
            state = sh('video-ready-' + str(attempt), 'dumpsys media.camera')
            try:
                report['streams_before'] = require_mode(state, 'video')
                break
            except ValueError:
                if attempt == 11:
                    raise
                time.sleep(2)
        assert provider() == original_pid
        guard()
        report['record_start_requests'] = 1
        (args.output / 'result.json').write_text(json.dumps(report, indent=2))
        sh('record-start', 'input keyevent 23')
        time.sleep(5)
        report['recording_streams'] = require_mode(sh('recording', 'dumpsys media.camera'), 'video', recording=True)
        guard()
        focus = sh('stop-window', 'dumpsys window')
        assert any('mCurrentFocus=' in x and 'com.tcl.camera/com.tcl.camera.CameraActivity' in x for x in focus.splitlines())
        report['record_stop_requests'] = 1
        sh('record-stop', 'input keyevent 23')
        new = set()
        for n in range(6):
            time.sleep(5)
            new = {f for f in files('files-after-' + str(n)) - before if f.lower().endswith('.mp4')}
            if new:
                break
        assert len(new) == 1, 'Expected one new finalized video'
        remote = new.pop()
        assert re.fullmatch(r'/data/media/0/DCIM/[A-Za-z0-9_./-]+\.[mM][pP]4', remote)
        local = args.output / 'captured.mp4'
        run('pull-video', ['pull', remote, str(local)])
        report['video_sha256'] = hashlib.sha256(local.read_bytes()).hexdigest()
        assert sh('remote-video-hash', 'sha256sum ' + remote).split()[0] == report['video_sha256']
        probe = subprocess.run(['ffprobe', '-v', 'error', '-show_streams', '-show_format', '-of', 'json', str(local)], capture_output=True, timeout=35)
        (args.output / 'ffprobe.json').write_bytes(probe.stdout)
        (args.output / 'ffprobe.stderr').write_bytes(probe.stderr)
        probe.check_returncode()
        info = json.loads(probe.stdout)
        streams = info['streams']
        assert len([x for x in streams if x['codec_type'] == 'video']) == 1
        assert len([x for x in streams if x['codec_type'] == 'audio']) == 1
        report['media_streams'] = [{k:x.get(k) for k in ('codec_type','codec_name','width','height','sample_rate','channels','start_time','duration','avg_frame_rate','nb_frames')} for x in streams]
        decode = subprocess.run(['ffmpeg', '-v', 'error', '-xerror', '-i', str(local), '-map', '0:v:0', '-map', '0:a:0', '-f', 'null', '-'], capture_output=True, timeout=60)
        (args.output / 'decode.stderr').write_bytes(decode.stderr)
        decode.check_returncode()
        report['video_audio_full_decode_passed'] = True
        sh('post-record-log', 'logcat -d -t 1500')
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
        report['limits'] = ['One injected-key recording; physical controls, video quality, microphone acoustics and audiovisual synchronization remain unverified.']
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    if not report['passed']:
        raise RuntimeError('Video trial failed; inspect retained evidence before any retry')


if __name__ == '__main__':
    main()
